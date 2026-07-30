/**
 * lunagi-coti-api — Backend del Cotizador LUNA GI
 *
 * Da soporte a lo que el HTML estatico no puede hacer solo:
 *   - Usuarios reales compartidos entre dispositivos (los crea el superadmin)
 *   - Auditoria de ingresos y acciones
 *
 * Patron tomado del worker de LINDERO.COTI (lindero-coti-api), simplificado
 * para lo que necesita este cotizador.
 *
 * Almacenamiento (KV namespace USUARIOS):
 *   user:<id>       -> datos del usuario (id = email o nombre, en minusculas)
 *   token:<token>   -> id del usuario  (TTL 7 dias)
 *   audit:<ts>:<r>  -> entrada de bitacora (TTL 90 dias)
 *   ratelimit:<k>   -> contador de rate limiting (TTL 60 s)
 */

const USERS_PREFIX = 'user:';
const TOKENS_PREFIX = 'token:';
const AUDIT_PREFIX = 'audit:';
const RATE_LIMIT_PREFIX = 'ratelimit:';

const TOKEN_TTL = 7 * 24 * 60 * 60;   // 7 dias
const AUDIT_TTL = 90 * 24 * 60 * 60;  // 90 dias
const RATE_LIMIT_WINDOW = 60;         // 1 minuto
const MAX_LOGIN_ATTEMPTS = 5;         // por IP y por minuto
const MAX_REQUESTS = 100;             // por IP y por minuto

// Permisos (bit flags)
const PERM = {
  VIEW_COTIZADOR: 1,
  VIEW_AUDIT: 64,
  MANAGE_USERS: 128
};

const ROLES = {
  SUPERADMIN: PERM.VIEW_COTIZADOR | PERM.VIEW_AUDIT | PERM.MANAGE_USERS, // 193
  ASESOR: PERM.VIEW_COTIZADOR                                            // 1
};

// ── Utilidades ────────────────────────────────────────────────────────

function normalizarId(v) {
  return String(v || '').trim().toLowerCase();
}

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/** PBKDF2-SHA256, 100k iteraciones, sal aleatoria de 16 bytes. */
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256
  );
  return { salt: bufToHex(salt), hash: bufToHex(bits) };
}

/** Comparacion en tiempo constante: no revela cuanto coincide. */
function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function generarToken() {
  return bufToHex(crypto.getRandomValues(new Uint8Array(32))); // 64 chars
}

function getIP(request) {
  return request.headers.get('CF-Connecting-IP') || 'desconocida';
}

async function checkRateLimit(env, clave, maximo) {
  const key = RATE_LIMIT_PREFIX + clave;
  const actual = parseInt(await env.USUARIOS.get(key) || '0', 10);
  if (actual >= maximo) return false;
  await env.USUARIOS.put(key, String(actual + 1), { expirationTtl: RATE_LIMIT_WINDOW });
  return true;
}

// ── Respuestas ────────────────────────────────────────────────────────

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,X-Auth-Token',
    'Access-Control-Max-Age': '86400'
  };
}

function json(env, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-store',
      ...corsHeaders(env)
    }
  });
}

const error = (env, msg, status) => json(env, { error: msg }, status);

// ── Usuarios y auditoria ──────────────────────────────────────────────

async function getUserByToken(env, token) {
  if (!token) return null;
  const id = await env.USUARIOS.get(TOKENS_PREFIX + token);
  if (!id) return null;
  const raw = await env.USUARIOS.get(USERS_PREFIX + id);
  if (!raw) return null;
  const user = JSON.parse(raw);
  if (user.activo === false) return null;
  return { id, ...user };
}

function tiene(user, permiso) {
  return user && (user.permissions & permiso) !== 0;
}

/** Los datos que se pueden devolver al frontend (nunca el hash ni la sal). */
function userPublico(id, u) {
  return {
    id,
    nombre: u.nombre,
    rol: u.rol,
    permissions: u.permissions,
    activo: u.activo !== false,
    creadoEn: u.creadoEn,
    creadoPor: u.creadoPor,
    ultimoAcceso: u.ultimoAcceso || null
  };
}

async function auditar(env, request, usuario, accion, detalles = {}) {
  const ts = new Date().toISOString();
  const sufijo = bufToHex(crypto.getRandomValues(new Uint8Array(4)));
  const entrada = {
    ts,
    usuario: usuario || '—',
    accion,
    ip: getIP(request),
    ua: (request.headers.get('User-Agent') || '').substring(0, 120),
    detalles
  };
  await env.USUARIOS.put(AUDIT_PREFIX + ts + ':' + sufijo, JSON.stringify(entrada), {
    expirationTtl: AUDIT_TTL
  });
}

// ── Worker ────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const ruta = url.pathname.replace(/\/+$/, '') || '/';
    const metodo = request.method;

    if (metodo === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    if (!env.USUARIOS) {
      return error(env, 'El namespace KV USUARIOS no esta configurado', 500);
    }

    // Rate limiting general por IP
    const ip = getIP(request);
    if (!await checkRateLimit(env, 'req:' + ip, MAX_REQUESTS)) {
      return error(env, 'Demasiadas solicitudes. Espera un minuto.', 429);
    }

    try {
      if (ruta === '/api/health') {
        return json(env, { ok: true, servicio: 'lunagi-coti-api' });
      }
      if (ruta === '/api/bootstrap' && metodo === 'POST') return bootstrap(request, env);
      if (ruta === '/api/login' && metodo === 'POST') return login(request, env);
      if (ruta === '/api/logout' && metodo === 'POST') return logout(request, env);
      if (ruta === '/api/me' && metodo === 'GET') return me(request, env);
      if (ruta === '/api/users') return usuarios(request, env, metodo);
      if (ruta.startsWith('/api/users/')) {
        return usuarioIndividual(request, env, metodo, decodeURIComponent(ruta.slice('/api/users/'.length)));
      }
      if (ruta === '/api/audit' && metodo === 'GET') return auditoria(request, env, url);

      return error(env, 'Ruta no encontrada', 404);
    } catch (e) {
      return error(env, 'Error interno: ' + e.message, 500);
    }
  }
};

// ── Handlers ──────────────────────────────────────────────────────────

/** Crea el primer superadmin. Solo funciona si aun no hay ningun usuario. */
async function bootstrap(request, env) {
  const existentes = await env.USUARIOS.list({ prefix: USERS_PREFIX, limit: 1 });
  if (existentes.keys.length > 0) {
    return error(env, 'Ya existen usuarios. El bootstrap solo corre una vez.', 409);
  }
  const body = await request.json().catch(() => ({}));
  // Se recortan espacios: al guardar el secreto por CLI es facil que se cuele
  // un salto de linea al final.
  const secreto = String(request.headers.get('X-Bootstrap-Secret') || '').trim();
  const esperado = String(env.BOOTSTRAP_SECRET || '').trim();
  if (!esperado || !timingSafeCompare(secreto, esperado)) {
    return error(env, 'Secreto de bootstrap invalido', 403);
  }
  const id = normalizarId(body.id);
  if (!id || !body.password) return error(env, 'Faltan id y password', 400);
  if (String(body.password).length < 8) {
    return error(env, 'La contrasena debe tener al menos 8 caracteres', 400);
  }

  const { salt, hash } = await hashPassword(String(body.password));
  await env.USUARIOS.put(USERS_PREFIX + id, JSON.stringify({
    nombre: body.nombre || body.id,
    rol: 'SUPERADMIN',
    permissions: ROLES.SUPERADMIN,
    passwordSalt: salt,
    passwordHash: hash,
    activo: true,
    creadoEn: new Date().toISOString(),
    creadoPor: 'bootstrap'
  }));
  await auditar(env, request, id, 'BOOTSTRAP', { rol: 'SUPERADMIN' });
  return json(env, { ok: true, id, rol: 'SUPERADMIN' }, 201);
}

async function login(request, env) {
  const ip = getIP(request);
  if (!await checkRateLimit(env, 'login:' + ip, MAX_LOGIN_ATTEMPTS)) {
    return error(env, 'Demasiados intentos. Espera un minuto.', 429);
  }

  const body = await request.json().catch(() => ({}));
  const id = normalizarId(body.id);
  const password = String(body.password || '');

  const raw = id ? await env.USUARIOS.get(USERS_PREFIX + id) : null;

  // Aunque el usuario no exista, calculamos un hash igual para que el tiempo
  // de respuesta no delate si el id es valido.
  const user = raw ? JSON.parse(raw) : null;
  const salt = user ? user.passwordSalt : '00000000000000000000000000000000';
  const { hash } = await hashPassword(password, salt);

  const ok = user && user.activo !== false && timingSafeCompare(hash, user.passwordHash);
  if (!ok) {
    await auditar(env, request, id || '—', 'LOGIN_FALLIDO', {});
    return error(env, 'Usuario o contrasena incorrectos', 401);
  }

  const token = generarToken();
  await env.USUARIOS.put(TOKENS_PREFIX + token, id, { expirationTtl: TOKEN_TTL });

  user.ultimoAcceso = new Date().toISOString();
  await env.USUARIOS.put(USERS_PREFIX + id, JSON.stringify(user));
  await auditar(env, request, id, 'LOGIN', { rol: user.rol });

  return json(env, { token, usuario: userPublico(id, user) });
}

async function logout(request, env) {
  const token = request.headers.get('X-Auth-Token');
  const user = await getUserByToken(env, token);
  if (token) await env.USUARIOS.delete(TOKENS_PREFIX + token);
  if (user) await auditar(env, request, user.id, 'LOGOUT', {});
  return json(env, { ok: true });
}

async function me(request, env) {
  const user = await getUserByToken(env, request.headers.get('X-Auth-Token'));
  if (!user) return error(env, 'No autenticado', 401);
  return json(env, { usuario: userPublico(user.id, user) });
}

async function usuarios(request, env, metodo) {
  const actual = await getUserByToken(env, request.headers.get('X-Auth-Token'));
  if (!actual) return error(env, 'No autenticado', 401);
  if (!tiene(actual, PERM.MANAGE_USERS)) return error(env, 'Sin permiso para gestionar usuarios', 403);

  if (metodo === 'GET') {
    const lista = await env.USUARIOS.list({ prefix: USERS_PREFIX });
    const items = [];
    for (const k of lista.keys) {
      const id = k.name.slice(USERS_PREFIX.length);
      const raw = await env.USUARIOS.get(k.name);
      if (raw) items.push(userPublico(id, JSON.parse(raw)));
    }
    items.sort((a, b) => String(a.id).localeCompare(String(b.id)));
    return json(env, { items });
  }

  if (metodo === 'POST') {
    const body = await request.json().catch(() => ({}));
    const id = normalizarId(body.id);
    const password = String(body.password || '');
    if (!id || !password) return error(env, 'Faltan id y password', 400);
    if (password.length < 8) return error(env, 'La contrasena debe tener al menos 8 caracteres', 400);

    if (await env.USUARIOS.get(USERS_PREFIX + id)) {
      return error(env, 'Ese usuario ya existe', 409);
    }
    const rol = body.rol === 'SUPERADMIN' ? 'SUPERADMIN' : 'ASESOR';
    const { salt, hash } = await hashPassword(password);
    await env.USUARIOS.put(USERS_PREFIX + id, JSON.stringify({
      nombre: body.nombre || body.id,
      rol,
      permissions: ROLES[rol],
      passwordSalt: salt,
      passwordHash: hash,
      activo: true,
      creadoEn: new Date().toISOString(),
      creadoPor: actual.id
    }));
    await auditar(env, request, actual.id, 'CREAR_USUARIO', { objetivo: id, rol });
    return json(env, { ok: true, id, rol }, 201);
  }

  return error(env, 'Metodo no permitido', 405);
}

async function usuarioIndividual(request, env, metodo, idBruto) {
  const actual = await getUserByToken(env, request.headers.get('X-Auth-Token'));
  if (!actual) return error(env, 'No autenticado', 401);
  if (!tiene(actual, PERM.MANAGE_USERS)) return error(env, 'Sin permiso para gestionar usuarios', 403);

  const id = normalizarId(idBruto);
  const raw = await env.USUARIOS.get(USERS_PREFIX + id);
  if (!raw) return error(env, 'Usuario no encontrado', 404);
  const user = JSON.parse(raw);

  if (metodo === 'PUT') {
    const body = await request.json().catch(() => ({}));
    const cambios = [];

    if (body.password) {
      if (String(body.password).length < 8) {
        return error(env, 'La contrasena debe tener al menos 8 caracteres', 400);
      }
      const { salt, hash } = await hashPassword(String(body.password));
      user.passwordSalt = salt;
      user.passwordHash = hash;
      cambios.push('password');
      await invalidarTokens(env, id); // al cambiar la clave, se cierran sus sesiones
    }
    if (body.nombre) { user.nombre = body.nombre; cambios.push('nombre'); }
    if (body.rol === 'SUPERADMIN' || body.rol === 'ASESOR') {
      if (id === actual.id && body.rol !== 'SUPERADMIN') {
        return error(env, 'No puedes quitarte a ti mismo el rol de superadmin', 400);
      }
      user.rol = body.rol;
      user.permissions = ROLES[body.rol];
      cambios.push('rol');
    }
    if (typeof body.activo === 'boolean') {
      if (id === actual.id && body.activo === false) {
        return error(env, 'No puedes desactivarte a ti mismo', 400);
      }
      user.activo = body.activo;
      cambios.push(body.activo ? 'reactivado' : 'desactivado');
      if (!body.activo) await invalidarTokens(env, id);
    }

    await env.USUARIOS.put(USERS_PREFIX + id, JSON.stringify(user));
    await auditar(env, request, actual.id, 'EDITAR_USUARIO', { objetivo: id, cambios });
    return json(env, { ok: true, usuario: userPublico(id, user) });
  }

  if (metodo === 'DELETE') {
    if (id === actual.id) return error(env, 'No puedes eliminarte a ti mismo', 400);
    await env.USUARIOS.delete(USERS_PREFIX + id);
    await invalidarTokens(env, id);
    await auditar(env, request, actual.id, 'ELIMINAR_USUARIO', { objetivo: id });
    return json(env, { ok: true });
  }

  return error(env, 'Metodo no permitido', 405);
}

/** Borra los tokens activos de un usuario (al cambiarle la clave o desactivarlo). */
async function invalidarTokens(env, id) {
  const lista = await env.USUARIOS.list({ prefix: TOKENS_PREFIX });
  for (const k of lista.keys) {
    const dueno = await env.USUARIOS.get(k.name);
    if (dueno === id) await env.USUARIOS.delete(k.name);
  }
}

async function auditoria(request, env, url) {
  const actual = await getUserByToken(env, request.headers.get('X-Auth-Token'));
  if (!actual) return error(env, 'No autenticado', 401);
  if (!tiene(actual, PERM.VIEW_AUDIT)) return error(env, 'Sin permiso para ver la bitacora', 403);

  const limite = Math.min(parseInt(url.searchParams.get('limite') || '100', 10), 500);
  const filtroUsuario = normalizarId(url.searchParams.get('usuario') || '');
  const filtroAccion = (url.searchParams.get('accion') || '').toUpperCase();

  const lista = await env.USUARIOS.list({ prefix: AUDIT_PREFIX });
  // Las claves llevan el timestamp ISO al inicio, asi que ordenan cronologicamente.
  const claves = lista.keys.map(k => k.name).sort().reverse();

  const items = [];
  for (const clave of claves) {
    if (items.length >= limite) break;
    const raw = await env.USUARIOS.get(clave);
    if (!raw) continue;
    const entrada = JSON.parse(raw);
    if (filtroUsuario && normalizarId(entrada.usuario) !== filtroUsuario) continue;
    if (filtroAccion && entrada.accion !== filtroAccion) continue;
    items.push(entrada);
  }

  return json(env, { items, total: items.length });
}
