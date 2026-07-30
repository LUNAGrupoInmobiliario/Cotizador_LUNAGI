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
const COT_PREFIX = 'cot:';
const LANDING_PREFIX = 'landing:';

const TOKEN_TTL = 7 * 24 * 60 * 60;      // 7 dias
const AUDIT_TTL = 90 * 24 * 60 * 60;     // 90 dias
const LANDING_TTL = 30 * 24 * 60 * 60;   // 30 dias
const RATE_LIMIT_WINDOW = 60;            // 1 minuto
const MAX_LOGIN_ATTEMPTS = 5;            // por IP y por minuto
const MAX_REQUESTS = 100;                // por IP y por minuto

// Permisos (bit flags)
const PERM = {
  VIEW_COTIZADOR: 1,
  CREATE_COTIZACIONES: 2,
  VIEW_ALL_COTIZACIONES: 8,
  VIEW_AUDIT: 64,
  MANAGE_USERS: 128
};

const ROLES = {
  SUPERADMIN: PERM.VIEW_COTIZADOR | PERM.CREATE_COTIZACIONES | PERM.VIEW_ALL_COTIZACIONES |
              PERM.VIEW_AUDIT | PERM.MANAGE_USERS,                    // 203
  ASESOR: PERM.VIEW_COTIZADOR | PERM.CREATE_COTIZACIONES              // 3
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
  // Los permisos se recalculan desde el rol en cada peticion. Si se guardara
  // solo el numero, los usuarios creados antes de agregar un permiso nuevo se
  // quedarian sin el hasta migrarlos a mano. El rol es la fuente de verdad.
  if (ROLES[user.rol] !== undefined) user.permissions = ROLES[user.rol];
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
    permissions: ROLES[u.rol] !== undefined ? ROLES[u.rol] : u.permissions,
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
      if (ruta === '/api/cotizaciones') return cotizaciones(request, env, metodo);
      if (ruta.startsWith('/api/cotizaciones/')) {
        return cotizacionIndividual(request, env, metodo, decodeURIComponent(ruta.slice('/api/cotizaciones/'.length)));
      }
      // Landing publica: la abre el cliente, sin sesion
      if (ruta.startsWith('/landing/') && metodo === 'GET') {
        return landing(request, env, decodeURIComponent(ruta.slice('/landing/'.length)));
      }

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

// ── LANDING PUBLICA ───────────────────────────────────────────────────

function escHtml(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function dinero(v, moneda) {
  if (v == null || v === '') return '—';
  const n = typeof v === 'number' ? v : parseFloat(String(v).replace(/[^0-9.-]/g, ''));
  if (isNaN(n)) return escHtml(v);
  return (moneda === 'USD' ? 'USD ' : '$') +
    n.toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function fechaLarga(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso.length <= 10 ? iso + 'T12:00:00' : iso);
    return d.toLocaleDateString('es-MX', { day: '2-digit', month: 'long', year: 'numeric' });
  } catch (e) { return escHtml(iso); }
}

function paginaSimple(titulo, mensaje) {
  return '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + escHtml(titulo) + '</title></head>' +
    '<body style="font-family:system-ui,sans-serif;background:#f3f4f6;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px">' +
    '<div style="background:#fff;border-radius:16px;padding:36px;max-width:420px;text-align:center;' +
    'box-shadow:0 4px 24px rgba(0,0,0,.08)">' +
    '<h1 style="color:#134289;font-size:21px;margin:0 0 10px">' + escHtml(titulo) + '</h1>' +
    '<p style="color:#4b5563;margin:0;line-height:1.6">' + escHtml(mensaje) + '</p>' +
    '</div></body></html>';
}

function htmlLanding(c) {
  const m = c.moneda;
  const filas = (c.amortizacion || []).map(function (f, i) {
    return '<tr><td>' + (i + 1) + '</td><td>' + escHtml(f.fecha || '') + '</td>' +
      '<td>' + dinero(f.balanceInicial, m) + '</td>' +
      '<td>' + dinero(f.pago, m) + '</td>' +
      '<td>' + dinero(f.interes, m) + '</td>' +
      '<td>' + dinero(f.capital, m) + '</td>' +
      '<td>' + dinero(f.balanceFinal, m) + '</td></tr>';
  }).join('');

  const ubicacion = [
    c.manzana ? 'Manzana ' + escHtml(c.manzana) : '',
    c.lote ? 'Lote ' + escHtml(c.lote) : ''
  ].filter(Boolean).join(' · ') || '—';

  return '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">' +
'<meta name="viewport" content="width=device-width,initial-scale=1">' +
'<meta name="theme-color" content="#134289">' +
'<meta name="robots" content="noindex,nofollow">' +
'<title>Cotizacion ' + escHtml(c.folio) + ' — LUNA Grupo Inmobiliario</title>' +
'<link rel="preconnect" href="https://fonts.googleapis.com">' +
'<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
'<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">' +
'<style>' +
'*{margin:0;padding:0;box-sizing:border-box}' +
'body{font-family:Inter,sans-serif;background:#f3f4f6;color:#111827;-webkit-font-smoothing:antialiased}' +
'header{background:#134289;color:#fff;padding:26px 20px;text-align:center}' +
'header h1{font-family:Barlow Condensed,sans-serif;font-size:26px;letter-spacing:.5px}' +
'header p{opacity:.85;font-size:13px;margin-top:4px}' +
'main{max-width:900px;margin:0 auto;padding:22px 16px 60px}' +
'.card{background:#fff;border-radius:14px;padding:22px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}' +
'.card h2{font-family:Barlow Condensed,sans-serif;font-size:16px;color:#134289;letter-spacing:.6px;' +
'text-transform:uppercase;margin-bottom:14px;padding-bottom:9px;border-bottom:2px solid #e5e7eb}' +
'.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}' +
'.dato .k{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#6b7280;margin-bottom:3px}' +
'.dato .v{font-size:15px;font-weight:600}' +
'.destacados{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}' +
'.destacado{background:linear-gradient(135deg,#134289,#00a3e0);color:#fff;border-radius:12px;padding:16px;text-align:center}' +
'.destacado .k{font-size:10px;text-transform:uppercase;letter-spacing:.8px;opacity:.9;margin-bottom:5px}' +
'.destacado .v{font-family:Barlow Condensed,sans-serif;font-size:23px;font-weight:700}' +
'.tabla-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}' +
'table{width:100%;border-collapse:collapse;font-size:12.5px;min-width:640px}' +
'th{background:#f9fafb;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.6px;' +
'color:#4b5563;padding:9px 7px;border-bottom:2px solid #e5e7eb;white-space:nowrap}' +
'td{padding:8px 7px;border-bottom:1px solid #f3f4f6;white-space:nowrap}' +
'tbody tr:nth-child(even){background:#fafafa}' +
'footer{max-width:900px;margin:0 auto;padding:0 16px 40px;font-size:11.5px;color:#6b7280;line-height:1.65}' +
'footer strong{color:#374151}' +
'@media print{body{background:#fff}.card{box-shadow:none;border:1px solid #e5e7eb}}' +
'</style></head><body>' +

'<header><h1>Cotizacion de Lote de Inversion</h1>' +
'<p>LUNA Grupo Inmobiliario · Folio ' + escHtml(c.folio) + '</p></header>' +

'<main>' +

'<div class="card"><h2>Datos generales</h2><div class="grid">' +
'<div class="dato"><div class="k">Inversionista</div><div class="v">' + escHtml(c.cliente || '—') + '</div></div>' +
'<div class="dato"><div class="k">Proyecto</div><div class="v">' + escHtml(c.proyecto || '—') + '</div></div>' +
'<div class="dato"><div class="k">Ubicacion</div><div class="v">' + ubicacion + '</div></div>' +
'<div class="dato"><div class="k">Asesor</div><div class="v">' + escHtml(c.asesor || '—') + '</div></div>' +
'<div class="dato"><div class="k">Fecha</div><div class="v">' + fechaLarga(c.creadoEn) + '</div></div>' +
'<div class="dato"><div class="k">Moneda</div><div class="v">' + escHtml(m) + '</div></div>' +
'</div></div>' +

'<div class="card"><h2>Resumen</h2><div class="destacados">' +
'<div class="destacado"><div class="k">Precio</div><div class="v">' + dinero(c.precioPropiedad, m) + '</div></div>' +
'<div class="destacado"><div class="k">Pago mensual</div><div class="v">' + dinero(c.pagoMensual, m) + '</div></div>' +
'<div class="destacado"><div class="k">Plazo</div><div class="v">' + escHtml(c.plazoMeses || '—') + ' meses</div></div>' +
'<div class="destacado"><div class="k">Total a pagar</div><div class="v">' + dinero(c.totalPagar, m) + '</div></div>' +
'</div></div>' +

'<div class="card"><h2>Detalle del lote y financiamiento</h2><div class="grid">' +
'<div class="dato"><div class="k">Precio por m2</div><div class="v">' + dinero(c.precioM2, m) + '</div></div>' +
'<div class="dato"><div class="k">Superficie</div><div class="v">' + escHtml(c.m2 || '—') + ' m2</div></div>' +
'<div class="dato"><div class="k">Apartado</div><div class="v">' + dinero(c.apartado, m) + '</div></div>' +
'<div class="dato"><div class="k">Enganche</div><div class="v">' + dinero(c.engancheCalculado, m) + '</div></div>' +
'<div class="dato"><div class="k">Comision de apertura</div><div class="v">' + dinero(c.comisionApertura, m) + '</div></div>' +
'<div class="dato"><div class="k">Monto a financiar</div><div class="v">' + dinero(c.montoFinanciar, m) + '</div></div>' +
'<div class="dato"><div class="k">Tasa anual</div><div class="v">' + escHtml(c.tasaAnual || '—') + '%</div></div>' +
'<div class="dato"><div class="k">Fecha de reserva</div><div class="v">' + fechaLarga(c.fechaReserva) + '</div></div>' +
'<div class="dato"><div class="k">Fecha de enganche</div><div class="v">' + fechaLarga(c.fechaEnganche) + '</div></div>' +
'<div class="dato"><div class="k">Primer pago</div><div class="v">' + fechaLarga(c.fechaPrimerPago) + '</div></div>' +
'</div></div>' +

(filas ?
'<div class="card"><h2>Tabla de amortizacion</h2><div class="tabla-wrap"><table>' +
'<thead><tr><th>#</th><th>Fecha</th><th>Balance inicial</th><th>Pago</th>' +
'<th>Interes</th><th>Capital</th><th>Balance final</th></tr></thead>' +
'<tbody>' + filas + '</tbody></table></div></div>' : '') +

'</main>' +

'<footer>' +
'<p><strong>Vigencia:</strong> esta cotizacion es valida por 5 dias naturales a partir de su emision. ' +
'Despues de ese plazo los precios y condiciones pueden cambiar.</p>' +
'<p style="margin-top:8px"><strong>Apartado:</strong> el pago del apartado no es reembolsable. ' +
'En caso de desistimiento se aplicara a gastos administrativos y de oportunidad.</p>' +
'<p style="margin-top:8px"><strong>Confidencialidad:</strong> este documento contiene informacion ' +
'confidencial de uso exclusivo para su destinatario.</p>' +
'<p style="margin-top:14px;color:#9ca3af">Enlace privado. Expira el ' + fechaLarga(c.landingExpira) + '.</p>' +
'</footer></body></html>';
}

async function landing(request, env, token) {
  if (!token) return new Response(paginaSimple('Enlace incompleto', 'El enlace no esta completo.'), {
    status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });

  const folio = await env.USUARIOS.get(LANDING_PREFIX + token);
  if (!folio) {
    return new Response(paginaSimple(
      'Enlace no disponible',
      'Este enlace ya expiro o no es valido. Los enlaces de cotizacion duran 30 dias. Pide uno nuevo a tu asesor.'
    ), { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  const raw = await env.USUARIOS.get(COT_PREFIX + folio);
  if (!raw) {
    return new Response(paginaSimple(
      'Cotizacion no disponible',
      'La cotizacion asociada a este enlace ya no existe.'
    ), { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  return new Response(htmlLanding(JSON.parse(raw)), {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Robots-Tag': 'noindex, nofollow',
      'Cache-Control': 'no-store'
    }
  });
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

// ── COTIZACIONES Y LANDINGS ───────────────────────────────────────────

function generarFolio(fecha) {
  const f = fecha.toISOString().slice(0, 10).replace(/-/g, '');
  const r = bufToHex(crypto.getRandomValues(new Uint8Array(2))).toUpperCase();
  return 'COT-' + f + '-' + r;
}

/** Resumen para listados: sin la tabla de amortizacion, que es larga. */
function cotResumen(c) {
  return {
    folio: c.folio,
    cliente: c.cliente,
    proyecto: c.proyecto,
    asesor: c.asesor,
    manzana: c.manzana,
    lote: c.lote,
    moneda: c.moneda,
    precioPropiedad: c.precioPropiedad,
    pagoMensual: c.pagoMensual,
    plazoMeses: c.plazoMeses,
    creadoEn: c.creadoEn,
    creadoPor: c.creadoPor,
    landingToken: c.landingToken,
    landingExpira: c.landingExpira
  };
}

async function cotizaciones(request, env, metodo) {
  const actual = await getUserByToken(env, request.headers.get('X-Auth-Token'));
  if (!actual) return error(env, 'No autenticado', 401);

  if (metodo === 'GET') {
    const lista = await env.USUARIOS.list({ prefix: COT_PREFIX });
    const verTodas = tiene(actual, PERM.VIEW_ALL_COTIZACIONES);
    const items = [];
    for (const k of lista.keys) {
      const raw = await env.USUARIOS.get(k.name);
      if (!raw) continue;
      const c = JSON.parse(raw);
      // El asesor solo ve las suyas; el superadmin ve todas.
      if (!verTodas && c.creadoPor !== actual.id) continue;
      items.push(cotResumen(c));
    }
    items.sort((a, b) => String(b.creadoEn).localeCompare(String(a.creadoEn)));
    return json(env, { items, total: items.length });
  }

  if (metodo === 'POST') {
    if (!tiene(actual, PERM.CREATE_COTIZACIONES)) {
      return error(env, 'Sin permiso para crear cotizaciones', 403);
    }
    const body = await request.json().catch(() => ({}));
    if (!body.cliente || !body.proyecto) {
      return error(env, 'Faltan el cliente y el proyecto', 400);
    }

    const ahora = new Date();
    const folio = generarFolio(ahora);
    const landingToken = bufToHex(crypto.getRandomValues(new Uint8Array(16))); // 32 chars
    const expira = new Date(ahora.getTime() + LANDING_TTL * 1000);

    const cot = {
      folio,
      landingToken,
      landingExpira: expira.toISOString(),
      creadoEn: ahora.toISOString(),
      creadoPor: actual.id,
      creadoPorNombre: actual.nombre || actual.id,

      cliente: String(body.cliente || ''),
      proyecto: String(body.proyecto || ''),
      asesor: String(body.asesor || ''),
      manzana: String(body.manzana || ''),
      lote: String(body.lote || ''),

      moneda: body.moneda === 'USD' ? 'USD' : 'MXN',
      tipoCambio: body.tipoCambio || null,
      precioM2: body.precioM2 || null,
      m2: body.m2 || null,
      precioPropiedad: body.precioPropiedad || null,
      apartado: body.apartado || null,
      engancheCalculado: body.engancheCalculado || null,
      comisionApertura: body.comisionApertura || null,
      montoFinanciar: body.montoFinanciar || null,
      tasaAnual: body.tasaAnual || null,
      plazoMeses: body.plazoMeses || null,
      pagoMensual: body.pagoMensual || null,
      totalPagar: body.totalPagar || null,

      fechaReserva: body.fechaReserva || null,
      fechaEnganche: body.fechaEnganche || null,
      fechaPrimerPago: body.fechaPrimerPago || null,

      amortizacion: Array.isArray(body.amortizacion) ? body.amortizacion.slice(0, 400) : []
    };

    await env.USUARIOS.put(COT_PREFIX + folio, JSON.stringify(cot));
    // El token de landing caduca solo a los 30 dias.
    await env.USUARIOS.put(LANDING_PREFIX + landingToken, folio, { expirationTtl: LANDING_TTL });
    await auditar(env, request, actual.id, 'CREAR_COTIZACION', { folio, cliente: cot.cliente });

    return json(env, {
      ok: true,
      folio,
      landingToken,
      landingUrl: new URL(request.url).origin + '/landing/' + landingToken,
      expira: cot.landingExpira
    }, 201);
  }

  return error(env, 'Metodo no permitido', 405);
}

async function cotizacionIndividual(request, env, metodo, folio) {
  const actual = await getUserByToken(env, request.headers.get('X-Auth-Token'));
  if (!actual) return error(env, 'No autenticado', 401);

  const raw = await env.USUARIOS.get(COT_PREFIX + folio);
  if (!raw) return error(env, 'Cotizacion no encontrada', 404);
  const cot = JSON.parse(raw);

  const propia = cot.creadoPor === actual.id;
  if (!propia && !tiene(actual, PERM.VIEW_ALL_COTIZACIONES)) {
    return error(env, 'Sin permiso para ver esta cotizacion', 403);
  }

  if (metodo === 'GET') return json(env, { cotizacion: cot });

  if (metodo === 'DELETE') {
    if (!tiene(actual, PERM.VIEW_ALL_COTIZACIONES)) {
      return error(env, 'Solo el administrador puede eliminar cotizaciones', 403);
    }
    await env.USUARIOS.delete(COT_PREFIX + folio);
    if (cot.landingToken) await env.USUARIOS.delete(LANDING_PREFIX + cot.landingToken);
    await auditar(env, request, actual.id, 'ELIMINAR_COTIZACION', { folio });
    return json(env, { ok: true });
  }

  return error(env, 'Metodo no permitido', 405);
}
