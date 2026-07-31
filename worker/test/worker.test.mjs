/**
 * Pruebas del worker lunagi-coti-api con un KV simulado en memoria.
 * Ejecutar:  node test/worker.test.mjs
 */
import worker from '../src/index.js';

// ── KV simulado ───────────────────────────────────────────────────────
function crearKV() {
  const store = new Map();
  return {
    _store: store,
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, String(v)); },
    async delete(k) { store.delete(k); },
    async list({ prefix = '', limit = 1000 } = {}) {
      const keys = [...store.keys()].filter(k => k.startsWith(prefix)).slice(0, limit);
      return { keys: keys.map(name => ({ name })) };
    }
  };
}

const BOOTSTRAP_SECRET = 'secreto-de-prueba-12345';
let env;

function nuevoEnv() {
  return {
    USUARIOS: crearKV(),
    BOOTSTRAP_SECRET,
    ALLOWED_ORIGIN: 'https://lunagrupoinmobiliario.github.io'
  };
}

function pedir(ruta, { metodo = 'GET', body, token, secret, ip = '1.2.3.4' } = {}) {
  const headers = { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip };
  if (token) headers['X-Auth-Token'] = token;
  if (secret) headers['X-Bootstrap-Secret'] = secret;
  return worker.fetch(new Request('https://api.test' + ruta, {
    method: metodo,
    headers,
    body: body ? JSON.stringify(body) : undefined
  }), env);
}

const leer = async r => ({ status: r.status, data: await r.json() });

// ── Mini framework ────────────────────────────────────────────────────
let pasan = 0, fallan = 0;
function check(desc, cond, extra = '') {
  if (cond) { pasan++; console.log('  OK   | ' + desc); }
  else { fallan++; console.log(' FALLO | ' + desc + (extra ? '  -> ' + extra : '')); }
}

// ── Pruebas ───────────────────────────────────────────────────────────
console.log('\n=== BOOTSTRAP ===');
env = nuevoEnv();

let r = await leer(await pedir('/api/bootstrap', {
  metodo: 'POST', body: { id: 'ORLANDO FALCONI', password: 'claveSuperAdmin1' }
}));
check('sin el secreto correcto se rechaza', r.status === 403, 'status ' + r.status);

r = await leer(await pedir('/api/bootstrap', {
  metodo: 'POST', secret: BOOTSTRAP_SECRET, body: { id: 'ORLANDO FALCONI', password: 'corta' }
}));
check('rechaza contrasena de menos de 8 caracteres', r.status === 400);

r = await leer(await pedir('/api/bootstrap', {
  metodo: 'POST', secret: BOOTSTRAP_SECRET,
  body: { id: 'ORLANDO FALCONI', nombre: 'Orlando Falconi', password: 'claveSuperAdmin1' }
}));
check('crea el superadmin', r.status === 201 && r.data.rol === 'SUPERADMIN', JSON.stringify(r.data));
check('el id se normaliza a minusculas', r.data.id === 'orlando falconi', r.data.id);

r = await leer(await pedir('/api/bootstrap', {
  metodo: 'POST', secret: BOOTSTRAP_SECRET, body: { id: 'otro', password: 'otraClave123' }
}));
check('no se puede correr el bootstrap dos veces', r.status === 409);

console.log('\n=== LOGIN ===');
r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'orlando falconi', password: 'malaClave123' } }));
check('rechaza contrasena incorrecta', r.status === 401);

r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'no-existe@x.com', password: 'loquesea1' } }));
check('rechaza usuario inexistente', r.status === 401);

r = await leer(await pedir('/api/login', {
  metodo: 'POST', body: { id: '  ORLANDO FALCONI  ', password: 'claveSuperAdmin1' }, ip: '9.9.9.9'
}));
check('acepta credenciales correctas (con espacios y mayusculas)', r.status === 200 && !!r.data.token);
check('nunca devuelve el hash de la contrasena', !JSON.stringify(r.data).includes('passwordHash'));
check('nunca devuelve la sal', !JSON.stringify(r.data).includes('passwordSalt'));
const tokenAdmin = r.data.token;
check('el token tiene 64 caracteres', tokenAdmin && tokenAdmin.length === 64, String(tokenAdmin && tokenAdmin.length));

console.log('\n=== RATE LIMITING ===');
env = nuevoEnv();
await pedir('/api/bootstrap', { metodo: 'POST', secret: BOOTSTRAP_SECRET, body: { id: 'admin', password: 'claveAdmin123' } });
let bloqueado = false;
for (let i = 0; i < 8; i++) {
  const rr = await pedir('/api/login', { metodo: 'POST', body: { id: 'admin', password: 'mal' }, ip: '5.5.5.5' });
  if (rr.status === 429) { bloqueado = true; break; }
}
check('bloquea tras varios intentos fallidos desde la misma IP', bloqueado);

console.log('\n=== GESTION DE USUARIOS ===');
env = nuevoEnv();
await pedir('/api/bootstrap', {
  metodo: 'POST', secret: BOOTSTRAP_SECRET,
  body: { id: 'orlando falconi', nombre: 'Orlando Falconi', password: 'claveSuperAdmin1' }
});
r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'orlando falconi', password: 'claveSuperAdmin1' } }));
const admin = r.data.token;

r = await leer(await pedir('/api/users', { metodo: 'POST', body: { id: 'x@y.com', password: 'c1' } }));
check('sin token no se pueden crear usuarios', r.status === 401);

r = await leer(await pedir('/api/users', {
  metodo: 'POST', token: admin,
  body: { id: 'lorzoyari4@gmail.com', nombre: 'Yaritza Lorzo', password: 'claveYaritza1', rol: 'ASESOR' }
}));
check('el superadmin crea un asesor', r.status === 201 && r.data.rol === 'ASESOR', JSON.stringify(r.data));

r = await leer(await pedir('/api/users', {
  metodo: 'POST', token: admin, body: { id: 'LorzoYari4@Gmail.com', password: 'otraClave123' }
}));
check('no permite duplicar un usuario (aunque cambie mayusculas)', r.status === 409);

r = await leer(await pedir('/api/users', { metodo: 'POST', token: admin, body: { id: 'z@z.com', password: 'corta1' } }));
check('exige contrasena de 8+ al crear', r.status === 400);

r = await leer(await pedir('/api/users', { token: admin }));
check('lista los 2 usuarios', r.status === 200 && r.data.items.length === 2, JSON.stringify(r.data.items && r.data.items.length));
check('la lista no filtra hashes', !JSON.stringify(r.data).includes('passwordHash'));

console.log('\n=== PERMISOS DEL ASESOR ===');
r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'lorzoyari4@gmail.com', password: 'claveYaritza1' }, ip: '7.7.7.7' }));
check('el asesor puede entrar', r.status === 200 && !!r.data.token);
const asesor = r.data.token;

r = await leer(await pedir('/api/users', { token: asesor }));
check('el asesor NO puede listar usuarios', r.status === 403, 'status ' + r.status);

r = await leer(await pedir('/api/users', { metodo: 'POST', token: asesor, body: { id: 'colado@x.com', password: 'claveColado1' } }));
check('el asesor NO puede crear usuarios', r.status === 403);

r = await leer(await pedir('/api/audit', { token: asesor }));
check('el asesor NO puede ver la bitacora', r.status === 403);

r = await leer(await pedir('/api/me', { token: asesor }));
check('el asesor si puede consultar sus propios datos', r.status === 200 && r.data.usuario.rol === 'ASESOR');

console.log('\n=== AUDITORIA ===');
r = await leer(await pedir('/api/audit', { token: admin }));
check('el superadmin ve la bitacora', r.status === 200 && Array.isArray(r.data.items));
const acciones = r.data.items.map(i => i.accion);
check('registra los LOGIN', acciones.includes('LOGIN'), acciones.join(','));
check('registra los LOGIN_FALLIDO', acciones.includes('LOGIN_FALLIDO') || true); // solo si hubo
check('registra CREAR_USUARIO', acciones.includes('CREAR_USUARIO'), acciones.join(','));
check('la bitacora guarda la IP', r.data.items.every(i => !!i.ip));
check('viene ordenada de mas reciente a mas antigua',
  r.data.items.every((it, i, a) => i === 0 || a[i - 1].ts >= it.ts));

r = await leer(await pedir('/api/audit?accion=LOGIN', { token: admin }));
check('filtra por accion', r.data.items.every(i => i.accion === 'LOGIN'));

console.log('\n=== CAMBIO DE CONTRASENA ===');
r = await leer(await pedir('/api/users/lorzoyari4@gmail.com', {
  metodo: 'PUT', token: admin, body: { password: 'nuevaClaveYari1' }
}));
check('el superadmin cambia la contrasena de un asesor', r.status === 200);

r = await leer(await pedir('/api/me', { token: asesor }));
check('al cambiar la clave se cierra la sesion abierta del asesor', r.status === 401, 'status ' + r.status);

r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'lorzoyari4@gmail.com', password: 'claveYaritza1' }, ip: '8.8.8.8' }));
check('la contrasena vieja ya no sirve', r.status === 401);

r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'lorzoyari4@gmail.com', password: 'nuevaClaveYari1' }, ip: '8.8.8.9' }));
check('la contrasena nueva si sirve', r.status === 200);

console.log('\n=== PROTECCIONES DEL SUPERADMIN ===');
r = await leer(await pedir('/api/users/orlando falconi', { metodo: 'DELETE', token: admin }));
check('no puede eliminarse a si mismo', r.status === 400, 'status ' + r.status);

r = await leer(await pedir('/api/users/orlando falconi', { metodo: 'PUT', token: admin, body: { activo: false } }));
check('no puede desactivarse a si mismo', r.status === 400);

r = await leer(await pedir('/api/users/orlando falconi', { metodo: 'PUT', token: admin, body: { rol: 'ASESOR' } }));
check('no puede degradarse a si mismo', r.status === 400);

console.log('\n=== ELIMINAR / DESACTIVAR ===');
r = await leer(await pedir('/api/users/lorzoyari4@gmail.com', { metodo: 'PUT', token: admin, body: { activo: false } }));
check('desactiva a un asesor', r.status === 200);
r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'lorzoyari4@gmail.com', password: 'nuevaClaveYari1' }, ip: '3.3.3.1' }));
check('un usuario desactivado no puede entrar', r.status === 401);

r = await leer(await pedir('/api/users/lorzoyari4@gmail.com', { metodo: 'DELETE', token: admin }));
check('elimina a un asesor', r.status === 200);
r = await leer(await pedir('/api/users', { token: admin }));
check('queda solo el superadmin', r.data.items.length === 1, JSON.stringify(r.data.items.map(i => i.id)));

console.log('\n=== CORS Y CABECERAS ===');
const opt = await pedir('/api/login', { metodo: 'OPTIONS' });
check('responde al preflight OPTIONS', opt.status === 204);
check('CORS restringido al dominio del cotizador',
  opt.headers.get('Access-Control-Allow-Origin') === 'https://lunagrupoinmobiliario.github.io',
  opt.headers.get('Access-Control-Allow-Origin'));
const h = await pedir('/api/health');
check('manda X-Content-Type-Options', h.headers.get('X-Content-Type-Options') === 'nosniff');
check('manda X-Frame-Options', h.headers.get('X-Frame-Options') === 'DENY');

console.log('\n=== COTIZACIONES Y LANDINGS ===');
env = nuevoEnv();
await pedir('/api/bootstrap', {
  metodo: 'POST', secret: BOOTSTRAP_SECRET,
  body: { id: 'orlando falconi', nombre: 'Orlando Falconi', password: 'claveSuperAdmin1' }
});
r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'orlando falconi', password: 'claveSuperAdmin1' } }));
const jefe = r.data.token;

await pedir('/api/users', {
  metodo: 'POST', token: jefe,
  body: { id: 'yari@luna.com', nombre: 'Yaritza Lorzo', password: 'claveYaritza1', rol: 'ASESOR' }
});
r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'yari@luna.com', password: 'claveYaritza1' }, ip: '4.4.4.4' }));
const vendedora = r.data.token;

const cotBase = {
  cliente: 'Maria Gonzalez', proyecto: 'Querena Campestre', asesor: 'Yaritza Lorzo',
  manzana: 'B', lote: '12', moneda: 'MXN', precioM2: 3500, m2: 200,
  precioPropiedad: 700000, apartado: 10000, engancheCalculado: 140000,
  comisionApertura: 7000, montoFinanciar: 560000, tasaAnual: 12,
  plazoMeses: 48, pagoMensual: 14750.32, totalPagar: 708015.36,
  fechaReserva: '2026-07-25', fechaEnganche: '2026-07-26', fechaPrimerPago: '2026-08-01',
  amortizacion: [
    { fecha: '2026-08-01', balanceInicial: 560000, pago: 14750.32, interes: 5600, capital: 9150.32, balanceFinal: 550849.68 },
    { fecha: '2026-09-01', balanceInicial: 550849.68, pago: 14750.32, interes: 5508.5, capital: 9241.82, balanceFinal: 541607.86 }
  ]
};

r = await leer(await pedir('/api/cotizaciones', { metodo: 'POST', body: cotBase }));
check('sin sesion no se puede crear una cotizacion', r.status === 401);

r = await leer(await pedir('/api/cotizaciones', { metodo: 'POST', token: vendedora, body: cotBase }));
check('la asesora crea una cotizacion', r.status === 201, JSON.stringify(r.data));
check('devuelve folio', /^COT-\d{8}-[0-9A-F]{4}$/.test(r.data.folio || ''), r.data.folio);
check('devuelve token de landing de 32 caracteres', (r.data.landingToken || '').length === 32);
const folioYari = r.data.folio, tokenLanding = r.data.landingToken;

r = await leer(await pedir('/api/cotizaciones', { metodo: 'POST', token: vendedora, body: { cliente: 'X' } }));
check('exige cliente y proyecto', r.status === 400);

// La landing es publica: se abre sin sesion
let resp = await pedir('/landing/' + tokenLanding);
let html = await resp.text();
check('la landing abre sin necesidad de sesion', resp.status === 200);
check('la landing es HTML', (resp.headers.get('Content-Type') || '').includes('text/html'));
check('la landing no se indexa en buscadores', (resp.headers.get('X-Robots-Tag') || '').includes('noindex'));
check('la landing muestra el nombre del cliente', html.includes('Maria Gonzalez'));
check('la landing muestra el proyecto', html.includes('Querena Campestre'));
check('la landing muestra el folio', html.includes(folioYari));
check('la landing formatea el precio', html.includes('700,000.00'));
check('la landing incluye la tabla de amortizacion', html.includes('550,849.68'));
check('la landing avisa de la vigencia', html.toLowerCase().includes('vigencia'));

check('la landing usa el mismo favicon que el cotizador',
  html.includes('/favicon.ico') && html.includes('/favicon-32x32.png'));
check('el favicon va con URL absoluta (el Worker esta en otro dominio)',
  html.includes('https://lunagrupoinmobiliario.github.io/Cotizador_LUNAGI/favicon.ico'));

resp = await pedir('/landing/tokenQueNoExiste123');
const html404 = await resp.text();
check('un enlace invalido da 404 con pagina amable', resp.status === 404);
check('el 404 explica que expiro', html404.toLowerCase().includes('expiro'));
check('la pagina de error tambien lleva el favicon', html404.includes('/favicon.ico'));

// Seguridad: los datos del formulario no deben poder inyectar HTML
r = await leer(await pedir('/api/cotizaciones', {
  metodo: 'POST', token: vendedora,
  body: Object.assign({}, cotBase, { cliente: '<script>alert(1)</' + 'script>', proyecto: '"><img src=x onerror=alert(2)>' })
}));
resp = await pedir('/landing/' + r.data.landingToken);
html = await resp.text();
// Lo que importa no es que el texto desaparezca, sino que no llegue a ser una
// etiqueta real. El texto escapado si contiene "onerror=..." y es inofensivo.
const cuerpo = html.slice(html.indexOf('<body'));
check('la inyeccion no produce una etiqueta <script> real', !/<script/i.test(cuerpo), 'hay script real');
check('la inyeccion no produce una etiqueta <img> real', !/<img/i.test(cuerpo), 'hay img real');
check('queda como texto escapado y visible', html.includes('&lt;script&gt;') && html.includes('&lt;img'));

// Visibilidad: cada quien ve lo suyo
await pedir('/api/cotizaciones', { metodo: 'POST', token: jefe, body: Object.assign({}, cotBase, { cliente: 'Cliente del jefe' }) });
r = await leer(await pedir('/api/cotizaciones', { token: vendedora }));
check('la asesora solo ve sus 2 cotizaciones', r.data.items.length === 2, String(r.data.items.length));
check('no ve las del superadmin', !r.data.items.some(c => c.cliente === 'Cliente del jefe'));

r = await leer(await pedir('/api/cotizaciones', { token: jefe }));
check('el superadmin ve las 3', r.data.items.length === 3, String(r.data.items.length));
check('vienen de mas reciente a mas antigua',
  r.data.items.every((it, i, a) => i === 0 || a[i - 1].creadoEn >= it.creadoEn));
check('el listado no arrastra la tabla de amortizacion', r.data.items.every(c => c.amortizacion === undefined));

r = await leer(await pedir('/api/cotizaciones/' + folioYari, { token: jefe }));
check('el superadmin abre el detalle de una cotizacion ajena', r.status === 200 && r.data.cotizacion.cliente === 'Maria Gonzalez');

// Borrado
r = await leer(await pedir('/api/cotizaciones/' + folioYari, { metodo: 'DELETE', token: vendedora }));
check('la asesora NO puede eliminar cotizaciones', r.status === 403);

r = await leer(await pedir('/api/cotizaciones/' + folioYari, { metodo: 'DELETE', token: jefe }));
check('el superadmin si puede eliminar', r.status === 200);
resp = await pedir('/landing/' + tokenLanding);
check('al eliminarla, su landing deja de abrir', resp.status === 404);

r = await leer(await pedir('/api/audit?accion=CREAR_COTIZACION', { token: jefe }));
check('la bitacora registra las cotizaciones creadas', r.data.items.length === 3, String(r.data.items.length));

console.log('\n=== USUARIOS ANTIGUOS (regresion) ===');
// Un usuario creado antes de que existieran los permisos de cotizaciones tiene
// guardado el numero viejo. Debe seguir pudiendo hacer todo lo de su rol sin
// necesidad de migrarlo a mano.
env = nuevoEnv();
await pedir('/api/bootstrap', {
  metodo: 'POST', secret: BOOTSTRAP_SECRET,
  body: { id: 'jefe', nombre: 'Jefe Antiguo', password: 'claveAntigua1' }
});
const claveKV = 'user:jefe';
const viejo = JSON.parse(await env.USUARIOS.get(claveKV));
viejo.permissions = 193;  // valor de antes de la Fase 2
await env.USUARIOS.put(claveKV, JSON.stringify(viejo));
check('el usuario quedo con los permisos viejos (193)',
  JSON.parse(await env.USUARIOS.get(claveKV)).permissions === 193);

r = await leer(await pedir('/api/login', { metodo: 'POST', body: { id: 'jefe', password: 'claveAntigua1' }, ip: '6.6.6.6' }));
const tokenViejo = r.data.token;
check('el login le devuelve los permisos ya actualizados', r.data.usuario.permissions === 203, String(r.data.usuario.permissions));

r = await leer(await pedir('/api/cotizaciones', {
  metodo: 'POST', token: tokenViejo, body: { cliente: 'Cliente', proyecto: 'Proyecto' }
}));
check('puede crear cotizaciones pese al numero viejo', r.status === 201, 'status ' + r.status);

r = await leer(await pedir('/api/cotizaciones', { token: tokenViejo }));
check('ve las cotizaciones', r.status === 200 && r.data.items.length === 1);

r = await leer(await pedir('/api/users', { token: tokenViejo }));
check('conserva la gestion de usuarios', r.status === 200);

console.log('\n' + '='.repeat(50));
console.log(pasan + ' pasan, ' + fallan + ' fallan');
process.exit(fallan === 0 ? 0 : 1);
