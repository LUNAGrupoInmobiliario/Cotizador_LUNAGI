/**
 * Cliente de la API del Cotizador LUNA GI.
 *
 * Lo incluyen index.html, login.html, cotizador.html y admin.html, para que la
 * URL de la API y el manejo de sesion vivan en UN solo lugar. Antes la lista de
 * usuarios estaba copiada en dos archivos y se desincronizaban.
 */
(function (global) {
  'use strict';

  var API = 'https://lunagi-coti-api.lindero-coti.workers.dev';

  // Claves de sessionStorage. `luna_auth` se conserva porque cotizador.html
  // ya la usaba antes de que existiera el backend.
  var K = {
    token: 'luna_token',
    id: 'luna_id',
    nombre: 'luna_user',
    rol: 'luna_rol',
    auth: 'luna_auth'
  };

  function guardarSesion(token, usuario) {
    sessionStorage.setItem(K.token, token);
    sessionStorage.setItem(K.id, usuario.id);
    sessionStorage.setItem(K.nombre, usuario.nombre || usuario.id);
    sessionStorage.setItem(K.rol, usuario.rol);
    sessionStorage.setItem(K.auth, 'true');
  }

  function limpiarSesion() {
    Object.keys(K).forEach(function (k) { sessionStorage.removeItem(K[k]); });
  }

  /** Llamada autenticada. Lanza un Error con el mensaje que manda el servidor. */
  async function pedir(ruta, opciones) {
    opciones = opciones || {};
    var headers = { 'Content-Type': 'application/json' };
    var token = sessionStorage.getItem(K.token);
    if (token) headers['X-Auth-Token'] = token;

    var resp = await fetch(API + ruta, {
      method: opciones.metodo || 'GET',
      headers: headers,
      body: opciones.body ? JSON.stringify(opciones.body) : undefined
    });

    var datos = null;
    try { datos = await resp.json(); } catch (e) { datos = {}; }

    if (!resp.ok) {
      // 401 = el token vencio o lo invalidaron (p. ej. le cambiaron la clave)
      if (resp.status === 401 && token) limpiarSesion();
      var err = new Error(datos.error || ('Error ' + resp.status));
      err.status = resp.status;
      throw err;
    }
    return datos;
  }

  var LunaAuth = {
    API: API,

    token: function () { return sessionStorage.getItem(K.token); },
    id: function () { return sessionStorage.getItem(K.id); },
    nombre: function () { return sessionStorage.getItem(K.nombre); },
    rol: function () { return sessionStorage.getItem(K.rol); },
    haySesion: function () { return !!sessionStorage.getItem(K.token); },
    esSuperadmin: function () { return sessionStorage.getItem(K.rol) === 'SUPERADMIN'; },

    async login(id, password) {
      var r = await pedir('/api/login', { metodo: 'POST', body: { id: id, password: password } });
      guardarSesion(r.token, r.usuario);
      return r.usuario;
    },

    async logout() {
      try { await pedir('/api/logout', { metodo: 'POST' }); } catch (e) { /* da igual si falla */ }
      limpiarSesion();
    },

    /** Confirma contra el servidor que la sesion sigue viva. */
    async verificarSesion() {
      if (!this.haySesion()) return null;
      try {
        var r = await pedir('/api/me');
        sessionStorage.setItem(K.rol, r.usuario.rol);
        sessionStorage.setItem(K.nombre, r.usuario.nombre || r.usuario.id);
        return r.usuario;
      } catch (e) {
        if (e.status === 401) return null;
        return { id: this.id(), nombre: this.nombre(), rol: this.rol(), sinConexion: true };
      }
    },

    // Gestion de usuarios (solo superadmin)
    listarUsuarios: function () { return pedir('/api/users'); },
    crearUsuario: function (u) { return pedir('/api/users', { metodo: 'POST', body: u }); },
    editarUsuario: function (id, cambios) {
      return pedir('/api/users/' + encodeURIComponent(id), { metodo: 'PUT', body: cambios });
    },
    eliminarUsuario: function (id) {
      return pedir('/api/users/' + encodeURIComponent(id), { metodo: 'DELETE' });
    },

    // Cotizaciones
    guardarCotizacion: function (datos) {
      return pedir('/api/cotizaciones', { metodo: 'POST', body: datos });
    },
    listarCotizaciones: function () { return pedir('/api/cotizaciones'); },
    verCotizacion: function (folio) {
      return pedir('/api/cotizaciones/' + encodeURIComponent(folio));
    },
    eliminarCotizacion: function (folio) {
      return pedir('/api/cotizaciones/' + encodeURIComponent(folio), { metodo: 'DELETE' });
    },
    urlLanding: function (token) { return API + '/landing/' + token; },

    // Bitacora (solo superadmin)
    bitacora: function (filtros) {
      filtros = filtros || {};
      var q = [];
      if (filtros.limite) q.push('limite=' + encodeURIComponent(filtros.limite));
      if (filtros.usuario) q.push('usuario=' + encodeURIComponent(filtros.usuario));
      if (filtros.accion) q.push('accion=' + encodeURIComponent(filtros.accion));
      return pedir('/api/audit' + (q.length ? '?' + q.join('&') : ''));
    },

    limpiarSesion: limpiarSesion
  };

  global.LunaAuth = LunaAuth;
})(window);
