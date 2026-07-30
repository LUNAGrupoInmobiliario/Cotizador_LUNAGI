# lunagi-coti-api — Backend del Cotizador LUNA GI

Da soporte a lo que el HTML estático no puede hacer solo: **usuarios reales compartidos entre dispositivos** y **auditoría de ingresos**.

Sigue el mismo patrón que `lindero-coti-api`, simplificado a lo que este cotizador necesita.

---

## Por qué hace falta

El cotizador vive en GitHub Pages, que solo sirve archivos: no puede guardar nada. Sin este Worker, un usuario creado por Orlando solo existiría en su navegador y la auditoría solo vería sus propios ingresos.

---

## Despliegue (una sola vez)

Desde esta carpeta (`COTIZADORES/LUNA_GI/worker`):

### 1. Crear el almacén de datos

```bash
npx wrangler kv namespace create USUARIOS
```

Copia el `id` que imprime y pégalo en `wrangler.toml`, reemplazando `PENDIENTE_CREAR_NAMESPACE`.

### 2. Definir el secreto de arranque

```bash
npx wrangler secret put BOOTSTRAP_SECRET
```

Pega una cadena larga y aleatoria cuando la pida. Sirve **una sola vez**, para crear el primer superadmin.

### 3. Publicar el Worker

```bash
npx wrangler deploy
```

Anota la URL que devuelve (algo como `https://lunagi-coti-api.<tu-cuenta>.workers.dev`).

### 4. Crear el superadmin

Reemplaza `<URL>`, `<SECRETO>` y la contraseña:

```bash
curl -X POST "<URL>/api/bootstrap" -H "Content-Type: application/json" -H "X-Bootstrap-Secret: <SECRETO>" -d "{\"id\":\"ORLANDO FALCONI\",\"nombre\":\"Orlando Falconi\",\"password\":\"UNA-CLAVE-LARGA\"}"
```

Si responde `409`, ya existían usuarios: el bootstrap solo corre una vez.

---

## Endpoints

| Método | Ruta | Quién | Qué hace |
|---|---|---|---|
| `GET` | `/api/health` | Cualquiera | Comprueba que el Worker responde |
| `POST` | `/api/bootstrap` | Secreto | Crea el primer superadmin (una sola vez) |
| `POST` | `/api/login` | Cualquiera | Devuelve un token de 7 días |
| `POST` | `/api/logout` | Autenticado | Invalida el token |
| `GET` | `/api/me` | Autenticado | Datos del usuario actual |
| `GET` | `/api/users` | Superadmin | Lista de usuarios |
| `POST` | `/api/users` | Superadmin | Crea un usuario |
| `PUT` | `/api/users/<id>` | Superadmin | Cambia contraseña, nombre, rol o lo activa/desactiva |
| `DELETE` | `/api/users/<id>` | Superadmin | Elimina un usuario |
| `GET` | `/api/audit` | Superadmin | Bitácora (`?limite=100&usuario=&accion=`) |
| `GET` | `/api/cotizaciones` | Autenticado | Lista. El asesor ve solo las suyas; el superadmin, todas |
| `POST` | `/api/cotizaciones` | Autenticado | Guarda una cotización y devuelve su enlace de landing |
| `GET` | `/api/cotizaciones/<folio>` | Autor o superadmin | Detalle completo |
| `DELETE` | `/api/cotizaciones/<folio>` | Superadmin | La elimina junto con su landing |
| `GET` | `/landing/<token>` | **Público** | La cotización en HTML, tal como la ve el cliente |

Autenticación: cabecera `X-Auth-Token: <token>`.

### Landings

Al guardar una cotización se genera un token aleatorio de 32 caracteres y una URL `/landing/<token>`, pensada para enviarse por WhatsApp o correo:

- **No pide contraseña**: quien tenga el enlace puede verla. Por eso el token es aleatorio y no un folio adivinable.
- **Caduca a los 30 días** por sí sola (TTL del KV).
- Lleva `X-Robots-Tag: noindex, nofollow` para que no la indexen los buscadores.
- Todo dato que venga del formulario se escapa antes de meterlo en el HTML, así que un nombre con `<script>` se muestra como texto, no se ejecuta.
- Al eliminar la cotización, su enlace deja de funcionar de inmediato.

---

## Roles

| Rol | Puede |
|---|---|
| `SUPERADMIN` | Usar el cotizador + gestionar usuarios + ver la bitácora |
| `ASESOR` | Solo usar el cotizador |

---

## Seguridad

- Contraseñas con **PBKDF2-SHA256, 100 000 iteraciones** y sal aleatoria por usuario. Nunca se guardan en claro ni se devuelven por la API.
- Comparación en **tiempo constante**: el tiempo de respuesta no delata si el usuario existe.
- **Rate limiting**: 5 intentos de login y 100 peticiones por minuto y por IP.
- **CORS** restringido a `https://lunagrupoinmobiliario.github.io` (se cambia en `wrangler.toml`).
- Cambiar la contraseña de alguien o desactivarlo **cierra sus sesiones abiertas**.
- El superadmin no puede eliminarse, desactivarse ni degradarse a sí mismo (evita quedarse sin acceso).
- Bitácora con retención de 90 días; tokens de 7 días.

---

## Pruebas

```bash
node test/worker.test.mjs
```

45 pruebas con un KV simulado en memoria: bootstrap, login, rate limiting, permisos por rol, auditoría, cambio de contraseña, protecciones del superadmin y cabeceras. No tocan datos reales.

---

## Costo

Cloudflare Workers y KV tienen capa gratuita (100 000 peticiones/día). Este uso queda muy por debajo.
