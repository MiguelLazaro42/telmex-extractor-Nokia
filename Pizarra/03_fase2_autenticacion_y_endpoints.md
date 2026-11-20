# 🔐 Fase 2: Autenticación Web y Descubrimiento de Endpoints (Nokia GPON / Telmex)

> **Estado:** ✅ **FASE 2 COMPLETADA** — `MF-2.1` ✅ · `MF-2.2` ✅ (login real, 1 intento) · `MF-2.3` ✅ **Completada** (mapeo de endpoints con sesión autenticada)
> **Fecha:** 2026-11-20
> **Target:** `http://192.168.99.254/` · **Nokia G-1425G-H** (modelo CONFIRMADO) · servidor `thttpd`
> **Credenciales usadas:** `TELMEX` / `sf3h5zkdtA` — logins **100 % exitosos** (HTTP 299 + X-SID); cada login reinicia `ErrorLimit`. Todas las sesiones de exploración se cerraron con `GET /login.cgi?out`.

---

## 🎯 Alcance de MF-2.1 (`get_login_challenge`)
Esta microfunción **NO autentica**. Su único trabajo:
1. Hacer un `GET /` real y extraer de forma **100 % limpia y determinista** el desafío de login: `pubkey` (PEM), `nonce`, `csrf_token` (var `token`), cookies iniciales (`lang=spa`), `operatorCheck`, `window.name`.
2. Dejar listos y **validados bit-a-bit** los helpers criptográficos de empaquetado (`b64url_escape`, AES-128-CBC estilo `sjcl.mode.cbc`, RSA-1024 PKCS#1 v1.5 estilo `JSEncrypt`) **sin gastar ningún intento de login**.

**Artefactos de código:**
- `nokia_auth.py` — módulo de autenticación (MF-2.1 + helpers cripto para MF-2.2).
- `tests/validate_crypto.py` — suite de validación de compatibilidad con el frontend JS.

---

## 🧩 Entorno criptográfico
- **No hay `node`** en el host → la validación contra el propio `sjcl.js` + `crypto_page.js` en local **no fue posible ejecutarla con JS**. Se sustituyó por: (a) **análisis a fondo del código fuente de `sjcl.js`** (abajo) + (b) **validación contra OpenSSL** como referencia estándar + (c) **round-trip RSA** con par de claves efímero. Dado que el análisis de fuente prueba que el CBC de sjcl es **PKCS#7 estándar** y su base64url es **urlsafe-sin-padding estándar**, igualar a OpenSSL ≡ igualar a sjcl/JSEncrypt.
- **Backend cripto Python:** librería `cryptography` (pyca) `50.0.2`, ya presente en `.venv`. (No hay `pycryptodome`.)
- Ejecutar siempre con aislamiento: `.venv/bin/python -I nokia_auth.py`.

---

## 🔬 Hallazgos EXACTOS sobre `sjcl.mode.cbc` y `base64url` (revisión de fuente)

### 1) `sjcl.mode.cbc.encrypt` = **AES-CBC + PKCS#7 estándar** (NO un padding propietario)
Fuente literal (`js_glb/sjcl.js`, minificada), bucle de bloques + relleno final:
```js
// ... por cada bloque completo:  c = aes.encrypt( xor(c, b.slice(d,d+4)) )
g = 0x1010101 * (16 - (g>>3 & 15));                       // g = bitLength del plaintext
c = a.encrypt( f(c, e.concat(b, [g,g,g,g]).slice(d,d+4)) ); // bloque final con relleno
```
Desglose del relleno:
- `g>>3` = **longitud en bytes** del plaintext; `& 15` = `len % 16` (bytes del último bloque parcial).
- `padval = 16 - (len % 16)` → **valor de relleno PKCS#7**.
- `0x1010101 * padval` = esa palabra de 32 bits con el byte `padval` repetido 4 veces.
- Cuando `len % 16 == 0` ⇒ `padval = 16 - 0 = 16` ⇒ **se añade un bloque COMPLETO de 16 bytes `0x10`** (comportamiento idéntico a PKCS#7 estándar, no "sin padding").

> ✅ **Conclusión:** `sjcl.mode.cbc.encrypt(aes, pt, iv)` ≡ `AES-128-CBC( PKCS7_pad(pt) )`. **Verificado contra OpenSSL** para `len ∈ {0, 11, 16, 49}` (incluye el caso múltiplo-exacto que fuerza el bloque completo de padding) — **idéntico byte a byte**.

- El IV debe ser de **128 bits** (lo exige sjcl: `if(128!==bitLength(c)) throw`). Usamos IV de 16 bytes.
- `decrypt` valida el padding PKCS#7 (`"pkcs#5 padding corrupt"`), confirmando que el `encrypt` lo produce.

### 2) `sjcl.codec.base64url.fromBits` = **base64 urlsafe SIN relleno `=`**
Fuente literal:
```js
sjcl.codec.base64 = { J:"ABCD…xyz0123456789+/",
  fromBits:function(a,b,c){ … c&&(f=f.substr(0,62)+"-_"); … for(;d.length&3&&!b;)d+="="; return d } };
sjcl.codec.base64url = { fromBits:function(a){ return sjcl.codec.base64.fromBits(a,1,1); } };
```
- `base64url.fromBits(a)` llama con `b=1, c=1`:
  - `c=1` ⇒ alfabeto = `…+/` con los dos últimos sustituidos por **`-_`** (urlsafe).
  - `b=1` ⇒ el bucle `while(d.length&3 && !b)` **no añade `=`** ⇒ **sin padding**.
- Para el `ct` (siempre múltiplo de 16 bytes), 16 B → 22 chars sin `=` (coincide con `urlsafe_b64encode(...).rstrip('=')`). **Verificado.**

### 3) `sjcl.codec.base64.fromBits` (estándar, para `aesinfo`)
- Llamado sin `b`/`c` ⇒ alfabeto `+/` y **con relleno `=`**. Es el que arma `aesinfo = base64(aeskey) + ' ' + base64(iv)` (cada uno 16 B → 24 chars con `==`). ≡ `base64.b64encode`. **Verificado.**

### 4) `crypto_page.base64url_escape` ≠ base64url estándar
Fuente literal (`js_glb/crypto_page.js`):
```js
if (c=='+') out+='-'; else if (c=='/') out+='_'; else if (c=='=') out+='.'; else out+=c;
```
- `'+'→'-'`, `'/'→'_'`, **`'='→'.'`** (¡un **punto**, no se elimina!). **No estándar.**
- Se aplica a `ck` (salida base64 **con** padding de `JSEncrypt`, RSA-1024 → 128 B → 172 chars con un `=` final) ⇒ `ck` **termina en `.`**.
- También se aplica a `enckey`/`enciv` en el `postdata` (base64 con `==` → `..`).

### 5) `JSEncrypt.encrypt` = **RSA-1024 PKCS#1 v1.5 (type 2)** estándar
- Padding tipo 2 con bytes de relleno **aleatorios** ⇒ el `ck` es **no determinista** (cambia en cada llamada aunque `aesinfo` sea igual). Esto es correcto y esperado; la única validación posible es **round-trip** (descifrar con la privada devuelve el mensaje).
- `aesinfo` = 49 bytes ≤ 117 (límite PKCS#1 v1.5 para RSA-1024) ⇒ cabe sin problema.
- ≡ `cryptography … padding.PKCS1v15()`. **Verificado por round-trip con OpenSSL.**

---

## 🧪 Resultado de la validación (`tests/validate_crypto.py`)
Ejecución: `.venv/bin/python -I tests/validate_crypto.py` → **TODAS las comprobaciones pasaron**:

| # | Comprobación | Resultado |
| :-: | :--- | :-: |
| 1 | `b64url_escape` mapea `+→- / →_ =→.` y no toca `A-Za-z0-9` | ✅ |
| 2 | `sjcl_base64` == `b64encode` (con `=`); `sjcl_base64url` == urlsafe sin `=` (16 B→22 chars) | ✅ |
| 3 | PKCS#7: pad(5)→+11×`0x0b`, pad(16)→bloque completo +16×`0x10`, pad(0)→16×`0x10` | ✅ |
| 4 | **AES-128-CBC Python == OpenSSL** para `len ∈ {0,11,16,49}` (byte a byte) | ✅ |
| 5 | **RSA-1024 PKCS#1 v1.5 round-trip**: cifra(Python)→descifra(OpenSSL)==mensaje; ct=128 B | ✅ |
| 6 | **Pubkey REAL** del equipo: carga como RSA-1024, `e=65537`, cifra→128 B | ✅ |
| 7 | `encrypt_post_data`: formato `encrypted=1&ct=…&ck=…`; `ct` determinista con key/iv fijos y sin `=+/` | ✅ |

> ⚠️ El `ck` **no** se valida por igualdad de bytes (padding RSA aleatorio por diseño). Se valida por round-trip, que es la prueba correcta de compatibilidad con JSEncrypt.

---

## 🧷 Prueba de extracción del challenge (MF-2.1, `GET /` real)
Ejecución: `.venv/bin/python -I nokia_auth.py` (GET real a `http://192.168.99.254/`, **sin** POST):
```json
{
  "pubkey": "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD7nE9L38HvcuWPLgmCFrEwfVVe\n4pbDLciv/c0DMyymkRb1T/dYsC9cTR4kWxLK/qfnWzPTmCfOEHDvEa9qNmupnNy7\nOP68cZs+JJAKXBncf5aI3H2hMpE0SVqThATtLz/SlfVlvFSEfx0Lf+w1pPN+aE6+\n8ri48nVMfCE2gDrlqQIDAQAB\n-----END PUBLIC KEY-----\n",
  "nonce": "HamWOWzHjgCA60xxy3QN/U0dgR+6snUUsFxVPaWYLaE=",   // rota en cada GET /
  "csrf_token": "linreZYDNPEfcfsZ",                             // rota en cada GET /
  "operatorCheck": "MXXT",
  "window_name": "Bell",
  "cookies": { "lang": "spa" },
  "html_size": 13806,
  "status": 200
}
```
**Observaciones de la prueba:**
- **`pubkey` 100 % limpia:** `_normalize_pem()` reconstruye el PEM desde el literal JS (que trae `\` de continuación + saltos reales) y `cryptography` lo carga como **RSA-1024, e=65537**. La pubkey coincide con la documentada en Fase 1 (estable en este equipo, pero **se re-lee en cada login**, no se hardcodea).
- **`nonce` + `csrf_token` rotan** en cada `GET /` (valores distintos a los de MF-1.2) → confirma que MF-2.2 debe hacer `GET /` fresco inmediatamente antes de cada `POST /login.cgi`.
- **Cookie inicial** `lang=spa` capturada por el `CookieJar` del `opener` (idioma, no sesión; la sesión llega como `X-SID` tras login).
- Extracción **determinista** (regex ancladas a `var pubkey`, `var nonce`, `var token`, `var operatorCheck`) → sin ambigüedad.

---

## 💻 Código de MF-2.1 y helpers (`nokia_auth.py`) — resumen

| Función | Equivalente JS | Rol |
| :--- | :--- | :--- |
| `b64url_escape(b64)` | `crypto_page.base64url_escape` | `+→- / →_ =→.` |
| `sjcl_base64(data)` | `sjcl.codec.base64.fromBits` | base64 estándar con `=` |
| `sjcl_base64url(data)` | `sjcl.codec.base64url.fromBits` | urlsafe sin `=` |
| `_pkcs7_pad(data)` | relleno de `sjcl.mode.cbc.encrypt` | PKCS#7 (bloque completo si múltiplo) |
| `aes128_cbc_encrypt_sjcl(key,iv,pt)` | `sjcl.mode.cbc.encrypt(aes,pt,iv)` | AES-128-CBC + PKCS#7 |
| `rsa_pkcs1v15_b64(pem,msg)` | `JSEncrypt.encrypt` | RSA-1024 PKCS#1 v1.5 → base64 |
| `encrypt_body(pem,pt,[key,iv])` | `crypto_page.encrypt` | `{ct, ck, aeskey, iv}` |
| `encrypt_post_data(pem,pt,...)` | `crypto_page.encrypt_post_data` | `encrypted=1&ct=…&ck=…` |
| `get_login_challenge(opener,ip)` | — (MF-2.1) | `GET /` + parse del desafío |
| `build_login_plaintext(...)` | `postdata` de `submit()` | arma texto plano (para MF-2.2, **no envía**) |
| `make_opener()` | — | `OpenerDirector` + `CookieJar` (patrón Huawei) |

> `encrypt_body`/`encrypt_post_data` aceptan `aeskey`/`iv` opcionales **solo para pruebas deterministas**; en producción (MF-2.2) se dejan en `None` → `os.urandom(16)` (efímeros por request, como `sjcl.random.randomWords(4,0)`).

---

## ✅ MF-2.2 (`authenticate_nokia`) — EJECUTADA (login real exitoso)

**Función implementada en `nokia_auth.py`:**
- `authenticate_nokia(opener, ip, user, password, timeout, save_html_path)` — flujo completo de login (1 intento).
- `aes128_cbc_decrypt_sjcl(enckey, enciv, ciphertext_b64)` — **réplica exacta de `crypto_page.aes_decrypt`** (AES-128-CBC + validación de padding PKCS#7; `base64.toBits` de `enckey`/`enciv` **estándar sin escapar**). Acepta `enckey`/`enciv` como str base64 estándar o `bytes` de 16. Round-trip validado contra `aes128_cbc_encrypt_sjcl` (incl. detección de "PKCS#7 padding corrupt").
- `_Pass2xxErrorProcessor` — handler que deja pasar **cualquier 2xx (incluido 299)** sin lanzar `HTTPError`; además `authenticate_nokia` captura `HTTPError` con `e.code==299` como blindaje doble, para no perder headers (X-SID/Set-Cookie) ni body.

> **Nota urllib:** el `HTTPErrorProcessor` por defecto evalúa `200 ≤ code < 300`, así que **299 normalmente NO lanza `HTTPError`**; aun así se instaló el handler `_Pass2xxErrorProcessor` + `try/except HTTPError (e.code==299)` para ser robustos ante cualquier versión/ruta de procesamiento.

### Flujo ejecutado (idéntico al `submit()` del HTML)
1. `GET /` fresco → `pubkey`/`nonce`/`csrf_token` nuevos.
2. `dec_key`/`dec_iv` = `os.urandom(16)` c/u → **base64 estándar CON `=`** (`sjcl_base64`, ≡ `base64.fromBits`). Se guardan sin escapar (ligados al X-SID) para descifrar respuestas.
3. `postdata = &username=TELMEX&password=<encodeURIComponent>&csrf_token=<token>&nonce=<nonce>&enckey=<b64url_escape(dec_key)>&enciv=<b64url_escape(dec_iv)>`.
4. `body = encrypt_post_data(pubkey, postdata)` → `encrypted=1&ct=…&ck=…` (AES-128 efímera + RSA-1024 de `aesinfo`).
5. `POST /login.cgi` (`Content-Type: application/x-www-form-urlencoded`).

### Resultado REAL del único intento (`.venv/bin/python -I nokia_auth.py login`)
| Campo | Valor observado |
| :--- | :--- |
| **HTTP status** | **`299`** ✅ (también en header `Status: 299`) |
| **`X-SID`** | `zTyYAkWRkTAzRZhk` (cambia por sesión) |
| **Body del `299`** | **vacío** (`Content-Length 0`, `Content-type: text/html;charset=UTF-8`) |
| **`enckey` (cliente)** | `U4oI8UaOJ5ErS0I1SqT8JA==` (base64 estándar; efímera, ligada al X-SID) |
| **`enciv` (cliente)** | `+6+46f2HQnzOj+lGRKgE7Q==` |

**Cookies de sesión asignadas por el `Set-Cookie` del 299** (capturadas por el `CookieJar`):
```
sid=zTyYAkWRkTAzRZhk; path=/; HttpOnly;          <- session id (== X-SID)
isAdminLoggedIn=1;    path=/; HttpOnly;          <- flag de admin logueado
lsid=WCdKFITldyyiVjLr; expires=2046-...; path=/; HttpOnly;   <- login/long session id
```
(más la previa `lang=spa` del `GET /`). Estado final del CookieJar: `{sid, isAdminLoggedIn, lsid, lang}`.

**Otros headers del 299:** `Cache-Control: private,max-age=0`, `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, `Content-Security-Policy: default-src 'self' blob: 'unsafe-inline' 'unsafe-eval'`, `Strict-Transport-Security`, `Referrer-Policy: no-referrer`.

### 🔑 Cómo se sostiene la sesión (hallazgo clave)
- **La sesión viaja por COOKIE `sid` (= X-SID), no por header.** El `GET /` autenticado tuvo éxito gracias a las cookies del `CookieJar`; se añadió `X-SID` como header por precaución, pero el mecanismo real es la cookie `sid`/`isAdminLoggedIn`/`lsid`.
- `aes128_cbc_decrypt_sjcl(enckey, enciv, ct)` queda listo para descifrar **respuestas CGI que vengan cifradas** (si las hubiera). En el login el body fue vacío y la UI autenticada responde en **texto plano** (ver abajo), así que el descifrado AES será necesario solo para endpoints CGI concretos de MF-2.3 que respondan `ct` cifrado.

### 🏠 Interfaz autenticada — `GET /` tras el 299 (punto de partida de MF-2.3)
- Guardada en **`/tmp/nokia_recon/authenticated_index.html`** (HTTP `200`, **20 053 bytes**, `looks_authenticated = True`).
- **NO es el formulario de login** (0 marcadores `id=username`/`loginform`/`submit()`): es el **shell autenticado** `GPON Home Gateway`.
- Estructura inicial observada:
  - `<title>GPON Home Gateway</title>`; carga `jsencrypt.min.js`, `sjcl.js`, `crypto_page.js`, `translate.js` y **`<script src="menu.cgi"></script>`**.
  - `var adminRole = 0;` (rol de la sesión TELMEX).
  - **`var pubkey = '-----BEGIN PUBLIC KEY-----…'`** también presente aquí → las **peticiones CGI autenticadas se cifran** con el mismo envoltorio RSA+AES del login.
  - **CSRF fresco en la UI interna:** `var token = "ZbTFkvnLGGfOrSXg";` → las llamadas POST a CGIs llevan `csrf_token=<token>` (ej. `index.cgi?getppp` usa `getppppostdata = "csrf_token="+token`).
  - **El menú se construye dinámicamente desde `menu.cgi`** (define `all_nodes.nodes[]`); cada nodo tiene `.name` (traducido vía `langjson`) y `.target` (un `*.cgi`). El contenido se carga en un **`<iframe name="mainFrame">`** cambiando su `src` al `target` del nodo.
  - Endpoints ya visibles en el shell: `menu.cgi`, `index.cgi?getppp`, `check_expire.cgi`, `device_status.cgi`, `us_classifier.cgi`, `parental_control.cgi`, `user_glb.cgi`, logout en **`login.cgi?out`**.

> ➡️ **Punto de entrada de MF-2.3:** pedir **`GET /menu.cgi`** (con la sesión) para enumerar `all_nodes.nodes[]` y localizar los `target` de (a) Backup/Restore de configuración y (b) Voz/VoIP (SIP).

---

## 🗂️ Endpoints (actualizado tras MF-2.2 — sesión autenticada)
| Endpoint | Método | Estado | Rol |
| :--- | :--- | :---: | :--- |
| `/` | GET | ✅ | Sin sesión: login (`pubkey`/`nonce`/`csrf_token` + `lang=spa`). Con sesión: **shell autenticado** (menu.cgi + iframe `mainFrame`) |
| `/login.cgi` | POST | ✅ | Login RSA+AES → **`299` + `X-SID`** + cookies `sid`/`isAdminLoggedIn`/`lsid` (**verificado**) |
| `/login.cgi?out` | GET | ✅ | Logout (cierra sesión) — `200`, ejecutado en cada ciclo |
| `/menu.cgi` | GET | ✅ | `all_nodes.nodes[]` (árbol, 43 targets) — ver **MF-2.3 §2** |
| `/device_status.cgi` | GET | ✅ | `dev_info` (modelo G-1425G-H, SN, firmware) — **MF-2.3 §1** |
| `/usb.cgi?export` | POST | ✅ | **Descarga backup** (urlencoded, `csrf_token`, sin cifrar) — **MF-2.3 §5a** |
| `/usb.cgi?import` | POST | ✅ | **Restore/subida** (multipart `filename`, `csrf_token`) — **MF-2.3 §5b** |
| `/voice_info.cgi` | GET | ✅ | Estado SIP (solo lectura; línea `Disabled`) — **MF-2.3 §3** |
| `/show_wan_status.cgi?ipv4` | GET | ✅ | WANs (VLAN 881 VOIP+TR069+INTERNET) — **MF-2.3 §4** |
| `/index.cgi?getppp` | POST | ✅ | Estado PPP/WAN (cifrado RSA+AES, `csrf_token`) |

---

## ✅ Cierre de MF-2.2
- **Login real exitoso en 1 solo intento:** HTTP `299` + `X-SID=zTyYAkWRkTAzRZhk`; sesión establecida vía cookies `sid`/`isAdminLoggedIn=1`/`lsid`.
- `authenticate_nokia()` y `aes128_cbc_decrypt_sjcl()` implementados; manejo de **HTTP 299** blindado (handler 2xx + captura `HTTPError 299`).
- **UI autenticada confirmada** (no login) y guardada en `/tmp/nokia_recon/authenticated_index.html` como base de MF-2.3.
- **Detenido aquí** (antes de explorar los endpoints de MF-2.3), según alcance.

### (Histórico) Cierre de MF-2.1
- `get_login_challenge()` extrae el desafío **limpio y determinista** desde un `GET /` real.
- Helpers cripto **validados**: AES-128-CBC/PKCS#7 ≡ OpenSSL ≡ `sjcl.mode.cbc`; base64url urlsafe-sin-`=` ≡ `sjcl.codec.base64url`; `base64url_escape` con `=→.`; RSA-1024 PKCS#1 v1.5 round-trip ≡ `JSEncrypt`.

---

# ✅ MF-2.3 (`map_authenticated_endpoints`) — EJECUTADA (mapeo completo con sesión real)

> **Ciclo ejecutado:** `login (299+X-SID) → GET /menu.cgi → GET /device_status.cgi → GET de los 43 targets del menú → sondas de voz oculta → GET /login.cgi?out`. **Un solo ciclo limpio, sesión cerrada.**
> **Driver:** `.venv/bin/python -I nokia_auth.py map` (login → `map_authenticated_endpoints(opener, x_sid)` → `logout_nokia(opener)`).
> **Artefactos:** `menu.cgi` crudo en `/tmp/nokia_recon/menu.cgi.js`; cada CGI guardado en `/tmp/nokia_recon/cgi/<target saneado>`; HTML del shell en `/tmp/nokia_recon/authenticated_index.html`.

## 1) 🏷️ Modelo y firmware CONFIRMADOS (de `device_status.cgi` → `var dev_info`)

> ⚠️ **Corrección vs. Fase 1:** el candidato era *G-2425G-A "Beacon 1"*. El modelo **real** es **Nokia G-1425G-H**.

| Campo | Valor real |
| :--- | :--- |
| **ModelName / ProductClass** | **`G-1425G-H`** |
| **Manufacturer / OUI** | `ALCATEL-LUCENT` / `E03005` |
| **Vendor (UI)** | `Nokia` |
| **Serial Number (= GPON SN)** | **`ALCLB472FD24`** (prefijo vendor `ALCL` + `B472FD24`) |
| **Hardware Version** | `3TN00990ADAA` |
| **Software / Firmware Version** | **`3TN00702IJMI00`** (build `IJM.I00p01`, visible en `?v=IJM.I00p01` de los `<script>`) |
| **Bootloader** | `U-Boot (Nov182024-23:46:33)` |
| **Chipset** | `MTK7552` (MediaTek) |
| **ProvisioningCode** | `TELMEX` |
| **FirstUseDate** | `2026-11-17T08:41:32Z` |
| **GPON Status** | `Up` · `GponConnectionStat:1` (RX `1010`, TX `180480`) |
| **Mem** | Total `463600` / Free `176944` KB · 1 hilo CPU · CPUTemp ~71 °C |

- El cuerpo de `device_status.cgi` llega en **TEXTO PLANO** (no AES). Los datos están en `var dev_info = {...}` y `var gpon_status = {...}`.

## 2) 🌳 Árbol completo de `menu.cgi` (`all_nodes.nodes[]`)

`GET /menu.cgi` → `Content-Type: text/javascript` (10 590 B, texto plano). Define `var all_nodes = { nodes:[ {name,target,nodes:[…]} ] }`. El shell lo carga como `<script src="menu.cgi">` y arma el menú en el iframe `mainFrame`. **`adminRole = 0`** (rol TELMEX, no superadmin). **Todos los 43 targets respondieron `200`** (ninguno redirigió a login).

| Sección | Submenú (name) | `target` (CGI) | Rol / Notas |
| :--- | :--- | :--- | :--- |
| **Status** | Overview | `overview.cgi` | Resumen |
| | Device Information | `device_status.cgi` | **Modelo/SN/firmware** (ver §1) |
| | LAN Status | `lan_status.cgi?lan` | |
| | WAN Status | `show_wan_status.cgi?ipv4` | **WAN activas** (ver §4) |
| | WAN Status IPv6 | `show_wan_status.cgi?ipv6` | |
| | Home Networking | `lan_status.cgi?wlan` | |
| | Optics Module Status | `wan_status.cgi?gpon` | Potencias ópticas GPON |
| | Statistics | `statistics.cgi` | |
| | Call Log | `call_history_statistics.cgi` | Registro de llamadas (voz) |
| | **Voice Information** | **`voice_info.cgi`** | **Estado SIP (solo lectura, ver §3)** |
| **Network** | LAN | `lan_ipv4.cgi` | |
| | LAN_IPv6 | `lan_ipv6.cgi` | |
| | **WAN** | **`wan_config_glb.cgi`** | **Config WAN PPPoE/VLAN (ver §4)** |
| | WAN DHCP | `wan_dhcp.cgi` | |
| | Wireless (2.4GHz) | `wlan_config.cgi` | |
| | Wireless (5GHz) | `wlan_config.cgi?v=11ac` | |
| | Wireless Schedule | `wifi_schedule.cgi` | |
| | IP Routing | `route.cgi` | |
| | DNS | `dns.cgi` | |
| | GRE Tunnel | `gre_tunnel.cgi` | |
| | US Classifier | `us_classifier.cgi` | |
| | MESH | `mesh.cgi` | |
| **Security** | Firewall | `firewall.cgi?fire` | |
| | MAC Filter | `macfilter.cgi` | |
| | IP Filter | `ipfilter.cgi` | |
| | URL Filter | `urlfilter.cgi` | |
| | Parental Control | `parental_control.cgi` | |
| | DMZ and ALG | `nat_glb.cgi?v=alg` | |
| **Application** | Port Forwarding | `nat_glb.cgi?v=vhost` | |
| | Port Triggering | `nat_glb.cgi?v=thost` | |
| | DDNS | `ddns.cgi` | |
| | NTP | `sntp.cgi` | |
| | UPNP and DLNA | `upnp.cgi` | |
| **Maintenance** | Password | `user_glb.cgi` | Cambio de contraseña |
| | LOID Configuration | `reg.cgi?loidcfg` | |
| | SLID Configuration | `gpon_config.cgi` | |
| | Device Management | `device_name.cgi` | |
| | **Backup and Restore** | **`usb.cgi?backup`** | **Descarga/subida de config (ver §5)** |
| | Firmware Upgrade | `upgrade.cgi` | Subida de firmware |
| | Reboot Device | `reboot.cgi` | *(no se hizo GET — omitido por precaución)* |
| | Factory Default | `restore.cgi` | Reset de fábrica |
| | Diagnostics | `diag.cgi?ping` | |
| | Log | `log.cgi` | |
| | PPPoE Diagnostics | `web_diag.cgi` | |
| **RG Troubleshooting** | *(sin hijos)* | — | Vacío para este rol |
| **SmartHome** | *(sin hijos)* | — | Vacío (IoT Z-Wave/ZigBee no expuesto a adminRole=0) |

## 3) 📞 VoIP / SIP — hallazgos

- **NO existe página de *configuración* VoIP** para `adminRole=0`. Sondas negativas (todas `404`, cuerpo de 388 B): `voice.cgi`, `voip.cgi`, `sip.cgi`, `voice_config.cgi`, `voice_glb.cgi`, `voice_advanced.cgi`, `voice_line.cgi`, `voip_glb.cgi`, `voice_basic.cgi`, `voice_sip.cgi` (`voice_setting.cgi` cerró la conexión sin responder → tampoco existe). Las cadenas i18n *"Primary SIP server"*, *"Voice Password"*, *"Voice Setting"* viven en `web-*.json` pero **sus CGIs no están habilitados para este rol**.
- **`voice_info.cgi` (Status ▸ Voice Information)** = **solo lectura**. Variables JS embebidas (texto plano):
  ```js
  var voip_cmd    = [{_oid:1, phNumber:'', status:'', proxyIp:'', regErrorCode:0, regErrorReason:''}];
  var lines_config= [{_oid:1, Status:'Disabled'}];            // ← línea de voz DESHABILITADA
  var user_agent  = { userAgentIp:'189.238.92.11' };          // IP del UA SIP (= WAN VLAN881)
  ```
  Muestra `#line_status`, `#phone_number`, `#register_status`, `#error_code` (todos vacíos aquí).
- **CONCLUSIÓN (clave para Fase 5):** en esta ONT la **línea SIP figura `Disabled`** y sin número/proxy en la UI → **no hay credenciales SIP visibles por Web**. El `AuthUserName`/`AuthPassword` SIP (IMS) **solo podrá obtenerse del backup de configuración** (Fase 3/4). La web **no** permite editar voz con este rol ⇒ la liberación de línea (Fase 5) tendrá que ir por **re-subida del `.cfg` modificado** (Vía A), no por POST a un CGI de voz inexistente.

## 4) 🌐 WAN / Network — hallazgos

- **`show_wan_status.cgi?ipv4`** (texto plano) → **3 WANs**, solo la primera activa:

  | # | Name (perfil WAN) | VLAN | Servicios | Estado | IP / MAC |
  | :-: | :--- | :-: | :--- | :--- | :--- |
  | 1 | **`1_VOIP_TR069_INTERNET_OTHER_R_VID_881`** | **881** | **VOIP + TR069 + INTERNET + OTHER** (Routed) | **Connected** | `189.238.92.11` / `e0:3d:a6:d0:bd:54` (iface `ppp111`) |
  | 2 | `2_NONE_R_VID_1081` | 1081 | NONE | Unconfigured | — |
  | 3 | `3_NONE_R_VID_981` | 981 | NONE | Unconfigured | — |

- **Topología Telmex confirmada:** **WAN única PPPoE sobre VLAN 881** que transporta **Internet + Voz (VoIP/IMS) + TR-069** en la misma conexión (`ConnectionType: IP_Routed`). El `userAgentIp` de voz (`189.238.92.11`) **== IP externa de la WAN 881** ⇒ la voz **no** tiene VLAN dedicada: va por la 881. Esto encaja con la nota de arquitectura (VLAN 881) y descarta bloqueo por puerto/VLAN local.
- **`wan_config_glb.cgi`** = formulario de edición de la WAN (plantilla con `vlanId`, `pppoe_password`, etc.); los valores reales se cargan por AJAX/getter y la contraseña PPPoE viene enmascarada en la UI ⇒ credenciales PPPoE reales también se extraerán del **backup** (Fase 4). El shell consulta el estado PPP con `POST /index.cgi?getppp` (cuerpo `csrf_token=<token>`, cifrado RSA+AES vía `encrypt_post_data`).

## 5) 💾 Backup / Restore — mecanismo EXACTO (página `usb.cgi?backup`)

La página (iframe `mainFrame`) trae **dos `<form>` nativos** que apuntan a `usb.cgi` (acción relativa) con `target="pfrm"` (iframe oculto). **Clave:** son *form submit nativos*, **no** `$.ajax`, así que **NO pasan por el hook `ajaxSend` → NO se cifran** (el cifrado RSA+AES solo aplica a POSTs AJAX). A cada `<form>` se le **prependen** dos hidden: `csrf_val=""` y `csrf_token="<token-de-sesión>"`.

> **CSRF token de sesión:** en toda la sesión mapeada fue **`MHlyCWWZDOaogecD`** (mismo valor embebido en *todos* los CGIs de esa sesión; **rota al re-loguear**, no por página). Debe leerse fresco de `GET /usb.cgi?backup` antes de exportar/importar.

### 5a) ⬇️ DESCARGAR backup (Export Config File)
```html
<form name="export" method="post" ENCTYPE="application/x-www-form-urlencoded"
      action="?export" target="pfrm"> … <input type="submit" value="Export"></form>
```
- **Endpoint:** `POST http://192.168.99.254/usb.cgi?export`
- **Content-Type:** `application/x-www-form-urlencoded`
- **Cuerpo (sin cifrar):** `csrf_val=&csrf_token=MHlyCWWZDOaogecD`
- **Respuesta:** el router devuelve el **archivo de configuración como descarga** (hacia el iframe `pfrm`; con `Content-Disposition` de adjunto). Formato/cifrado del `.cfg` → a analizar en **MF-3.1/3.2**.
- ⚠️ **No se ejecutó la descarga** (se dejó limpio para MF-3.1; solo se inspeccionó el formulario/JS).

### 5b) ⬆️ SUBIR / RESTAURAR backup (Import Config File)
```html
<form name="import" method="post" ENCTYPE="multipart/form-data"
      action="?import" target="pfrm">
   <input type="file" name="filename"> … <input type="submit" id="imp" value="Import"></form>
```
- **Endpoint (defecto):** `POST http://192.168.99.254/usb.cgi?import`
- **Variante con serial:** si se usa el popup de número de serie, el submit reescribe la acción a
  **`POST /usb.cgi?v=import&sl_num=<SerialNumber>`** (p.ej. `sl_num=ALCLB472FD24`). El JS valida el serial: **12 chars, prefijo `ALCL`, alfanumérico** (`isvalidSerialNum`).
- **Content-Type:** `multipart/form-data`; campo de archivo **`filename`** = el `.cfg`.
- **CSRF:** hidden `csrf_token=MHlyCWWZDOaogecD` (+ `csrf_val=`) prependidos al form.
- **Confirmación UI:** `confirm("Are you sure to restore configuration file to ONT?")`; éxito → `"Import Completed!"`; fallo → *"Failed to restore the configuration, please ensure the configuration backup is valid."* El equipo **reinicia** tras un restore válido.

### 5c) Otros endpoints de Maintenance (mismo patrón csrf)
- **Firmware Upgrade:** `POST /upgrade.cgi` (self, `action=''`), `multipart/form-data`, campo `filename` = imagen de firmware, + `csrf_token`.
- **Factory Default (`restore.cgi`):** botón *Factory Default* → POST con `csrf_token` (⚠️ borra config — **no** ejecutar).

## 6) 🔑 Patrón de peticiones autenticadas (consolidado)
- **Sesión:** cookies `sid` (=X-SID) / `isAdminLoggedIn=1` / `lsid` (+ `lang`). El `X-SID` también se re-presenta como header por precaución, pero **manda la cookie `sid`**.
- **POST AJAX a CGIs** (los que modifican/consultan vía `$.ajax`): el hook `ajaxSend` añade `csrf_token=<token>` y luego **cifra todo** con `crypto_page.encrypt_post_data(pubkey, data)` → `encrypted=1&ct=…&ck=…` (mismo envoltorio RSA-1024+AES-128 del login). Respuestas cifradas se descifran con `aes128_cbc_decrypt_sjcl(enckey, enciv, ct)` (clave/IV del cliente ligados al X-SID).
- **POST de FORMULARIO nativo** (export/import/upgrade/factory): **sin cifrar**, `csrf_token` en hidden field. ← Esto hace que la **descarga del backup (5a) sea un POST directo** trivial de replicar en Python (Fase 3).
- **Respuestas de *status* (`device_status.cgi`, `menu.cgi`, `voice_info.cgi`, `show_wan_status.cgi`):** **texto plano** (no AES).

## 7) 💻 Código de MF-2.3 (`nokia_auth.py`)
| Función | Rol |
| :--- | :--- |
| `map_authenticated_endpoints(opener, ip, outdir, x_sid, …)` | Con sesión ya autenticada: GET `menu.cgi`+parse `all_nodes`, GET `device_status.cgi`+parse `dev_info`, GET de todos los targets del menú, sondas de voz. Devuelve dict estructurado y guarda cada CGI. **No** hace login/logout (lo hace el driver). |
| `_parse_menu_nodes(js_text)` | Convierte el literal JS `all_nodes` a JSON (comillas en `name/target/nodes`, quita comas colgantes) → secciones/filas/targets; fallback por regex. |
| `_authget(opener, ip, target, outdir, x_sid)` | GET autenticado que guarda el cuerpo en `outdir/cgi/<saneado>` y reporta status/size/content-type/preview. |
| `logout_nokia(opener, ip)` | `GET /login.cgi?out` — cierra la sesión (ejecutado **siempre** en `finally`). |
| CLI `nokia_auth.py map` | Driver: `login → map_authenticated_endpoints → logout` (ciclo limpio). |

## ✅ Cierre de MF-2.3 y de la FASE 2
- **Modelo/firmware confirmados:** **Nokia G-1425G-H**, SW `3TN00702IJMI00`, HW `3TN00990ADAA`, SN/GPON `ALCLB472FD24`.
- **Árbol `menu.cgi` completo mapeado** (43 targets, todos `200`, `adminRole=0`).
- **Descarga de backup localizada:** `POST /usb.cgi?export` (urlencoded, `csrf_token`, **sin cifrar**, descarga directa) → entrada de **MF-3.1**.
- **Subida/restore localizada:** `POST /usb.cgi?import` (o `?v=import&sl_num=<serial>`, multipart `filename`, `csrf_token`) → entrada de **MF-5.2**.
- **VoIP:** sin CGI de config (rol 0); línea SIP `Disabled`; credenciales SIP **solo** en el backup.
- **WAN:** WAN única PPPoE **VLAN 881** (Internet+VoIP+TR069), voz sin VLAN dedicada.
- **Sesión cerrada** con `GET /login.cgi?out` en cada ciclo (sin sesiones colgadas).
- ➡️ **Siguiente: Fase 3 (MF-3.1 `download_nokia_backup`)** usando `POST /usb.cgi?export`.
