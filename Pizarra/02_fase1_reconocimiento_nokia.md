# 🔍 Fase 1: Reconocimiento No Intrusivo de la ONT Nokia

> **Estado:** ✅ **FASE 1 COMPLETADA** — `MF-1.1` ✅ · `MF-1.2` ✅ · `MF-1.3` ✅
> **Fecha:** 2026-11-20

---

## 🎯 Alcance de esta Etapa
Ejecutar las microfunciones de reconocimiento inicial sobre la red local para identificar la ONT Nokia:
1. **`MF-1.1` (`detect_default_gateway`)**: Identificar la IP de la pasarela predeterminada en macOS (`route -n get default` / `netstat -rn`) y comprobar que responde.
2. **`MF-1.2` (`fingerprint_nokia_web`)**: Inspeccionar la respuesta HTTP/HTTPS inicial de la pasarela (headers, redirecciones, HTML/JS de login, modelo exacto del Nokia).
3. **`MF-1.3` (`scan_management_ports`)**: Verificar qué puertos de gestión están abiertos en la IP de la pasarela (`80`, `443`, `22`, `23`).

---

## 📝 Registro de Ejecución y Hallazgos

### ✅ MF-1.1 — `detect_default_gateway()` — [2026-11-20 14:39]
**Estado:** ✅ Completado (reconocimiento no intrusivo, sin login).
**SO:** macOS (Darwin 27.2.0), interfaz usada: `en0` (Ethernet/Wi-Fi activa).

#### Comandos ejecutados y resultados exactos

**1) Default gateway**
```console
$ route -n get default
   route to: default
destination: default
       mask: default
    gateway: 192.168.99.254
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
...
$ netstat -rn -f inet | grep '^default'
default            192.168.99.254     UGScg                 en0
default            link#21            UCSIg               utun4
```
> **Gateway detectado:** `192.168.99.254` vía interfaz **`en0`**.
> ⚠️ *No* es el típico `192.168.1.254` de Telmex (ver Hallazgos).

**2) Interfaz activa `en0`**
```console
$ ifconfig en0
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether e2:03:01:b3:24:15
	inet 192.168.99.209 netmask 0xffffff00 broadcast 192.168.99.255
	status: active
```
> IP local del Mac: `192.168.99.209/24` — mismo segmento que el gateway. `status: active`.

**3) Ping (2 paquetes)**
```console
$ ping -c 2 -t 3 192.168.99.254
64 bytes from 192.168.99.254: icmp_seq=0 ttl=64 time=3.559 ms
64 bytes from 192.168.99.254: icmp_seq=1 ttl=64 time=3.529 ms
2 packets transmitted, 2 packets received, 0.0% packet loss
```
> ✅ Gateway **vivo**: 0% pérdida, RTT ~3.5 ms, `ttl=64`.

**4) Tabla ARP (MAC / OUI del gateway)**
```console
$ arp -n 192.168.99.254
? (192.168.99.254) at e0:3d:a6:d0:bd:50 on en0 ifscope [ethernet]
```
> **MAC del gateway:** `e0:3d:a6:d0:bd:50` → **OUI `E0:3D:A6`**.

**5) Prueba de conexión TCP (80 / 443)**
```console
$ nc -z -v -G 3 -w 3 192.168.99.254 80
Connection to 192.168.99.254 port 80 [tcp/http] succeeded!

$ nc -z -v -G 3 -w 3 192.168.99.254 443
nc: connectx to 192.168.99.254 port 443 failed: Operation timed out
```
> ✅ **TCP/80 ABIERTO** · ❌ **TCP/443 no responde** (cerrado/filtrado en 3 s).

**6) Banner HTTP mínimo (solo cabecera, sin login)**
```console
$ curl -s -m 5 -I http://192.168.99.254/
HTTP/1.1 501 Not Implemented
Referrer-Policy: no-referrer
Server: thttpd
Content-Type: text/html; charset=utf-8
Connection: close
```
> **Servidor web:** `thttpd` (devuelve `501` ante `HEAD`; se reintentará con `GET` en MF-1.2).

#### 🔎 Hallazgos clave
- **Gateway confirmado y accesible:** `192.168.99.254` (en0), responde ICMP y TCP/80.
- ⚠️ **Subred atípica:** `192.168.99.0/24`, no la LAN Telmex de fábrica `192.168.1.254`. Probablemente la subred LAN fue personalizada, o hay un router/segmento intermedio distinto a la ONT Nokia. A confirmar en MF-1.2/MF-1.3.
- ⚠️ **OUI `E0:3D:A6` ≠ bloque propio Nokia/Alcatel-Lucent.** Según consulta externa, `E0:3D:A6` está registrado a **Taicang T&W Electronics** (Suzhou, China), un **ODM/OEM** de ONTs y CPE. Nota: T&W fabrica equipos de marca blanca y para terceros (incluidos algunos ONT re-etiquetados), por lo que **no descarta** que sea la ONT objetivo, pero **no confirma marca Nokia por OUI**. La identificación definitiva del modelo se hará por fingerprint web (MF-1.2).
- **Pista de firmware:** servidor `thttpd` + `443` cerrado → perfil de servidor web ligero embebido; coherente con CPE/ONT. El modelo exacto (G-240W-x / G-2425G-x / G-140W-x u otro) queda **pendiente de MF-1.2**.

#### ⛳ Conclusión MF-1.1
Objetivo de administración vivo en **`http://192.168.99.254`** (TCP/80, `thttpd`). Gateway alcanzable y en el mismo segmento L2 que el host. **Dos banderas abiertas para las siguientes microfunciones**: (a) subred no estándar y (b) OUI = T&W (ODM), no Nokia directo. **No se avanzó a MF-1.2 ni se realizó login** (según instrucción).

---

### ✅ MF-1.2 — `fingerprint_nokia_web()` — [2026-11-20 20:46]
**Estado:** ✅ Completado (reconocimiento sin autenticar; **no se ejecutó login**, eso es Fase 2).
**Target:** `http://192.168.99.254/` · Servidor: **thttpd** (customizado) · HTTP/1.0.

#### 1) Respuesta HTTP inicial (`GET /`, siguiendo redirecciones)
- **No hay redirección:** `GET /` → **`200 OK`** directo (la página de login se sirve en la raíz; `FINAL_URL = http://192.168.99.254/`, `SIZE = 13806 bytes`).
- **Cabeceras de la página de login (200):**
```http
HTTP/1.0 200 OK
Cache-Control:private,max-age=0;
X-Frame-Options:SAMEORIGIN
X-Content-Type-Options:nosniff
X-XSS-Protection:1; mode=block
Content-Security-Policy:default-src 'self' blob: 'unsafe-inline' 'unsafe-eval';img-src * data: 'unsafe-inline'
Strict-Transport-Security:max-age=2592000; includeSubdomains
Referrer-Policy: no-referrer
Set-Cookie: lang=spa; path=/;
Content-type:text/html;charset=UTF-8;
```
  > En el `200 OK` **no** aparece `Server:`; pero ante métodos no implementados (`HEAD`, `OPTIONS`) el servidor responde **`501 Not Implemented`** con `Server: thttpd`. ⇒ El servidor web embebido **solo implementa `GET` y `POST`**.
- **Sin cabecera `WWW-Authenticate`** → la autenticación es **por formulario web (CGI) + cripto en el frontend**, no HTTP Basic/Digest.
- **Cookie inicial:** `lang=spa` (idioma, no sesión). La sesión se gestiona vía cabecera **`X-SID`** tras el login (ver más abajo).

#### 2) Identificación del equipo (modelo / fabricante)
| Evidencia | Fuente | Valor |
| :--- | :--- | :--- |
| Título de página | `GET /` | `GPON Home Gateway` |
| `window.name` | script login | `'Bell'` |
| Tag de operador | `var operatorCheck="MXXT"` / `operatorid="MXXT"` | **MXXT = México Telmex** |
| Fabricante | `js_glb/web-spa.json` | **"Nokia"**, "**Nokia** Solutions and Networks Oy ['Nokia']" |
| Línea de producto | `web-spa.json` | **"Beacon Serial Number"**, "Beacon Entries reached", "Beacons are not connected to the LAN ports…" |
| Subsistema IoT | `web-spa.json`/`web-eng.json` | **"IOTGW Version", "JVM Version", "Z-Wave Firmware Version", "ZigBee Firmware Version"**, "Upgradation of IoT firmware" |
| Versiones HW/SW (etiquetas de la UI, aún sin valores) | `web-eng.json` | "Hardware Version", "Boot Version", "Software Version", "Firmware Upgrade" |

> **🎯 Conclusión de modelo:** Es una **ONT/Gateway Nokia GPON con IoT Gateway integrado (Z-Wave + ZigBee + JVM)** y soporte **mesh Beacon** → firma característica del **Nokia G-2425G-A ("Beacon 1" / Smart Home Gateway)** distribuido por Telmex (candidato principal; alternativa G-2426G-A). ⚠️ La **cadena exacta de modelo y versión de firmware** vive en la página autenticada *Device Information* → se confirmará en **Fase 2 (MF-2.3)**. El OUI del gateway (`E0:3D:A6` = Taicang T&W, ODM de la MF-1.1) es coherente: T&W fabrica ONTs Nokia de marca blanca.

#### 3) ⭐ Mecanismo de LOGIN (lo más importante para Fase 2)
El `<form id="loginform" action="javascript:submit();">` tiene `username` (id=`username`, prellenado **`TELMEX`**) y `password` (id=`password`). Al enviar se ejecuta la función **`submit()`** embebida en el HTML. **Este es el flujo real y activo** (hay además un `login_page.submit()` alternativo tipo challenge-response SHA-256 en `crypto_page.js`, **pero no se usa** en esta página).

**Librerías cripto cargadas en el login:**
```html
<script src="/common/js/jquery-3.5.1.js"></script>
<script src="js_glb/jsencrypt.min.js"></script>   <!-- JSEncrypt v3.0.0  (RSA PKCS#1 v1.5) -->
<script src="js_glb/sjcl.js"></script>             <!-- Stanford JS Crypto Lib: AES + CBC + SHA-256 -->
<script src="js_glb/crypto_page.js"></script>      <!-- envoltorio hibrido RSA+AES de Nokia -->
<script src="js_glb/translate.js"></script>
```

**Clave pública RSA embebida en la página (1024-bit, PKCS#1 v1.5):**
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD7nE9L38HvcuWPLgmCFrEwfVVe
4pbDLciv/c0DMyymkRb1T/dYsC9cTR4kWxLK/qfnWzPTmCfOEHDvEa9qNmupnNy7
OP68cZs+JJAKXBncf5aI3H2hMpE0SVqThATtLz/SlfVlvFSEfx0Lf+w1pPN+aE6+
8ri48nVMfCE2gDrlqQIDAQAB
-----END PUBLIC KEY-----
```
> ⚠️ Esta pubkey puede ser por-dispositivo o por-firmware. **Fase 2 debe re-leerla del HTML en cada login** (no hardcodear a ciegas).

**Parámetros anti-CSRF/anti-replay embebidos por-carga (rotan en cada `GET /`):**
```js
var nonce = "pIZuaZpPuHO0iO/0B6DubQHjtMhZcJzF7CcBaf0XZo0=";   // base64, 32 bytes
var token = "QfCVljsPWNbDGtUX";                                // csrf_token, 16 chars
```
> ⚠️ **Fase 2 (MF-2.1) debe hacer `GET /` fresco y extraer por regex `nonce`, `token` y `pubkey` ANTES de cada intento de login.**

**Función `submit()` activa (fragmento literal del HTML servido):**
```js
function submit() {
    var username = $(":input[id=username]").val();
    var password = $(":input[id=password]").val();
    var nonce = "pIZuaZpPuHO0iO/0B6DubQHjtMhZcJzF7CcBaf0XZo0=";
    var token = "QfCVljsPWNbDGtUX";

    var base64 = sjcl.codec.base64;
    var dec_key = base64.fromBits(sjcl.random.randomWords(4, 0));   // 128-bit, clave para DESCIFRAR respuestas
    var dec_iv  = base64.fromBits(sjcl.random.randomWords(4, 0));   // 128-bit IV

    var postdata = '&username=' + username
                 + '&password=' + encodeURIComponent(password)
                 + '&csrf_token=' + token
                 + '&nonce=' + nonce
                 + '&enckey=' + crypto_page.base64url_escape(dec_key)
                 + '&enciv='  + crypto_page.base64url_escape(dec_iv);

    var encryptdata = crypto_page.encrypt_post_data(pubkey, postdata);  // -> RSA+AES

    $.ajax({
        url: '/login.cgi', type: 'POST', data: encryptdata,
        success: function(data, textstatus, jqXHR) {
            if (jqXHR.status == 299) {                       // <-- ÉXITO = HTTP 299
                var sid = jqXHR.getResponseHeader('X-SID');  // <-- ID de sesión
                localStorage.clear();
                localStorage.setItem(sid, dec_key + ' ' + dec_iv);  // guarda clave p/ descifrar respuestas
                window.top.location = "/";
            } else {                                         // fallo -> re-render del HTML de error
                var doc = document.open("text/html","replace");
                doc.write(data); doc.close();
            }
        }
    });
}
```

**Envoltorio cripto (`crypto_page.js`, funciones clave, literal):**
```js
// Cifra el cuerpo del POST: AES-128-CBC(plaintext) + la clave AES se cifra con RSA
var encrypt = function(pubkey, plaintext) {
    var aeskey = sjcl.random.randomWords(4, 0);      // 128-bit (efimera, por request)
    var iv     = sjcl.random.randomWords(4, 0);      // 128-bit
    var pt     = sjcl.codec.utf8String.toBits(plaintext);
    var aes    = new sjcl.cipher.aes(aeskey);
    var ct     = sjcl.mode.cbc.encrypt(aes, pt, iv); // AES-128-CBC, padding PKCS#7 (sjcl)
    var rsa    = new JSEncrypt(); rsa.setPublicKey(pubkey);
    var aesinfo = base64.fromBits(aeskey) + ' ' + base64.fromBits(iv);  // "<b64 key> <b64 iv>"
    var ck      = rsa.encrypt(aesinfo);              // RSA-1024 PKCS#1 v1.5 sobre "key iv"
    return { ct: base64url.fromBits(ct), ck: base64url_escape(ck) };
};

var encrypt_post_data = function(pubkey, plaintext) {
    var p = encrypt(pubkey, plaintext);
    return 'encrypted=1&ct=' + p.ct + '&ck=' + p.ck;   // <-- FORMATO EXACTO DEL CUERPO POST
};

// Descifra las RESPUESTAS del router (que vienen AES-CBC con enckey/enciv ligadas al X-SID)
var aes_decrypt = function(sid, ciphertext) {
    var key_iv = localStorage.getItem(sid).split(' ');
    var key = base64.toBits(key_iv[0]), iv = base64.toBits(key_iv[1]);
    var pt  = sjcl.mode.cbc.decrypt(new sjcl.cipher.aes(key), base64.toBits(ciphertext), iv);
    return sjcl.codec.utf8String.fromBits(pt);
};

// base64url_escape:  '+' -> '-'   '/' -> '_'   '=' -> '.'   (NO es base64url estándar: usa '.' por '=')
```

#### 🧭 Modelo exacto del protocolo de login (a reimplementar en Python — Fase 2)
1. **`GET /`** → extraer `pubkey` (PEM), `nonce` (b64), `token` (csrf).
2. Generar **`enckey`/`enciv`** (16 bytes aleatorios c/u, base64) → son la clave/IV con que **el router cifrará sus respuestas**.
3. Construir **`postdata`** (texto plano, con `&` inicial):
   `&username=TELMEX&password=<encodeURIComponent(pw)>&csrf_token=<token>&nonce=<nonce>&enckey=<b64url_escape(enckey)>&enciv=<b64url_escape(enciv)>`
4. Generar **AES efímera** `aeskey`/`iv` (16 bytes c/u) → `ct = base64url( AES-128-CBC(aeskey, iv, postdata, PKCS#7) )`.
5. `ck = base64url_escape( RSA1024_PKCS1v1.5_encrypt( "<b64(aeskey)> <b64(iv)>" ) )`.
6. **`POST /login.cgi`** con `Content-Type: application/x-www-form-urlencoded`, cuerpo:
   `encrypted=1&ct=<ct>&ck=<ck>`.
7. **Éxito ⇔ HTTP status `299`** + cabecera **`X-SID: <sid>`**. Guardar `sid` y asociar `enckey`/`enciv` para **descifrar (AES-128-CBC) todas las respuestas posteriores**. (Fallo ⇒ devuelve HTML de error con conteo de intentos; `ErrorLimit = 4`.)
8. ⚠️ **A descubrir en Fase 2:** cómo se re-presenta el `X-SID` en peticiones autenticadas subsecuentes (cookie vs. cabecera/param) y si las respuestas vienen siempre AES-cifradas.

> **Notas de seguridad operativa (Telmex/Nokia):** `ErrorLimit=4` sugiere bloqueo/aviso tras ~4 fallos → Fase 2 **no** debe hacer fuerza bruta; usaremos la contraseña conocida `sf3h5zkdtA` en **un** intento limpio. `base64url_escape` es **no estándar** (`=`→`.`): hay que replicarlo exacto o el CGI rechazará el token.

#### Endpoints descubiertos (sin autenticar)
| Endpoint | Método | Resultado sin login | Rol |
| :--- | :--- | :--- | :--- |
| `/` | GET | `200` HTML login | Página de login (sirve nonce/token/pubkey) |
| `/login.cgi` | POST | (destino del login) | Autenticación RSA+AES → devuelve `299`+`X-SID` |
| `/reg.cgi` | GET | `200` → `Bad request for invalid parameter in the coookie` + `window.location.replace('/')` | Registro/popup; requiere cookie/sesión |
| `/js_glb/jsencrypt.min.js` | GET | `200` (JSEncrypt v3.0.0) | RSA frontend |
| `/js_glb/sjcl.js` | GET | `200` | AES-CBC + SHA-256 frontend |
| `/js_glb/crypto_page.js` | GET | `200` | Envoltorio híbrido RSA+AES |
| `/js_glb/translate.js` + `/js_glb/web-{spa,eng}.json` | GET | `200` | i18n (fuente de la huella "Nokia/Beacon/IoT") |
| `/common/js/jquery-3.5.1.js` | GET | `200` | jQuery 3.5.1 |
| `/css_glb/main.css` | GET | `200` | Estilos |
| `/favicon.ico`, `/version.txt`, `/index.asp`, `/top.html`, `/menu.html`, `/robots.txt` | GET | `404` | No existen |
> ⚠️ El servidor devuelve **`400`** si la ruta lleva **doble barra inicial** (`//ruta`) → normalizar siempre a una sola `/` en los scripts.

---

### ✅ MF-1.3 — `scan_management_ports()` — [2026-11-20 20:46]
**Estado:** ✅ Completado (TCP connect-scan no intrusivo desde la LAN `192.168.99.209` → `192.168.99.254`; sin login).

#### Tabla de puertos (vista desde la LAN)
| Puerto | Servicio | Estado LAN | Notas |
| :---: | :--- | :---: | :--- |
| 21 | FTP | ❌ cerrado/filtrado | — |
| 22 | SSH | ❌ cerrado/filtrado | **Sin banner** (no se intentó login) |
| 23 | Telnet | ❌ cerrado/filtrado | **Sin banner** (no se intentó login) |
| 53 | DNS | ❌ cerrado/filtrado | — |
| **80** | **HTTP** | ✅ **ABIERTO** | `thttpd`; única superficie de gestión en LAN |
| 443 | HTTPS | ❌ cerrado/filtrado | Pese a enviar `Strict-Transport-Security`, no escucha en LAN |
| 5060 | SIP (TCP/UDP) | ❌ no detectado | TCP cerrado; UDP `OPTIONS` sin respuesta (cliente SIP IMS vive en WAN, no expuesto a LAN) |
| 7547 | TR-069 (CWMP) | ❌ cerrado/filtrado | ACS de Telmex alcanza al equipo por WAN, no por LAN |
| 8080 | HTTP alt | ❌ cerrado/filtrado | — |

#### 🔎 Hallazgos y consecuencias para fases posteriores
- **Única puerta de gestión en la LAN = HTTP/80.** Todo (login, descarga de backup, deshabilitar SIP) deberá hacerse **vía Web/CGI** sobre `http://192.168.99.254` con el envoltorio cripto de MF-1.2.
- **SSH(22)/Telnet(23) NO expuestos en LAN** ⇒ la **"Vía B/Opción 3" de Fase 5 (consola CLI con superusuario) queda descartada por ahora** salvo que se habilite desde la propia UI. La liberación de la línea SIP (Fase 5) se enfocará en **Web/CGI (Opción 1)** o **re-upload del `.cfg` modificado (Opción 2)**.
- **TR-069/7547 cerrado en LAN** ⇒ no hay gestión remota accesible localmente; coherente con CPE Telmex (gestionado por ACS vía WAN).
- **SIP/5060 no visible en LAN** ⇒ el cliente SIP interno del Nokia registra contra el IMS por la interfaz WAN; para evitar colisión con Asterisk habrá que **desactivarlo por configuración**, no bloquear un puerto local.

---

## 🏁 Cierre de la Fase 1 — Resumen Ejecutivo
| Ítem | Resultado |
| :--- | :--- |
| **IP de gestión** | `http://192.168.99.254` (LAN `192.168.99.0/24`, atípica) |
| **Fabricante** | **Nokia** (confirmado por i18n: "Nokia Solutions and Networks Oy") |
| **Modelo (candidato fuerte)** | **Nokia G-2425G-A "Beacon 1"** (GPON + IoT GW Z-Wave/ZigBee/JVM + mesh Beacon); cadena exacta → Fase 2 |
| **Operador** | `MXXT` = **Telmex México** |
| **Servidor web** | **thttpd** (customizado, solo `GET`/`POST`, HTTP/1.0) |
| **Auth** | Formulario → `POST /login.cgi` con **envoltorio híbrido RSA-1024(PKCS#1) + AES-128-CBC** (JSEncrypt 3.0.0 + sjcl) |
| **Anti-CSRF** | `nonce` (b64 32B) + `csrf_token` (16 char), **rotan por `GET /`** |
| **Señal de éxito** | HTTP **`299`** + cabecera **`X-SID`**; respuestas posteriores **AES-CBC** con `enckey`/`enciv` del cliente |
| **Puertos LAN** | **Solo TCP/80**; 22/23/443/5060/7547/8080/53/21 cerrados |
| **Credenciales a usar (Fase 2)** | `TELMEX` / `sf3h5zkdtA` — **un** intento (ojo `ErrorLimit=4`) |
| **Artefactos guardados** | `/tmp/nokia_recon/` (HTML login, `crypto_page.js`, `jsencrypt.min.js`, `sjcl.js`, `web-{spa,eng}.json`) |

> ✅ **MF-1.2 y MF-1.3 completadas. Fase 1 cerrada. NO se ejecutó login real (reservado para Fase 2).**
