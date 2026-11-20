regre# 🔓 Fase 3: Descarga y Análisis Forense / Criptográfico del Respaldo (Nokia G-1425G-H / Telmex)

> **Estado:** 🟠 **BLOQUEADA (parcial)** — `MF-3.1` ✅ · `MF-3.2` ✅ (formato 100%) · `MF-3.3` ⚠️ (clave derivada en el dispositivo) · **Fase 3.5:** `MF-3.4` ✅ (modo = flujo, keystream estático) · `MF-3.5` ✅ (auditoría 43 CGIs → username PPPoE en claro + endpoint `command.cgi?cat+`)
> **Fecha:** 2026-11-20
> **Target:** `http://192.168.99.254/` · **Nokia G-1425G-H** · SW `3TN00702IJMI00` · SN/GPON `ALCLB472FD24`
> **Objetivo de la fase:** Descargar el `.cfg` de configuración y determinar su estructura binaria/criptográfica hasta obtener el XML/texto en claro (donde viven las credenciales SIP IMS, que la Web **no** expone con `adminRole=0`).

> **⚠️ RESULTADO EJECUTIVO (MF-3.2 + MF-3.3):** El contenedor quedó **identificado con certeza total** como el formato Alcatel-Lucent/Nokia `cfg` **legacy** (magic `0x00123123`, header LE de 20 B, **CRC32 del payload verificado = `0x9bf0704f`**). El payload interno (137 526 B, entropía **7.9983**, `len%16=6`) está **cifrado con una clave simétrica DERIVADA EN EL DISPOSITIVO** (dentro del firmware `3TN00702IJMI00`): **no** empieza con header zlib, **no** trae marcador de capa `0xFF` (rajkosto) ni `0x11` (udaravima), y **ninguna** de 1150+ combinaciones de claves públicas/derivables del archivo lo descifra. Este es el **mismo estado público no resuelto** para esta familia (G-1425G-B build Dic-2024, repo `udaravima`). **Conclusión:** el XML en claro **no es recuperable únicamente desde el `.cfg`**; se requiere extraer la clave del binario del firmware (ver §Rutas Pendientes). Las credenciales SIP IMS **no** se pueden leer por esta vía todavía.

---

## 🎯 Alcance de MF-3.1 (`download_nokia_backup`)
Esta microfunción **solo descarga** el respaldo de configuración **crudo e intacto** y lo caracteriza (headers, filename original, tamaño exacto, SHA-256, MD5, preview de recepción). **NO** analiza ni descifra el contenedor (eso es MF-3.2 / MF-3.3).

**Artefacto de código:** `nokia_backup.py` (módulo dedicado que importa `nokia_auth.py`).

---

## 🔁 Flujo ejecutado (idéntico al form nativo `export` de `usb.cgi?backup`)
1. **Login** con `authenticate_nokia()` (`TELMEX` / `sf3h5zkdtA`) → HTTP `299` + `X-SID` + cookies `sid`/`isAdminLoggedIn`/`lsid`.
2. **`GET /usb.cgi?backup`** → se lee el **csrf_token activo de la sesión**.
3. **`POST /usb.cgi?export`** · `Content-Type: application/x-www-form-urlencoded` · cuerpo **`csrf_val=&csrf_token=<token>`** · `Referer: http://192.168.99.254/usb.cgi?backup`.
4. Captura de **todos los headers** de respuesta + **bytes crudos**.
5. Guardado intacto en **`output/nokia_backup_raw.cfg`** + copia con el **filename original** del `Content-Disposition` (`output/config.cfg`).
6. Cálculo de **tamaño exacto, SHA-256 y MD5**.
7. **`logout_nokia()`** (`GET /login.cgi?out`) **siempre** en `finally`.

> **Driver:** `.venv/bin/python -I nokia_backup.py` (ciclo limpio `login → GET backup → POST export → logout`). Sesión cerrada (logout `200`), sin sesiones colgadas.

---

## 🔑 Hallazgo clave — dónde está el csrf_token en `usb.cgi?backup`
A diferencia del shell principal (que usa `var token = "…"`), la página `usb.cgi?backup` **no** declara `var token`. El csrf_token de sesión aparece **embebido en el JS/HTML del form** de tres formas equivalentes (mismo valor):
```js
settings.data = 'csrf_token=XlzYYFFhwtIzGNJG';                         // prepend AJAX
// y como hidden inyectado al <form name="export">:
$(...).prepend('<input type="hidden" name="csrf_val"   value="" />');
$(...).prepend('<input type="hidden" name="csrf_token" value="XlzYYFFhwtIzGNJG" />');
```
Por eso `download_nokia_backup` extrae el token con **tres regex en cascada** (`var token=…`, `csrf_token=…`, `name="csrf_token" value="…"`). El token **rota al re-loguear** (cada ejecución nueva trae uno distinto; p.ej. `rOkaQyJFuyEZChfx`), por eso **debe leerse fresco** de `GET /usb.cgi?backup` justo antes del `POST ?export`.

Los dos `<form>` nativos confirmados en la página (submit nativo ⇒ **sin cifrar RSA+AES**):
```html
<form name="import" method='post' ENCTYPE='multipart/form-data'             action="?import" target="pfrm">
<form name="export" method='post' ENCTYPE='application/x-www-form-urlencoded' action="?export" target="pfrm">
```

---

## 📥 Resultado REAL de la descarga (MF-3.1)

### Headers de respuesta recibidos (`POST /usb.cgi?export` → `200`)
| Header | Valor |
| :--- | :--- |
| **HTTP status** | `200` ✅ |
| **`Content-Disposition`** | `attachment;filename="config.cfg" ` |
| **`Content-Type`** | `application/octet-stream` |
| **`Content-Length`** | *(no enviado por el router — transferencia sin longitud anunciada)* |
| **Cuerpo de la petición** | `csrf_val=&csrf_token=rOkaQyJFuyEZChfx` |

- **Filename original asignado por el router:** **`config.cfg`** (del `Content-Disposition`).
- El router **no** envía `Content-Length`; el tamaño se midió del stream recibido.

### Archivo descargado — caracterización forense preliminar
| Métrica | Valor |
| :--- | :--- |
| **Guardado crudo intacto** | `output/nokia_backup_raw.cfg` |
| **Copia con filename original** | `output/config.cfg` (byte-idéntica al crudo — `cmp` OK) |
| **Tamaño exacto** | **`137546` bytes** |
| **SHA-256** | `f1ba78af7a5145576bf295c3d2db826a7f52c1ef3639dfa48930dbea9ee8c5c7` |
| **MD5** | `1f570942e9e9babd88c2ac110f7dba10` |
| **Content-Type** | `application/octet-stream` (binario, **no** texto/XML plano) |

> Hashes **verificados de forma independiente** con `shasum -a 256` y `md5` del sistema (coinciden byte-a-byte con el cálculo de `hashlib` en Python). Ambos archivos (`nokia_backup_raw.cfg` y `config.cfg`) son **idénticos** (`cmp` sin diferencias).

### Primeros 64 bytes (vista preliminar de recepción — **solo diagnóstico**, no análisis)
```
hex : 23311200 36190200 4f70f09b 74a21300 feffffff c5dcbc71 593456dc 42f9c27c
      c4597a94 e4661ce5 0b98f61d e9773fe1 9b5ab9ef df92327a f1cbfe9a 022cc4d1
ascii: #1..6...Op..t..........qY4V.B..|.Yz..f.......w?..Z....2z.....,..
```
**Observaciones de recepción (preliminares, se formalizan en MF-3.2):**
- Magic inicial **`23 31`** = ASCII **`#1`** → encabezado propietario Alcatel-Lucent/Nokia (**no** es `1F 8B` gzip crudo ni `78 9C`/`78 DA` zlib ni `<?xml`).
- Tras el magic, los bytes `36 19 02 00` interpretados como `uint32` little-endian = **`0x00021936` = 137526** (≈ `137546 − 20`), lo que sugiere un **header de ~20 bytes** seguido de un **payload cifrado/comprimido** de 137526 bytes. El resto presenta **alta entropía** (aspecto de cifrado AES del contenedor Nokia).
- ⚠️ Esto es **solo una lectura superficial de la cabecera para confirmar recepción correcta**. La inspección formal (magic bytes, entropía, estructura de bloques, detección zlib/gzip/AES) es trabajo de **MF-3.2 (`analyze_container_format`)**.

---

## 💻 Código de MF-3.1 (`nokia_backup.py`)
| Función | Rol |
| :--- | :--- |
| `download_nokia_backup(opener=None, ip, output_dir='output', x_sid=None, user, password, timeout, raw_name)` | Ciclo completo: (login si `opener=None`) → `GET usb.cgi?backup` → `POST usb.cgi?export` → guardar crudo + copia filename → sha256/md5/tamaño → **logout en `finally`**. Devuelve dict con headers, filename, tamaño, hashes y preview. |
| `_extract_csrf_token(html)` | Extrae el csrf_token activo (3 regex en cascada: `var token`, `csrf_token=`, hidden `value`). |
| `_parse_cd_filename(cd)` | Extrae el filename original del `Content-Disposition` (comillas, RFC 5987, basename seguro). |
| `_safe_filename(name)` | Sanea el nombre para escribir en disco preservando el nombre real del router. |

**Notas de implementación:**
- `opener` es el 1.er parámetro (compatible con `download_nokia_backup(opener, ip, output_dir, x_sid, …)`). Si se pasa `None`, la función **abre y cierra su propia sesión** (login + logout). Si se pasa un `opener` ya autenticado + `x_sid`, lo reutiliza y **no** hace logout (lo gestiona el llamador).
- Se reutilizan `make_opener`, `_Pass2xxErrorProcessor`, `authenticate_nokia` y `logout_nokia` de `nokia_auth.py`.
- Ejecutar con aislamiento `-I`; el módulo inserta su propio directorio en `sys.path` (porque `python -I` no agrega el dir del script ni respeta `PYTHONPATH`).
- La descarga es un **POST de formulario nativo sin cifrar** (como se documentó en MF-2.3 §5a) → réplica trivial en Python, sin envoltorio RSA+AES.

---

## ✅ Cierre de MF-3.1
- **Backup descargado con éxito** (1 ciclo limpio): `POST /usb.cgi?export` → `200` + `Content-Disposition: attachment;filename="config.cfg"` + `Content-Type: application/octet-stream`.
- **Archivo crudo intacto** en `output/nokia_backup_raw.cfg` (+ copia `output/config.cfg`), **137546 bytes**, SHA-256 `f1ba78af…c5c7`, MD5 `1f570942…ba10` (verificados con herramientas del sistema).
- **Contenedor binario propietario** (magic `#1` / `23 31`), **no** texto plano → requiere análisis/descifrado en MF-3.2/3.3.
- **Sesión cerrada** con `GET /login.cgi?out` (logout `200`) en `finally`.
- ⏸️ **Detenido aquí según alcance** — **NO** se ejecutó MF-3.2 (`analyze_container_format`) ni MF-3.3 (`unpack_and_decrypt_config`).

### ➡️ Entrada lista para MF-3.2
`output/nokia_backup_raw.cfg` (137546 B) · magic `23 31 12 00` (`#1`) · posible header de ~20 B + payload 137526 B de alta entropía → **analizar magic bytes / entropía / zlib-gzip / AES Alcatel-Lucent**.

---

# 🔬 MF-3.2 — `analyze_container_format(raw_bytes)` ✅ COMPLETADA [2026-11-20]

## 🧩 Identificación DEFINITIVA del formato
El `23 31` inicial **NO es el ASCII `#1`**: es el **`uint32` little-endian `0x00123123`**, el **magic del formato de respaldo Alcatel-Lucent/Nokia `cfg`** documentado públicamente por **thedroidgeek** y extendido por **rajkosto** (herramienta `nokia-router-cfg-tool.py`, MIT). Confirmado contra el código fuente de ambas gists.

### Header LEGACY de 20 bytes (0x14) — todos `uint32` little-endian
| Offset | Campo | Bytes (nuestro archivo) | Valor | Interpretación |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | **magic** | `23 31 12 00` | **`0x00123123`** | Magic `cfg` legacy (LE). *(BE sería `00 12 31 23`; new-header sería `0x00124126`.)* |
| `0x04` | **compressed_size** | `36 19 02 00` | **`137526`** | Tamaño del payload almacenado. **Coincide** con los bytes reales tras el header. |
| `0x08` | **crc32** | `4f 70 f0 9b` | **`0x9bf0704f`** | **CRC32 (`binascii.crc32`) del payload almacenado.** ✅ **VERIFICADO: coincide byte-a-byte.** |
| `0x0C` | **uncompressed_size+1** | `74 a2 13 00` | **`1286772`** | Tamaño del XML descomprimido **+1** (off-by-one del empaquetador) → **XML real = `1286771` B (~1.23 MiB)**. |
| `0x10` | **fw_magic** | `fe ff ff ff` | **`0xfffffffe`** | Campo "firmware/build/flags" (sin identificar; en otros Telmex se ha visto `0xffffffff`). |
| `0x14` | **payload** | `c5 dc bc 71 …` | 137526 B | Datos comprimidos **+ cifrados** (ver abajo). |

> **La verificación del CRC32 es la prueba irrefutable** de que (a) tenemos el formato correcto, (b) la frontera header/payload está en el offset 20 exacto, y (c) el payload descargado está íntegro. El empaquetador del firmware calculó ese CRC **sobre estos 137526 bytes tal cual** (post-compresión/post-cifrado).

### Variante NEW (no aplica aquí, documentada por completitud)
`magic = 0x00124126` ⇒ header de **40 bytes (0x28)**: los mismos 5 campos pero cada `uint32` seguido de un `uint32=0` (ensanchado a 64 bits). El lector detecta la variante cuando el `u32` en `0x04` es `0`. Nuestro archivo es **legacy**.

## 📊 Métricas forenses del payload
| Métrica | Valor | Lectura |
| :--- | :--- | :--- |
| Tamaño payload | `137526` B | = `compressed_size` del header ✅ |
| **Entropía de Shannon** | **`7.9983` bits/byte** | ≈ máximo teórico (8.0) ⇒ **datos comprimidos *y/o* cifrados**. |
| `len % 16` | **`6`** | **NO múltiplo de 16** ⇒ **imposible** AES-CBC/ECB sobre el payload completo. Si es AES, es **modo de flujo** (CTR/CFB/OFB) o CBC sobre un sub-bloque alineado dejando residuo. |
| Primeros bytes | `c5 dc bc 71 59 34 56 dc …` | **NO** es header zlib (`78 01/9c/da/5e`), **NO** gzip (`1f 8b`), **NO** marcador de capa `0xFF`/`0x11`. |
| Ratio de compresión | `1286771 / 137526 ≈ 9.36×` | Coherente con XML (muy comprimible) → el contenido *interno* casi seguro es **zlib** (el desempaquetador usa `zlib.decompress`). |

## 🧪 Barridos de criptoanálisis ejecutados (reproducibles)
Scripts de trabajo en `tests/` (ejecutar con `.venv/bin/python -I tests/<script>.py`):
1. **`tests/analyze_container.py`** — transformaciones de byte *stateless* sobre el payload (identidad, `NOT`, nibble-swap, bit-reverse, `ROL/ROR 1..7`, `XOR k` para `k=0..255`) con pre-filtro de magic zlib/gzip + intento de `zlib/deflate/gzip/lzma/bz2`. **Resultado: 0 coincidencias.** (Descarta XOR/NOT/rotación/sustitución simple sobre un stream comprimido — la entropía ~8.0 ya lo anticipaba: una transformación *stateless* no altera la entropía y ninguna produjo un header zlib.)
2. **`tests/try_droidgeek.py`** — formato thedroidgeek: verifica CRC32 (✅), prueba whole-file AES-256-CBC (no aplica: `len%16=10`), modos de flujo CTR/CFB/OFB sobre el payload con la clave/IV fijos de thedroidgeek, y CBC sobre el prefijo alineado. **Resultado: 0 coincidencias** (ningún head `78xx`).
3. **`tests/key_search.py`** — **1150 combinaciones**: 230 claves candidatas × modos {CTR, CFB, OFB, CBC-alineado, ECB-alineado}. Fuentes de clave: clave fija droidgeek; serial `ALCLB472FD24` (crudo/lc/hex); `ALCL`, `NOKA`, `TELMEX`, password fijo rajkosto; sus `MD5`, `SHA-256`, `MD5×2`; y **PBKDF2-HMAC-SHA256** del password fijo con salts {`key10`, vacío, serial, primeros 8/16 B del payload, IV droidgeek} × {10,100,1000} iteraciones. Además barrido de **prefijo 0..32 B + CBC alineado** (por si hay cabecera interna). **Resultado: 0 coincidencias.**

> **Veredicto MF-3.2:** Contenedor **Nokia cfg LEGACY** verificado (magic `0x123123` + CRC32 OK). El payload está **cifrado** con una **clave simétrica derivada en el dispositivo**; no hay header zlib ni marcador de capa conocido y ninguna clave pública/derivable del `.cfg` lo abre.

## 🌐 Contexto público (investigación 2026-11-20)
- **thedroidgeek** `80c379aa43b71015d71da130f85a435a` y **rajkosto** `e2b2455d457cc2be82dbb5c85e22d708`: definen el formato exacto (magic/header/CRC/zlib) y la clave/IV fijos AES-256-CBC `3DA373D7…779EA4` / `D0E6DCCD…05EA`. **Funcionan solo en firmware viejo.**
- **rajkosto** añadió la **capa `0xFF`** para "G2425 y posteriores": `0xFF | salt(8) | AES-256-CBC` con `PBKDF2-HMAC-SHA256(pw_fijo, salt, 10 iter, 48 B → 32 clave + 16 IV)`, `pw_fijo = "S23l7nZm47XyMGs6y6oJpN9CR4nbfIZHJ4VRwp7HcdV6o2YvUmeNYFlz08Otwz78"`. **Nuestro payload NO empieza en `0xFF`** (empieza en `0xc5`) ⇒ no aplica.
- **Comentarios de usuarios Telmex G-1425G** (carlos-chavez-p, Louisthexv, yunez, borchacalas): **mismo síntoma exacto** — `fw_magic` tipo `0xfffffffe`/`0xffffffff` + `zlib.error: Error -3 … incorrect header check`. **Sin solución publicada.** borchacalas: *"Telmex usa una segunda encriptación para las contraseñas que no he podido crackear."*
- **udaravima** (`github.com/udaravima/Nokia-G_1425_G_B_GPON-NAND`, G-1425G-B, build Dic-2024): documenta **exactamente** nuestro caso — magic `23 31 12 00`, CRC válido, **entropía 7.998**, longitud no múltiplo de 16, "falla todo descompresor estándar". Su conclusión: *"cifrado con una clave que la herramienta de 2022 no lleva… derivada en el dispositivo"*. Su payload empieza en `0x11` (otra sub-variante). **Problema abierto.**
- **Derivación device-key de rajkosto** (solo para `dmdb_encryption.cfg`, **NO** `config.cfg`): `pbkdf2_hmac('sha256', serial+progdate+extfshash, b'key10', 100, 64)` → `base64[:64]`. Requiere `extfshash` (hash del rootfs, **solo en el firmware**).

---

# 🔓 MF-3.3 — `unpack_and_decrypt_config(raw_bytes, out_path)` ⚠️ COMPLETADA CON BLOQUEO [2026-11-20]

## Cadena de descifrado implementada (en orden, todo automatizado)
`nokia_backup.py → unpack_and_decrypt_config()`:
1. **zlib directo** — por si el payload ya fuera un stream zlib sin cifrar. ❌
2. **whole-file AES-256-CBC legacy (thedroidgeek)** — descifra todo el archivo y re-parsea buscando el magic interno (para la variante donde el header también va cifrado). No aplica (`len(archivo)%16=10`). ❌
3. **capa `0xFF` rajkosto** — si `payload[0]==0xFF`: `salt=payload[1:9]`, PBKDF2-HMAC-SHA256(pw, salt, 10, 48), AES-256-CBC, strip PKCS#7, zlib. **No aplica** (`payload[0]=0xc5`). ❌
4. **claves candidatas** — `_candidate_keys()` (serial/ALCL/TELMEX/pw-fijo + MD5/SHA256/PBKDF2) × modos de flujo + bloque alineado. ❌

**Discriminador usado:** el formato descomprime con `zlib.decompress`, así que un descifrado correcto **debe** empezar con `78 01/9c/da/5e`. Ningún intento lo produjo.

## Resultado: `success=false`, `blocked=true`
```json
{ "success": false, "blocked": true,
  "reason": "Contenedor Nokia cfg LEGACY verificado (magic 0x123123 + CRC32 OK), pero el
  payload interno está cifrado con una clave simétrica DERIVADA EN EL DISPOSITIVO (firmware
  3TN00702IJMI00). No existe header zlib ni marcador de capa 0xFF/0x11, y ninguna clave
  pública/derivable del archivo lo descifra. … Para recuperar la clave hace falta extraer y
  analizar el binario del firmware (no incluido en el backup)." }
```
**`output/nokia_config_decrypted.xml` NO se generó** (política: no inventar un XML falso). La función deja el resultado estructurado para que Fase 4 sepa que aún no hay texto en claro.

## 🌐 Vía fallback verificada — pistas desde la sesión web autenticada (`probe_key_hints()`)
Sonda **read-only** (solo `GET`, login→probes→logout limpio) ejecutada contra `192.168.99.254` con `TELMEX`/`sf3h5zkdtA`. Salida guardada en `output/key_hints/cgi/`. Resumen:

| Endpoint | Status | Hallazgo |
| :--- | :---: | :--- |
| `diag.cgi` | 200 | Cuerpo vacío (0 B) — stub sin datos. |
| `usb.cgi?backup` | 200 | Tokens `encrypt`/`key` presentes **pero son el RSA de login** (`jsencrypt`, `encrypt_submit`, `encrypt_post_data`, `PUBLIC KEY`). **No** hay opción de "export sin cifrar" ni material de clave del backup. |
| `usb.cgi?export` | 200 | Devuelve el **mismo `.cfg` cifrado** (137546 B) — no hay variante en claro. |
| `device_status.cgi` | 200 | Expone **`Progdate`** (de `dev_info.lot_number`, campos `ProgdateYear/Month/Day`). Es **1 de los 3 ingredientes** de la device-key de rajkosto, **pero esa derivación es para `dmdb_encryption.cfg`, no `config.cfg`**, y además falta `extfshash` (solo en firmware). |
| `diagnostic.cgi`, `sysinfo.cgi`, `gpon_status.cgi`, `backup.cgi`, `cfg.cgi`, `config.cgi`, `mgmt.cgi` | 404 | No existen. |

> **Conclusión del fallback:** la UI web (rol `adminRole=0`) **NO expone** la clave del contenedor, ni un botón de export sin cifrar, ni un endpoint de configuración en claro. Los únicos tokens "encrypt/key" son el envoltorio RSA/JSEncrypt del login. **La clave de `config.cfg` vive dentro del firmware, no en ninguna CGI.**

## 🧱 Por qué es criptográficamente un muro (resumen honesto)
- El cifrado es **simétrico con clave fija embebida/derivada en el firmware** del G-1425G-H Telmex. AES con clave de 128/256 bits **no es fuerza-brutable**.
- La clave **no deriva de nada presente en el `.cfg`** (serial, fw_magic, salt): lo demuestran los 1150+ intentos fallidos y la ausencia de salt/marcador.
- El estado coincide con el **problema público abierto** para toda la familia G-1425G (Telmex MX y SLT) con firmware ≳2023.

## 🧭 Rutas PENDIENTES para desbloquear (fuera del alcance de un `.cfg`)
1. **Extraer la clave del firmware** (vía con mayor probabilidad): obtener la imagen del firmware G-1425G-H `3TN00702IJMI00` (upgrade `.img`/dump NAND/UART) y localizar la rutina de (des)cifrado del `config.cfg` (`libdmcfg`, `dm`, `/bin/*`, o la lib de respaldo) + su clave/KDF. Es exactamente el "siguiente paso" que documenta el repo `udaravima`.
2. **Shell en el equipo** (UART/root) para volcar el `config.cfg` ya descifrado desde `/tmp` durante un backup, o leer la clave en memoria. En Fase 1 **SSH/Telnet LAN están cerrados**; requeriría acceso físico (UART) o un exploit de la UI.
3. **Pedir la línea en claro al IMS/soporte** o leer VoIP desde un **superusuario** (rol > 0) si se obtiene una credencial admin de nivel superior — la UI rol 0 no muestra `AuthPassword` SIP.
4. **Reusar la capa rajkosto si una futura actualización** cambia el payload a formato `0xFF`/`0x124126`: la cadena de MF-3.3 **ya lo soporta** y lo resolvería automáticamente.

## 💻 Código MF-3.2 / MF-3.3 (`nokia_backup.py`)
| Función | Rol |
| :--- | :--- |
| `analyze_container_format(raw_bytes)` | Parseo+diagnóstico del header (magic/endianness/variante/5 campos), **verificación CRC32**, entropía de Shannon, detección de capa interna (`zlib`/`gzip`/`0xFF`/`0x11`/desconocida) y veredicto. Sin red. |
| `unpack_and_decrypt_config(raw_bytes, out_path, pkcs_password, extra_keys)` | Cadena completa de descifrado (1→4). Escribe el XML **solo** si tiene éxito; si no, devuelve `blocked` + `reason` + `attempts`. Acepta `pkcs_password`/`extra_keys` para inyectar claves nuevas (p.ej. futuras pistas de firmware) sin tocar el código. |
| `probe_key_hints(ip,user,password,outdir)` | Sonda **read-only** autenticada (login→GET de 11 endpoints→logout en `finally`) que marca tokens sospechosos de clave y guarda los cuerpos en `output/key_hints/`. |
| `_aes_decrypt`, `_zlib_try`, `_candidate_keys`, `_shannon_entropy` | Helpers (AES multi-modo con `cryptography`; zlib/deflate/gzip; lista de claves candidatas; entropía). |

**CLI añadido:** `.venv/bin/python -I nokia_backup.py {download|analyze|decrypt|probe}` (`--file`, `--out`, `--ip`).
- `analyze`  → MF-3.2 (JSON de diagnóstico).
- `decrypt`  → MF-3.3 (cadena de descifrado; genera `output/nokia_config_decrypted.xml` si desbloquea).
- `probe`    → sonda read-only de pistas en la sesión web.

## ✅ Cierre de MF-3.2 / MF-3.3
- **MF-3.2 ✅:** formato **100% identificado y verificado** (Nokia cfg legacy `0x123123`, header de 20 B, **CRC32 del payload OK**, XML objetivo = 1 286 771 B).
- **MF-3.3 ⚠️ bloqueada:** payload cifrado con **clave derivada en el dispositivo**; XML en claro **no** obtenible solo desde el `.cfg` (1150+ claves probadas, 0 éxitos; coincide con el estado público no resuelto). Fallback web verificado: la UI **no** filtra la clave.
- **Sesión del probe cerrada** (logout `200`). Sin cambios en el router (solo `GET`).
- ➡️ **Impacto en el plan:** la extracción de credenciales SIP IMS **por la vía del backup** queda **bloqueada** hasta extraer la clave del firmware. Fase 4 no puede parsear el XML todavía. Ver "Rutas Pendientes".

---

# 🧬 FASE 3.5 — Investigación Forense de Desbloqueo (MF-3.4 + MF-3.5) ✅ EJECUTADA [2026-11-20]

> **Objetivo de la Fase 3.5:** sin tocar la clave del firmware todavía, exprimir todo lo que los artefactos ya descargados (`output/nokia_backup_raw*.cfg` y `/tmp/nokia_recon/cgi/`) pueden revelar sobre **(a)** el modo exacto de cifrado del payload (MF-3.4) y **(b)** credenciales/endpoints filtrados o explotables en los 43 CGIs (MF-3.5).
> **Scripts:** `tests/forensic_residue.py` (residuo + entropía por segmentos) · `tests/forensic_diff.py` (diff diferencial A vs B). **Muestras de backup:** `output/nokia_backup_raw.cfg` (#1) + `output/nokia_backup_raw_2.cfg` … `_5.cfg` (#2–#5, descargadas en esta fase; ciclos `login→export→logout` limpios, logout `200`, sin cambios de config).

---

## 🔬 MF-3.4 — Análisis forense del residuo de 6 bytes y estructura de bloques

### a) Primeros/últimos 32 bytes del payload y el residuo de 6 bytes
`output/nokia_backup_raw.cfg` (#1), payload = 137526 B tras el header de 20 B. **`137526 = 8595·16 + 6 = 17190·8 + 6`** (residuo 6 tanto para bloque de 16 como de 8).

```
PRIMEROS 32 B: c5 dc bc 71 59 34 56 dc 42 f9 c2 7c c4 59 7a 94
               e4 66 1c e5 0b 98 f6 1d e9 77 3f e1 9b 5a b9 ef
ULTIMOS  32 B: c5 d4 cc 84 4a be 2a fd 26 c8 05 83 52 68 c0 db
               7a 9d 7e ba 7a 0a 63 06 e9 4e f4 07 36 2d 6d 50
ULTIMOS   6 B (residuo): f4 07 36 2d 6d 50
```

**Hipótesis "cola zlib en claro" (4 B Adler-32 + 2 B fin de deflate) → DESCARTADA.** Si los últimos 6 bytes fueran el final en claro de un stream zlib, los 4 últimos serían el Adler-32 (big-endian) del XML y deberían tener aspecto de checksum, no de ruido; además la **entropía de la cola sería menor**. Medición real:

| Segmento | Entropía (bits/byte) | Lectura |
| :--- | :---: | :--- |
| primeros 1024 B | 7.8067 | cifrado |
| medio 1024 B | 7.8040 | cifrado |
| **últimos 1024 B** | **7.8107** | cifrado (igual que el resto) |
| últimos 64 B | 26/64 imprimible | ruido, no ASCII/XML |

La entropía es **uniforme ~7.80** de principio a fin (y ~8.0 sobre todo el payload): **no hay zona en claro ni cola zlib en claro**. El residuo de 6 bytes es **ciphertext de alta entropía**, no un campo estructural ni un Adler-32. `zlib`/`raw-deflate`/`gzip` directos sobre el payload siguen fallando (`incorrect header check`). ⇒ El residuo de 6 bytes **no** es "6 bytes sin cifrar al inicio/fin"; es simplemente `compressed_size mod 16`.

### b) ★ Comparación diferencial de descargas consecutivas (LA PRUEBA CLAVE)

Se descargaron **5 backups** (`#1`…`#5`), **sin cambiar configuración**, #3/#4/#5 con **segundos** de diferencia. Comparación de headers y payloads:

| # | archivo | tamaño | `comp_size` (0x04) | `crc32` payload (0x08) | `unc_size+1` (0x0C) | SHA-256 (16) |
| :-: | :--- | :---: | :---: | :---: | :---: | :--- |
| 1 | `nokia_backup_raw.cfg`   | 137546 | **137526** | `0x9bf0704f` | 1286772 | `f1ba78af7a514557` |
| 2 | `nokia_backup_raw_2.cfg` | 137545 | **137525** | `0x5da25cbb` | 1286772 | `4d0dcff338ebec54` |
| 3 | `nokia_backup_raw_3.cfg` | 137545 | 137525 | `0x09a6ca7a` | 1286772 | `c06cab23c2c1288d` |
| 4 | `nokia_backup_raw_4.cfg` | 137545 | 137525 | `0x8f45c18f` | 1286772 | `2415510fd632c950` |
| 5 | `nokia_backup_raw_5.cfg` | 137545 | 137525 | `0x06e55a9e` | 1286772 | `43eedafc89ad8618` |

**Observaciones diferenciales (todas verificadas con `tests/forensic_diff.py`):**

1. **El ciphertext cambia por COMPLETO en cada descarga.** A vs B: primer byte distinto en **offset 0**; **0 de 8595 bloques de 16 B idénticos**; **0 bytes idénticos** contando desde el inicio **o** desde el final; ventanas de 4096 B con ~0 % de coincidencia. Incluso #3 vs #4 (segundos de diferencia): **0 islas idénticas de ≥4 B**, `C3 ⊕ C4` con **entropía 7.9988** y **0.39 % de bytes cero** (= exactamente 1/256, indistinguible de aleatorio puro).
2. **`unc_size+1` es SIEMPRE idéntico (1286772 ⇒ XML = 1 286 771 B).** El tamaño del XML descomprimido no cambia entre exports.
3. **`comp_size` SÍ cambió: 137526 (#1) → 137525 (#2–#5).** `comp_size` es el tamaño del **plaintext comprimido**, una propiedad que **depende solo del contenido**, no del cifrado ni de ningún IV. Que cambie **demuestra que el XML en claro varía entre exports** (hay un campo volátil de longitud casi constante — uptime/contador/timestamp de export — que altera la compresión en ±1 B y deja el `unc_size` fijo).
4. **El residuo sigue a la longitud:** `#1 → 137526 % 16 = 6`; `#2–#5 → 137525 % 16 = 5`. El residuo **no es un campo fijo**; es `comp_size mod 16`.

### c) 🔑 Veredicto criptográfico de MF-3.4

| Pregunta | Respuesta forense | Evidencia |
| :--- | :--- | :--- |
| ¿Tamaño de bloque 16 u 8 con padding? | **No hay padding de bloque.** El ciphertext mide **exactamente** `comp_size` (payload == plaintext comprimido, sin relleno ni IV prepend). | `len(payload)==comp_size` del header, y `comp_size` varía 1 B con el contenido (137526/137525). |
| ¿ECB / CBC (block) o flujo? | **Cifrado de FLUJO** (CTR / CFB / OFB / RC4 / XOR-keystream), **NO** ECB/CBC clásico. | Longitud no múltiplo de 16 ni de 8 (residuo 6/5) **e igual a la del plaintext** ⇒ imposible en ECB/CBC sin ciphertext-stealing; el residuo sigue a la longitud. |
| ¿Clave/IV estáticos o salt/IV aleatorio por backup? | **Clave/keystream ESTÁTICO (derivado de constantes del equipo), SIN IV/salt almacenado.** La variación total del ciphertext la causa el **plaintext volátil**, no un IV aleatorio. | (i) El archivo **no tiene campo IV/salt** (header de 20 B todo asignado; payload == plaintext comprimido, sin espacio para IV). (ii) El **restore debe ser determinista**: el equipo tiene que descifrar su propio `.cfg` sin nonce externo ⇒ el keystream debe reconstruirse solo de constantes del equipo. (iii) **`comp_size` (propiedad solo del plaintext) cambia entre #1 y #2–5**, probando que el **plaintext** varía por sí mismo ⇒ basta eso para explicar que todo el ciphertext difiera, sin postular IV aleatorio. |
| ¿ECB? (prueba directa) | **Descartado ECB con clave estática y plaintext estable:** un cambio pequeño daría **muchos** bloques de 16 B idénticos; observamos **0**. Es coherente con flujo + plaintext que difiere desde (casi) el byte 0 del deflate. | 0/8595 bloques iguales A vs B y #3 vs #4. |

> **Conclusión MF-3.4:** el payload está protegido por un **cifrado de flujo con keystream estático derivado del dispositivo** (consistente con un AES-CTR/OFB o RC4 cuya clave/nonce salen del firmware/serial, **sin** salt por-backup). El residuo de 6 bytes **no** es texto en claro ni Adler-32: es `compressed_size mod 16`. **Implicación ofensiva:** un ataque de *two-time-pad* (XOR de dos ciphertexts con keystream común) sería teóricamente posible **pero NO es práctico aquí**, porque el **plaintext cambia en cada export** (campo volátil) y, al comprimirse, diverge desde el byte 0 → nunca obtenemos dos backups con plaintext idéntico para cancelar el keystream. Esto **refuerza** la conclusión de MF-3.3: sin la clave del firmware, el `.cfg` no se abre; MF-3.4 además **precisa el modo** (flujo, keystream estático) para cuando se recupere la clave.

---

## 🛡️ MF-3.5 — Auditoría forense de los 43 CGIs y endpoints de diagnóstico

Fuente: `/tmp/nokia_recon/cgi/` (capturados en MF-2.3, sesión `adminRole=0`). Patrón común en **todos** los CGIs: hook `ajaxSend` que para POST AJAX añade `csrf_token=<tok>` y **cifra** con `crypto_page.encrypt_post_data(pubkey,…)` (RSA-1024+AES-128); los `<form>` nativos van **sin cifrar** con hidden `csrf_token`/`csrf_val`.

### a) Parámetros POST/GET de `diag.cgi?ping`, `web_diag.cgi`, `log.cgi`, `usb.cgi`

| CGI | Método / endpoint | Parámetros | Notas forenses |
| :--- | :--- | :--- | :--- |
| **`diag.cgi?ping`** | `POST diag.cgi?ping` (form serializado) | `ipaddr`, `ipversion` (4/6), `iface` (LAN/WAN), `pingcount` (1–1000), `packetlength` (64–1500), `tracehops` (1–255), `ch_ping`/`ch_trace`, `csrf_token` | El POST **devuelve un nombre de archivo de resultado**; la UI luego lo transmite por `command.cgi` (ver ★). |
| **★ `command.cgi?cat+<archivo>`** | `POST command.cgi?cat+<f>` | `f` = ruta de archivo de resultado | **Endpoint NO listado en el menú**, descubierto dentro de `diag.cgi` (`function cat(f){ $.post('command.cgi?cat+'+f, …) }`). Hace de facto un `cat` del archivo. Convención: respuesta que empieza con `>` ⇒ "hay más, re-pedir". **Lead de mayor valor de toda la Fase 3.5** (posible lectura arbitraria de archivos → leer el `config.cfg` ya descifrado en `/tmp` durante un backup, o material de clave). **Requiere prueba activa autorizada (MF-3.6), no ejecutada aquí.** |
| **`web_diag.cgi?diag`** | `POST web_diag.cgi?diag` (cuerpo vacío) | — | Devuelve JSON de estado PPPoE: `name`, `connection_status`, `connection_status_v6`. **Solo estado, sin credenciales.** |
| **`log.cgi?vlog_glb`** | `GET/POST log.cgi?vlog_glb` | — | **Devuelve el texto del syslog del sistema** → se vuelca a `#logtxt` (botón "View/Export Log"). Es el endpoint que contendría los mensajes de arranque VoIP/SIP/PPPoE/cfgmgr. **No capturado** en los artefactos estáticos (sólo se guardó la plantilla de `log.cgi`); debe pedirse en vivo. |
| **`log.cgi?set_log_glb`** | `POST` (form) | `serverIpAddr`, `enable`, … (syslog remoto) | Syslog remoto actualmente **`Disabled`**, `ServerIPAddress 0.0.0.0:514`. |
| **`log.cgi?set_log_sftp`** | `POST` (form) | `loglocation`, `sftpusername`, `sftppassword`, `uploadtype` (once), `polltime` (1–1440 min), `enable` | **Exfiltración de logs por SFTP** a un host arbitrario: vía potencial para sacar el syslog/depuración a un servidor propio. Prueba activa = MF-3.6. |
| **`usb.cgi?backup` / `?export` / `?import`** | GET (página) / `POST ?export` / `POST ?import` | export: `csrf_val=&csrf_token=<tok>` (urlencoded, **sin cifrar**); import: `multipart filename` + `csrf_token` (variante `?v=import&sl_num=<serial ALCL…>`) | **Sin cambios** respecto a MF-2.3/MF-3.1. No expone clave ni export sin cifrar. |

### b) `wan_config_glb.cgi` — carga de la WAN 881 y credenciales PPPoE

**Hallazgo:** el detalle de la WAN **viene embebido server-side en el HTML** (no por AJAX diferido), en `var wan_conns = [ … pppConns:[{ … }] ]`. Extracción literal de la conexión `1_VOIP_TR069_INTERNET_OTHER_R_VID_881`:

| Campo | Valor | Observación |
| :--- | :--- | :--- |
| `Name` | `1_VOIP_TR069_INTERNET_OTHER_R_VID_881` | WAN única |
| `VLANIDMark` | `881` | VLAN Telmex |
| `ConnectionType` | `IP_Routed` · `ConnectionTrigger:'AlwaysOn'` | |
| **`Username` (PPPoE)** | **`E03005LALCLB472FD24@prodigyweb.com.mx`** | ✅ **EN CLARO.** Formato = OUI `E03005` + `L` + **SN GPON `ALCLB472FD24`** + `@prodigyweb.com.mx`. **Derivable del serial** (ya conocido). |
| **`Password` (PPPoE)** | `!!!@@@###$$$^^^&&&***` | ❌ **MÁSCARA fija** (placeholder server-side). El password PPPoE real **NO** se filtra por la Web (sigue solo en el backup cifrado). |
| `ExternalIPAddress` | `189.238.92.11` | == `userAgentIp` SIP (voz por la 881). |
| `DNSServers` | `189.233.12.5,189.233.15.2` | |
| `X_CT_COM_ServiceList` | `VOIP,TR069,INTERNET,OTHER` | Voz, gestión e Internet en la misma WAN. |
| `InterfaceMtu` | `1492` | |
| IPv6 | `X_CT_COM_IPv6Prefix 2806:10a6:20:4719::/64`, DNSv6 `2806:10a8:…::e, 2806:10a0:…::2` | |

> **Confirmado:** el **username PPPoE** se obtiene en claro y es **reconstruible del serial** (`E03005L` + `<SN>` + `@prodigyweb.com.mx`). El **password PPPoE** y las **credenciales SIP IMS** siguen **solo** en el backup cifrado (enmascarados/ausentes en la Web).

### c) `log.cgi` — mensajes de arranque VoIP/SIP/PPPoE/cfgmgr

- El cuerpo estático de `log.cgi` **no** contiene el texto del log (se carga en vivo por `?vlog_glb`). `grep` de `sip|voip|pppoe|cfgmgr|register|voice|ppp[0-9]` sobre el artefacto guardado → **0 coincidencias** (es solo la plantilla + config de syslog).
- El **syslog remoto está `Disabled`** y el buffer se expone únicamente vía `GET log.cgi?vlog_glb`. ⇒ Para capturar nombres de binarios internos / arranque VoIP-SIP-PPPoE-cfgmgr hay que **pedir `?vlog_glb` en vivo** (pendiente, read-only, de bajo riesgo → candidato inmediato de MF-3.6).

### d) Barrido de secretos embebidos en el resto de CGIs clave

| CGI | Hallazgo | Sensibilidad |
| :--- | :--- | :--- |
| `gpon_config.cgi` (SLID) | `gpon_info = {HexSLID:0, Password:'44454641554C54'}` → hex = **`DEFAULT`** | SLID GPON por defecto. **No** sirve para SIP/PPPoE. |
| `reg.cgi?loidcfg` (LOID) | LOID se rellena por AJAX (`uinfo.UserName`); `session_id='iKSZFMTojQzZcJKM'` embebido. Sin LOID estático. | Bajo. |
| `user_glb.cgi` (cambio de pass) | Form `?savedb` (`upswd` actual, `pswdNew`, `pswdConfirm`). `SavePWtoDB(data)` **re-rellena** lo que el usuario tecleó; **no** trae la contraseña admin actual desde el servidor. | **No hay fuga** de la contraseña admin. |
| `voice_info.cgi` | `phNumber:''`, `proxyIp:''`, `lines_config=[{Status:'Disabled'}]` | Confirma: **sin credenciales SIP** por Web. |
| `device_name.cgi`, `call_history_statistics.cgi` | Sin secretos embebidos. | — |

### ✅ Veredicto MF-3.5

- **Credencial filtrada en claro:** **username PPPoE** `E03005LALCLB472FD24@prodigyweb.com.mx` (derivable del serial). El **password PPPoE** y **todo lo SIP** siguen enmascarados/ausentes en la Web → **solo** en el backup cifrado.
- **Endpoints explotables descubiertos (para una futura MF-3.6, prueba activa autorizada):**
  1. **★ `command.cgi?cat+<archivo>`** — posible lectura arbitraria de archivos (vía más prometedora para leer el `config.cfg` **ya descifrado** desde `/tmp` durante un backup, o material de clave del firmware). **Máxima prioridad.**
  2. **`log.cgi?vlog_glb`** — volcado del syslog en vivo (nombres de binarios/arranque VoIP-SIP-PPPoE-cfgmgr; pistas de rutas y procesos). Read-only, bajo riesgo.
  3. **`log.cgi?set_log_sftp`** — exfiltración de logs por SFTP a host propio.
- **Sin cambios de estado** en el router durante MF-3.5 (solo lectura de artefactos locales ya capturados).

---

## 🧭 Estado tras Fase 3.5 y siguiente paso (MF-3.6 propuesta)

- **MF-3.4** precisó el **modo de cifrado**: flujo con **keystream estático derivado del dispositivo**, sin IV/salt por-backup; el residuo de 6 B es `comp_size mod 16`, no texto en claro. Confirma que el muro de MF-3.3 es real y define cómo descifrar en cuanto se tenga la clave.
- **MF-3.5** extrajo el **username PPPoE en claro** y, sobre todo, descubrió **`command.cgi?cat+<archivo>`** como el **lead de desbloqueo más prometedor sin firmware**.
- ➡️ **MF-3.6 (pendiente, requiere OK explícito — prueba activa):** probar `GET log.cgi?vlog_glb` (read-only) y, con autorización, `POST command.cgi?cat+<ruta>` contra rutas candidatas (`/tmp/config.cfg`, `/tmp/*.xml`, archivos de clave) para intentar leer la config **ya descifrada** o el material de clave, evitando por completo la extracción de firmware.

---

# 🧪 MF-6.1 — `test_diag_ping_and_cat` ✅ EJECUTADA [2026-11-20] (prueba activa autorizada, read-only / diagnóstico)

> **Objetivo:** ejecutar en modo controlado (login → prueba → logout garantizado en `finally`) el par `diag.cgi?ping` + `command.cgi?cat+<archivo>`, documentar el comportamiento EXACTO del bug de cifrado señalado en MF-3.5 (el segundo POST de `cat()` viaja **sin** el envoltorio RSA+AES) y **cerrar formalmente** el lead #1 de MF-3.5 (`command.cgi?cat+` como posible lectura arbitraria de archivos).
> **Target:** `http://192.168.99.254/` · Nokia G-1425G-H · sesión `TELMEX`/`sf3h5zkdtA` (`adminRole=0`).
> **Script:** `tests/mf6_1_diag_ping_cat.py` (reutiliza `make_opener`/`authenticate_nokia`/`logout_nokia`/`encrypt_post_data` de `nokia_auth.py`). Ejecutado con `.venv/bin/python -I tests/mf6_1_diag_ping_cat.py`.
> **Cambios de estado en el router:** **ninguno.** `diag.cgi?ping` es la operación de diagnóstico nativa de la UI (1 ping ICMP a `127.0.0.1`, loopback del propio equipo); `command.cgi?cat+<f>` sólo se probó en modo lectura contra nombres de archivo que **no existen** en el equipo o que están **restringidos por validación de parámetro antes de tocar el sistema de archivos** (ver abajo). Sesión cerrada con `logout_nokia()` en `finally` en las 3 corridas (status `200` siempre).

## 1️⃣ Mecanismo de cifrado por petición — confirmado bit a bit

Ambos endpoints comparten el mismo hook `$(document).ajaxSend(...)` (ver `04_fase3_extraccion_y_criptografia.md` §MF-3.5-a y `/tmp/nokia_recon/cgi/diag.cgi_ping` líneas 85–112):

```js
$(document).ajaxSend(function(event, request, settings) {
    if (settings.type == "POST") {
        if (settings.data === undefined || settings.data === "") {
            settings.data = 'csrf_token=MHlyCWWZDOaogecD';                 // ← SIN CIFRAR
            request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        } else {
            if ((settings.contentType||"").indexOf("application/x-www-form-urlencoded") < 0) { ...abort... }
            if (settings.data.indexOf("csrf_token") < 0) settings.data += '&csrf_token=MHlyCWWZDOaogecD';
            settings.data = crypto_page.encrypt_post_data(pubkey, settings.data);   // ← CIFRADO RSA+AES
        }
    }
});
```

El **único** criterio para decidir si una petición POST se cifra o no es si **`settings.data` llega vacío/indefinido al hook**, no el endpoint ni la sensibilidad del dato:

| Llamada en el JS real | Forma de la llamada jQuery | `settings.data` al entrar al hook | Rama tomada | Resultado en la red |
| :--- | :--- | :--- | :--- | :--- |
| `do_ping()` → `$.post(self.location.href, $('form').serialize())` | 2 args: `(url, data)`, `data` = string de formulario (`ipversion=ipv4&iface=...&checkall=ping&pingcount=1&packetlength=64`, **nunca vacío**) | string no vacía | **ELSE** → se antepone `csrf_token` si falta y se **cifra completo** con `crypto_page.encrypt_post_data(pubkey, data)` | `encrypted=1&ct=<AES-128-CBC base64url>&ck=<RSA-1024 PKCS#1 base64>` |
| `cat(f)` → `$.post('command.cgi?cat+'+f, function(data,status){...})` | 2 args: `(url, successCallback)` — **jQuery interpreta el 2.º argumento como callback, no como `data`**, por lo que `settings.data` queda `undefined` | `undefined` | **IF** → `settings.data = 'csrf_token=<tok>'` **tal cual, SIN pasar por `encrypt_post_data`** | `csrf_token=<tok>` **en texto plano**, con `Content-Type: application/x-www-form-urlencoded` forzado por el propio hook |

**Confirmado con tráfico real** (capturado por el script, ver §3 y §4): el POST a `diag.cgi?ping` efectivamente viaja como `encrypted=1&ct=...&ck=...`; el POST a `command.cgi?cat+<f>` viaja literalmente como el cuerpo **`csrf_token=<tok>`**, sin `ct`/`ck`, sin `encrypted=1`. Esto **no es una decisión de seguridad deliberada** (p. ej. "cat no necesita cifrado porque no es sensible"): es un **efecto colateral de la forma en que se invoca `$.post()`** — cualquier CGI de este firmware cuyo JS llame `$.post(url, callback)` (2 args, sin payload explícito) caerá en la misma rama sin cifrar. El csrf_token sigue viajando (mitiga CSRF básico) pero **la confidencialidad del payload del segundo POST depende enteramente de que no haya datos que cifrar**, no de un diseño explícito.

## 2️⃣ `GET /diag.cgi?ping` (autenticado) — reto por página

A diferencia de `GET /` (login), `diag.cgi?ping` **no** declara `var token = "..."`; el `csrf_token` vigente de la sesión aparece embebido **literalmente dentro del cuerpo del hook `ajaxSend`** (`settings.data = 'csrf_token=<tok>'`, línea ~91) y duplicado como hidden inyectado al formulario (`$("form").prepend('<input ... name="csrf_token" value="<tok>" />')`, línea ~1211). `var pubkey` (el mismo RSA-1024 global del login) sigue presente para que `encrypt_post_data` funcione dentro de esta página. Igual que en `usb.cgi?backup` (MF-3.1), **el token rota por carga** → debe leerse fresco justo antes del POST.

**Resultado real:** `GET http://192.168.99.254/diag.cgi?ping` (sesión `TELMEX`) → **HTTP `200`**, HTML de **34 721 B**, `csrf_token` extraído = `qBBMNFnIcBDdkwzX` (ejemplo de una corrida; rota en cada repetición).

## 3️⃣ `POST /diag.cgi?ping` — ping real de 1 paquete a `127.0.0.1`

**Petición en claro reconstruida** (idéntica a `$('form').serialize()` + el `csrf_token` ya presente en el campo oculto, exactamente los parámetros especificados):
```
csrf_val=&csrf_token=qBBMNFnIcBDdkwzX&ipversion=ipv4&iface=pp,1,1,1&ip_address_name=0&ipaddr=127.0.0.1&checkall=ping&pingcount=1&packetlength=64
```
(`iface=pp,1,1,1` reproduce el valor que `bindWanInf()` genera para la única conexión PPPoE del equipo: prefijo `"pp,"` + `wandev_id=1` + `conn_id=1` + `_oid=1`, ver `/tmp/nokia_recon/cgi/diag.cgi_ping` líneas 930–932.)

**Envuelta** con `encrypt_post_data(pubkey, plaintext)` (idéntico a `crypto_page.encrypt_post_data`, ya validado bit a bit en MF-2.1) → cuerpo real enviado:
```
encrypted=1&ct=euLe_GgE4uWsxE4CjYt3gJh06zlrbyLjwIRWV8DEwJFIGnWnSqAK_FjKLH_uogPT0nnJ7iPTrbSYY6ZB3vlk7yrbaDfcce-csirzn6l_I...
```

**Respuesta real del router:** **HTTP `200`**, cuerpo de **7 bytes**, **texto plano SIN cifrar**: `497.cmd`. ⇒ **`f = "497.cmd"`** (el router crea un archivo temporal de resultado nombrado `<id numérico>.cmd` y devuelve ese nombre tal cual; la respuesta de este CGI, a diferencia de las respuestas AES-CBC del flujo de login, **no** se cifra con `enckey`/`enciv` — viaja en claro).

## 4️⃣ `POST /command.cgi?cat+497.cmd` — lectura del resultado del ping

**Petición real enviada** (réplica exacta de `cat(f)`): `POST http://192.168.99.254/command.cgi?cat+497.cmd`, cuerpo **`csrf_token=qBBMNFnIcBDdkwzX`** (texto plano, confirmado §1), `Content-Type: application/x-www-form-urlencoded; charset=UTF-8`.

El protocolo de paginación real de `cat()` se reprodujo con éxito: mientras la respuesta **empiece con `>`**, hay más datos pendientes y hay que volver a pedir **el mismo archivo** (`setTimeout("cat('"+f+"')",100)`); la respuesta final no lleva el prefijo `>`. **6 peticiones** (`polls`) bastaron para drenar el resultado completo del ping:

```
Please wait! Ping is in progress...
PING 127.0.0.1 (127.0.0.1): 64 data bytes

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
```

(El `100% packet loss` contra `127.0.0.1` es un artefacto del `ping` interno del equipo —netns/iptables del propio BusyBox— sin relevancia criptográfica; confirma simplemente que el comando se ejecutó.) Cada petición devolvió **HTTP `200`**; ninguna devolvió error.

**Conclusión §3+§4:** el flujo completo `ping encriptado → filename en claro → cat sin cifrar → resultado en claro` funciona exactamente como describe MF-3.5, y el **segundo POST viaja sin el envoltorio RSA+AES** por el motivo exacto documentado en §1 (no por diseño, sino por la forma `$.post(url, callback)`).

## 5️⃣ Alcance de `command.cgi?cat+<archivo>` — **lead #1 de MF-3.5 CERRADO: NO es lectura arbitraria de archivos**

Se sondearon, en la misma sesión y de forma puramente de lectura, **9 rutas candidato** que un `cat` sin sanitizar permitiría leer (incluida una ruta con *path traversal* clásico):

| Ruta probada | Resultado |
| :--- | :--- |
| `/tmp/ping_result`, `/tmp/config.cfg`, `/tmp/backup.cfg`, `/tmp/dmdb_encryption.cfg` | `HTTP 200` + `<script>alert(window.langjson["Invalid cat parameter."]);</script>` |
| `/configs/config.cfg`, `/configs/`, `/etc/config/` | idéntico: `"Invalid cat parameter."` |
| `/etc/passwd` | idéntico: `"Invalid cat parameter."` |
| `../../../../etc/passwd` (path traversal clásico) | idéntico: `"Invalid cat parameter."` |

**Caracterización de la validación** (barrido adicional de variantes del propio nombre ya válido `497.cmd`, todo en modo lectura, sin generar tráfico destructivo):

| Candidato | Resultado |
| :--- | :--- |
| `1.cmd`, `99999.cmd` | **Pasan la validación** (`HTTP 200`, cuerpo vacío — el archivo numérico `.cmd` no existe en disco, pero el parámetro es aceptado) |
| `497.CMD` (mayúsculas) | `"Invalid cat parameter."` |
| `497.txt`, `497` (sin extensión `.cmd`) | `"Invalid cat parameter."` |
| `abc.cmd` (no numérico) | `"Invalid cat parameter."` |
| `/tmp/497.cmd` (ruta completa) | `"Invalid cat parameter."` |
| `497.cmd.bak` | `"Invalid cat parameter."` |

**Veredicto:** `command.cgi?cat+<f>` aplica una **validación de parámetro estricta ANTES de tocar el sistema de archivos**, equivalente a un patrón `^[0-9]+\.cmd$` (dígitos puros + extensión literal `.cmd` en minúsculas, sin rutas, sin mayúsculas, sin otra extensión). El manejador resuelve internamente el nombre validado dentro de un **directorio fijo propio del subsistema de diagnóstico** (no bajo control del cliente) — de ahí que `1.cmd`/`99999.cmd` (formato válido pero archivo inexistente) devuelvan `200` vacío en vez de error, mientras que **cualquier desviación de formato** (mayúsculas, extensión distinta, ruta absoluta/relativa, caracteres no numéricos) es rechazada con el mismo mensaje de error de UI, **sin diferenciar "no existe" de "ruta inválida"** y **sin llegar jamás a ejecutar un `cat` real sobre el argumento crudo**.

➡️ **Impacto en el plan:** el **lead #1 de MF-3.5** ("`command.cgi?cat+<archivo>` como posible lectura arbitraria de archivos, máxima prioridad para leer el `config.cfg` ya descifrado desde `/tmp` durante un backup, o material de clave") queda **descartado y cerrado**. Este endpoint es un **lector de resultados de diagnóstico con alcance restringido a sus propios archivos `.cmd` numéricos**, no una primitiva de lectura arbitraria de archivos. **No aporta una vía nueva para recuperar la clave de `config.cfg` ni el XML en claro.** El muro documentado en MF-3.3 (clave simétrica derivada en el firmware) **permanece intacto**; las rutas pendientes siguen siendo las de MF-3.3 §"Rutas Pendientes" (extracción de firmware, UART/shell físico, o credencial de superusuario).

## 6️⃣ Higiene de sesión

3 corridas del script (`tests/mf6_1_diag_ping_cat.py`), cada una con ciclo limpio `login (299 + X-SID) → GET diag.cgi?ping → POST diag.cgi?ping → POST command.cgi?cat+ (×6 polls) → POST command.cgi?cat+ (9 + 8 sondas adicionales) → logout`. **Logout `GET /login.cgi?out` → `200` en las 3 corridas**, sin sesiones colgadas. Ningún cambio de configuración persistente en el router (el único efecto lateral es un ping ICMP transitorio del propio equipo a su loopback, ya limpiado por el firmware tras el `cat` final).

## 💻 Código de MF-6.1

`tests/mf6_1_diag_ping_cat.py` — funciones `diag_ping_challenge()` (GET + extracción de `pubkey`/`csrf_token` propios de `diag.cgi?ping`), `do_ping_1_packet()` (POST cifrado con `encrypt_post_data` de `nokia_auth.py`), `do_cat()` / `cat_full()` (POST sin cifrar + protocolo de paginación `>`), y el driver `main()` (login → challenge → ping → cat del resultado → 9 sondas de alcance → logout en `finally`). Reporte completo (incluyendo cada petición/respuesta cruda) guardado en `/tmp/nokia_recon/mf6_1/mf6_1_report.json`.

## ✅ Cierre de MF-6.1

- **Mecanismo de cifrado por petición:** confirmado bit a bit — depende únicamente de si `settings.data` llega vacío/indefinido al hook `ajaxSend`, no de una política de seguridad explícita por endpoint.
- **`diag.cgi?ping`:** POST cifrado RSA+AES → devuelve el nombre de archivo de resultado **en texto plano** (`497.cmd` en la corrida real), sin cifrado de respuesta.
- **`command.cgi?cat+<f>`:** POST con sólo `csrf_token=<tok>` **sin cifrar** (confirmado); **NO** es lectura arbitraria de archivos — validación estricta `^[0-9]+\.cmd$` previa al filesystem, alcance limitado a los propios resultados de diagnóstico del equipo.
- **Lead #1 de MF-3.5 cerrado** (sin éxito): no existe una vía de lectura de `/tmp/config.cfg`, `/etc/passwd` ni ningún otro archivo del sistema a través de este endpoint.
- **Sin cambios de estado** persistentes en el router; sesión cerrada (`logout 200`) en todas las corridas.
- ➡️ **Siguiente paso:** las únicas rutas de desbloqueo de Fase 3 que quedan abiertas son las de MF-3.3 §"Rutas Pendientes" (extracción de firmware / UART-shell físico / credencial de superusuario). `log.cgi?vlog_glb` (MF-3.6, aún no ejecutada) sigue siendo la única sonda read-only pendiente de bajo riesgo para buscar pistas de rutas/binarios internos en el syslog en vivo.
