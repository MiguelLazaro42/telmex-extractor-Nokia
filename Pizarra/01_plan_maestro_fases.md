# 📋 Plan de Implementación Detallado: Fases y Microfunciones (Nokia ONT -> Asterisk)

Este documento desglosa la estrategia completa en **5 Fases** y **15 Microfunciones** atómicas, independientes y verificables. Ninguna fase avanza a la siguiente sin antes registrar sus resultados, encabezados HTTP o muestras binarias en esta `Pizarra/`.

---

## 🔍 FASE 1: Reconocimiento No Intrusivo de la ONT Nokia — ✅ **COMPLETADA [2026-11-20]**
**Objetivo:** Identificar con exactitud la dirección IP del módem Nokia, su modelo exacto de hardware (ej. `G-240W-B`, `G-2425G-A`, `G-2425G-B`, `G-140W-H`), versión de firmware, puertos abiertos y arquitectura de su servidor web sin alterar nada.

> **Resultado Fase 1 (resumen):** IP `http://192.168.99.254` · Fabricante **Nokia** · modelo candidato **G-2425G-A "Beacon 1"** (GPON + IoT Z-Wave/ZigBee/JVM) · operador `MXXT` (Telmex) · servidor **thttpd** · login **RSA-1024 + AES-128-CBC → `POST /login.cgi`** (éxito=`299`+`X-SID`) · **solo TCP/80 abierto en LAN**. Detalle en `02_fase1_reconocimiento_nokia.md`.

### Microfunciones de la Fase 1:  *(✅ MF-1.1 · ✅ MF-1.2 · ✅ MF-1.3)*
- **`MF-1.1: detect_default_gateway()`**  ✅ — Gateway `192.168.99.254` (en0), vivo, TCP/80 abierto.
  - **Entrada:** Tabla de rutas del sistema operativo (macOS `route -n get default`).
  - **Proceso:** Identificar la IP de la pasarela local (típicamente `192.168.1.254`) y verificar conectividad ICMP/TCP.
  - **Salida esperada:** IP confirmada del router Nokia.
- **`MF-1.2: fingerprint_nokia_web()`**
  - **Entrada:** IP del router (`http://<ip>` y `https://<ip>`).
  - **Proceso:** Realizar una petición `GET /` (siguiendo redirecciones) e inspeccionar:
    - Headers HTTP (`Server`, `Set-Cookie`, `WWW-Authenticate`).
    - HTML y scripts JS de la página de login (identificar si usa `/login.cgi`, `/goform/login`, `login.lua`, qué funciones de hash o cifrado aplica en el frontend a la contraseña antes de enviarla).
  - **Salida esperada:** Modelo exacto del Nokia, versión del portal web y mecanismo exacto de login documentado en `Pizarra/02_fase1_reconocimiento_nokia.md`.
  - **✅ Salida real:** Nokia (candidato **G-2425G-A "Beacon 1"**, GPON+IoT); server **thttpd**; login = `POST /login.cgi` con `encrypted=1&ct=<AES-128-CBC>&ck=<RSA-1024>` (JSEncrypt 3.0.0 + sjcl); `nonce`+`csrf_token` por `GET /`; éxito `299`+`X-SID`; respuestas AES-CBC. Pubkey y JS literales en `02_...md`.
- **`MF-1.3: scan_management_ports()`**
  - **Entrada:** IP del router.
  - **Proceso:** Verificar de forma rápida y segura si puertos de administración adicionales responden en la LAN (`80` HTTP, `443` HTTPS, `22` SSH, `23` Telnet, `5060` SIP local).
  - **Salida esperada:** Mapa de servicios disponibles en la ONT.
  - **✅ Salida real:** **Solo TCP/80 abierto** en LAN. Cerrados: 21, 22 (SSH), 23 (Telnet), 53, 443, 5060 (SIP), 7547 (TR-069), 8080. ⇒ Gestión exclusivamente Web/CGI; sin CLI (SSH/Telnet) desde LAN.

---

## 🔐 FASE 2: Autenticación Web y Descubrimiento de Endpoints — ✅ **COMPLETADA [2026-11-20]** (✅ MF-2.1 · ✅ MF-2.2 · ✅ MF-2.3)
**Objetivo:** Construir el módulo de inicio de sesión automatizado con el usuario `TELMEX` y contraseña `sf3h5zkdtA`, mantener la sesión activa (cookies/tokens CSRF) y mapear dónde están la configuración de respaldo y la sección de VoIP.

> **Resultado Fase 2 (resumen):** Login `POST /login.cgi` (RSA-1024+AES-128) → `299`+`X-SID`+cookies `sid/isAdminLoggedIn/lsid`. **Modelo CONFIRMADO: Nokia G-1425G-H** · SW `3TN00702IJMI00` · HW `3TN00990ADAA` · SN/GPON `ALCLB472FD24` · `adminRole=0`. **Backup:** descarga `POST /usb.cgi?export` (urlencoded, `csrf_token`, sin cifrar); restore `POST /usb.cgi?import` (multipart `filename`). **VoIP:** sin CGI editable (rol 0); línea SIP `Disabled`; creds SIP solo en backup. **WAN:** única PPPoE VLAN 881 (Internet+VoIP+TR069). Detalle en `03_fase2_autenticacion_y_endpoints.md`.

### Microfunciones de la Fase 2:
- **`MF-2.1: get_login_challenge(opener, ip)`**  ✅ **Completada [2026-11-20]**
  - **Entrada:** Sesión HTTP (`cookiejar`) e IP.
  - **Proceso:** Obtener el nonce, token aleatorio, `sessionKey` o parámetros ocultos del formulario de login que requiere el Nokia antes de autenticar.
  - **Salida esperada:** Diccionario con tokens/nonces de desafío.
  - **✅ Salida real:** `GET /` real → `pubkey` (PEM RSA-1024, `e=65537`), `nonce`+`csrf_token` (rotan por carga), cookie `lang=spa`, `operatorCheck=MXXT`, `window.name=Bell`. Código en `nokia_auth.py`; helpers cripto (`b64url_escape`, AES-128-CBC/PKCS#7 ≡ `sjcl.mode.cbc`, RSA-1024 PKCS#1 v1.5 ≡ `JSEncrypt`, base64url urlsafe-sin-`=` ≡ `sjcl.codec.base64url`) **validados bit-a-bit** vía OpenSSL + round-trip (`tests/validate_crypto.py`, todas ✅; sin `node` en el host). **NO se hizo POST a `/login.cgi`.** Detalle en `03_fase2_autenticacion_y_endpoints.md`.
- **`MF-2.2: authenticate_nokia(opener, ip, user, password)`**  ✅ **Completada [2026-11-20]**
  - **Entrada:** `user="TELMEX"`, `password="sf3h5zkdtA"`, token de `MF-2.1`.
  - **Proceso:** Aplicar la transformación requerida por el frontend JS del Nokia (ya sea texto plano, Base64, MD5, SHA-256 con nonce, etc.) y enviar el `POST` de login. Validar que la sesión quede autenticada.
  - **Salida esperada:** Sesión autenticada con cookies válidas.
  - **✅ Salida real:** Login en **1 intento** → `POST /login.cgi` (RSA-1024+AES-128) → **HTTP `299`** + **`X-SID=zTyYAkWRkTAzRZhk`**; sesión por cookies **`sid`/`isAdminLoggedIn=1`/`lsid`** (body del 299 vacío). Implementados `authenticate_nokia()` + `aes128_cbc_decrypt_sjcl()` (≡ `crypto_page.aes_decrypt`) + manejo blindado de **HTTP 299** (handler 2xx + captura `HTTPError 299`). `GET /` autenticado = shell **"GPON Home Gateway"** (menú vía `menu.cgi`, iframe `mainFrame`, `adminRole=0`), guardado en `/tmp/nokia_recon/authenticated_index.html`. Detalle en `03_fase2_autenticacion_y_endpoints.md`. **Detenido antes de MF-2.3.**
- **`MF-2.3: map_authenticated_endpoints(opener, ip)`**  ✅ **Completada [2026-11-20]**
  - **Entrada:** Sesión autenticada.
  - **Proceso:** Explorar el árbol de menús del Nokia para localizar dos rutas clave:
    1. **Endpoint de Backup / Restore de Configuración** (para descargar el archivo `.cfg` / `.xml` / `.bin`).
    2. **Endpoint de Estado y Configuración VoIP / SIP** (ver qué muestra la interfaz web sobre la línea telefónica y si expone parámetros o botones de activación).
  - **Salida esperada:** URLs exactas y parámetros requeridos para descargar el backup y consultar VoIP.
  - **✅ Salida real:** Ciclo limpio `login → GET /menu.cgi → GET /device_status.cgi → GET de 43 targets → sondas voz → logout`. **Árbol `menu.cgi` completo** (ver tabla en `03_...md §2`; `adminRole=0`). **Device (de `device_status.cgi`):** **G-1425G-H**, SW `3TN00702IJMI00`, HW `3TN00990ADAA`, SN `ALCLB472FD24`, OUI `E03005`, chipset `MTK7552`. **① Backup/Restore (`usb.cgi?backup`):** descarga = `POST /usb.cgi?export` (`application/x-www-form-urlencoded`, cuerpo `csrf_val=&csrf_token=<tok>`, **sin cifrar**, descarga directa al iframe); subida = `POST /usb.cgi?import` (o `?v=import&sl_num=<serial ALCL…>`), `multipart/form-data`, campo archivo **`filename`**, hidden `csrf_token`. **② VoIP:** no hay CGI de config para rol 0 (sondas `voice*/voip*/sip*.cgi` → 404); `voice_info.cgi` solo lectura → `lines_config=[{Status:'Disabled'}]`, `phNumber/proxyIp` vacíos, `userAgentIp=189.238.92.11` ⇒ credenciales SIP **solo en el backup**. **WAN:** única PPPoE **VLAN 881** `1_VOIP_TR069_INTERNET_OTHER_R` (Connected, `189.238.92.11`), voz sin VLAN dedicada. Implementado en `nokia_auth.py` (`map_authenticated_endpoints`, `_parse_menu_nodes`, `_authget`, `logout_nokia`, CLI `map`); logout `GET /login.cgi?out` siempre. Detalle en `03_fase2_autenticacion_y_endpoints.md`.

---

## 🔓 FASE 3: Descarga y Análisis Forense / Criptográfico del Respaldo — 🟠 **BLOQUEADA PARCIAL [2026-11-20]** (✅ MF-3.1 · ✅ MF-3.2 · ⚠️ MF-3.3 clave en firmware)
**Objetivo:** Descargar el archivo de configuración del Nokia y determinar su estructura binaria/criptográfica para obtener el XML/texto en claro.

> **Resultado Fase 3 (MF-3.1 ✅):** Backup descargado vía `POST /usb.cgi?export` (urlencoded `csrf_val=&csrf_token=<tok>`, sin cifrar) → `200` + `Content-Disposition: attachment;filename="config.cfg"` + `Content-Type: application/octet-stream`. Crudo en `output/nokia_backup_raw.cfg` (`137546` B) · SHA-256 `f1ba78af…c5c7` · MD5 `1f570942…ba10`.

> **Resultado Fase 3 (MF-3.2 ✅):** Formato **100% identificado** = contenedor **Alcatel-Lucent/Nokia `cfg` LEGACY** (magic `uint32` LE **`0x00123123`**, header **20 B**). **CRC32 del payload VERIFICADO** (`0x9bf0704f`). `compressed_size=137526`, **XML objetivo=1 286 771 B**, `fw_magic=0xfffffffe`. Payload interno **cifrado** (entropía 7.9983, `len%16=6`).

> **Resultado Fase 3 (MF-3.3 ⚠️ BLOQUEADA):** Cadena de descifrado completa ejecutada (zlib directo → AES-256-CBC whole-file droidgeek → capa `0xFF` rajkosto → 1150+ claves candidatas en CTR/CFB/OFB/CBC/ECB) → **0 éxitos**. El payload usa una **clave simétrica derivada en el dispositivo (firmware `3TN00702IJMI00`)**, igual que el problema público abierto del repo `udaravima` (G-1425G-B). **`output/nokia_config_decrypted.xml` NO generado.** Fallback web (`probe_key_hints`, read-only) confirma que la UI rol 0 **no** expone la clave. **El XML en claro NO es recuperable solo desde el `.cfg`** → se requiere extraer la clave del binario del firmware. Detalle en `04_fase3_extraccion_y_criptografia.md`.

### Microfunciones de la Fase 3:
- **`MF-3.1: download_nokia_backup(opener, ip, output_dir)`**  ✅ **Completada [2026-11-20]**
  - **Entrada:** Sesión autenticada y endpoint descubierto en `MF-2.3`.
  - **Proceso:** Solicitar la descarga del archivo de respaldo de configuración y guardarlo intacto en `output/nokia_backup_raw.cfg` (o `.xml` / `.bin`).
  - **Salida esperada:** Archivo crudo de respaldo en disco y su hash SHA-256.
  - **✅ Salida real:** Ciclo limpio `login → GET /usb.cgi?backup (csrf) → POST /usb.cgi?export → logout`. Router respondió `200` + `Content-Disposition: attachment;filename="config.cfg"` + `Content-Type: application/octet-stream` (sin `Content-Length`). Guardado en **`output/nokia_backup_raw.cfg`** (+ copia `output/config.cfg`, idéntica). **`137546` bytes** · **SHA-256** `f1ba78af7a5145576bf295c3d2db826a7f52c1ef3639dfa48930dbea9ee8c5c7` · **MD5** `1f570942e9e9babd88c2ac110f7dba10` (verificados con `shasum`/`md5`). Contenedor **binario propietario** (magic `23 31`=`#1`, header ~20 B + payload 137526 B alta entropía). Código en `nokia_backup.py` (importa `nokia_auth.py`); logout `GET /login.cgi?out` siempre en `finally`. **Detenido antes de MF-3.2/3.3.** Detalle en `04_fase3_extraccion_y_criptografia.md`.
- **`MF-3.2: analyze_container_format(raw_bytes)`**  ✅ **Completada [2026-11-20]**
  - **Entrada:** Bytes del archivo descargado.
  - **Proceso:** Inspección forense de cabeceras (Magic Bytes, entropía, estructura de bloques, firmas zlib/gzip `1F 8B` / `78 9C` / `78 DA`, cabeceras XML, o contenedores cifrados AES de Alcatel-Lucent/Nokia).
  - **Salida esperada:** Diagnóstico exacto en la Pizarra de cómo está protegido el archivo.
  - **✅ Salida real:** Contenedor **Alcatel-Lucent/Nokia `cfg` LEGACY** (magic `uint32` LE **`0x00123123`** — NO el ASCII `#1`; formato thedroidgeek/rajkosto). Header **20 B** = `magic | compressed_size=137526 | crc32=0x9bf0704f | uncompressed+1=1286772 | fw_magic=0xfffffffe`. **CRC32 del payload VERIFICADO** (coincide ⇒ formato y frontera correctos). Payload 137526 B, **entropía 7.9983**, `len%16=6` (⇒ no AES-CBC/ECB completo), sin header zlib ni marcador de capa `0xFF`/`0x11`. Implementado en `nokia_backup.py` (`analyze_container_format`, `_shannon_entropy`). Scripts de criptoanálisis en `tests/analyze_container.py`.
- **`MF-3.3: unpack_and_decrypt_config(raw_bytes)`**  ⚠️ **Completada con BLOQUEO técnico [2026-11-20]**
  - **Entrada:** Archivo crudo de configuración.
  - **Proceso:** Descomprimir y/o descifrar el contenedor (y cualquier campo de contraseña ofuscado internamente) hasta obtener el árbol XML o archivo de configuración legible en texto plano (`output/nokia_config_decrypted.xml`).
  - **Salida esperada:** Configuración completa en texto plano.
  - **⚠️ Salida real:** Cadena completa implementada y ejecutada (zlib directo → AES-256-CBC whole-file droidgeek → capa `0xFF`+PBKDF2 rajkosto → **1150+ claves candidatas** serial/ALCL/TELMEX/pw-fijo + MD5/SHA256/PBKDF2 en CTR/CFB/OFB/CBC/ECB) → **0 éxitos** (discriminador: head zlib `78xx`). ⇒ **clave simétrica derivada en el dispositivo (firmware)**; coincide con el problema público abierto (`udaravima` G-1425G-B). **`output/nokia_config_decrypted.xml` NO generado** (no se inventa XML; devuelve `blocked`+`reason`). **Fallback verificado:** `probe_key_hints()` (read-only, login→11 GET→logout) confirma que la UI rol 0 **no** expone clave de backup, export sin cifrar, ni endpoint en claro (tokens `encrypt/key` = RSA de login; `Progdate` en `device_status.cgi` solo sirve a `dmdb_encryption.cfg`, falta `extfshash`). Implementado en `nokia_backup.py` (`unpack_and_decrypt_config`, `probe_key_hints`, `_aes_decrypt`, `_zlib_try`, `_candidate_keys` + CLI `analyze/decrypt/probe`). **Rutas de desbloqueo:** (1) extraer la clave del binario del firmware `3TN00702IJMI00`; (2) shell UART/root en el equipo; (3) credencial de superusuario (rol > 0). La cadena **ya soporta** las variantes `0xFF`/`0x124126` si un firmware futuro las usa.

---

## 🧬 FASE 3.5: Investigación Forense de Desbloqueo — ✅ **COMPLETADA [2026-11-20]** (✅ MF-3.4 · ✅ MF-3.5)
**Objetivo:** exprimir los artefactos ya descargados (`output/nokia_backup_raw*.cfg`, `/tmp/nokia_recon/cgi/`) para precisar el **modo de cifrado** del payload y auditar los **43 CGIs** en busca de credenciales/endpoints explotables, **sin** depender aún de la clave del firmware.

> **Resultado Fase 3.5 (resumen):** **MF-3.4** → cifrado de **FLUJO con keystream ESTÁTICO derivado del dispositivo** (sin IV/salt por-backup; residuo de 6 B = `comp_size mod 16`, no texto en claro); probado con diff de 5 backups (ciphertext 100 % distinto cada vez, pero `unc_size` fijo y `comp_size` variable ⇒ el **plaintext** varía por un campo volátil). **MF-3.5** → **username PPPoE en claro** `E03005LALCLB472FD24@prodigyweb.com.mx` (derivable del serial) y descubrimiento del endpoint oculto **`command.cgi?cat+<archivo>`** (posible lectura arbitraria de archivos). Detalle en `04_fase3_extraccion_y_criptografia.md`.

### Microfunciones de la Fase 3.5:
- **`MF-3.4: forensic_block_and_diff_analysis()`**  ✅ **Completada [2026-11-20]**
  - **Entrada:** `output/nokia_backup_raw.cfg` + backups consecutivos `_2`…`_5.cfg`.
  - **Proceso:** inspeccionar primeros/últimos 32 B y el residuo de 6 B (entropía por segmentos, hipótesis zlib-tail/Adler-32); descargar backups frescos y comparar byte-a-byte (headers, bloques de 16 B, islas idénticas, `C⊕C`).
  - **✅ Salida real:** residuo de 6 B = `comp_size mod 16` (ciphertext, **no** claro ni Adler-32; entropía uniforme ~7.80). 5 backups → ciphertext 100 % distinto en cada export (0/8595 bloques iguales, `C3⊕C4`≡aleatorio), `unc_size+1` siempre 1286772, `comp_size` 137526→137525. Como `comp_size` depende solo del plaintext ⇒ el XML varía entre exports (campo volátil). **Veredicto:** cifrado de **flujo** (CTR/CFB/OFB/RC4/XOR), **no** ECB/CBC; **keystream estático derivado del equipo**, sin IV/salt en el archivo (restore determinista). Two-time-pad no práctico (plaintext diverge desde byte 0 por compresión). Scripts `tests/forensic_residue.py`, `tests/forensic_diff.py`.
- **`MF-3.5: audit_cgi_endpoints()`**  ✅ **Completada [2026-11-20]**
  - **Entrada:** los 43 CGIs en `/tmp/nokia_recon/cgi/`.
  - **Proceso:** revisar parámetros POST/GET de `diag.cgi?ping`, `web_diag.cgi`, `log.cgi`, `usb.cgi`; cómo `wan_config_glb.cgi` carga la WAN 881 (username/password PPPoE); y si `log.cgi` revela arranque VoIP/SIP/PPPoE/cfgmgr.
  - **✅ Salida real:** `diag.cgi?ping` POST(`ipaddr/ipversion/iface/pingcount/packetlength/tracehops/csrf_token`) → devuelve filename transmitido por **`command.cgi?cat+<archivo>`** (endpoint oculto, posible LFI → leer `config.cfg` ya descifrado en `/tmp` o clave; **lead #1**). `web_diag.cgi?diag`=solo estado PPPoE. `log.cgi?vlog_glb`=volcado syslog en vivo (no capturado; contendría VoIP/SIP/PPPoE/cfgmgr); `log.cgi?set_log_sftp`=exfil SFTP. **`wan_config_glb.cgi`** (`var wan_conns`): **username PPPoE EN CLARO** `E03005LALCLB472FD24@prodigyweb.com.mx`; **password enmascarado** `!!!@@@###$$$^^^&&&***`. `gpon_config.cgi` SLID=`DEFAULT`(hex); `user_glb.cgi` no filtra pass admin; SIP solo en backup.

> **MF-3.6 (pendiente, prueba ACTIVA — requiere OK explícito):** probar `GET log.cgi?vlog_glb` (read-only) y, con autorización, `POST command.cgi?cat+<ruta>` contra `/tmp/config.cfg`, `/tmp/*.xml` y archivos de clave, para leer la config **ya descifrada** o material de clave sin extraer firmware.

---

## 📞 FASE 4: Extracción de Credenciales SIP (IMS) y WAN + Generador Asterisk
**Objetivo:** Extraer de forma determinista todos los parámetros necesarios para tu servidor Asterisk y para modo Bridge/PPPoE.

### Microfunciones de la Fase 4:
- **`MF-4.1: parse_sip_ims_credentials(config_text)`**
  - **Entrada:** Configuración descifrada.
  - **Proceso:** Localizar los nodos de voz (`VoiceService`, `VoiceProfile`, `SIP`, `Line`, `X_ALU-COM_...` o equivalentes TR-098/TR-104 en Nokia) y extraer:
    - Número / URI (`+52...`)
    - `AuthUserName` (`+52...@vims-h.telmex.com` o dominio IMS asignado)
    - `AuthPassword` (contraseña SIP en texto plano)
    - `RegistrarServer` / `ProxyServer` / `OutboundProxy` y puertos
    - VLAN de Voz (si la voz viaja por la misma VLAN `881` o por una VLAN dedicada de VoIP/IMS en el Nokia).
  - **Salida esperada:** Diccionario JSON validado con las credenciales SIP completas.
- **`MF-4.2: parse_wan_and_wifi(config_text)`**
  - **Entrada:** Configuración descifrada.
  - **Proceso:** Extraer credenciales PPPoE (`@prodigyweb.com.mx`), VLAN ID (`881`), usuarios de administración web (incluyendo superusuario `admin` / `root` si existe en el XML) y claves Wi-Fi.
  - **Salida esperada:** Reporte unificado `output/credentials.json` y `output/credentials.md`.
- **`MF-4.3: generate_asterisk_config(sip_data)`**
  - **Entrada:** Diccionario `sip_voip` extraído en `MF-4.1`.
  - **Proceso:** Generar plantillas listas para copiar y pegar en tu servidor Asterisk (`pjsip.conf` y `sip.conf`), incluyendo el formato especial de autenticación IMS de Telmex (`from_domain`, `outbound_proxy`, `contact_user`, `qualify`, códec `alaw`).
  - **Salida esperada:** Archivo `output/asterisk_pjsip_telmex.conf` documentado.

---

## 🛠️ FASE 5: Liberación de la Línea SIP en el Módem Nokia y Prueba en Asterisk
**Objetivo:** Evitar que el cliente SIP interno del módem Nokia compita con tu Asterisk por el registro en el IMS de Telmex.

### Microfunciones de la Fase 5:
- **`MF-5.1: evaluate_sip_disable_method()`**
  - **Entrada:** Hallazgos de Fase 2 (Web UI / SSH / Telnet) y Fase 3 (estructura del backup).
  - **Proceso:** Evaluar el método más limpio, seguro y reversible para apagar el cliente SIP del Nokia:
    - *Opción 1:* Petición HTTP POST / CGI directa si la interfaz web o superusuario permite deshabilitar VoIP/SIP.
    - *Opción 2:* Modificar `Enable="Disabled"` (o invalidar el proxy SIP) en el XML de respaldo, re-empaquetarlo con `nokia_config_packer.py` y cargarlo al módem (`nokia_sip_manager.py --disable --apply`).
    - *Opción 3:* Vía CLI (SSH/Telnet) con credenciales de superusuario extraídas del XML en la Fase 4.
  - **Salida esperada:** Método elegido y validado con respaldo de seguridad previo.
- **`MF-5.2: nokia_config_packer() & nokia_sip_manager()`**
  - **Entrada:** Configuración original y estado deseado (`--disable` o `--enable`).
  - **Proceso:** Implementar el script equivalente a `huawei_sip_manager.py` adaptado a Nokia, con verificación de integridad antes de aplicar cualquier cambio.
  - **Salida esperada:** Herramienta CLI funcional para activar/desactivar SIP en el Nokia.
- **`MF-5.3: verify_asterisk_registration()`**
  - **Entrada:** Configuración generada en `MF-4.3` y línea liberada en el Nokia.
  - **Proceso:** Guía y verificación de que el servidor Asterisk pueda alcanzar el `OutboundProxy` de Telmex (verificando ruteo hacia la red IMS `10.x.x.x` o resolución DNS del módem) y logre el estado `Registered`.
  - **Salida esperada:** Cuenta SIP de Telmex registrada y operativa en Asterisk.
