# 🗂️ Pizarra de Trabajo — Proyecto Telmex Extractor Nokia (VoIP SIP / Asterisk)

> **Propósito de este directorio (`Pizarra/`):** Servir como bitácora viva, memoria técnica de estado, registro de hallazgos, arquitectura y puntos de control (checkpoints). Si algún proceso falla, cambia el alcance o requerimos intervención manual, aquí queda documentado exactamente qué sabemos, qué se probó y en qué microfunción nos encontramos.

---

## 📌 Contexto y Objetivo Principal
- **Objetivo Final:** Extraer las credenciales **VoIP SIP (IMS Telmex)** de una ONT/Router marca **Nokia** (y desactivar o evitar colisión con el cliente SIP interno de la ONT) para registrar la línea telefónica en un servidor **Asterisk** externo.
- **Repositorio Base:** `/Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia`
- **Credenciales del Módem Objetivo:**
  - **Usuario:** `TELMEX`
  - **Contraseña:** `sf3h5zkdtA`
- **Metodología de Referencia:** Basada en la arquitectura modular del extractor de Huawei (`huawei_hg8145v5_extractor.py`, `huawei_config_packer.py`, `huawei_sip_manager.py`).

---

## 🔬 Análisis Forense del Proyecto Base (Metodología Huawei)

El proyecto actual clonado en el repositorio contiene la implementación de referencia para ONTs **Huawei EchoLife (`HG8145V5` / `HG8245`)**. Su metodología se divide en **3 módulos principales** y **7 micro-etapas**:

1. **Descubrimiento y Reconocimiento (`detect_default_gateway`):**
   - Identifica la IP de la puerta de enlace predeterminada (usualmente `192.168.1.254` en Telmex) de forma multiplataforma (`route -n get default` en macOS).
2. **Autenticación Web y Manejo de Sesión (`login`):**
   - En Huawei: Solicita un token CSRF/nonce (`GetRandCount.asp`) y envía `UserName`, `PassWord` (Base64) y token a `login.cgi` guardando cookies de sesión.
   - *Equivalente en Nokia a investigar:* Los módems Nokia de Telmex (ej. **G-240W-B**, **G-2425G-A**, **G-2425G-B**, **G-140W-C/H**) usan su propio flujo de autenticación HTTP/HTTPS (a menudo vía `login.cgi`, `/goform/login`, o desafío nonce SHA-256/MD5 con sesiones CGI/Lua).
3. **Extracción / Descarga del Respaldo de Configuración (`download_config`):**
   - En Huawei: Extrae `hw_ctree.xml` vía `cfgfiledown.cgi`.
   - *Equivalente en Nokia a investigar:* En ONTs Nokia (Alcatel-Lucent), el respaldo suele descargarse como `config.cfg`, `backup.cfg`, `psi_backup` o `config.xml` (o bien consultarse desde endpoints CGI/HTML de voz si son accesibles o mediante descarga del backup de configuración).
4. **Desempaquetado y Descifrado del Contenedor (`decrypt_config`):**
   - En Huawei: Contenedor Type-1 (`AES-256-CBC` + KDF SHA-256 8192 rondas + `Gzip`).
   - *Equivalente en Nokia a investigar:* Según el modelo y versión de firmware de Nokia (`3FE...`):
     - Algunos modelos Nokia exportan un contenedor XML comprimido con `zlib`/`gzip` o cifrado con **AES-128-CBC / AES-256-CBC** (usando claves fijas conocidas del binario `/bin/web` o derivadas del Serial/MAC), o un archivo `.cfg` con encabezado propietario de Alcatel-Lucent/Nokia.
5. **Descifrado de Contraseñas Ofuscadas Internas (`decrypt_value`):**
   - En Huawei: Hashes reversibles `$2...$` descifrados con tablas White-Box AES (`src/hw_passwd.cpp`).
   - *Equivalente en Nokia a investigar:* Determinar si dentro del XML/CFG de Nokia las claves (`AuthPassword` SIP y `Password` PPPoE) vienen en texto plano tras descifrar el contenedor, codificadas en Base64/Hex, o cifradas con una rutina específica de Nokia.
6. **Parseo y Generación de Reportes (`parse_credentials`):**
   - Extracción estructurada de:
     - **SIP VoIP (IMS):** `AuthUserName` (`+52...`), `AuthPassword`, `URI`, `RegistrarServer` (`vims-h.telmex.com` o regional), `OutboundProxyServer` (`nir...telmex.net`), puertos y códecs.
     - **WAN PPPoE:** Usuario, contraseña, VLAN (`881`).
     - **Exportación lista para Asterisk (`pjsip.conf` / `sip.conf`).**
7. **Gestión Quirúrgica del Cliente SIP y Re-empaquetado (`packer` + `sip_manager`):**
   - Para que Asterisk pueda registrarse sin que el IMS de Telmex rechace por colisión o que la ONT secuestre las llamadas entrantes:
     - **Vía A (Config Re-upload):** Modificar el nodo de Voz (`VoiceProfile` / `Line` -> `Disabled` o cambiar puerto/servidor SIP en el XML), re-empaquetar el `.cfg` y subirlo al Nokia.
     - **Vía B (Web API / CGI / Telnet / SSH):** Desactivar la línea FXS/SIP directamente mediante petición POST al endpoint CGI de VoIP o consola si el firmware lo permite.

---

## 🗺️ Plan Maestro de Implementación por Fases y Microfunciones

| Fase | Nombre | Estado | Archivo de Pizarra |
| :--- | :--- | :---: | :--- |
| **Fase 0** | Análisis de Metodología Base y Planeación | ✅ Completado | `00_indice_y_arquitectura.md`, `01_plan_maestro_fases.md` |
| **Fase 1** | Reconocimiento No Intrusivo de la ONT Nokia | ✅ Completada (MF-1.1 ✅ / MF-1.2 ✅ / MF-1.3 ✅) | `02_fase1_reconocimiento_nokia.md` |
| **Fase 2** | Autenticación Web y Exploración de Sesión/Endpoints | ✅ Completada (MF-2.1 ✅ / MF-2.2 ✅ / MF-2.3 ✅) | `03_fase2_autenticacion_y_endpoints.md` |
| **Fase 3** | Obtención y Análisis Criptográfico del Backup (`config`) | 🟠 Bloqueada parcial (MF-3.1 ✅ / MF-3.2 ✅ / MF-3.3 ⚠️ clave en firmware) | `04_fase3_extraccion_y_criptografia.md` |
| **Fase 3.5** | Investigación de Desbloqueo (estructura de flujo + revisión de CGIs) | ✅ Completada (MF-3.4 ✅ / MF-3.5 ✅: PPPoE user en claro) | `04_fase3_extraccion_y_criptografia.md` |
| **Plan Fases 4 y 5** | Redefinición granular de microfunciones (`MF-4.1a`..`MF-5.3a`) | ✅ Completado | `05_plan_detallado_fases_4_y_5.md` |
| **Fase 4** | Extracción Estructurada, Reportes y Plantillas Asterisk (`MF-4.1a`..`4.3b`) | ✅ Completada (MF-4.1a ✅ / MF-4.1b ✅ / MF-4.2a ✅ / MF-4.2b ✅ / MF-4.3a ✅ / MF-4.3b ✅) | `06_fase4_extraccion_y_asterisk.md` |
| **Fase 5** | Empaquetador `.cfg`, Gestor SIP y Verificación de Red (`MF-5.1a`..`5.3a`) | ✅ Completada (MF-5.1a ✅ / MF-5.1b ✅ / MF-5.2a ✅ / MF-5.2b ✅ / MF-5.2c ✅ / MF-5.3a ✅) | `07_fase5_empaquetador_y_sip_manager.md` |

---

## 📝 Registro Cronológico de Avances (Bitácora)
- **[2026-11-20]** ✅ **MF-5.3a (`verify_ims_network_reachability`) completada** → 🏁 **FASE 5 COMPLETADA.** Añadida a `nokia_sip_manager.py` (CLI `--check-network`, `--out`): checklist de red de solo lectura (cliente SIP ONT vía `voice_info.cgi`, WAN VLAN 881/VOIP/DNS vía `wan_config_glb.cgi` + `show_wan_status.cgi?ipv4`, SIP ALG vía `var alg_obj` de `nat_glb.cgi?v=alg`) que genera `output/asterisk_network_checklist.md`. **Prueba real contra 192.168.99.254:** WAN Connected `189.238.92.11`, DNS `189.233.12.5,189.233.15.2`, VOIP ok, línea SIP ONT `Disabled`, **`SIPEnable=1`** → recomendación de desmarcar "SIP" en *Security → DMZ and ALG*; `checklist_ready=false` por el ALG; `logout_status=200`. 15/15 pruebas en `tests/test_sip_manager.py` (2 nuevas con `SIPEnable:1`/`0`, mock en memoria). Detalle en `07_fase5_empaquetador_y_sip_manager.md`.
- **[2026-11-20]** ✅ **MF-5.2c (`upload_nokia_configuration`) completada.** Añadida a
  `nokia_sip_manager.py`: cliente HTTP de restauración controlada hacia
  `POST /usb.cgi?import` (o `?v=import&sl_num=<serial>` si se pasa número de serie).
  **PASO 0 de bloqueo de seguridad, obligatorio ANTES de abrir cualquier sesión/red:**
  (1) `cfg_path` debe existir (`FileNotFoundError` si no); (2) `verify_nokia_pack(cfg_path)`
  debe validar magic+CRC32 (`ValueError` si el contenedor está corrupto); (3) si se da
  `serial_number`, debe cumplir el formato `isvalidSerialNum` del JS Nokia (12
  alfanuméricos, prefijo `ALCL`, p.ej. `ALCLB472FD24`) o lanza `ValueError`. Solo tras las
  tres validaciones se abre sesión (`authenticate_nokia()` si `opener is None`, con
  `logout_nokia()` siempre en `finally`), se obtiene un `csrf_token` fresco de
  `GET /usb.cgi?backup` (reutilizando `nokia_backup._extract_csrf_token`) y se construye el
  cuerpo `multipart/form-data` (boundary propio, 3 partes: `csrf_val=""`, `csrf_token`,
  `filename="config.cfg"` con `Content-Type: application/octet-stream`). Detecta
  `"Import Completed!"` en la respuesta (`import_completed`). CLI nueva `--apply`/`--serial`:
  `--disable`/`--enable --apply` ahora encadena `toggle_xml_sip_state()` +
  `pack_nokia_configuration()` + `upload_nokia_configuration()`; sin `--apply` el flujo sigue
  siendo 100% offline (comportamiento previo intacto). 13/13 pruebas en
  `tests/test_sip_manager.py` (3 nuevas de seguridad + 4 de flujo exitoso con `MockOpener` en
  memoria, **sin red real en ningún caso**): rechazo de `.cfg` corrupto (1 bit alterado) y de
  `serial_number` inválido **antes** de cualquier llamada HTTP (`len(mock_opener.requests)==0`
  verificado), construcción exacta del multipart y detección de `"Import Completed!"` con
  `MockOpener` simulando `GET /usb.cgi?backup` + `POST /usb.cgi?import`/`?v=import&sl_num=...`.
  Detalle en `07_fase5_empaquetador_y_sip_manager.md`. (Siguiente: MF-5.3a, ya completada.)
- **[2026-11-20]** ✅ **MF-5.2b (`toggle_xml_sip_state`) completada.** Añadida a
  `nokia_sip_manager.py`: edita (offline) el estado `Enable`/`Status` únicamente en los
  nodos de voz (`VoiceProfile`/`VoiceProfileInstance`/`Line`/`LineInstance`), tolerante a
  ambos esquemas Nokia/TR-104 (por atributo propio o por hijo directo `<Enable>`/
  `<Status>`), sin tocar `WANPPPConnection`/WLAN/cuentas web. Lanza `ValueError` si no hay
  nodos de voz. CLI nueva `--disable`/`--enable --xml ... -o ...` que encadena
  `toggle_xml_sip_state()` + `pack_nokia_configuration()` (MF-5.2a) en modo 100% offline
  (nada se sube al router todavía). Round-trip `Disabled<->Enabled` verificado con
  `parse_xml_voice_profile()` (MF-4.1b) sobre ambos esquemas sin alterar credenciales/URI;
  integración con `pack_nokia_configuration()`/`verify_nokia_pack()` confirmada. 10/10
  pruebas nuevas en `tests/test_sip_manager.py`. Detalle en
  `07_fase5_empaquetador_y_sip_manager.md`. **Siguiente: MF-5.2c.**
- **[2026-11-20]** ✅ **MF-5.1a (`check_ont_voice_state`) completada.** Nuevo módulo
  `nokia_sip_manager.py` (solo lectura, `voice_info.cgi`, sesión propia con `logout` en `finally`,
  CLI `--status`). Prueba real contra 192.168.99.254: `LineStatus=Disabled` → `is_active=false`
  (cliente SIP interno ya inactivo), `logout_status=200`. Detalle en
  `07_fase5_empaquetador_y_sip_manager.md`. **Siguiente: MF-5.2b.**
- **[2026-11-20]** ✅ **MF-5.1b (`build_cfg_header_and_crc`) y MF-5.2a (`pack_nokia_configuration`
  + `verify_nokia_pack`) completadas** → 🟡 **Fase 5 en progreso.** Nuevo módulo
  `nokia_config_packer.py` (equivalente a `huawei_config_packer.py` para el contenedor
  `config.cfg` de Nokia). `build_cfg_header_and_crc()` empaqueta la cabecera de 20 bytes
  (`<5I`: magic/compressed_size/crc32/uncompressed_size+1/fw_magic, LE) o la variante de
  40 bytes (`<10I`); **reconstruye bit a bit** el header real de
  `output/nokia_backup_raw.cfg` (`23 31 12 00 36 19 02 00 4f 70 f0 9b 74 a2 13 00 fe ff ff
  ff`) a partir de su payload + `uncompressed_len=1286771` + `fw_magic=0xfffffffe`.
  `verify_nokia_pack()` reutiliza `analyze_container_format()` de `nokia_backup.py` para
  validar magic/`compressed_size`/CRC32 (`ValueError` si falla), verificado exitosamente
  contra el backup real (`compressed_size=137526`, CRC32 `0x9bf0704f`). `pack_nokia_configuration()`
  comprime un XML con `zlib` (nivel 9), aplica `cipher_hook` opcional, antepone la cabecera
  y verifica el `.cfg` resultante antes de retornar; **round-trip 100%** confirmado
  descomprimiendo con `unpack_and_decrypt_config()` (modo `zlib-directo`). CLI homologada
  con `huawei_config_packer.py` (`<xml_file> -o -t` / `--verify`). 10/10 pruebas en
  `tests/test_nokia_packer.py` (header real bit-exacto, round-trip XML, detección de
  corrupción de 1 bit en payload y en cada campo del header). Detalle en
  `07_fase5_empaquetador_y_sip_manager.md`. **Siguiente: MF-5.2b.**
- **[2026-11-20]** ✅ **MF-4.2b (`build_unified_reports`), MF-4.3a (`render_asterisk_pjsip_conf`)
  y MF-4.3b (`render_asterisk_sip_conf`) completadas → 🏁 FASE 4 COMPLETADA.** `build_unified_reports()`
  combina `web_telemetry` (MF-4.1a) con `xml_data` opcional (MF-4.1b/4.2a), priorizando siempre el
  dato en texto claro sobre los marcadores `"Pendiente / No disponible en XML"` y la máscara fija
  `!!!@@@###$$$^^^&&&***`, y escribe `output/credentials.json`/`credentials.md` (4 secciones:
  identidad/GPON, WAN PPPoE, VoIP SIP, Wi-Fi + acceso web). `render_asterisk_pjsip_conf()` genera
  `output/asterisk_pjsip_telmex.conf` (stack `res_pjsip`: `transport-udp`/`telmex-ims`/`telmex-auth`/
  `telmex-aor`/`telmex-endpoint`/`telmex-identify`) y `render_asterisk_sip_conf()` genera
  `output/asterisk_sip_legacy_telmex.conf` (`chan_sip` clásico, `register =>` + peer `[telmex-ims]`)
  y `output/asterisk_extensions_sample.conf` (`[from-telmex]` entrante + `[salientes-telmex]`
  patrón `_XXXXXXXXXX` saliente a 10 dígitos). Ambas plantillas Asterisk insertan placeholders
  explícitos (`+5255XXXXXXXX` / `TU_PASSWORD_SIP_IMS`) con aviso en comentarios cuando los datos
  SIP siguen pendientes (sin XML descifrado). Se agregó un **CLI completo con `argparse`**
  (subcomandos `telemetry`/`all`, flags `--ip/-u/-p/--xml/--sip-user/--sip-pass/--sip-number/
  -o/--json/--offline`, estilo homologado con `huawei_hg8145v5_extractor.py`); `--offline` reutiliza
  `output/web_telemetry.json` ya existente sin reconectar al router. Probado end-to-end con
  `--offline` contra la telemetría real capturada (MF-4.1a) + un XML sintético vía `--xml`:
  las 4 plantillas se generaron correctamente y las credenciales SIP reales sustituyeron los
  placeholders (verificado en `pjsip`/`sip.conf`/`register =>`). 11/11 pruebas unitarias en
  `tests/test_xml_parsers.py` (5 nuevas para MF-4.2b/4.3a/4.3b, además de las 6 previas de
  MF-4.1b/4.2a). Código en `nokia_g1425gh_extractor.py`. Detalle exhaustivo en
  `06_fase4_extraccion_y_asterisk.md`.
- **[2026-11-20]** ✅ **MF-4.1b (`parse_xml_voice_profile`) y MF-4.2a (`parse_xml_wan_and_wlan`)
  completadas** (parsers offline, sin dependencia de red). Ambas toleran los dos esquemas
  XML TR-098/TR-104 del firmware Nokia: jerárquico por sub-elementos (`<ProxyServer>x</ProxyServer>`)
  y de atributos (`<SIP ProxyServer="x" .../>`, incluyendo nodos aplanados
  `VoiceProfileInstance`/`LineInstance`/`WANPPPConnectionInstance`/`WLANConfigurationInstance`),
  mediante helpers XML compartidos (`_elem_fields`, `_iter_by_tag`, `_pick`, mapa de padres
  para distinguir `SIP` de perfil vs. de línea). `parse_xml_voice_profile` extrae
  proxy/registrar/outbound (con defaults `vims-h.telmex.com`/`nir8.norte.telmex.net`/`5060`),
  la lista `lines[]` y expone también los campos planos compatibles con `credentials.json`
  (`auth_username`, `auth_password`, `uri`, `directory_number`, `line_status`, etc.).
  `parse_xml_wan_and_wlan` extrae `pppoe` (VLAN 881, MTU 1492 por defecto), `wifi_networks`
  (SSID/PSK/Enable/Standard) y `web_admin` (cuentas locales). Validadas al 100% con dos XML
  sintéticos TR-098/TR-104 realistas en `tests/test_xml_parsers.py` (6/6 pruebas, 40+
  aserciones). Código en `nokia_g1425gh_extractor.py`. Detalle en
  `06_fase4_extraccion_y_asterisk.md`. **No se avanzó a MF-4.2b.**
- **[2026-11-20 23:59]** ✅ **MF-4.1a (`collect_web_telemetry`) completada** (ciclo propio de sesión, solo lectura). Ciclo limpio `login (299+X-SID) → 9 consultas GET/POST de solo lectura → logout (200)`. Consultados: `device_status.cgi`, `wan_config_glb.cgi`, `show_wan_status.cgi?ipv4`, `voice_info.cgi`, `wlan_config.cgi` (2.4GHz), `wlan_config.cgi?v=11ac` (5GHz), `lan_status.cgi?wlan`, `gpon_config.cgi`, `log.cgi?vlog_glb`. **Datos extraídos:** identidad de equipo (`G-1425G-H`, SN `ALCLB472FD24`, SW `3TN00702IJMI00`), WAN PPPoE VLAN 881 (`Username=E03005LALCLB472FD24@prodigyweb.com.mx`, `Password` enmascarada, `ConnectionStatus=Connected`, IP pública `189.238.92.11`), telefonía (`LineStatus=Disabled`, confirma MF-2.3), 4 SSIDs 2.4GHz + 6 SSIDs 5GHz (PSK cifradas, no descifradas), SLID GPON (`DEFAULT`). **`log.cgi?vlog_glb` rechazó** la réplica exacta del envoltorio cifrado RSA+AES del propio JS del firmware (`Bad request for invalid parameter in the coookie`); reportado limpiamente sin reintentos para no activar el `ErrorLimit`; **no afectó la sesión** (logout posterior = 200). **Dos bugs corregidos en la implementación tras la primera corrida real:** (1) índices anidados de `wlan_config` (`psks:{1:{...}}}`) sobrescribían los campos de nivel superior del SSID; (2) campo `Name` ambiguo entre `lan_ether` y `wan_conns` en `wan_config_glb.cgi` tomaba el valor equivocado (`eth0.0` en vez de la conexión PPPoE). Código en `nokia_g1425gh_extractor.py` (nuevo módulo, importa `nokia_auth.py`). Salida guardada en `output/web_telemetry.json` (10 841 B, SHA-256 `4167702a...`). Detalle exhaustivo en `06_fase4_extraccion_y_asterisk.md`. **No se avanzó a MF-4.1b.**
- **[2026-11-20 14:36]** Se inspeccionó la estructura completa del repositorio `/Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia`.
- **[2026-11-20 14:36]** Se verificaron los scripts base de Huawei (`huawei_hg8145v5_extractor.py`, `huawei_config_packer.py`, `huawei_sip_manager.py` y `src/hw_passwd.cpp`).
- **[2026-11-20 14:37]** Se inicializó la carpeta `Pizarra/` con la arquitectura y el plan detallado de fases y microfunciones antes de tocar o enviar cualquier paquete al módem Nokia.
- **[2026-11-20 14:39]** ✅ **MF-1.1 (`detect_default_gateway`) completada** (no intrusiva). Gateway = `192.168.99.254` vía `en0`; ping 0% pérdida (RTT ~3.5 ms); TCP/80 abierto (`Server: thttpd`), TCP/443 no responde. MAC gateway `e0:3d:a6:d0:bd:50` (OUI `E0:3D:A6` → **Taicang T&W Electronics**, ODM; **no** es bloque OUI propio de Nokia/ALU). ⚠️ Subred no estándar `192.168.99.0/24` (no `192.168.1.254`). Detalle completo en `02_fase1_reconocimiento_nokia.md`. **No se avanzó a MF-1.2 ni se hizo login.**
- **[2026-11-20 20:46]** ✅ **MF-1.2 (`fingerprint_nokia_web`) completada** (sin login). `GET /` → `200` HTML de login (sin redirección). Fabricante **Nokia** confirmado (i18n `web-spa.json`: "Nokia Solutions and Networks Oy"); firma **Beacon + IoT GW (Z-Wave/ZigBee/JVM)** ⇒ candidato **Nokia G-2425G-A "Beacon 1"**; operador `MXXT`=Telmex; servidor **thttpd** (solo GET/POST). **Login descifrado:** `POST /login.cgi` con envoltorio híbrido **RSA-1024 PKCS#1 (JSEncrypt 3.0.0) + AES-128-CBC (sjcl)**, cuerpo `encrypted=1&ct=...&ck=...`; `nonce`+`csrf_token` rotan por `GET /`; éxito = HTTP **`299`** + cabecera **`X-SID`**; respuestas posteriores AES-CBC con `enckey`/`enciv` del cliente. Pubkey RSA, nonce/token de ejemplo y fragmentos JS literales en `02_fase1_reconocimiento_nokia.md`.
- **[2026-11-20 20:46]** ✅ **MF-1.3 (`scan_management_ports`) completada** (connect-scan no intrusivo). **Único puerto abierto en LAN = TCP/80**. Cerrados/filtrados: 21, 22 (SSH, sin banner), 23 (Telnet, sin banner), 53, 443, 5060 (SIP), 7547 (TR-069), 8080. ⇒ Gestión solo por **Web/CGI**; Vía CLI (SSH/Telnet) de Fase 5 descartada por ahora; cliente SIP interno vive en WAN (no bloqueable por puerto local → se desactivará por config).
- **[2026-11-20 20:46]** 🏁 **FASE 1 COMPLETADA.** Siguiente: Fase 2 (MF-2.1 `get_login_challenge` → leer `nonce`/`token`/`pubkey` de `GET /` y replicar el envoltorio RSA+AES en Python). **No se ejecutó login real.**
- **[2026-11-20 21:10]** ✅ **MF-2.1 (`get_login_challenge`) completada** (sin POST de login). `GET /` real → parser determinista extrae `pubkey` (PEM RSA-1024 limpio, `e=65537`), `nonce` + `csrf_token` (rotan por carga), cookie `lang=spa`, `operatorCheck=MXXT`, `window.name=Bell`. Helpers cripto en `nokia_auth.py` **validados bit-a-bit** (`tests/validate_crypto.py`, todas ✅): **AES-128-CBC/PKCS#7 ≡ OpenSSL ≡ `sjcl.mode.cbc.encrypt`** (incl. bloque de padding completo cuando `len%16==0`), **base64url urlsafe SIN `=` ≡ `sjcl.codec.base64url`**, **`base64url_escape` con `=→.`**, **RSA-1024 PKCS#1 v1.5 round-trip ≡ `JSEncrypt`**. No hay `node` en el host → validación vía análisis de fuente `sjcl.js` + OpenSSL + round-trip RSA. Detalle en `03_fase2_autenticacion_y_endpoints.md`. **NO se hizo POST a `/login.cgi` (reservado para MF-2.2).**
- **[2026-11-20 21:55]** ✅ **MF-2.3 (`map_authenticated_endpoints`) completada** → 🏁 **FASE 2 COMPLETADA.** Ciclo limpio `login (299+X-SID) → menu.cgi → device_status.cgi → 43 targets → sondas voz → logout`. **Modelo CONFIRMADO: Nokia G-1425G-H** (antes se adivinó *G-2425G-A*); Manufacturer `ALCATEL-LUCENT`/OUI `E03005`; **SW `3TN00702IJMI00`** (build `IJM.I00p01`), **HW `3TN00990ADAA`**, **SN/GPON `ALCLB472FD24`**, chipset `MTK7552`, `ProvisioningCode=TELMEX`, `adminRole=0`. **Backup:** descarga = `POST /usb.cgi?export` (urlencoded, `csrf_token`, **sin cifrar**, descarga directa); restore = `POST /usb.cgi?import` (o `?v=import&sl_num=<serial ALCL…>`, multipart `filename`, `csrf_token`). **VoIP:** sin CGI de config para rol 0 (sondas `voice/voip/sip*.cgi` → 404); `voice_info.cgi` solo lectura, línea SIP **`Disabled`**, sin número/proxy ⇒ credenciales SIP **solo en el backup**. **WAN:** única PPPoE **VLAN 881** `1_VOIP_TR069_INTERNET_OTHER_R` (Connected, `189.238.92.11`), voz sin VLAN dedicada; WAN 1081/981 Unconfigured. Código en `nokia_auth.py` (`map_authenticated_endpoints`, `_parse_menu_nodes`, `logout_nokia`, CLI `map`). Sesión cerrada con `GET /login.cgi?out`. Detalle exhaustivo en `03_fase2_autenticacion_y_endpoints.md`. **Siguiente: Fase 3 / MF-3.1** (`download_nokia_backup` vía `POST /usb.cgi?export`).
- **[2026-11-20 23:30]** ✅ **MF-3.2 (`analyze_container_format`) completada** + ⚠️ **MF-3.3 (`unpack_and_decrypt_config`) completada CON BLOQUEO.** **Formato identificado al 100%:** contenedor **Alcatel-Lucent/Nokia `cfg` LEGACY** (magic `uint32` LE **`0x00123123`**, header de **20 B**, 5 campos `uint32` LE). El `23 31` inicial **no es `#1`**, es el magic de thedroidgeek/rajkosto. **CRC32 del payload VERIFICADO** (`binascii.crc32` = `0x9bf0704f`, coincide con offset `0x08`); `compressed_size=137526`; **XML objetivo = `1286771` B** (campo `0x0C` = `+1`); `fw_magic=0xfffffffe`. **Payload interno CIFRADO** (entropía **7.9983**, `len%16=6` ⇒ no CBC/ECB completo). **No** header zlib `78xx`, **no** capa `0xFF` (rajkosto) ni `0x11` (udaravima). **1150+ claves probadas** (serial `ALCLB472FD24`, `ALCL/NOKA/TELMEX`, pw-fijo rajkosto, MD5/SHA256/PBKDF2, modos CTR/CFB/OFB/CBC/ECB) → **0 éxitos**. ⇒ **clave simétrica DERIVADA EN EL DISPOSITIVO (firmware `3TN00702IJMI00`)**, igual que el problema público no resuelto (repo `udaravima` G-1425G-B build Dic-2024). **`output/nokia_config_decrypted.xml` NO generado** (no se inventa XML). **Fallback web verificado** (`probe_key_hints`, read-only, logout OK): la UI rol 0 **no** expone clave de backup ni export sin cifrar (tokens `encrypt/key` = RSA de login); `device_status.cgi` expone `Progdate` pero solo sirve a `dmdb_encryption.cfg` (otro archivo) y falta `extfshash` del firmware. Código en `nokia_backup.py` (`analyze_container_format`, `unpack_and_decrypt_config`, `probe_key_hints` + CLI `analyze/decrypt/probe`); scripts de criptoanálisis en `tests/`. **Fase 4 bloqueada hasta extraer la clave del firmware.** Detalle exhaustivo en `04_fase3_extraccion_y_criptografia.md`.
- **[2026-11-20 23:55]** ✅ **FASE 3.5 (Investigación Forense de Desbloqueo) completada — MF-3.4 ✅ + MF-3.5 ✅.** **MF-3.4 (residuo/diff):** inspección de primeros/últimos 32 B + residuo de 6 B del payload → **entropía uniforme ~7.80** de principio a fin (sin zona en claro ni cola zlib/Adler-32 en claro); el residuo de 6 B **es `comp_size mod 16`**, no un campo. **Diff diferencial de 5 backups consecutivos** (`output/nokia_backup_raw.cfg` + `_2`…`_5.cfg`, sin cambiar config): el ciphertext **cambia por completo en cada export** (primer byte distinto en offset 0; **0/8595 bloques de 16 B idénticos**; `C3⊕C4` entropía 7.9988 / 0.39 % ceros ≡ aleatorio puro), pero **`unc_size+1` SIEMPRE idéntico (1286772)** y **`comp_size` cambió 137526→137525**. Como `comp_size` depende **solo del plaintext**, eso **prueba que el XML en claro varía entre exports** (campo volátil: uptime/contador). **Veredicto:** cifrado de **FLUJO** (CTR/CFB/OFB/RC4/XOR), **NO** ECB/CBC (longitud == plaintext comprimido, no múltiplo de 16/8, sin IV/salt en el archivo); **keystream ESTÁTICO derivado del dispositivo** (el restore debe ser determinista ⇒ sin nonce externo). Two-time-pad **no práctico** (plaintext difiere desde el byte 0 por compresión). **MF-3.5 (auditoría 43 CGIs):** `diag.cgi?ping` POST(`ipaddr/ipversion/iface/pingcount/packetlength/tracehops/csrf_token`) → devuelve filename que se transmite por **★ `command.cgi?cat+<archivo>`** (endpoint oculto = posible **lectura arbitraria de archivos**, lead #1 de desbloqueo sin firmware). `web_diag.cgi?diag` solo estado PPPoE; `log.cgi?vlog_glb` = volcado syslog en vivo (no capturado); `log.cgi?set_log_sftp` = exfil de logs por SFTP. **`wan_config_glb.cgi`:** `var wan_conns` trae **username PPPoE EN CLARO** `E03005LALCLB472FD24@prodigyweb.com.mx` (= OUI+`L`+SN+`@prodigyweb.com.mx`, derivable del serial); **password PPPoE enmascarado** `!!!@@@###$$$^^^&&&***`. `gpon_config.cgi` SLID=`DEFAULT`(hex); `user_glb.cgi` **no** filtra la pass admin; SIP sigue solo en el backup. Scripts `tests/forensic_residue.py`, `tests/forensic_diff.py`. **Siguiente propuesto: MF-3.6** (prueba activa autorizada de `log.cgi?vlog_glb` y `command.cgi?cat+<ruta>`). Detalle en `04_fase3_extraccion_y_criptografia.md`.
- **[2026-11-20 22:30]** ✅ **MF-3.1 (`download_nokia_backup`) completada** → 🟡 **FASE 3 iniciada.** Ciclo limpio `login (299+X-SID) → GET /usb.cgi?backup → POST /usb.cgi?export → logout`. **Backup descargado:** `POST /usb.cgi?export` (urlencoded `csrf_val=&csrf_token=<tok>`, `Referer` backup, **sin cifrar**) → **HTTP `200`** + **`Content-Disposition: attachment;filename="config.cfg"`** + **`Content-Type: application/octet-stream`** (sin `Content-Length`). Guardado crudo en **`output/nokia_backup_raw.cfg`** (+ copia `output/config.cfg`, byte-idéntica). **Tamaño `137546` bytes** · **SHA-256** `f1ba78af7a5145576bf295c3d2db826a7f52c1ef3639dfa48930dbea9ee8c5c7` · **MD5** `1f570942e9e9babd88c2ac110f7dba10` (verificados con `shasum`/`md5`). **Contenedor binario propietario** (magic `23 31` = `#1`, header ~20 B + payload 137526 B de alta entropía; **no** XML/gzip/zlib plano). csrf_token embebido en `usb.cgi?backup` como `csrf_token=…` / hidden `value` (no `var token`). Código en `nokia_backup.py` (importa `nokia_auth.py`). Sesión cerrada (logout `200`). Detalle en `04_fase3_extraccion_y_criptografia.md`. **Detenido antes de MF-3.2/MF-3.3.**
- **[2026-11-20 21:40]** ✅ **MF-2.2 (`authenticate_nokia`) completada** (login real exitoso, **1 intento limpio**). `POST /login.cgi` con `TELMEX`/`sf3h5zkdtA` (envoltorio RSA-1024+AES-128) → **HTTP `299`** + **`X-SID=zTyYAkWRkTAzRZhk`**; sesión por cookies **`sid`/`isAdminLoggedIn=1`/`lsid`** (body del 299 vacío). Implementado también `aes128_cbc_decrypt_sjcl()` (≡ `crypto_page.aes_decrypt`, round-trip OK) y manejo blindado de **HTTP 299** (`_Pass2xxErrorProcessor` 2xx + captura `HTTPError e.code==299`). `GET /` inmediato (como `window.top.location='/'`) devolvió el **shell autenticado "GPON Home Gateway"** (200, 20 053 B, `looks_authenticated=True`): menú dinámico vía **`menu.cgi`** (`all_nodes.nodes[]` → `target` CGI en iframe `mainFrame`), `adminRole=0`, CSRF fresco `token`, `var pubkey` presente (CGIs autenticados también se cifran RSA+AES). HTML guardado en **`/tmp/nokia_recon/authenticated_index.html`**. Detalle en `03_fase2_autenticacion_y_endpoints.md`. **Detenido antes de MF-2.3** (mapeo de endpoints).
