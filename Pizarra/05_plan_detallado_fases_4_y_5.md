# 📐 Plan Detallado y Granular: Fases 4 y 5 (Interoperabilidad VoIP SIP, Empaquetado y Asterisk)

> **Propósito de este documento:** Redefinir y subdividir las **Fases 4 y 5** en microfunciones más pequeñas, atómicas, limpias y estrictamente orientadas a ingeniería de software, telecomunicaciones e interoperabilidad de equipos (VoIP SIP / TR-098 / TR-104 / Asterisk PBX).
> **Fecha:** 2026-11-20
> **Modelo Objetivo:** Nokia `G-1425G-H` (Firmware `3TN00702IJMI00`, Serial `ALCLB472FD24`)

---

## 🏗️ Visión General de la Subdivisión

Para evitar funciones monolíticas y mantener la misma arquitectura modular del proyecto de referencia (`extractor`, `config_packer`, `sip_manager`), hemos dividido el trabajo restante en **12 sub-funciones granulares** distribuidas entre la **Fase 4** (6 microfunciones) y la **Fase 5** (6 microfunciones):

```
FASE 4: Extracción Estructurada, Reportes y Plantillas Asterisk
 ├── MF-4.1a: collect_web_telemetry()       -> ✅ Completada. Recolección de datos disponibles vía CGI (WAN, Device, Voice Info, System Log)
 ├── MF-4.1b: parse_xml_voice_profile()     -> ✅ Completada. Lector tolerante (elementos/atributos) del árbol XML TR-104 (VoiceService / SIP / Line)
 ├── MF-4.2a: parse_xml_wan_and_wlan()      -> ✅ Completada. Lector tolerante (elementos/atributos) del árbol XML TR-098 (WANPPPConnection, VLAN 881, WLAN, Usuarios)
 ├── MF-4.2b: build_unified_reports()       -> ✅ Completada. Generador de reportes estructurados (output/credentials.json y credentials.md)
 ├── MF-4.3a: render_asterisk_pjsip_conf()  -> ✅ Completada. Generador de configuración moderna para Asterisk (pjsip.conf)
 └── MF-4.3b: render_asterisk_sip_conf()    -> ✅ Completada. Generador de configuración clásica (sip.conf) y plan de marcado (extensions.conf)

FASE 5: Empaquetador de Configuración, Gestor de Estado SIP y Verificación de Red
 ├── MF-5.1a: check_ont_voice_state()       -> Verificación del estado actual de la línea SIP en la ONT (voice_info.cgi)
 ├── MF-5.1b: build_cfg_header_and_crc()    -> Constructor de cabecera Nokia (20 bytes, magic 0x00123123 y cálculo CRC32)
 ├── MF-5.2a: pack_nokia_configuration()    -> Compresión zlib y empaquetado del contenedor config.cfg + verificación de integridad
 ├── MF-5.2b: toggle_xml_sip_state()        -> Modificación limpia de atributos Enable (Enabled/Disabled) en nodos de voz del XML
 ├── MF-5.2c: upload_nokia_configuration()  -> ✅ Completada. Cliente HTTP multipart para restauración controlada de respaldo (usb.cgi?import)
 └── MF-5.3a: verify_ims_network_reachability() -> ✅ Completada. Diagnóstico de rutas, DNS e interoperabilidad de red hacia el servidor IMS
```

---

## 📞 FASE 4: Extracción Estructurada de Parámetros, Reportes y Plantillas Asterisk

**Objetivo de la Fase 4:** Consolidar toda la información de red, dispositivo, WAN PPPoE y telefonía SIP tanto desde las páginas de estado web del Nokia `G-1425G-H` como desde archivos XML de configuración (modo online y modo offline `--xml`), generando los reportes estándar y los archivos de configuración listos para un servidor Asterisk.

---

### 🔹 `MF-4.1a`: `collect_web_telemetry(opener, ip)` — ✅ Completada (2026-11-20)
> Implementada y ejecutada contra el equipo real en `nokia_g1425gh_extractor.py`. Ciclo
> `login → 9 consultas de solo lectura → logout (200)` verificado; `log.cgi?vlog_glb` quedó
> documentado como no disponible (rechazo aplicativo del router, sin reintentos). Detalle
> exhaustivo, hallazgos y estructura de salida en `06_fase4_extraccion_y_asterisk.md`.
- **Descripción:** Consulta de forma ordenada y en modo de solo lectura las páginas de estado del router (`device_status.cgi`, `show_wan_status.cgi?ipv4`, `wan_config_glb.cgi`, `voice_info.cgi`, `lan_status.cgi?wlan`, `gpon_config.cgi` y `log.cgi?vlog_glb`) para reunir todos los parámetros que la interfaz web entrega directamente.
- **Datos que recolecta:**
  - **Identidad del equipo:** Modelo (`G-1425G-H`), número de serie GPON (`ALCLB472FD24`), OUI (`E03005`), versión de software (`3TN00702IJMI00`) y hardware (`3TN00990ADAA`).
  - **Parámetros WAN PPPoE visibles:** Usuario PPPoE (`E03005LALCLB472FD24@prodigyweb.com.mx`), VLAN ID (`881`), MTU (`1492`), lista de servicios (`VOIP,TR069,INTERNET,OTHER`), IP pública asignada y servidores DNS.
  - **Telemetría de Voz (`voice_info.cgi`):** Estado actual de la línea (`Enabled` / `Disabled`), número registrado (`phNumber`), IP del proxy (`proxyIp`), IP del agente de usuario (`userAgentIp`) y código de registro.
  - **Bitácora de eventos (`log.cgi?vlog_glb`):** Eventos de inicialización de red, PPPoE y telefonía registrados por el sistema.
- **Entrada:** Sesión HTTP autenticada (`opener`) e IP del router (`192.168.99.254`).
- **Salida:** Diccionario Python estructurado `web_telemetry` con todos los datos recolectados en vivo.

---

### 🔹 `MF-4.1b`: `parse_xml_voice_profile(xml_text)` — ✅ Completada (2026-11-20)
- **Descripción:** Analiza un árbol XML de configuración de Nokia/Alcatel-Lucent (estándar TR-098 / TR-104 `InternetGatewayDevice.Services.VoiceService`) para extraer las credenciales y parámetros de registro SIP IMS. **Tolerante a ambos esquemas:** jerárquico por sub-elementos XML y de atributos TR-098/TR-104 (incluye nodos aplanados `VoiceProfileInstance`/`LineInstance`).
- **Nodos y atributos que procesa:**
  - `VoiceProfile` / `VoiceProfileInstance` / `SIP`: `ProxyServer`, `ProxyServerPort`, `RegistrarServer`, `RegistrarServerPort`, `OutboundProxy` / `OutBoundProxyServer`, `OutboundProxyPort`, `UserAgentDomain`.
  - `Line` / `LineInstance` / `SIP`: `AuthUserName`, `AuthPassword`, `URI`, `DirectoryNumber`.
  - `Line` / `LineInstance`: atributo o elemento `Enable` / `Status` (`Enabled` / `Disabled`).
- **Entrada:** Cadena de texto `xml_text` (proveniente de un archivo XML descomprimido o proporcionado vía argumento `--xml`).
- **Salida:** Diccionario `sip_voip` con `lines[]` por instancia, más campos planos de compatibilidad `auth_username`, `auth_password`, `uri`, `directory_number`, `registrar_server`, `outbound_proxy`, `proxy_server`, `port` y `line_status`. Si `xml_text` es vacío/`None`, devuelve defaults marcados `"Pendiente / No disponible en XML"`.
- **Prueba:** `tests/test_xml_parsers.py` (2 XML sintéticos, 100% de campos validados).

---

### 🔹 `MF-4.2a`: `parse_xml_wan_and_wlan(xml_text)` — ✅ Completada (2026-11-20)
- **Descripción:** Extrae del árbol XML de configuración los parámetros de conexión WAN PPPoE, redes inalámbricas Wi-Fi y cuentas de usuario del dispositivo. **Tolerante a ambos esquemas** (elementos/atributos, incluyendo `WANPPPConnectionInstance`/`WLANConfigurationInstance`).
- **Nodos y atributos que procesa:**
  - `WANPPPConnection` / `WANPPPConnectionInstance`: `Username`, `Password`, `X_ALU-COM_VLANID` / `VLANIDMark` / `X_HW_VLAN` / `X_CT-COM_VLANID` (default `881`), `MaxMRUSize` / `InterfaceMtu` (default `1492`), `X_CT-COM_ServiceList` / `X_HW_SERVICELIST`, `ConnectionType`, `NATEnabled`.
  - `WLANConfiguration` / `WLANConfigurationInstance`: `SSID`, `PreSharedKey` / `KeyPassphrase`, `Enable`, `Standard`, para las bandas de 2.4 GHz y 5 GHz.
  - Nodos de administración local (`UserInterface` / `X_ALU_COM_UserAccount` / `Account` / `User` / `X_HW_WebUserInfoInstance`): nombres de usuario, contraseña y nivel de acceso.
- **Entrada:** Cadena `xml_text`.
- **Salida:** Diccionario con las secciones `pppoe`, `wifi_networks` y `web_admin`. Si `xml_text` es vacío/`None`, devuelve defaults (`vlan_id=881`, `mtu=1492`) y listas vacías.
- **Prueba:** `tests/test_xml_parsers.py` (2 XML sintéticos, 100% de campos validados).

---

### 🔹 `MF-4.2b`: `build_unified_reports(web_telemetry, xml_data, output_dir)` — ✅ Completada (2026-11-20)
- **Descripción:** Combina los datos obtenidos en vivo por telemetría web (`MF-4.1a`) con los datos extraídos del XML (`MF-4.1b` y `MF-4.2a`, cuando están disponibles) y genera los reportes estandarizados del proyecto, manteniendo compatibilidad de formato con el extractor original.
- **Archivos que genera:**
  1. `output/credentials.json`: Estructura JSON limpia con las secciones `device_info`, `pppoe`, `sip_voip`, `wifi_networks` y `web_admin`.
  2. `output/credentials.md`: Reporte legible en Markdown con tablas de resumen de parámetros de red, GPON, PPPoE y estado de la cuenta SIP.
- **Entrada:** Diccionarios `web_telemetry`, `xml_data` y ruta `output_dir`.
- **Salida:** Rutas de los archivos `credentials.json` y `credentials.md` escritos en disco.

---

### 🔹 `MF-4.3a`: `render_asterisk_pjsip_conf(sip_data, output_dir)` — ✅ Completada (2026-11-20)
- **Descripción:** Toma los parámetros de la cuenta SIP IMS de Telmex (o parámetros pasados por línea de comandos si el usuario los ingresa manualmente) y genera el archivo de configuración para el stack moderno **PJSIP** de Asterisk (`pjsip.conf`).
- **Secciones PJSIP que construye:**
  - `[transport-udp]`: Transporte UDP en puerto `5060`.
  - `[telmex-ims]` (`type=registration`): Configuración de registro con `server_uri`, `client_uri`, `contact_user`, `outbound_proxy` (`sip:<proxy>:5060\;lr`), `retry_interval=60` y `expiration=3600`.
  - `[telmex-auth]` (`type=auth`): `auth_type=userpass`, `username` (`+52...@vims-h.telmex.com`) y `password`.
  - `[telmex-aor]` (`type=aor`): `contact`, `outbound_proxy` y `qualify_frequency=30`.
  - `[telmex-endpoint]` (`type=endpoint`): Contexto `from-telmex`, códecs `disallow=all`, `allow=alaw,ulaw`, `from_domain=vims-h.telmex.com`, `from_user`, `dtmf_mode=rfc4733`, `direct_media=no` y opciones de NAT (`rtp_symmetric=yes`, `force_rport=yes`, `rewrite_contact=yes`).
  - `[telmex-identify]` (`type=identify`): Asociación de tráfico entrante por IP/dominio del proxy IMS.
- **Entrada:** Diccionario `sip_data` y directorio de salida.
- **Salida:** Archivo `output/asterisk_pjsip_telmex.conf`.

---

### 🔹 `MF-4.3b`: `render_asterisk_sip_conf(sip_data, output_dir)` — ✅ Completada (2026-11-20)
- **Descripción:** Genera una plantilla complementaria para instalaciones de Asterisk que utilicen el driver clásico `chan_sip` (`sip.conf`) junto con un ejemplo básico de plan de marcado (`extensions.conf`) para pruebas de llamadas entrantes y salientes.
- **Entrada:** Diccionario `sip_data` y directorio de salida.
- **Salida:** Archivos `output/asterisk_sip_legacy_telmex.conf` y `output/asterisk_extensions_sample.conf`.

---

## 🛠️ FASE 5: Empaquetador de Configuración, Gestor de Estado SIP y Verificación de Red

**Objetivo de la Fase 5:** Proveer las herramientas equivalentes a `huawei_config_packer.py` y `huawei_sip_manager.py` adaptadas al formato de contenedor de Nokia (`0x00123123`), así como una herramienta de verificación de conectividad de red para asegurar que el servidor Asterisk pueda comunicarse con el servidor IMS de Telmex sin colisiones de registro.

---

### 🔹 `MF-5.1a`: `check_ont_voice_state(opener, ip)` — ✅ Completada (2026-11-20)
- **Descripción:** Consulta `voice_info.cgi` en el módem Nokia y evalúa si el cliente SIP interno de la ONT está activo (`Enabled` / `Registered`) o inactivo (`Disabled`).
- **Propósito práctico:**
  - Si la línea ya reporta `Status: 'Disabled'` (como observamos actualmente en tu Nokia `G-1425G-H`), informa al usuario que **el cliente SIP interno de la ONT ya se encuentra inactivo**, por lo que no hay colisión de registro activa desde el módem.
  - Si la línea reporta `Status: 'Enabled'`, indica qué perfil y línea están activos para proceder a su desactivación.
- **Entrada:** Sesión HTTP autenticada (`opener`) e IP.
- **Salida:** Diccionario de diagnóstico `{ "is_active": bool, "lines": [...], "user_agent_ip": str }`.

---

### 🔹 `MF-5.1b`: `build_cfg_header_and_crc(payload_bytes, uncompressed_len, fw_magic)` — ✅ Completada (2026-11-20)
- **Descripción:** Construye y valida la cabecera binaria de 20 bytes (o 40 bytes en variante extendida) del formato `config.cfg` de Nokia/Alcatel-Lucent.
- **Cálculos que realiza:**
  - `magic`: `0x00123123` (`uint32` little-endian).
  - `compressed_size`: `len(payload_bytes)` (`uint32` little-endian).
  - `crc32`: `binascii.crc32(payload_bytes) & 0xFFFFFFFF` (`uint32` little-endian).
  - `uncompressed_size_plus_1`: `uncompressed_len + 1` (`uint32` little-endian).
  - `fw_magic`: `0xfffffffe` (o el valor conservado de la plantilla original).
- **Entrada:** `payload_bytes`, longitud original del XML `uncompressed_len` y `fw_magic`.
- **Salida:** Cabecera binaria de 20 bytes verificada.
- **Resultado:** Implementada en `nokia_config_packer.py`; reconstruye bit a bit el header real de `output/nokia_backup_raw.cfg` (`23 31 12 00 36 19 02 00 4f 70 f0 9b 74 a2 13 00 fe ff ff ff`) a partir de su payload + `uncompressed_len=1286771` + `fw_magic=0xfffffffe`. Detalle completo en `07_fase5_empaquetador_y_sip_manager.md`.

---

### 🔹 `MF-5.2a`: `pack_nokia_configuration(xml_path, output_cfg_path, cipher_hook=None)` — ✅ Completada (2026-11-20)
- **Descripción:** Módulo empaquetador (`nokia_config_packer.py`, equivalente a `huawei_config_packer.py`). Comprime un archivo XML de configuración con `zlib`, aplica el hook de cifrado correspondiente (si se proporciona clave de dispositivo o formato estándar), antepone la cabecera de 20 bytes con `MF-5.1b` y verifica con `verify_nokia_pack()` que el `CRC32` y los tamaños coincidan bit a bit.
- **Resultado:** Round-trip 100% verificado: XML de prueba empaquetado, validado con `verify_nokia_pack()` y recuperado byte-idéntico al descomprimir con `unpack_and_decrypt_config()` de `nokia_backup.py` (modo `zlib-directo`). `verify_nokia_pack()` detecta corrupción de 1 bit tanto en el payload como en cada campo del header. 10/10 pruebas en `tests/test_nokia_packer.py`. Detalle completo en `07_fase5_empaquetador_y_sip_manager.md`.
- **Entrada:** Ruta al XML (`xml_path`), ruta de salida (`output_cfg_path`) y función/clave de cifrado opcional.
- **Salida:** Archivo `.cfg` empaquetado y verificado.

---

### 🔹 `MF-5.2b`: `toggle_xml_sip_state(input_xml_path, output_xml_path, enable=False)` — ✅ Completada (2026-11-20)
- **Descripción:** Recorre el árbol XML de configuración y modifica de forma limpia el estado (`"Enabled"` o `"Disabled"`) únicamente en las instancias de voz (`VoiceProfile`/`VoiceProfileInstance`/`Line`/`LineInstance`), conservando intacto el resto de la configuración del router (`WANPPPConnection`, WLAN, cuentas web, etc.). Soporta ambos esquemas Nokia/TR-104: por atributo (`Enable`/`Status` en el propio nodo) y por sub-elemento (`<Enable>`/`<Status>` como hijo directo).
- **Resultado:** Round-trip `Disabled <-> Enabled` verificado con `parse_xml_voice_profile()` (`MF-4.1b`) sobre ambos esquemas sintéticos, sin alterar `AuthUserName`/`AuthPassword`/`URI`/`WANPPPConnection`. `ValueError` si el XML no trae nodos de voz. Integrado con `pack_nokia_configuration()` (`MF-5.2a`) y verificado con `verify_nokia_pack()`. 10/10 pruebas en `tests/test_sip_manager.py`. CLI offline: `nokia_sip_manager.py --disable/--enable --xml ... -o ...`. Detalle completo en `07_fase5_empaquetador_y_sip_manager.md`.
- **Entrada:** Archivo XML de entrada, ruta XML de salida y bandera booleana `enable`.
- **Salida:** Archivo XML modificado y conteo de nodos actualizados (`voice_profiles_modified`, `lines_modified`, `target_state`, `output_xml_path`).

---

### 🔹 `MF-5.2c`: `upload_nokia_configuration(opener, ip, cfg_path, serial_number=None)` — ✅ Completada (2026-11-20)
- **Descripción:** Implementa el cliente de restauración controlada de configuración hacia el endpoint oficial `POST /usb.cgi?import` (o `/usb.cgi?v=import&sl_num=<serial>`), construyendo la petición `multipart/form-data` con el campo `filename` y el `csrf_token` obtenido previamente de `GET /usb.cgi?backup`.
- **Medidas de seguridad:**
  - Verifica primero con `verify_nokia_pack()` que el archivo `.cfg` tenga un encabezado `0x00123123` válido y un `CRC32` íntegro antes de permitir cualquier envío por red (`FileNotFoundError`/`ValueError` abortan antes de abrir sesión o tocar la red).
  - Si se pasa `serial_number`, valida el formato `isvalidSerialNum` del JS Nokia (12 alfanuméricos, prefijo `ALCL`) antes de la red.
  - Solo se ejecuta desde el CLI si el usuario pasa explícitamente la bandera `--apply`.
- **Entrada:** Sesión autenticada (o `opener=None` para que la función la abra y cierre ella misma), IP, ruta del archivo `.cfg` validado y número de serie opcional.
- **Salida:** `{"status", "endpoint", "cfg_size", "crc32", "import_completed", "response_preview", "_session"}`.
- **Resultado:** Implementada en `nokia_sip_manager.py`; 13/13 pruebas en `tests/test_sip_manager.py`
  con `MockOpener` en memoria (sin red real). Detalle completo en
  `07_fase5_empaquetador_y_sip_manager.md`.

---

### 🔹 `MF-5.3a`: `verify_ims_network_reachability(opener, ip, registrar_host, proxy_host)` — ✅ Completada (2026-11-20)
- **Descripción:** Verifica los requisitos de red necesarios para que un servidor Asterisk en la LAN pueda registrarse exitosamente en la plataforma IMS de Telmex a través de la ONT Nokia:
  1. Comprueba el estado de la interfaz WAN `VLAN 881` (`1_VOIP_TR069_INTERNET_OTHER_R_VID_881`) y su dirección IP/DNS (`189.233.12.5`, `189.233.15.2`).
  2. Verifica en `nat_glb.cgi?v=alg` si el **SIP ALG** del router está activo o inactivo (para orientar al administrador sobre cómo evitar que el NAT del módem reescriba erróneamente las cabeceras SIP de Asterisk).
  3. Verifica la resolución DNS y alcanzabilidad del `OutboundProxy` y `RegistrarServer` de Telmex.
- **Entrada:** Sesión autenticada, IP de la ONT y nombres de host IMS.
- **Salida:** Diagnóstico paso a paso en consola y en `output/asterisk_network_checklist.md`.
- **Resultado:** implementada en `nokia_sip_manager.py` (CLI `--check-network`/`--out`), solo lectura, `logout` garantizado en `finally`. Prueba real: WAN VLAN 881 Connected (DNS `189.233.12.5`/`189.233.15.2`, VOIP ok), cliente SIP ONT `Disabled`, **`SIPEnable=1` detectado** en `alg_obj` → recomendación de desmarcar "SIP" en *Security → DMZ and ALG*; `logout_status=200`. 15/15 pruebas en `tests/test_sip_manager.py` (incl. `SIPEnable:1` y `SIPEnable:0` con mock en memoria). **Con esto la Fase 5 queda completada.** Detalle en `07_fase5_empaquetador_y_sip_manager.md`.

---

## 📦 Entregables de Código que Producirán las Fases 4 y 5

Al completar estas microfunciones, el repositorio contará con la suite equivalente a la de Huawei pero diseñada para **Nokia `G-1425G-H`**:

1. **`nokia_g1425gh_extractor.py`**: Script principal CLI (integra `nokia_auth.py`, `nokia_backup.py`, `MF-4.1a`, `MF-4.1b`, `MF-4.2a`, `MF-4.2b`, `MF-4.3a`, `MF-4.3b`).
2. **`nokia_config_packer.py`**: Empaquetador y verificador de contenedores `.cfg` (`MF-5.1b`, `MF-5.2a`).
3. **`nokia_sip_manager.py`**: Gestor del estado VoIP SIP y verificador de red para Asterisk (`MF-5.1a`, `MF-5.2b`, `MF-5.2c`, `MF-5.3a`).
