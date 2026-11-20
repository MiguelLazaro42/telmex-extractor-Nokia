# 📞 Fase 4 — Extracción Estructurada, Reportes y Plantillas Asterisk

> **Objetivo de la Fase 4:** Consolidar los parámetros de identidad de equipo, conectividad WAN
> (PPPoE/VLAN 881), telefonía SIP (VoIP IMS Telmex), redes Wi-Fi y bitácora de sistema del Nokia
> `G-1425G-H`, tanto desde las páginas de estado web (modo en línea / lectura directa) como —en
> microfunciones posteriores— desde el árbol XML de configuración, para producir reportes
> estandarizados y plantillas de interoperabilidad hacia un servidor Asterisk (PJSIP / `chan_sip`).
>
> **Modelo objetivo:** Nokia `G-1425G-H` (OUI `E03005`, Fabricante declarado `ALCATEL-LUCENT`),
> Firmware `3TN00702IJMI00` (build `IJM.I00p01`), Hardware `3TN00990ADAA`,
> Serial GPON `ALCLB472FD24`, `ProvisioningCode=TELMEX`.
>
> **Alcance de esta entrega:** `MF-4.1a` (`collect_web_telemetry`, sesión previa) +
> `MF-4.1b` (`parse_xml_voice_profile`) + `MF-4.2a` (`parse_xml_wan_and_wlan`) +
> `MF-4.2b` (`build_unified_reports`) + `MF-4.3a` (`render_asterisk_pjsip_conf`) +
> `MF-4.3b` (`render_asterisk_sip_conf`), **todas implementadas y validadas** (XML
> sintéticos + `web_telemetry.json` real en `tests/test_xml_parsers.py`, 11/11 pruebas).
> 🏁 **Con esta entrega la Fase 4 queda completa.** Ver `05_plan_detallado_fases_4_y_5.md`.

---

## 🔹 MF-4.1a — `collect_web_telemetry(opener, ip)`

### Descripción funcional

`collect_web_telemetry()` recolecta, en **modo estrictamente de solo lectura**, la telemetría
que el propio Nokia `G-1425G-H` expone a través de sus páginas de estado CGI (sin requerir el
backup `.cfg` descargado en la Fase 3 ni ningún descifrado criptográfico). La función:

1. **Gestiona su propio ciclo de sesión** si no recibe un `opener` ya autenticado: ejecuta
   `authenticate_nokia()` (Fase 2, `nokia_auth.py`) y garantiza el cierre de sesión con
   `logout_nokia()` dentro de un bloque `finally`, de forma que **nunca** queda una sesión
   HTTP colgada en el router, incluso si alguna de las consultas falla.
2. Si recibe un `opener` ya autenticado (patrón reutilizado de `map_authenticated_endpoints`
   en Fase 2), respeta ese ciclo de vida externo y **no** hace login ni logout.
3. Consulta, en orden, siete páginas de estado CGI mediante `GET` autenticado (más una que
   exige `POST` cifrado, ver más abajo), aplica un mini-parser de literales JS embebidos en
   el HTML (`var nombre = {...}` / `var nombre = [...]`) y devuelve un diccionario Python
   estructurado `web_telemetry`.

### Endpoints consultados y datos extraídos

| Endpoint | Método | Datos extraídos |
| :--- | :--- | :--- |
| `device_status.cgi` | GET | `var dev_info` (ModelName, SerialNumber, Manufacturer, ManufacturerOUI, SoftwareVersion, HardwareVersion, ProvisioningCode, UpTime, FirstUseDate) + `var gpon_status` (Enable, Status, TXPower, RXPower, TransceiverTemperature) |
| `wan_config_glb.cgi` | GET | `var wan_conns[0].pppConns[0]`: Username PPPoE, Password (enmascarada), VLANIDMark, InterfaceMtu, `X_CT_COM_ServiceList`; además `var wlan_route` (mapa SSID ↔ interfaz `ra0..rai4`) |
| `show_wan_status.cgi?ipv4` | GET | Estado en vivo de la misma conexión PPPoE: ConnectionStatus, ExternalIPAddress, RemoteIPAddress, MACAddress, DNSServers, Uptime, PPPoEACName, LastConnectionError |
| `voice_info.cgi` | GET | `var voip_cmd` (phNumber, proxyIp, regErrorCode, regErrorReason), `var lines_config` (Status de la línea SIP), `var user_agent` (userAgentIp) |
| `wlan_config.cgi` | GET | `var wlan_config` índices 1–4 (SSIDs 2.4 GHz): SSID, BSSID, Enable, RadioEnabled, Channel, AutoChannelEnable, Standard, BeaconType, modo de autenticación/cifrado WPA, PreSharedKey (cifrada, ver nota) |
| `wlan_config.cgi?v=11ac` | GET | `var wlan_config` índices 5–10 (SSIDs 5 GHz): mismos campos que arriba |
| `lan_status.cgi?wlan` | GET | Página de resumen de interfaz local/hosts conectados (consultada por completitud del alcance solicitado; no aporta campos adicionales no cubiertos por los puntos anteriores) |
| `gpon_config.cgi` | GET | `var gpon_info` (SLID: `HexSLID` + valor hex, decodificado a ASCII cuando es imprimible) |
| `log.cgi?vlog_glb` | **POST cifrado** | Volcado de syslog en vivo — ver hallazgo específico abajo |

### Mini-parser de literales JS

El HTML servido por el `thttpd` del Nokia embebe la configuración como literales JavaScript
(`var dev_info = {...};`, `var wlan_config = {1:{...}, 2:{...}};`, etc.), no como JSON válido
(mezcla de claves con y sin comillas, valores numéricos sin comillas, comas finales). Se
implementó un extractor ad-hoc de tres piezas, sin dependencias externas:

- `_match_braces()`: balanceo de `{}`/`[]` por conteo de profundidad, para aislar el bloque
  exacto de un literal aunque contenga objetos anidados (p. ej. `psks:{1:{PreSharedKey:...}}}`
  dentro de cada SSID de `wlan_config`).
- `_extract_block()` / `_extract_indexed_object()`: ubica `var <nombre> = {`/`[` y devuelve el
  bloque balanceado completo; para objetos indexados por número (`{1:{...}, 2:{...}}`, usados
  para los SSIDs), avanza secuencialmente el cursor tras cada sub-objeto consumido para evitar
  que un índice anidado (p. ej. la clave `1` dentro de `psks:{1:{...}}`) se confunda con un
  índice de nivel superior y sobrescriba los datos reales del SSID. **Este fue el primer bug
  detectado y corregido durante la validación real** (ver más abajo).
- `_fields()`: expresión regular única que captura pares `clave:valor` (clave con o sin
  comillas, valor en comillas simples/dobles o numérico), conservando siempre la **primera**
  aparición de cada clave (que en los literales del Nokia corresponde al nivel superior del
  objeto consultado).

### Hallazgos de la ejecución real (validados contra el equipo)

1. **Bug de índices anidados en `wlan_config` (corregido).** La primera implementación de
   `_extract_indexed_object()` usaba `re.finditer()` sin avanzar el cursor, por lo que la
   clave numérica `1` dentro de `psks:{1:{PreSharedKey:'...'}}` sobrescribía el SSID #1
   completo (`SSID`, `Enable`, `Channel`, etc. quedaban en `null`, dejando solo la
   `PreSharedKey` encontrada por una búsqueda directa aparte). Se corrigió haciendo que el
   extractor saltara explícitamente todo el sub-objeto recién consumido antes de buscar el
   siguiente índice, eliminando la colisión. Verificado con los 4 SSIDs de 2.4 GHz y los 6 de
   5 GHz (incluye dos SSIDs ocultos — `SSIDAdvertisementEnabled:0` — con nombres `1YBjiShS` y
   `ykWlx2e2`, visibles en ambas bandas por sincronización 2.4G/5G del firmware).
2. **Bug de precedencia de campos ambiguos (corregido).** `wan_config_glb.cgi` declara un
   campo `Name` en dos literales distintos (`lan_ether` para los puertos Ethernet, y
   `wan_conns[].pppConns[]` para la conexión PPPoE); al tomar la primera aparición global del
   archivo, el valor recuperado era `'eth0.0'` (puerto LAN) en vez de
   `'1_VOIP_TR069_INTERNET_OTHER_R_VID_881'` (la conexión WAN real). Se corrigió dando
   prioridad a `show_wan_status.cgi?ipv4` —donde `Name` solo aparece una vez, sin ambigüedad—
   sobre `wan_config_glb.cgi` para ese campo específico.
3. **Doble envoltorio RSA+AES en `log.cgi?vlog_glb` y descifrado en texto claro de Wi-Fi (`PreSharedKey_cleartext`) resueltos en la revisión de integración:**
   - **Syslog en vivo (`log.cgi?vlog_glb`):** En `log.cgi`, el manejador `$("#logbtn").click()` cifra `"csrf_token=checkcsrf_token"` con `crypto_page.encrypt_post_data(pubkey, ...)` y lo pasa a `$.ajax({type:'POST', data: encryptdata})`. A continuación, el interceptor global `$(document).ajaxSend` verifica si `settings.data` contiene la cadena literal `"csrf_token"`; como ya viene cifrado (`"encrypted=1&ct=..."`), no la encuentra, le concatena `&csrf_token=<token_real_de_sesion>` y vuelve a aplicar `crypto_page.encrypt_post_data()`. Al replicar este doble envoltorio en `_post_encrypted()`, el router entregó las **7,432 líneas del syslog real** (`raw_available: true`, con eventos de `sbintr-MAPPER: wan_init`, `voice_init`, `cfgmgr` y `TR069`).
   - **Descifrado de claves Wi-Fi (`PreSharedKey_cleartext`):** Las páginas `wlan_config.cgi` y `wlan_config.cgi?v=11ac` cifran `PreSharedKey` con la clave efímera `enckey_b64` / `enciv_b64` que el cliente registró durante `authenticate_nokia()`. Al conectar `_parse_wlan_config()` con `nokia_auth.aes128_cbc_decrypt_sjcl(enckey_b64, enciv_b64, psk_enc)`, **todas las contraseñas Wi-Fi de los 10 SSIDs (2.4 GHz y 5 GHz) se obtienen en texto plano**:
     - SSID `SITAI` (2.4 GHz y 5 GHz): **`Sitai10925`**
     - SSIDs `INFINITUMFD24_2`, `_3`, `_4`: **`sf3h5zkdtA`**
     - SSID oculto `1YBjiShS` (backhaul/mesh 2.4 GHz): **`LoesmX4T`**
     - SSID oculto `ykWlx2e2` (backhaul/mesh 5 GHz): **`WjmgDGZb`**

### Datos relevantes recolectados en la prueba real (2026-11-20)

- **Identidad de equipo:** `G-1425G-H`, `ALCATEL-LUCENT`/`E03005`, SN `ALCLB472FD24`,
  SW `3TN00702IJMI00`, HW `3TN00990ADAA`, `ProvisioningCode=TELMEX`, GPON `Status=Up`.
- **WAN PPPoE (VLAN 881):** `Name=1_VOIP_TR069_INTERNET_OTHER_R_VID_881`,
  `Username=E03005LALCLB472FD24@prodigyweb.com.mx`, `Password` **enmascarada**
  (`!!!@@@###$$$^^^&&&***`, no es la contraseña real — confirma el hallazgo de Fase 3.5),
  `ConnectionStatus=Connected`, `ExternalIPAddress=189.238.92.11`,
  `DNSServers=189.233.12.5,189.233.15.2`, `InterfaceMtu=1492`,
  `X_CT_COM_ServiceList=VOIP,TR069,INTERNET,OTHER`, `MACAddress=e0:3d:a6:d0:bd:54`.
- **Telefonía (`voice_info.cgi`):** `LineStatus=Disabled` (cliente SIP interno de la ONT
  inactivo, confirma MF-2.3), sin `phNumber`/`proxyIp` (línea sin aprovisionar vía CGI),
  `userAgentIp=189.238.92.11` (misma IP pública WAN).
- **Wi-Fi:** 4 SSIDs en 2.4 GHz (`SITAI` activo, canal 6, WPA2-PSK/AES) y 6 SSIDs en 5 GHz
  (`SITAI` activo, canal 100, WPA2-PSK/AES, 80 MHz), más 2 SSIDs ocultos sincronizados entre
  bandas. **Todas las `PreSharedKey` viajan cifradas** con AES propio de sesión del router
  (`crypto_page.aes_decrypt(session_id, ...)`, una clave efímera ligada al `localStorage` del
  navegador, **no** la clave RSA de login) — se reportan como `PreSharedKey_encrypted_b64` con
  nota explícita; **no** se intenta ni se simula su descifrado en esta microfunción.
- **GPON:** SLID `44454641554C54` (hex) → decodificado a ASCII = `DEFAULT` (valor de fábrica,
  no es la credencial SIP ni PPPoE).
- **Syslog:** no disponible por la razón documentada arriba (hallazgo #3).

### Prueba real ejecutada

```
$ .venv/bin/python3 nokia_g1425gh_extractor.py telemetry
MF-4.1a collect_web_telemetry() -> output/web_telemetry.json
logout status: 200
```

- **Objetivo:** `http://192.168.99.254` (usuario `TELMEX`).
- **Ciclo de sesión:** login (`authenticate_nokia`, HTTP 299 + `X-SID`) → 9 consultas de
  solo lectura → `logout_nokia()` (`GET /login.cgi?out`) → **`200`** confirmado.
- **Salida:** `output/web_telemetry.json` (10 841 bytes),
  SHA-256 `4167702a074d1c1f3e336fd161cbc541bf5e998e52044c73e7e09de153fe22e5`.
- **Endpoints — todos `HTTP 200`:** `device_status.cgi`, `wan_config_glb.cgi`,
  `show_wan_status.cgi?ipv4`, `voice_info.cgi`, `wlan_config.cgi`, `wlan_config.cgi?v=11ac`,
  `lan_status.cgi?wlan`, `gpon_config.cgi`, `log.cgi?vlog_glb` (200 con cuerpo de error
  aplicativo, ver hallazgo #3 — no es un fallo de transporte).
- **Ninguna petición de escritura** (`?set`, `?config`, `?import`) fue enviada en ningún
  momento de esta prueba.

### Entregable de código

- **Archivo:** `nokia_g1425gh_extractor.py` (nuevo módulo, importa `nokia_auth.py` de Fase 2
  sin duplicar su lógica de autenticación/cifrado).
- **Función pública:** `collect_web_telemetry(opener=None, ip="192.168.99.254", user="TELMEX", password="", x_sid=None, timeout=10)`.
- **CLI:** `python3 nokia_g1425gh_extractor.py telemetry` — ejecuta el ciclo completo con las
  credenciales de Telmex, guarda `output/web_telemetry.json` e imprime el estado de logout.

### Estructura de salida `web_telemetry`

```
web_telemetry = {
    "ip": "192.168.99.254",
    "device_info": { ModelName, SerialNumber, Manufacturer, ManufacturerOUI,
                      SoftwareVersion, HardwareVersion, ProvisioningCode,
                      UpTime_seconds, FirstUseDate, gpon_status{...} },
    "wan_pppoe": { Name, VLANIDMark, Username, Password_masked, ConnectionStatus,
                   ExternalIPAddress, RemoteIPAddress, DNSServers, InterfaceMtu,
                   X_CT_COM_ServiceList, MACAddress, Uptime_seconds, ... },
    "voice_telemetry": { LineStatus, phNumber, proxyIp, regErrorCode,
                          regErrorReason, userAgentIp },
    "wlan_info": { "2.4GHz": [...SSIDs...], "5GHz": [...SSIDs...],
                   "interface_map": [...SSID<->interfaz ra*/rai*...] },
    "gpon_info": { HexSLID_flag, SLID_hex, SLID_ascii_decoded },
    "system_log_summary": { raw_available, total_lines, relevant_lines, note? },
    "_endpoints": { "<cgi>": <http_status>, ... },   # diagnostico por endpoint
    "_session": { self_managed, logout_status },     # auditoria del ciclo de sesion
}
```

### Estado

✅ **MF-4.1a completada** (código implementado, bug de índices anidados y de precedencia de
campo corregidos tras la primera ejecución real, prueba contra el equipo real ejecutada y
verificada, sesión cerrada limpiamente con `logout=200`).

---

## 🔹 MF-4.1b — `parse_xml_voice_profile(xml_text)`

### Descripción funcional

Analiza, de forma **completamente offline** (no abre sesión HTTP ni toca el router), un
árbol XML de configuración Nokia/Alcatel-Lucent (TR-098 / TR-104
`InternetGatewayDevice.Services.VoiceService`) para extraer las credenciales y parámetros
de registro SIP IMS. Diseñada para recibir el XML descomprimido del backup `.cfg` (Fase 5,
cuando se resuelva la clave de cifrado) o un archivo pasado manualmente vía `--xml`.

**Tolerancia a dos esquemas Nokia/TR-098 distintos**, resuelta con helpers XML genéricos
compartidos con `MF-4.2a` (`_local_tag`, `_elem_fields`, `_iter_by_tag`, `_pick`):

1. **Esquema jerárquico por sub-elementos XML:** `<SIP><ProxyServer>x</ProxyServer></SIP>`.
2. **Esquema de atributos TR-098/TR-104:** `<SIP ProxyServer="x" .../>`, incluyendo nodos ya
   aplanados `VoiceProfileInstance` / `LineInstance` (vistos en algunos volcados de
   configuración junto a los nombres canónicos `VoiceProfile` / `Line`).

`_elem_fields(elem)` combina en un solo diccionario los atributos del propio nodo y el
texto de sus hijos directos (los atributos tienen prioridad si ambos declaran la misma
clave), de modo que el resto de la lógica de extracción es agnóstica al esquema. Para
distinguir un `<SIP>` a nivel de `VoiceProfile` de un `<SIP>` anidado dentro de una
`<Line>` (misma etiqueta local, significado distinto) se construye un mapa de padres
(`parent_map`) y se recorren los ancestros de cada nodo `SIP` encontrado.

### Campos extraídos

- **Nivel perfil:** `proxy_server`, `proxy_server_port` (default `5060`),
  `registrar_server` (default `vims-h.telmex.com`), `registrar_server_port` (default
  `5060`), `outbound_proxy` (acepta `OutboundProxy` u `OutBoundProxyServer`, default
  `nir8.norte.telmex.net`), `outbound_proxy_port` (default `5060`), `user_agent_domain`.
- **`lines`:** lista de diccionarios por cada `<Line>`/`<LineInstance>` encontrada:
  `instance_id`, `enable` (acepta `Enable` o `Status`), `directory_number`, `uri`,
  `auth_username`, `auth_password`.
- **Campos planos de compatibilidad con `credentials.json`** (de la línea principal, la
  primera detectada), expuestos también en el nivel raíz de `sip_voip`: `auth_username`,
  `auth_password`, `uri`, `directory_number`, `registrar_server`, `outbound_proxy`,
  `proxy_server`, `port` (alias de `proxy_server_port`), `line_status`.
- Si `xml_text` es `None` o cadena vacía, devuelve únicamente los valores por defecto
  (incluido `registrar_server`/`outbound_proxy` fijos del operador), con los campos de
  línea marcados como `"Pendiente / No disponible en XML"`.

### Estado

✅ **MF-4.1b completada.** Validada al 100% contra dos XML sintéticos (esquema por
elementos y esquema por atributos TR-098/TR-104 con nodos aplanados) en
`tests/test_xml_parsers.py`: 20+ aserciones por esquema, todas `OK`. **No se ejecutó
contra el router** (sigue bloqueado el descifrado del `.cfg`, ver Fase 3/3.5); la función
es puramente un parser de cadenas XML en memoria, sin dependencia de red.

---

## 🔹 MF-4.2a — `parse_xml_wan_and_wlan(xml_text)`

### Descripción funcional

Extrae del mismo árbol XML de configuración los parámetros de la conexión WAN PPPoE, las
redes Wi-Fi y las cuentas de administración web locales, reutilizando los mismos helpers
XML tolerantes a ambos esquemas (sub-elementos vs. atributos) que `MF-4.1b`.

### Nodos y campos procesados

- **`WANPPPConnection` / `WANPPPConnectionInstance` → `pppoe`:** `username`, `password`,
  `vlan_id` (acepta `X_ALU-COM_VLANID`, `VLANIDMark`, `X_HW_VLAN`, `X_CT-COM_VLANID`,
  default `881`), `mtu` (acepta `MaxMRUSize` o `InterfaceMtu`, default `1492`),
  `service_list` (acepta `X_CT-COM_ServiceList` o `X_HW_SERVICELIST`), `connection_type`,
  `nat_enabled`.
- **`WLANConfiguration` / `WLANConfigurationInstance` → `wifi_networks`:** lista de
  diccionarios con `ssid_index`, `ssid`, `psk` (acepta `PreSharedKey` o `KeyPassphrase`),
  `enable`, `standard`.
- **`UserInterface` / `X_ALU_COM_UserAccount` / `Account` / `User` /
  `X_HW_WebUserInfoInstance` → `web_admin`:** lista de cuentas locales con `username`,
  `password`, `level` (acepta `X_HW_UserLevel`, `Role`, `Level` o `AccessLevel`). Se
  descartan nodos homónimos sin ninguno de estos tres datos (evita falsos positivos de
  nombres de etiqueta reutilizados en otras secciones del árbol).
- Si `xml_text` es `None` o cadena vacía, devuelve `pppoe` con los valores por defecto
  (`vlan_id=881`, `mtu=1492`, resto `"Pendiente / No disponible en XML"`) y
  `wifi_networks`/`web_admin` como listas vacías.

### Estado

✅ **MF-4.2a completada.** Validada al 100% contra los mismos dos XML sintéticos
(elementos y atributos) en `tests/test_xml_parsers.py`: `pppoe` completo, 2 SSIDs (2.4/5
GHz, `PreSharedKey`/`KeyPassphrase`) y 2 cuentas de administración (`admin`/`TELMEX`)
extraídas correctamente en ambos esquemas. **No se ejecutó contra el router** (parser
offline, sin dependencia de red). **No se avanzó a `MF-4.2b`.**

### Prueba unitaria — `tests/test_xml_parsers.py`

```
$ .venv/bin/python3 -I tests/test_xml_parsers.py
...
6/6 pruebas pasaron
```

Cubre, con dos XML sintéticos TR-098/TR-104 realistas (uno por sub-elementos, otro por
atributos con nodos aplanados `VoiceProfileInstance`/`LineInstance`/
`WANPPPConnectionInstance`/`WLANConfigurationInstance`):
`test_parse_xml_voice_profile_elementos`, `test_parse_xml_voice_profile_atributos`,
`test_parse_xml_voice_profile_vacio`, `test_parse_xml_wan_and_wlan_elementos`,
`test_parse_xml_wan_and_wlan_atributos`, `test_parse_xml_wan_and_wlan_vacio`. No requiere
red ni acceso al router.

---

## 🔹 MF-4.2b — `build_unified_reports(web_telemetry, xml_data=None, output_dir="output")`

### Descripción funcional

Combina, en un único diccionario `credentials`, la telemetría web en vivo de `MF-4.1a`
(`web_telemetry`) con los datos offline del XML de configuración (`xml_data`, el dict
opcional `{"sip_voip": ..., "pppoe": ..., "wifi_networks": ..., "web_admin": ...}` que
produce la combinación de `MF-4.1b` + `MF-4.2a`), y escribe `output/credentials.json` y
`output/credentials.md` con las 4 secciones solicitadas.

**Regla de prioridad (helper `_first_real()` / `_is_placeholder()`):** para cada campo se
toma el primer valor disponible que **no** sea `None`, cadena vacía, el marcador
`"Pendiente / No disponible en XML"` (`_PENDIENTE`, de MF-4.1b/4.2a) ni la máscara fija
`!!!@@@###$$$^^^&&&***` que el firmware Nokia devuelve en lugar de contraseñas reales en
sus páginas de estado (ver hallazgo de Fase 3.5). El orden de prioridad evaluado es
`xml_data` (texto claro del backup descifrado) → `web_telemetry` (texto claro ya
descifrado en vivo, p. ej. `PreSharedKey_cleartext` de Wi-Fi) → valor por defecto del
operador (`881`, `1492`, `vims-h.telmex.com`, `nir8.norte.telmex.net`, `5060`). Si ningún
candidato es "real", se conserva el primer valor no-`None` disponible para que el reporte
siga mostrando algo útil en vez de `None` puro.

### Secciones generadas (`credentials.json` / `credentials.md`)

1. **Identidad del Equipo y Estado GPON** (`device_info`): `model_name`, `manufacturer`
   (+`manufacturer_oui`), `serial_number`, `software_version`, `hardware_version`,
   `provisioning_code`, `gpon_status`, `slid_ascii`/`slid_hex`.
2. **Conexión WAN PPPoE** (`pppoe`): `vlan_id` (VLAN 881), `username`, `password`
   (+ bandera `password_is_masked` cuando el único dato disponible es la máscara fija),
   `mtu`, `service_list`, `connection_status`, `external_ip`, `dns_servers`, `mac_address`.
3. **Telefonía Fija VoIP** (`sip_voip`): `line_status_ont` (estado del cliente SIP interno
   de la ONT, de `MF-4.1a`), `directory_number`, `uri`, `auth_username`, `auth_password`,
   `registrar_server`(+puerto), `outbound_proxy`(+puerto), `user_agent_ip`.
4. **Redes Inalámbricas Wi-Fi y Acceso Web** (`wifi_networks` + `web_admin`): por cada SSID
   (2.4/5 GHz) `band`, `ssid`, `bssid`, `channel`, `enable`, `wpa_mode` y `psk_cleartext`
   (prioriza el PSK ya descifrado en vivo por `MF-4.1a`, `aes128_cbc_decrypt_sjcl`, sobre
   el `psk` del XML); `web_admin` (cuentas de acceso web locales) proviene exclusivamente
   de `xml_data`, pues la telemetría web de solo lectura no expone esa información.

### Estado

✅ **MF-4.2b completada.** Validada con `tests/test_xml_parsers.py`
(`test_build_unified_reports_con_xml`, `test_build_unified_reports_sin_xml`): combinación
XML+web real (`WEB_TELEMETRY_FIXTURE`, recorte fiel del `web_telemetry.json` capturado en
MF-4.1a) + `XML_ELEMENTOS`/`XML_ATRIBUTOS` sintéticos, y el caso sin XML (solo telemetría
web, con `password_is_masked=True` y `sip_voip` marcado `Pendiente`). Ejecutada también en
modo real vía CLI (`--offline`, ver más abajo) contra `output/web_telemetry.json`: genera
`output/credentials.json`/`credentials.md` con las 10 redes Wi-Fi (PSK en claro), identidad
de equipo y WAN PPPoE reales, y la sección VoIP correctamente marcada `Pendiente` (no se
cuenta aún con el XML descifrado del backup, ver Fase 3/3.5).

---

## 🔹 MF-4.3a — `render_asterisk_pjsip_conf(sip_data, output_dir="output")`

### Descripción funcional

Genera `output/asterisk_pjsip_telmex.conf`, una plantilla completa para el stack moderno
`res_pjsip` de Asterisk que registra la cuenta SIP IMS de Telmex, a partir del diccionario
`sip_voip` que produce `build_unified_reports()` (o un dict equivalente pasado por el
usuario vía `--sip-user/--sip-pass/--sip-number`).

**Secciones generadas:** `[transport-udp]` (UDP `0.0.0.0:5060`); `[telmex-ims]`
(`type=registration`, `server_uri`/`client_uri` sobre el `registrar_server`,
`contact_user`=número, `outbound_proxy=sip:<proxy>:5060\;lr`, `retry_interval=60`,
`expiration=3600`); `[telmex-auth]` (`type=auth`, `auth_type=userpass`,
`username`/`password`); `[telmex-aor]` (`type=aor`, `contact`, `outbound_proxy`,
`qualify_frequency=30`); `[telmex-endpoint]` (`type=endpoint`, `context=from-telmex`,
`disallow=all`/`allow=alaw,ulaw`, `outbound_auth`/`aors`, `from_domain`/`from_user`,
opciones de NAT `direct_media=no`/`rtp_symmetric=yes`/`force_rport=yes`/
`rewrite_contact=yes`, `dtmf_mode=rfc4733`); `[telmex-identify]` (`type=identify`,
`endpoint=telmex-endpoint`, `match=<outbound_proxy>`).

**Placeholders explícitos:** si `sip_data` aún contiene los marcadores `"Pendiente / No
disponible en XML"` (número/`auth_username`/`auth_password`), la plantilla usa
`+5255XXXXXXXX` / `TU_PASSWORD_SIP_IMS` y antepone un bloque de comentarios `; ⚠️ AVISO`
indicando exactamente qué sustituir y por qué (requiere el XML descifrado del backup,
bloqueado desde Fase 3/3.5). Cuando los datos son reales, el aviso no se incluye.

### Estado

✅ **MF-4.3a completada.** Validada en `tests/test_xml_parsers.py`
(`test_render_asterisk_pjsip_conf_con_datos_reales`, `..._sin_datos`): con credenciales
reales (XML sintético) verifica las 6 secciones, `username`/`password`/`contact_user`
correctos, el `outbound_proxy=...\;lr` con el `;` escapado y la ausencia de placeholders/
aviso; sin datos, verifica la presencia de ambos placeholders y del aviso. Probada también
end-to-end vía CLI contra `output/web_telemetry.json` real (sin XML aún disponible):
`output/asterisk_pjsip_telmex.conf` generado con el aviso de "Pendiente" y los placeholders
esperados.

---

## 🔹 MF-4.3b — `render_asterisk_sip_conf(sip_data, output_dir="output")`

### Descripción funcional

Genera dos archivos complementarios para instalaciones Asterisk que usen el driver
clásico `chan_sip`, reutilizando la misma lógica de placeholders/aviso que `MF-4.3a`:

1. **`output/asterisk_sip_legacy_telmex.conf`**: `[general]` (contexto, codecs, NAT) +
   `register => <auth_username>:<auth_password>@<registrar_server>/<numero>` + el peer
   `[telmex-ims]` (`type=peer`, `host`/`outboundproxy=<outbound_proxy>`,
   `fromdomain`/`fromuser`/`username`/`secret`, `insecure=port,invite`,
   `nat=force_rport,comedia`, `dtmfmode=rfc4733`).
2. **`output/asterisk_extensions_sample.conf`**: dialplan de ejemplo con `[from-telmex]`
   (llamada entrante al número SIP real, más un fallback genérico `exten => s,1,...`) y
   `[salientes-telmex]` (patrón `_XXXXXXXXXX` para llamadas nacionales/celulares a 10
   dígitos, `Dial(PJSIP/telmex-endpoint/sip:${EXTEN}@<registrar_server>,60)`).

### Estado

✅ **MF-4.3b completada.** Validada en `tests/test_xml_parsers.py`
(`test_render_asterisk_sip_conf`): ambos archivos se escriben en disco, contienen
`[telmex-ims]`/`[from-telmex]`/`[salientes-telmex]`, la línea `register =>` y `secret=`
con las credenciales reales del XML sintético, y la variable de dialplan `${EXTEN}` se
preserva intacta (sin corromperse por el formateo de cadenas de Python). Probada también
end-to-end vía CLI contra la telemetría real.

---

## 🖥️ CLI completo (`argparse`)

`nokia_g1425gh_extractor.py` expone ahora un CLI único, homologado en estilo con
`huawei_hg8145v5_extractor.py`:

```
python3 nokia_g1425gh_extractor.py [telemetry|all] [--ip IP] [-u USER] [-p PASSWORD]
       [--xml RUTA_XML] [--sip-user U] [--sip-pass P] [--sip-number N]
       [-o OUT_DIR] [--json] [--offline]
```

- **`telemetry`** (compatible con el uso previo `python3 nokia_g1425gh_extractor.py
  telemetry`): ejecuta únicamente `MF-4.1a` y guarda `output/web_telemetry.json`.
- **`all`** (valor por defecto): ejecuta la telemetría (en vivo, o reutilizada con
  `--offline`), parsea `--xml` si se indica (`MF-4.1b`+`MF-4.2a`), aplica los overrides
  `--sip-user/--sip-pass/--sip-number` si se pasan, y genera los 5 artefactos de la Fase 4:
  `credentials.json`, `credentials.md`, `asterisk_pjsip_telmex.conf`,
  `asterisk_sip_legacy_telmex.conf` y `asterisk_extensions_sample.conf`.
- **`--offline`**: reutiliza `output/web_telemetry.json` ya existente **sin reconectar al
  router**, para poder iterar sobre los reportes/plantillas offline cuantas veces se quiera.
- La contraseña (`-p/--password`) se solicita de forma segura con `getpass.getpass()` si
  se omite en modo en línea (ya no queda hardcodeada en el script).

### Prueba real ejecutada (modo `all --offline`)

```
$ .venv/bin/python3 nokia_g1425gh_extractor.py all --offline -o output
ℹ️  --offline: reutilizando output/web_telemetry.json (sin reconectar al router).
MF-4.2b build_unified_reports()        -> output/credentials.json
                                           output/credentials.md
MF-4.3a render_asterisk_pjsip_conf()    -> output/asterisk_pjsip_telmex.conf
MF-4.3b render_asterisk_sip_conf()      -> output/asterisk_sip_legacy_telmex.conf
                                           output/asterisk_extensions_sample.conf
```

Generado contra la telemetría real de MF-4.1a (sin `--xml`, pues el backup sigue bloqueado
en Fase 3/3.5): identidad de equipo, WAN PPPoE y las 10 claves Wi-Fi en texto plano quedaron
correctas en `credentials.md`; la sección VoIP SIP quedó correctamente marcada `Pendiente`
y las plantillas Asterisk incluyeron el aviso `; ⚠️ AVISO` + placeholders
`+5255XXXXXXXX`/`TU_PASSWORD_SIP_IMS`, listos para completarse en cuanto se resuelva el
descifrado del backup. Se verificó además, con un XML sintético vía `--xml`, que al existir
credenciales SIP reales las plantillas las usan directamente y el aviso desaparece.

### Prueba unitaria (ampliación de `tests/test_xml_parsers.py`)

```
$ .venv/bin/python3 -I tests/test_xml_parsers.py
...
11/11 pruebas pasaron
```

Se agregaron 5 pruebas nuevas (`test_build_unified_reports_con_xml`,
`test_build_unified_reports_sin_xml`, `test_render_asterisk_pjsip_conf_con_datos_reales`,
`test_render_asterisk_pjsip_conf_sin_datos`, `test_render_asterisk_sip_conf`) a las 6 ya
existentes de `MF-4.1b`/`MF-4.2a`, reutilizando los mismos XML sintéticos
(`XML_ELEMENTOS`/`XML_ATRIBUTOS`) más un nuevo fixture `WEB_TELEMETRY_FIXTURE` (recorte
fiel de `web_telemetry.json`). No requiere red ni acceso al router.

---

## 🏁 Estado de la Fase 4

✅ **FASE 4 COMPLETADA.** `MF-4.1a` a `MF-4.3b` implementadas, probadas (unitariamente y
contra el equipo/telemetría real) y documentadas. Pendiente para la Fase 5: resolver el
descifrado del backup `.cfg` (bloqueado desde Fase 3/3.5) para poder alimentar `--xml` con
las credenciales SIP reales sin depender de overrides manuales (`--sip-user/--sip-pass/
--sip-number`).
