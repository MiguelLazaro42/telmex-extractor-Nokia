# 🏗️ Fase 5 — Empaquetador de Configuración, Gestor de Estado SIP y Verificación de Red

> Documentación de avance de la **Fase 5** (`MF-5.1a`..`MF-5.3a`), equivalente funcional de
> `huawei_config_packer.py` + `huawei_sip_manager.py` adaptada al formato de contenedor
> propietario Alcatel-Lucent/Nokia (`config.cfg`, magic `0x00123123`). Ver el plan original
> en `05_plan_detallado_fases_4_y_5.md` y el diagnóstico forense del contenedor en
> `04_fase3_extraccion_y_criptografia.md` (`analyze_container_format()` / `unpack_and_decrypt_config()`
> en `nokia_backup.py`).

---

## ✅ MF-5.1b — `build_cfg_header_and_crc(payload_bytes, uncompressed_len, fw_magic, magic, extended_40b)`

**Estado:** ✅ Completada — `nokia_config_packer.py`

### Descripción
Constructor puro (sin I/O) de la cabecera binaria del contenedor `config.cfg` de
Nokia/Alcatel-Lucent. Replica exactamente el formato identificado en `MF-3.2`
(`analyze_container_format()`): 5 campos `uint32` little-endian empaquetados con
`struct.pack("<5I", ...)`, o su variante extendida de 40 bytes (`<10I`, cada campo
seguido de un `uint32` en cero) usada por la variante *new* del contenedor
(`magic 0x00124126`).

### Cálculos
| Campo | Fórmula | Offset (header 20B) |
| :--- | :--- | :--- |
| `magic` | `0x00123123` (legacy) por defecto, o `0x00124126` (new) | `0x00` |
| `compressed_size` | `len(payload_bytes)` | `0x04` |
| `crc32` | `binascii.crc32(payload_bytes) & 0xFFFFFFFF` | `0x08` |
| `uncompressed_size_plus_1` | `uncompressed_len + 1` | `0x0C` |
| `fw_magic` | `0xFFFFFFFE` por defecto (observado en el backup real), o preservado de la plantilla | `0x10` |

El **CRC32 y `compressed_size` se calculan sobre `payload_bytes`**, es decir, sobre los
bytes **finales** que seguirán a la cabecera en el archivo — ya sea el stream `zlib` puro
(modo estándar Nokia) o el resultado de aplicar un `cipher_hook` externo si en el futuro se
recupera la clave de cifrado del dispositivo (ver `MF-3.3`, bloqueada por clave derivada en
firmware). Esto es deliberado: el firmware del router valida el `CRC32` **del contenido
exactamente como está en el archivo**, sin importar si ese contenido está cifrado o no.

### Firma
```python
def build_cfg_header_and_crc(payload_bytes, uncompressed_len,
                              fw_magic=0xFFFFFFFE, magic=0x00123123,
                              extended_40b=False) -> tuple[bytes, dict]:
    ...
```

### Validación — reconstrucción bit a bit del header real
Usando el payload exacto de `output/nokia_backup_raw.cfg` (bytes `[20:]`, 137 526 B) y
`uncompressed_len=1286771`, `fw_magic=0xfffffffe`:

```
Header real del archivo:      23 31 12 00 36 19 02 00 4f 70 f0 9b 74 a2 13 00 fe ff ff ff
Header reconstruido (MF-5.1b): 23 31 12 00 36 19 02 00 4f 70 f0 9b 74 a2 13 00 fe ff ff ff
```

**Coincidencia exacta** (`assertEqual` byte a byte, `tests/test_nokia_packer.py::
TestRealBackupVerification::test_build_cfg_header_and_crc_reconstructs_real_header_bit_for_bit`),
confirmando:
- `magic = 0x00123123` ✅
- `compressed_size = 137526` ✅
- `crc32 = 0x9bf0704f` ✅ (coincide con el CRC32 validado en `MF-3.2`)
- `uncompressed_size_plus_1 = 1286772` (⇒ XML objetivo de `1286771` B) ✅
- `fw_magic = 0xfffffffe` ✅

También se validó la variante extendida de 40 bytes (`extended_40b=True`), confirmando el
intercalado correcto de los `uint32` en cero entre cada campo real.

---

## ✅ `verify_nokia_pack(cfg_path_or_bytes)` — verificación de integridad standalone

**Estado:** ✅ Completada — `nokia_config_packer.py` (soporte directo para `MF-5.2a` y para
la futura `MF-5.2c: upload_nokia_configuration()`)

### Descripción
Reutiliza `analyze_container_format()` de `nokia_backup.py` (sin duplicar el parseo del
header) para:
1. Confirmar que el `magic` es conocido (`0x00123123` legacy o `0x00124126` new).
2. Confirmar que `compressed_size` del header coincide con `len(payload)` real del archivo.
3. Recalcular `binascii.crc32(payload) & 0xFFFFFFFF` y compararlo contra el campo `crc32`
   del header.

Acepta tanto una ruta (`str`/`Path`) como `bytes` crudos ya en memoria. Si cualquiera de las
tres validaciones falla, **lanza `ValueError`** con el detalle exacto (en vez de devolver un
booleano silencioso), para que un flujo de restauración (`MF-5.2c`) nunca suba al router un
`.cfg` corrupto. Si todo es correcto, devuelve el diccionario de diagnóstico completo de
`analyze_container_format()` con `crc32_ok=True` añadido.

### Validación
- ✅ Verifica exitosamente el backup real (`output/nokia_backup_raw.cfg`): magic
  `0x00123123`, `compressed_size=137526`, `CRC32=0x9bf0704f` — **OK**.
- ✅ Detecta corrupción de **1 bit** tanto en el payload como en cualquiera de los campos
  de la cabecera (`compressed_size`, `crc32`) — lanza `ValueError` en los tres casos
  (`tests/test_nokia_packer.py::TestCorruptionDetection`).

---

## ✅ MF-5.2a — `pack_nokia_configuration(xml_path, output_cfg_path, template_raw_path=None, cipher_hook=None, compresslevel=9)`

**Estado:** ✅ Completada — `nokia_config_packer.py` (equivalente a `pack_ctree()` de
`huawei_config_packer.py`)

### Descripción
Empaquetador de alto nivel que convierte un XML de configuración plano (p.ej. el resultado
de `toggle_xml_sip_state()` en `MF-5.2b`, pendiente) en un contenedor `.cfg` listo para
restaurar al router Nokia, en el **mismo formato y orden de campos** que el backup real
descargado en `MF-3.1`.

### Flujo
1. Lee `xml_path` en UTF-8 → `xml_bytes`; `uncompressed_len = len(xml_bytes)`.
2. Si se pasa `template_raw_path` (un `.cfg` real del propio router) y existe, lee sus
   primeros 20 bytes y **preserva exactamente** su `magic` y `fw_magic` originales —
   evitando adivinar o hardcodear valores que pudieran variar por modelo/firmware.
3. Comprime `xml_bytes` con `zlib.compress(xml_bytes, compresslevel)` (nivel 9 por defecto).
4. Si se pasa `cipher_hook` (`callable(compressed_bytes) -> encrypted_bytes`), lo aplica
   para producir `payload_bytes` — punto de extensión para cuando se recupere la clave de
   cifrado del dispositivo (`MF-3.3`, hoy bloqueada). Si `cipher_hook=None`, `payload_bytes
   = compressed_bytes` (**modo zlib estándar sin cifrar**, el mismo que acepta
   `unpack_and_decrypt_config()` en su intento 1 — `zlib-directo`).
5. Construye la cabecera de 20 bytes con `build_cfg_header_and_crc()` (`MF-5.1b`).
6. Escribe `header + payload_bytes` en `output_cfg_path` y ejecuta `verify_nokia_pack()`
   sobre el archivo recién escrito **antes de retornar**, garantizando que nunca se deja en
   disco un `.cfg` con CRC32 inconsistente.

### Firma
```python
def pack_nokia_configuration(xml_path, output_cfg_path,
                              template_raw_path=None, cipher_hook=None,
                              compresslevel=9) -> dict:
    ...
```

### Validación — round-trip 100%
`tests/test_nokia_packer.py::TestPackRoundTrip`:
1. Se empaqueta un XML de prueba (nodo `VoiceProfile`/`Line`/`SIP` sintético) con
   `pack_nokia_configuration()` en modo zlib estándar.
2. `verify_nokia_pack()` sobre el `.cfg` resultante → **OK** (CRC32 y `compressed_size`
   válidos).
3. Se descomprime con `unpack_and_decrypt_config()` de `nokia_backup.py` (intento 1,
   `zlib-directo`, el mismo camino que usaría el firmware real) → **el XML recuperado es
   byte-idéntico al original** (`assertEqual(recovered, xml_bytes)`), y
   `xml_len_matches_header=True` (el tamaño descomprimido coincide con
   `uncompressed_size_plus_1 - 1` del header).
4. Se probó también con un `cipher_hook` sintético (XOR) para confirmar que el CRC32/
   `compressed_size` se calculan sobre el payload **posterior** al hook, no sobre el
   `zlib.compress()` crudo.

### CLI (homologado con `huawei_config_packer.py`)
```bash
# Empaquetar un XML en un .cfg nuevo
python3 nokia_config_packer.py <xml_file> -o <output.cfg> -t <template_backup_real.cfg>

# Solo verificar un .cfg existente (no empaqueta)
python3 nokia_config_packer.py --verify <cfg_file>
```
Probado end-to-end contra `output/nokia_backup_raw.cfg` (`--verify`) y contra un XML
sintético de prueba (empaquetado + verificación automática post-escritura).

---

## ✅ MF-5.1a — `check_ont_voice_state(opener=None, ip, user, password, x_sid=None, timeout=10)`

**Estado:** ✅ Completada (2026-11-20) — `nokia_sip_manager.py`

### Descripción
Diagnóstico de **solo lectura** del cliente SIP interno de la ONT vía `voice_info.cgi`.
Reutiliza `_get_text` y `_parse_voice_info` de `nokia_g1425gh_extractor.py` y `nokia_auth.py`.
Si `opener is None` abre su propia sesión (`authenticate_nokia`) y la cierra siempre con
`logout_nokia()` en un bloque `finally`; si recibe un `opener`, no toca su ciclo de vida.

Se considera **activo** si `LineStatus` ∈ `("Enabled", "Up", "Registered", "1")`; `"Disabled"`
(u otro valor) se reporta como inactivo.

### Salida
```python
{"ip", "is_active", "line_status", "ph_number", "proxy_ip", "user_agent_ip",
 "reg_error_code", "reg_error_reason", "summary_message",
 "_session": {"self_managed": bool, "logout_status": int|None}}
```

### CLI
```bash
python3 nokia_sip_manager.py --status -p sf3h5zkdtA
```

### Validación real (contra http://192.168.99.254)
`is_active=false`, `line_status="Disabled"`, `user_agent_ip=189.238.92.11`,
`reg_error_code="0"`, `ph_number`/`proxy_ip`/`reg_error_reason` = `null`;
`_session = {"self_managed": true, "logout_status": 200}` ✅. Conclusión: el cliente SIP
interno de la ONT ya está inactivo; no hay colisión de registro con Asterisk.

---

## ✅ MF-5.2b — `toggle_xml_sip_state(input_xml_path, output_xml_path, enable=False)`

**Estado:** ✅ Completada (2026-11-20) — `nokia_sip_manager.py`

### Descripción
Edición **offline** (sin tocar la red ni el router) del estado SIP en un XML de
configuración Nokia/TR-104: equivalente a `modify_sip_state()` de
`huawei_sip_manager.py`, pero tolerante a los **dos esquemas** que usa el firmware
Nokia (los mismos que reconoce `parse_xml_voice_profile()` / `MF-4.1b` en
`nokia_g1425gh_extractor.py`):

- **Esquema por atributos** (`VoiceProfileInstance` / `LineInstance`): el estado
  vive en el propio atributo `Enable` (o `Status` si el nodo solo trae ese) del
  nodo de voz; se sobrescribe ese atributo directamente.
- **Esquema por sub-elementos** (`VoiceProfile` / `Line`): el estado vive en un
  hijo directo `<Enable>...</Enable>` o `<Status>...</Status>`; se sobrescribe
  el `.text` de ese hijo (y se sincroniza el atributo homónimo si el nodo
  también lo tuviera, por si el XML mezcla ambos esquemas).

Recorre **todos** los nodos cuyo nombre local (sin namespace, insensible a
mayúsculas) sea `VoiceProfile`, `VoiceProfileInstance`, `Line` o
`LineInstance`, y no toca ningún otro nodo del árbol (`WANPPPConnection`,
`WLANConfiguration`, cuentas web, etc. quedan intactos). Si no encuentra
ningún nodo de voz, lanza `ValueError` — igual que `modify_sip_state()`.

### Firma
```python
def toggle_xml_sip_state(input_xml_path, output_xml_path,
                          enable=False) -> dict:
    ...
```

### Salida
```python
{"voice_profiles_modified": int, "lines_modified": int,
 "target_state": "Enabled"|"Disabled", "output_xml_path": str}
```

### Validación
`tests/test_sip_manager.py` (10 pruebas, todas en memoria/`tempfile`, sin red):
- `TestToggleXmlSipStateSubelementos` / `TestToggleXmlSipStateAtributos`: round-trip
  `Disabled -> Enabled` sobre ambos esquemas sintéticos, verificado reparseando el
  XML de salida con `parse_xml_voice_profile()` (`line_status` cambia correctamente
  en ambas direcciones) y confirmando que `AuthUserName`, `AuthPassword`, `URI` y el
  `WANPPPConnection`/`WANPPPConnectionInstance` **no se alteran**.
- `TestToggleXmlSipStateErrors`: `ValueError` si el XML no contiene ningún nodo
  `VoiceProfile`/`Line` (p.ej. solo `WANPPPConnectionInstance`).
- `TestIntegrationToggleAndPack`: el XML modificado por `toggle_xml_sip_state()`
  se empaqueta con `pack_nokia_configuration()` (`MF-5.2a`) y el `.cfg` resultante
  pasa `verify_nokia_pack()` (`crc32_ok=True`).

### CLI (homologado con `huawei_sip_manager.py`, modo offline)
```bash
# Desactivar SIP: edita el XML (MF-5.2b) y empaqueta el .cfg (MF-5.2a), sin subir nada
python3 nokia_sip_manager.py --disable --xml <input.xml> -o <output.cfg> [--template <backup_real.cfg>]

# Reactivar SIP
python3 nokia_sip_manager.py --enable --xml <input.xml> -o <output.cfg> [--template <backup_real.cfg>]
```
El flujo encadena `toggle_xml_sip_state()` + `pack_nokia_configuration()` en un XML
temporal que se elimina al terminar; **no sube nada al router** — eso queda para
`MF-5.2c` (`--apply`, pendiente), que además repetirá `verify_nokia_pack()` justo
antes del `POST`.

---

## ✅ MF-5.2c — `upload_nokia_configuration(opener=None, ip, cfg_path, serial_number=None, user, password, x_sid=None, timeout=30)`

**Estado:** ✅ Completada (2026-11-20) — `nokia_sip_manager.py`

### Descripción
Cliente HTTP de **restauración controlada** del contenedor `config.cfg` hacia el endpoint
oficial `POST /usb.cgi?import` (sin número de serie) o `POST /usb.cgi?v=import&sl_num=<serial>`
(con número de serie), documentado en `MF-2.3 §5b`. Es el paso final (opcional, bajo
bandera explícita) del flujo `toggle_xml_sip_state()` (MF-5.2b) → `pack_nokia_configuration()`
(MF-5.2a) → **`upload_nokia_configuration()`**.

### PASO 0 — Bloqueo de seguridad obligatorio (ANTES de abrir sesión o tocar la red)
1. `cfg_path` debe existir — si no, `FileNotFoundError` (propagado sin abrir sesión).
2. `verify_nokia_pack(cfg_path)` (`nokia_config_packer.py`) debe validar magic
   (`0x00123123`/`0x00124126`), `compressed_size` y `CRC32` del contenedor — `ValueError` si
   el archivo está corrupto (p.ej. 1 bit alterado en el payload o en cualquier campo del
   header).
3. Si se proporciona `serial_number`, debe cumplir el formato `isvalidSerialNum` del JS del
   Nokia: **12 caracteres alfanuméricos con prefijo `ALCL`** (p.ej. `ALCLB472FD24`,
   regex `^ALCL[A-Za-z0-9]{8}$`) — `ValueError` si no.

Solo cuando las tres validaciones pasan se procede a abrir sesión (si `opener is None`) o a
reutilizar la pasada por el llamador.

### Flujo (tras el PASO 0)
1. Si `opener is None`: `authenticate_nokia()` (con `logout_nokia()` garantizado en
   `finally`, incluso si el router ya no responde — p.ej. tras un reinicio posterior a un
   restore exitoso).
2. `GET /usb.cgi?backup` → `csrf_token` fresco vía `nokia_backup._extract_csrf_token(html)`
   (reutiliza el mismo parser que `download_nokia_backup()`, sin duplicar regex).
3. Construye el cuerpo `multipart/form-data` con un boundary propio (`----NokiaCfgUpload<hex>`)
   y exactamente 3 partes, en este orden:
   - `name="csrf_val"` → `""`
   - `name="csrf_token"` → `<csrf_token>`
   - `name="filename"; filename="config.cfg"` (`Content-Type: application/octet-stream`) →
     bytes crudos de `cfg_path`.
4. `POST` al endpoint correspondiente (`?import` o `?v=import&sl_num=<serial>`) con headers
   `Content-Type: multipart/form-data; boundary=<boundary>` y `Referer: .../usb.cgi?backup`.
5. Interpreta la respuesta: `"Import Completed!"` en el cuerpo ⇒ `import_completed=True`.

### Firma
```python
def upload_nokia_configuration(opener=None, ip="192.168.99.254", cfg_path=None,
                               serial_number=None, user="TELMEX", password="",
                               x_sid=None, timeout=30) -> dict:
    ...
```

### Salida
```python
{"status": int, "endpoint": str, "cfg_size": int, "crc32": str,
 "import_completed": bool, "response_preview": str,
 "_session": {"self_managed": bool, "logout_status": int|None}}
```

### CLI
```bash
# Offline (comportamiento previo, sin tocar el router):
python3 nokia_sip_manager.py --disable --xml <input.xml> -o <output.cfg>

# Offline + subida real al router (MF-5.2c), sin número de serie:
python3 nokia_sip_manager.py --disable --xml <input.xml> -o <output.cfg> --apply

# Con número de serie (endpoint ?v=import&sl_num=...):
python3 nokia_sip_manager.py --enable --xml <input.xml> -o <output.cfg> --apply --serial ALCLB472FD24
```
Sin `--apply`, el flujo sigue siendo **100% offline** — comportamiento idéntico al de
`MF-5.2b`, sin ningún cambio de conducta para quien no pase la bandera.

### Validación
`tests/test_sip_manager.py` (13 pruebas en total; 7 nuevas para `MF-5.2c`, todas con un
`MockOpener` en memoria — **nunca se envía un restore real al router**):
- `TestUploadNokiaConfigurationSecurityGate`:
  - `.cfg` inexistente → `FileNotFoundError`, `len(mock_opener.requests) == 0`.
  - `.cfg` corrupto (1 bit alterado en el payload) → `ValueError`,
    `len(mock_opener.requests) == 0`.
  - `serial_number` inválido (varios casos: prefijo erróneo, longitud corta, caracteres
    extra, cadena vacía) → `ValueError`, `len(mock_opener.requests) == 0`.
- `TestUploadNokiaConfigurationHappyPath` (con `.cfg` válido generado por
  `pack_nokia_configuration()`):
  - Sin `serial_number` → `POST /usb.cgi?import`; secuencia exacta `GET` (backup) seguida de
    `POST` (import); multipart contiene `name="csrf_val"`, `name="csrf_token"` con el token
    simulado, y `name="filename"; filename="config.cfg"` con
    `Content-Type: application/octet-stream`; `import_completed=True` al detectar
    `"Import Completed!"`.
  - Con `serial_number="ALCLB472FD24"` → `POST /usb.cgi?v=import&sl_num=ALCLB472FD24`.
  - Respuesta sin `"Import Completed!"` → `import_completed=False` (sin lanzar excepción).
  - Con `opener` externo (no `None`) → `_session.self_managed=False`,
    `logout_status=None`, y **ningún** request a `login.cgi` (no gestiona el ciclo de vida
    de una sesión que no abrió).

---

## ✅ MF-5.3a — `verify_ims_network_reachability(opener=None, ip, user, password, registrar_host, proxy_host, output_dir="output", x_sid=None, timeout=10)`

### Descripción
Checklist de red **100% de solo lectura** para que un Asterisk en la LAN pueda registrarse en el IMS de
Telmex a través del Nokia. Si `opener is None` abre su propia sesión (`authenticate_nokia()`) y garantiza
`logout_nokia()` en `finally`; si recibe `opener`, no toca su ciclo de vida (`_session.self_managed=False`).

### Consultas (mismo opener y `x_sid`)
1. **Cliente SIP interno ONT:** `check_ont_voice_state()` (MF-5.1a) → `is_active`, `line_status`, `user_agent_ip`.
2. **WAN VLAN 881:** `wan_config_glb.cgi` + `show_wan_status.cgi?ipv4` vía `_get_text` y `_parse_wan_pppoe`
   → `ConnectionStatus == "Connected"`, `ExternalIPAddress`, `DNSServers`, `VOIP` en `X_CT_COM_ServiceList`.
3. **SIP ALG:** `nat_glb.cgi?v=alg` → bloque `var alg_obj = { H323Enable:1, TFTPEnable:1, SIPEnable:1, ... };`
   (`_extract_block` + `_fields`). `sip_alg_enabled = str(alg.get("SIPEnable","")) == "1"`. Si es `True` se
   registra la recomendación de desmarcar "SIP" en *Security → DMZ and ALG* para que el NAT del Nokia no
   reescriba cabeceras SIP/SDP de Asterisk.

### Salida
`{"voice_state", "wan_state", "alg_state", "checklist_ready", "checklist_md_path", "_session"}`.
`checklist_ready` = ONT SIP inactivo ∧ WAN conectada con VOIP ∧ SIP ALG deshabilitado.
Genera `output/asterisk_network_checklist.md` con: (1) tabla de resumen de interoperabilidad (3 chequeos),
(2) DNS y ruteo (`vims-h.telmex.com` / `nir8.norte.telmex.net` son dominios internos IMS; resolver con los DNS
de la WAN `189.233.12.5` y `189.233.15.2` o usando `192.168.99.254` como DNS primario del host Asterisk),
(3) comandos de Asterisk CLI (`pjsip show registrations`, `pjsip show endpoints`, `pjsip set logger on`).

### CLI
```bash
python3 nokia_sip_manager.py --check-network -p <password> [--out output] [--ip 192.168.99.254]
```

### Validación real (contra http://192.168.99.254, solo lectura)
`python3 nokia_sip_manager.py --check-network -p sf3h5zkdtA`:
- `voice_state`: `LineStatus=Disabled`, `is_active=false`, `user_agent_ip=189.238.92.11`.
- `wan_state`: VLAN 881 `Connected`, IP `189.238.92.11`, DNS `189.233.12.5,189.233.15.2`,
  ServiceList `VOIP,TR069,INTERNET,OTHER` → `voip_service=true`.
- `alg_state`: `alg_obj` = `H323/TFTP/SIP/RTSP/L2TP/IPSEC/FTP/PPTP Enable:1` → **`SIPEnable=1` → `sip_alg_enabled=true`**
  (recomendación emitida en el checklist).
- `checklist_ready=false` (por el SIP ALG activo); `_session = {self_managed: true, logout_status: 200}`.
- `output/asterisk_network_checklist.md` generado con los datos reales.
**Acción pendiente para el administrador (no ejecutada por esta herramienta):** desmarcar "SIP" en
*Security → DMZ and ALG* del Nokia.

### Pruebas unitarias
`tests/test_sip_manager.py` (15 pruebas en total; 2 nuevas, `NetworkMockOpener` en memoria que solo admite GET):
- `SIPEnable:1` → `sip_alg_enabled=True`, `checklist_ready=False`, el `.md` contiene la recomendación
  *Security → DMZ and ALG*, DNS `189.233.12.5` y comandos `pjsip`; sin `login.cgi` ni métodos no-GET.
- `SIPEnable:0` → `sip_alg_enabled=False`, `recommendation=None`, `checklist_ready=True`, sin sección de recomendación.

---

## 🏁 Fase 5 — COMPLETADA

## Estado de la Fase 5

| Microfunción | Descripción | Estado |
| :--- | :--- | :---: |
| **`MF-5.1a`** | **`check_ont_voice_state()` — diagnóstico del cliente SIP interno vía `voice_info.cgi`** | **✅ Completada** |
| **`MF-5.1b`** | **`build_cfg_header_and_crc()` — cabecera 20/40 B + CRC32** | **✅ Completada** |
| **`MF-5.2a`** | **`pack_nokia_configuration()` / `verify_nokia_pack()` — empaquetado zlib + verificación** | **✅ Completada** |
| **`MF-5.2b`** | **`toggle_xml_sip_state()` — editar `Enable`/`Status` en `VoiceProfile`/`Line` del XML (ambos esquemas)** | **✅ Completada** |
| **`MF-5.2c`** | **`upload_nokia_configuration()` — restauración controlada vía `POST /usb.cgi?import`** | **✅ Completada** |
| **`MF-5.3a`** | **`verify_ims_network_reachability()` — checklist de red para Asterisk/IMS Telmex** | **✅ Completada** |

**Nota de seguridad:** `MF-5.2a`/`verify_nokia_pack()` dejaron listo el bloqueo previo que
exige `MF-5.2c`: ningún `.cfg` generado por `pack_nokia_configuration()` puede llegar a
`output_cfg_path` sin haber pasado `verify_nokia_pack()` primero (`ValueError` detiene el
flujo), y `upload_nokia_configuration()` **repite** esa misma verificación justo antes de
tocar la red, además de exigir la bandera explícita `--apply` en el CLI y validar el formato
de `serial_number` cuando se proporciona.
