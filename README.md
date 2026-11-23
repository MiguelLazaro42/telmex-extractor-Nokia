# 📡 Nokia G-1425G-H & Huawei ONT (Telmex) — Extractor de Parámetros, Empaquetador y Gestor VoIP SIP / Asterisk

Conjunto modular de herramientas en Python (y C++ para variantes Huawei) diseñado para la interoperabilidad, diagnóstico técnico, extracción de telemetría de red, análisis de respaldos de configuración y preparación de telefonía fija **VoIP SIP (IMS Telmex)** hacia conmutadores **Asterisk PBX** (`res_pjsip` y `chan_sip`) en terminales ópticas GPON (**ONT**) distribuidas por **Telmex**:

- **Nokia / Alcatel-Lucent:** Modelo **`G-1425G-H`** (Firmware serie `3TN00702IJMI00`, chipset MediaTek `MTK7552`, servidor web `thttpd`) y variantes compatibles de la familia `G-1425G` / `G-2425G`.
- **Huawei EchoLife (legado en el repositorio):** Modelos `HG8145V5`, `HG8145V5V3`, `HG8245W5`, `EG8145`.

---

## 🏗️ Arquitectura de la Suite Nokia (`G-1425G-H`)

```
+---------------------------------------------------------------------------------------------------+
|                                   ONT NOKIA G-1425G-H (thttpd)                                    |
|  1. GET / -> Desafío dinámico: pubkey (RSA-1024), nonce (32B), csrf_token (16 chars)              |
|  2. POST /login.cgi -> Sobre híbrido RSA-1024 (PKCS#1 v1.5) + AES-128-CBC (PKCS#7, sjcl)          |
|  3. Respuesta HTTP 299 + Header X-SID + Cookies HttpOnly (sid, isAdminLoggedIn=1, lsid)           |
+---------------------------------------------------------------------------------------------------+
                                                 │
                    ┌────────────────────────────┴────────────────────────────┐
                    ▼                                                         ▼
   [ Telemetría Web CGI (Solo Lectura) ]                     [ Respaldo config.cfg (usb.cgi?export) ]
   - device_status.cgi (Modelo, SN GPON, FW)                 - Header 20B LE (magic 0x00123123 + CRC32)
   - wan_config_glb.cgi (Usuario PPPoE VLAN 881)             - Compresión zlib / contenedor de dispositivo
   - wlan_config.cgi (10 SSIDs + PSK AES-128-CBC)            - Empaquetador y verificador CRC32
   - voice_info.cgi (Estado SIP ONT)                         - Modificador XML TR-098 / TR-104
   - nat_glb.cgi?v=alg (Diagnóstico SIP ALG)
   - log.cgi?vlog_glb (Doble sobre RSA+AES -> Syslog)
                    │                                                         │
                    └────────────────────────────┬────────────────────────────┘
                                                 ▼
                         Reportes Unificados + Configuración Asterisk PBX
                         - output/credentials.json & output/credentials.md
                         - output/asterisk_pjsip_telmex.conf (res_pjsip)
                         - output/asterisk_sip_legacy_telmex.conf (chan_sip)
                         - output/asterisk_extensions_sample.conf
                         - output/asterisk_network_checklist.md
```

### Módulos Principales (Nokia)

| Archivo | Fases / Microfunciones | Descripción |
| :--- | :--- | :--- |
| [`nokia_auth.py`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/nokia_auth.py) | `MF-2.1`, `MF-2.2`, `MF-2.3` | Cliente criptográfico bit-exacto para el login híbrido **RSA-1024 + AES-128-CBC** (`JSEncrypt` + `sjcl`), manejo de estado `HTTP 299` / `X-SID`, descifrador AES de sesión (`aes128_cbc_decrypt_sjcl`), mapeo de los 43 endpoints de `menu.cgi` y cierre garantizado (`GET /login.cgi?out`). |
| [`nokia_backup.py`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/nokia_backup.py) | `MF-3.1`, `MF-3.2`, `MF-3.3` | Descarga limpia del respaldo `config.cfg` vía `POST /usb.cgi?export`, análisis estructural de la cabecera de 20 bytes (`magic 0x00123123`, `compressed_size`, `CRC32`, `uncompressed_size + 1`, `fw_magic`) y cadena de desempaquetado. |
| [`nokia_g1425gh_extractor.py`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/nokia_g1425gh_extractor.py) | `MF-4.1a` .. `MF-4.3b` | Extractor principal: recolecta telemetría web en vivo, descifra todas las contraseñas Wi-Fi (`PreSharedKey`) en texto plano con la clave AES de sesión, descarga el syslog mediante doble envoltorio RSA+AES, parsea árboles XML TR-098/TR-104 y genera los reportes y plantillas para **Asterisk**. |
| [`nokia_config_packer.py`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/nokia_config_packer.py) | `MF-5.1b`, `MF-5.2a` | Constructor de cabecera binaria de 20/40 bytes (`build_cfg_header_and_crc`), compresor `zlib` (`pack_nokia_configuration`) y verificador de integridad `CRC32` (`verify_nokia_pack`). |
| [`nokia_sip_manager.py`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/nokia_sip_manager.py) | `MF-5.1a`, `MF-5.2b`, `MF-5.2c`, `MF-5.3a` | Diagnóstico en vivo del cliente SIP interno de la ONT (`--status`), diagnóstico de red y **SIP ALG** para Asterisk (`--check-network`), edición de estado `Enable` en nodos XML de voz (`--disable` / `--enable`) y restauración verificada (`--apply`). |
| [`telmex_launcher.py`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/telmex_launcher.py) | Lanzador Unificado | Menú interactivo para elegir modelo (**Nokia** o **Huawei**), IP, usuario, contraseña, perfiles preconfigurados y generación de plantillas Asterisk. |
| [`setup_and_run.bat`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/setup_and_run.bat) / [`setup_and_run.sh`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/setup_and_run.sh) | Auto-Instaladores 1-Click | Scripts de arranque automático para **Windows**, **macOS** y **Linux**: descargan el proyecto si se ejecutan sueltos, instalan Python 3.12 + `PATH`, crean `.venv`, instalan `requirements.txt` y lanzan el menú interactivo. |

---

## 🗂️ Memoria del Proyecto y Bitácora Técnica (`Pizarra/`)

Todo el proceso de ingeniería, hallazgos por fase, pruebas diferenciales y decisiones de arquitectura se encuentra documentado paso a paso en la carpeta [`Pizarra/`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/Pizarra/00_indice_y_arquitectura.md):

1. [`00_indice_y_arquitectura.md`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/Pizarra/00_indice_y_arquitectura.md) — Índice general, estado de todas las fases y bitácora cronológica.
2. [`01_plan_maestro_fases.md`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/Pizarra/01_plan_maestro_fases.md) — Estrategia general y resultados de las Fases 1 a 3.5.
3. [`02_fase1_reconocimiento_nokia.md`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/Pizarra/02_fase1_reconocimiento_nokia.md) — Reconocimiento de red, `thttpd` y análisis del frontend criptográfico JS (`crypto_page.js`, `sjcl.js`).
4. [`03_fase2_autenticacion_y_endpoints.md`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/Pizarra/03_fase2_autenticacion_y_endpoints.md) — Autenticación `HTTP 299` + `X-SID`, identificación del Nokia `G-1425G-H` y catálogo de los 43 CGIs.
5. [`04_fase3_extraccion_y_criptografia.md`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/Pizarra/04_fase3_extraccion_y_criptografia.md) — Análisis de cabecera `0x00123123`, `CRC32` y pruebas diferenciales sobre `config.cfg`.
6. [`05_plan_detallado_fases_4_y_5.md`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/Pizarra/05_plan_detallado_fases_4_y_5.md) — Especificación granular de las 12 microfunciones de las Fases 4 y 5 (`MF-4.1a` a `MF-5.3a`).
7. [`06_fase4_extraccion_y_asterisk.md`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/Pizarra/06_fase4_extraccion_y_asterisk.md) — Documentación e integración de los recolectores de telemetría, descifrado Wi-Fi, syslog y plantillas Asterisk.
8. [`07_fase5_empaquetador_y_sip_manager.md`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/Pizarra/07_fase5_empaquetador_y_sip_manager.md) — Documentación del empaquetador `.cfg`, gestor SIP y checklist de interoperabilidad Asterisk ↔ IMS Telmex.

---

## ⚡ Inicio Rápido 1-Click (Auto-Instalador con Menú Interactivo)

No necesitas tener Python, Git ni compiladores C++ preinstalados. Tanto el descifrado `$2` de Huawei como el cifrado híbrido `RSA-1024 + AES-128-CBC` de Nokia funcionan **100% en Python puro**.

### 🪟 En Windows (`setup_and_run.bat`)
1. Haz **doble clic** sobre [`setup_and_run.bat`](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/setup_and_run.bat) (incluso puedes copiar únicamente el archivo `setup_and_run.bat` a un PC nuevo sin nada instalado).
   - O ejecútalo en una sola línea desde `CMD` / `PowerShell`:
     ```powershell
     curl -L -o setup_and_run.bat https://raw.githubusercontent.com/MiguelLazaro42/telmex-extractor-Nokia/main/setup_and_run.bat && .\setup_and_run.bat
     ```
2. El script automáticamente:
   - Descarga y descomprime este repositorio desde GitHub si ejecutaste el `.bat` suelto.
   - Detecta si falta Python 3.8+ y, de ser necesario, descarga e instala silenciosamente **Python 3.12 (64-bit)** agregándolo al `PATH`.
   - Crea el entorno virtual `.venv`, instala `requirements.txt` (`cryptography`) y abre el **Menú Interactivo Unificado** (`telmex_launcher.py`).

### 🍎 / 🐧 En macOS y Linux (`setup_and_run.sh`)
```bash
chmod +x setup_and_run.sh
./setup_and_run.sh
```

### 🎛️ Vista del Menú Interactivo (`telmex_launcher.py`)
```text
========================================================================
 📡 TELMEX ONT EXTRACTOR & GESTOR SIP / ASTERISK — MENÚ INTERACTIVO
========================================================================
   • Marca / Modelo actual : [NOKIA] Nokia G-1425G-H
   • Dirección IP objetivo : 192.168.99.254
   • Usuario Web           : TELMEX
   • Contraseña Web        : (sin definir — se solicitará al ejecutar)
   • Carpeta de salida     : output/
------------------------------------------------------------------------
  CONFIGURACIÓN DE OBJETIVO:
   [1] Cambiar Marca / Modelo (Huawei / Nokia) o Cargar Perfil Rápido
   [2] Configurar IP, Usuario, Contraseña y Carpeta de Salida
------------------------------------------------------------------------
  ACCIONES SOBRE EL MÓDEM Y ASTERISK:
   [3] Extraer Credenciales (PPPoE, Wi-Fi, VoIP SIP) y Generar Config Asterisk
   [4] Desactivar Cliente SIP Interno en el Módem (--disable para liberar línea)
   [5] Reactivar Cliente SIP Interno en el Módem (--enable)
   [6] Diagnóstico de Red / SIP ALG / Descarga de Backup Crudo (Nokia)
   [7] Generar Plantillas de Asterisk Ingresando Datos SIP Manualmente
   [0] Salir
========================================================================
```

---

## 💻 Instalación Manual (Opcional)

- **Python:** 3.8 o superior.
- **Dependencias:**
  ```bash
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
  ```

---

## 🚀 Guía de Uso (Nokia `G-1425G-H`)

### 1. Extracción Completa de Telemetría, Reportes y Plantillas Asterisk

Conéctate a la red local del módem Nokia (ej. `192.168.99.254` o `192.168.1.254`) y ejecuta:

```bash
.venv/bin/python nokia_g1425gh_extractor.py --ip 192.168.99.254 -u TELMEX -p TuPasswordWeb
```

- Si ya recolectaste previamente `output/web_telemetry.json` y deseas regenerar los reportes y configuraciones de Asterisk sin conectarte al módem (modo `--offline`), o inyectar un archivo XML (`--xml`) / parámetros SIP conocidos (`--sip-number`, `--sip-user`, `--sip-pass`):
  ```bash
  .venv/bin/python nokia_g1425gh_extractor.py --offline \
    --sip-number +5255XXXXXXXX \
    --sip-user +5255XXXXXXXX \
    --sip-pass TuPasswordSIP
  ```

**Archivos generados en `output/`:**
- `output/web_telemetry.json`: Telemetría completa (identidad GPON, WAN VLAN 881, estado SIP, 10 redes Wi-Fi con sus claves WPA en texto claro y resumen de las 7,432 líneas del syslog).
- `output/credentials.json` y `output/credentials.md`: Reporte consolidado de credenciales y parámetros de red.
- `output/asterisk_pjsip_telmex.conf`: Configuración lista para el stack moderno **PJSIP (`res_pjsip`)** de Asterisk.
- `output/asterisk_sip_legacy_telmex.conf`: Configuración para el driver clásico **`chan_sip`**.
- `output/asterisk_extensions_sample.conf`: Plan de marcado de ejemplo (`extensions.conf`) para llamadas entrantes y salientes a 10 dígitos.

---

### 2. Verificación del Estado SIP en la ONT y Checklist de Red para Asterisk (`nokia_sip_manager.py`)

1. **Consultar si el cliente SIP interno del Nokia está activo o inactivo (`MF-5.1a`):**
   ```bash
   .venv/bin/python nokia_sip_manager.py --status --ip 192.168.99.254 -p TuPasswordWeb
   ```
2. **Ejecutar el diagnóstico de red, DNS IMS y SIP ALG para Asterisk (`MF-5.3a`):**
   ```bash
   .venv/bin/python nokia_sip_manager.py --check-network --ip 192.168.99.254 -p TuPasswordWeb
   ```
   Genera `output/asterisk_network_checklist.md` verificando:
   - Que el cliente SIP interno del Nokia esté `Disabled`.
   - Que la WAN `VLAN 881` esté conectada, incluya el servicio `VOIP` y exponga los DNS de Telmex (`189.233.12.5`, `189.233.15.2`).
   - Si el **SIP ALG** (`nat_glb.cgi?v=alg` → `SIPEnable`) está activo en el router (recomendando desactivarlo en *Security → DMZ and ALG* para evitar que el NAT altere los paquetes SIP/SDP de Asterisk).

3. **Modificar el estado SIP en un XML de configuración y empaquetar `.cfg` (`MF-5.2b` + `MF-5.2a`):**
   ```bash
   # Modo 100% offline (genera el contenedor .cfg verificado sin subirlo al router)
   .venv/bin/python nokia_sip_manager.py --disable --xml ruta/config.xml -o output/config_sip_disabled.cfg

   # Subida controlada al router (verifica magic y CRC32 antes de enviar a /usb.cgi?import)
   .venv/bin/python nokia_sip_manager.py --disable --xml ruta/config.xml -o output/config_sip_disabled.cfg --apply --ip 192.168.99.254 -p TuPasswordWeb
   ```

---

### 3. Descarga y Verificación Forense de Respaldos `config.cfg` (`nokia_backup.py` y `nokia_config_packer.py`)

```bash
# Descargar config.cfg en crudo desde el módem Nokia (MF-3.1)
.venv/bin/python nokia_backup.py download --ip 192.168.99.254 -p TuPasswordWeb

# Analizar cabecera de 20 bytes (magic 0x00123123), entropía y verificar CRC32 (MF-3.2)
.venv/bin/python nokia_backup.py analyze --file output/nokia_backup_raw.cfg

# Verificar integridad de cualquier contenedor .cfg con nokia_config_packer.py
.venv/bin/python nokia_config_packer.py --verify output/nokia_backup_raw.cfg
```

---

## 🚀 Guía de Uso Manual por CLI — Huawei (`HG8145V5` / `HG8145V5V3` / `HG8245`)

Si prefieres ejecutar los scripts de **Huawei** directamente por línea de comandos en vez de usar el menú interactivo:

1. **Extraer credenciales PPPoE, Wi-Fi, VoIP SIP (en texto claro) y plantillas de Asterisk:**
   ```bash
   .venv/bin/python huawei_hg8145v5_extractor.py --ip 192.168.1.254 -u TELMEX -p TuPasswordWeb
   ```
   *(El descifrado del contenedor Type-1 AES-256-CBC y de los hashes `$2...$` se realiza automáticamente en Python puro sin necesidad de compilar C++).*

2. **Desactivar el cliente SIP interno del módem Huawei para liberar la línea hacia Asterisk:**
   ```bash
   .venv/bin/python huawei_sip_manager.py --disable --apply --ip 192.168.1.254 -p TuPasswordWeb
   ```

3. **Reactivar la telefonía SIP en el módem Huawei si deseas revertir los cambios:**
   ```bash
   .venv/bin/python huawei_sip_manager.py --enable --apply --ip 192.168.1.254 -p TuPasswordWeb
   ```

---

## 🧪 Ejecución de la Suite de Pruebas Automatizadas

El proyecto incluye pruebas unitarias y de validación criptográfica en la carpeta `tests/` (todas se ejecutan 100% en memoria sin alterar el router):

```bash
# 1. Validación bit a bit de primitivas criptográficas (AES-128-CBC sjcl, RSA-1024 PKCS#1 v1.5, base64url)
.venv/bin/python -I tests/validate_crypto.py

# 2. Pruebas unitarias de parsers XML TR-098/TR-104, reportes y plantillas Asterisk (11 pruebas)
.venv/bin/python -I tests/test_xml_parsers.py

# 3. Pruebas del empaquetador Nokia .cfg y gestor SIP (25 pruebas)
.venv/bin/python -I -m unittest discover -s tests
```

---

## 📄 Licencia

Este proyecto está bajo la Licencia **MIT**. Consulta el archivo [LICENSE](file:///Users/miguellazarosantiago/Documents/Tools/telmex-extractor-Nokia/LICENSE) para más detalles.
