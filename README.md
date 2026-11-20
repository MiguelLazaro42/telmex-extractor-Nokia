# 📡 Huawei EchoLife HG8145V5 / HG8245 (Telmex) — Extractor Forense de Credenciales, Descifrador y Gestor SIP

Herramienta autónoma en Python y C++ para interactuar con la API web y la arquitectura criptográfica de las terminales de red óptica (ONT GPON) **Huawei EchoLife** (modelos `HG8145V5`, `HG8145V5V3`, `HG8245W5`, `EG8145` y variantes compatibles) distribuidas ampliamente por **Telmex** en servicios de fibra óptica Infinitum.

Permite la identificación automática de la pasarela, descarga del respaldo maestro `hw_ctree.xml`, descifrado del contenedor binario Type-1, descifrado inverso de hashes `$2` de Huawei a texto plano, y gestión quirúrgica de perfiles VoIP SIP.

---

## ⚡ ¿Qué hace este conjunto de herramientas?

Las ONTs de Huawei implementan un esquema de seguridad de dos niveles para proteger sus configuraciones sensibles:

```
+-----------------------------------------------------------------------------------------+
|                               CONTENEDOR TYPE-1 (AES-256-CBC)                           |
| [Encabezado 8B] [IV 16B] [Payload Cifrado AES-256-CBC (N x 16B)] [HMAC-SHA256 (32B)]   |
+-----------------------------------------------------------------------------------------+
                                            │
                                  KDF SHA-256 (8,192 rondas)
                                            │
                                            ▼
                                [ Gzip Decompress ]
                                            │
                                            ▼
                             hw_ctree.xml (Árbol de Texto XML)
                                            │
                      ┌─────────────────────┴─────────────────────┐
                      ▼                                           ▼
          Nodos WAN PPP / SIP / Wi-Fi                 Hashes Propietarios $2
             (Atributos XML)                       (White-Box AES Obfuscation)
                      │                                           │
                      │                                           ▼
                      │                               [ Binario C++ hw_passwd ]
                      │                                           │
                      └─────────────────────┬─────────────────────┘
                                            ▼
                           Credenciales en Texto Plano (Cleartext)
```

1. **Detección Automática de Pasarela Multiplataforma:** Identifica de forma nativa la IP local del router en **Windows**, **macOS** y **Linux** sin requerir intervención manual.
2. **Descarga Atómica de Configuración:** Autentica en el módem vía HTTP (`GetRandCount.asp` + `login.cgi`) y obtiene el token de respaldo (`onttoken`) para descargar `hw_ctree.xml`.
3. **Descifrado de Contenedor Type-1:** 
   - Deriva la clave AES mediante **8,192 rondas sucesivas de SHA-256** combinando el Vector de Inicialización (IV) de 16 bytes con la clave maestra de Huawei (`hex:13395537D2730554A176799F6D56A239`).
   - Descifra el bloque con **AES-256-CBC**.
   - Ajusta el padding final según el nibble codificado en `IV[15] & 0x0F`.
   - Descomprime el flujo **Gzip** (`1F 8B`) obteniendo el archivo XML en texto claro.
4. **Descifrado de Hashes Internos `$2`:**
   - Huawei almacena contraseñas de usuario, Wi-Fi y VoIP ofuscadas bajo el prefijo `$2...`.
   - El script integra la herramienta compilada `hw_passwd` (C++11) basada en el análisis inverso de las tablas White-Box AES de Huawei, traduciendo cada hash a texto plano de manera determinista.
5. **Empaquetado y Firma (Packer):** Permite volver a comprimir, cifrar en AES-256-CBC y calcular el HMAC-SHA256 de configuraciones modificadas para cargarlas nuevamente en el módem.
6. **Gestión de Telefonía SIP:** Permite desactivar quirúrgicamente el cliente SIP interno de Huawei para liberar la línea telefónica y utilizarla en conmutadores Asterisk / FreePBX o Softphones.

---

## 🎯 ¿Qué se puede hacer con la información extraída?

La extracción y descifrado de estos parámetros permite desbloquear la infraestructura de red sin depender de las restricciones del ISP:

### 1. Router Neutro en Modo Puente (Bridge)
* **Objetivo:** Eliminar el Doble NAT y delegar el cortafuegos, NAT y QoS a un router perimetral profesional (**pfSense**, **OPNsense**, **OpenWrt**, **MikroTik RouterOS** o gateways Linux dedicados como **PuertaOS**).
* **Parámetros obtenidos:**
  * **Usuario PPPoE:** `00259ELHWTC66CXXXXX@prodigyweb.com.mx`
  * **Contraseña PPPoE:** Clave en texto plano de 30 caracteres.
  * **Etiqueta VLAN (802.1Q):** **VLAN ID 881** (MTU 1492, CoS 0).
  * **Gateway BRAS:** Dirección IP de la pasarela del operador.

### 2. Telefonía Fija en Conmutador IP o Softphone (VoIP SIP IMS)
* **Objetivo:** Recibir y realizar llamadas de la línea fija desde conmutadores PBX locales (**Asterisk**, **FreePBX**, **3CX**) o softphones en smartphone/PC (**MicroSIP**, **Zoiper**, **Linphone**).
* **Parámetros obtenidos:**
  * **Directorio / Número:** Número a 10 dígitos (ej. `+5255XXXXXXXX`).
  * **Usuario Digest Auth:** `+5255XXXXXXXX@vims-h.telmex.com`
  * **Contraseña SIP Secreta:** Clave de autenticación para el Core IMS.
  * **Servidor Registrar:** `vims-h.telmex.com:5060` (UDP).
  * **Outbound Proxy:** `nir8.norte.telmex.net:5060` (UDP) o proxy regional asignado.
  * **Códec de Voz:** `G.711 A-law` (PCMA, 20ms packetization).

### 3. Sustitución de ONT por Módulo SFP GPON Stick
* **Objetivo:** Conectar la fibra óptica directamente a una ranura SFP+ en un router o switch administrado.
* **Parámetros obtenidos:**
  * **GPON Serial Number (SN / Hex):** Identificador de registro GPON en la OLT.
  * **OUI / Fabricante:** `HWTC` (Huawei Technologies).
  * **SLID / Password GPON:** Clave de autenticación PLOAM (si aplica en la zona).

---

## 💻 Requisitos del Sistema

* **Python:** Versión 3.8 o superior.
* **Librerías Python:**
  ```bash
  pip install -r requirements.txt
  ```
* **Compilador C++ (para compilar `hw_passwd` en el primer uso):**
  * **Linux (Debian / Ubuntu / Pop!_OS):** `sudo apt install build-essential libssl-dev cmake`
  * **macOS:** Xcode Command Line Tools (`xcode-select --install`) y OpenSSL (`brew install openssl`).
  * **Windows:** MinGW-w64 o MSVC con CMake.

> [!NOTE]
> El script intentará compilar automáticamente `hw_passwd` al ejecutarse por primera vez si no encuentra el binario precompilado. También puedes compilarlo manualmente ejecutando:
> ```bash
> cd src && make
> ```

---

## 🚀 Guía de Uso

### 1. Extracción Interactiva en Red Local

Conecta tu equipo a cualquier puerto LAN del módem Huawei (por cable Ethernet o Wi-Fi) y ejecuta:

```bash
python huawei_hg8145v5_extractor.py
```

*Salida interactiva en terminal:*
```text
====================================================================
📡 HUAWEI ONT AUTOMATED CREDENTIAL EXTRACTOR & DECRYPTOR
   EchoLife HG8145V5 / HG8145V5V3 / HG8245 / EG8145 Series (Telmex)
====================================================================
[+] Dirección IP de la ONT identificada: 192.168.1.254
🔑 Ingrese el password web del router (192.168.1.254): ********
📡 Conectando y autenticando en el módem (http://192.168.1.254)...
✅ Autenticación exitosa en el módem.
📥 Solicitando archivo de respaldo de configuración (hw_ctree.xml)...
✅ Archivo cifrado recibido (46,824 bytes) -> output/hw_ctree_encrypted.xml
🔓 Descifrando contenedor Type-1 AES-256-CBC con KDF SHA-256 (8,192 rondas)...
✅ Configuración XML descifrada exitosamente (335,737 caracteres) -> output/hw_ctree_decrypted.xml
🔍 Extrayendo parámetros de red, WAN PPPoE y cuentas VoIP SIP...
✅ Reportes generados:
  - output/credentials.json
  - output/credentials.md

====================================================================
📋 PARÁMETROS CRÍTICOS EXTRAÍDOS:
====================================================================
  🌐 Usuario WAN PPPoE:    00259ELHWTC66CXXXXX@prodigyweb.com.mx
  🔑 Contraseña PPPoE:     38e35eef346e584626c9f9XXXXXXXX
  🏷️  VLAN ID (802.1Q):     881
  📞 Usuario SIP (Digest): +5255XXXXXXXX@vims-h.telmex.com
  🔐 Contraseña SIP:       bdcc1652XXXX
  🌐 Servidor Registrar:   vims-h.telmex.com
====================================================================
✨ Proceso completado exitosamente.
```

---

### 2. Modo Desatendido (Línea de Comandos)

Especificando la dirección IP y contraseña de acceso:

```bash
python huawei_hg8145v5_extractor.py --ip 192.168.1.254 -u TELMEX -p TuPasswordDeEtiqueta
```

---

### 3. Salida Estructurada en JSON

Para automatización en scripts bash o integración en pipelines:

```bash
python huawei_hg8145v5_extractor.py -p TuPasswordDeEtiqueta --json
```

---

### 4. Modo Offline (Descifrado de Respaldo Local)

Si ya descargaste manualmente el archivo `hw_ctree.xml` desde la interfaz web del módem o mediante un respaldo previo:

```bash
python huawei_hg8145v5_extractor.py --file ruta/al/hw_ctree.xml
```

---

### 5. Desactivación de Telefonía SIP (`huawei_sip_manager.py`)

Para evitar conflictos de registro SIP cuando configuras un cliente VoIP externo (Asterisk o Softphone), puedes apagar la cuenta telefónica dentro del módem Huawei:

1. **Generar archivo cifrado con SIP desactivado:**
   ```bash
   python huawei_sip_manager.py --disable
   ```
2. **Aplicar directamente al módem y reiniciar:**
   ```bash
   python huawei_sip_manager.py --disable --apply --ip 192.168.1.254 -p TuPasswordDeEtiqueta
   ```
3. **Reactivar la telefonía en el módem si deseas revertir los cambios:**
   ```bash
   python huawei_sip_manager.py --enable --apply --ip 192.168.1.254 -p TuPasswordDeEtiqueta
   ```

---

## 🔒 Descargo de Responsabilidad (Disclaimer)

Esta herramienta ha sido desarrollada exclusivamente con fines de **auditoría de red personal, diagnóstico técnico, optimización de infraestructura propia e interoperabilidad de equipos**. 

El autor no se responsabiliza por el uso indebido de esta herramienta ni por modificaciones inapropiadas en el firmware o configuración de equipos proporcionados por operadores de telecomunicaciones.

---

## 📄 Licencia

Este proyecto está bajo la Licencia **MIT**. Consulta el archivo [LICENSE](file:///Users/edward/Documents/herramientasdered/tools/router_extractors/huawei-hg8145v5-telmex-extractor/LICENSE) para más detalles.
