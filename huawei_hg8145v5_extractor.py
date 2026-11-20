#!/usr/bin/env python3
"""
📡 Huawei HG8145V5 / HG8245 (Telmex) — Extractor Autónomo de Credenciales y Descifrador
======================================================================================
Herramienta en Python para interactuar con módems y terminales ONT Huawei EchoLife
(HG8145V5, HG8145V5V3, HG8245W5, EG8145 y compatibles) distribuidos por Telmex e ISPs similares.

Capacidades:
1. Detección automática multiplataforma de la IP del router (Windows, macOS, Linux).
2. Autenticación web automatizada (GetRandCount.asp + login.cgi).
3. Descarga atómica del archivo de configuración maestro (hw_ctree.xml).
4. Descifrado de contenedor Type-1 AES-256-CBC con KDF SHA-256 (8,192 rondas) + Gzip.
5. Descifrado de hashes propietarios Huawei ($2) a texto plano vía hw_passwd.
6. Extracción de credenciales PPPoE (VLAN 881), VoIP SIP IMS, usuarios web y claves Wi-Fi.
7. Modo offline (--file) para procesar respaldos locales sin conectarse al módem.
"""

import os
import sys
import re
import gzip
import json
import html
import struct
import base64
import getpass
import hashlib
import argparse
import subprocess
import urllib.request
import urllib.parse
import http.cookiejar
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("❌ Falta la librería 'cryptography'. Instálala ejecutando: pip install cryptography")
    sys.exit(1)

# Clave maestra de derivación oficial para contenedores Type-1 de Huawei
HUAWEI_MASTER_KEY = b"hex:13395537D2730554A176799F6D56A239"

# Claves AES-256 pre-derivadas de las tablas White-Box AES de Huawei (src/rev_hw.cpp)
# Permiten descifrar hashes $1...$ y $2...$ en Python puro sin requerir compilador C++/OpenSSL
HUAWEI_DOLLAR2_AES256_KEY = bytes.fromhex(
    "6fc6e3436a53b6310dc09a475494ac774e7afb21b9e58fc8e58b5660e48e2498"
)
HUAWEI_DOLLAR1_AES256_BASE = bytearray.fromhex(
    "b8363c9b77daed4b9abb9f2f6df5f1d5cb64975d5d3bcee8827f2f42235f9229"
)
HUAWEI_DOLLAR1_SALT_POS = (0x0B, 0x11, 0x17, 0x1D)


def decrypt_huawei_password_native(enc_val: str) -> str:
    """Descifra hashes reversibles $1...$ y $2...$ de Huawei en Python puro (sin C++)."""
    if not enc_val or len(enc_val) < 23 or enc_val[0] != "$" or enc_val[-1] != "$":
        return enc_val
    fmt = enc_val[1]
    if fmt not in ("1", "2"):
        return enc_val

    inner = [(0x1E if ord(c) == ord("~") else (ord(c) - 0x21) & 0xFF) for c in enc_val[2:-1]]

    def plain20_to_bin16(chunk20):
        words = []
        for i in range(4):
            val = 0
            mul = 1
            for j in range(5):
                val += mul * chunk20[i * 5 + j]
                mul *= 93
            words.append(val & 0xFFFFFFFF)
        return struct.pack("<4I", *words)

    if fmt == "2":
        if len(inner) < 40 or len(inner) % 20 != 0:
            return enc_val
        blocks = [plain20_to_bin16(inner[i : i + 20]) for i in range(0, len(inner), 20)]
        iv = blocks[-1]
        ct = b"".join(blocks[:-1])
        dec = Cipher(algorithms.AES(HUAWEI_DOLLAR2_AES256_KEY), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        return pt.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")

    # Formato $1...$
    if len(inner) < 24 or len(inner) % 24 != 0:
        return enc_val
    key = bytearray(HUAWEI_DOLLAR1_AES256_BASE)
    for idx, pos in enumerate(HUAWEI_DOLLAR1_SALT_POS):
        key[pos] = inner[20 + idx]
    dec = Cipher(algorithms.AES(bytes(key)), modes.ECB()).decryptor()
    out = bytearray()
    for i in range(0, len(inner), 24):
        blk = plain20_to_bin16(inner[i : i + 20])
        out.extend(dec.update(blk))
    out.extend(dec.finalize())
    return bytes(out).split(b"\x00", 1)[0].decode("utf-8", errors="ignore")


def detect_default_gateway():
    """Detecta la dirección IP de la pasarela predeterminada en Windows, macOS y Linux."""
    # 1. Windows
    if sys.platform.startswith("win"):
        try:
            salida = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="cp850",
                errors="ignore"
            )
            matches = re.findall(
                r"0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
                salida
            )
            for ip in matches:
                ip = ip.strip()
                if ip and ip != "0.0.0.0":
                    return ip
        except Exception:
            pass

        try:
            cmd = ["powershell", "-NoProfile", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop"]
            salida = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
            ips = re.findall(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", salida)
            for ip in ips:
                if ip and ip != "0.0.0.0":
                    return ip
        except Exception:
            pass

    # 2. macOS (Darwin)
    if sys.platform == "darwin":
        try:
            salida = subprocess.check_output(["route", "-n", "get", "default"], stderr=subprocess.DEVNULL, text=True)
            m = re.search(r"gateway:\s*(\S+)", salida)
            if m:
                return m.group(1).strip()
        except Exception:
            pass

    # 3. Linux (ip route)
    try:
        salida = subprocess.check_output(["ip", "route", "show", "default"], stderr=subprocess.DEVNULL, text=True)
        m = re.search(r"default via\s*(\S+)", salida)
        if m:
            return m.group(1).strip()
    except Exception:
        pass

    # 4. Fallback estándar BSD/Unix
    try:
        salida = subprocess.check_output(["netstat", "-rn"], stderr=subprocess.DEVNULL, text=True)
        m = re.search(r"(?:default|0\.0\.0\.0)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", salida)
        if m:
            return m.group(1).strip()
    except Exception:
        pass

    # 5. IP por defecto habitual en Telmex
    return "192.168.1.254"


class HuaweiHG8145V5Extractor:
    def __init__(self, ip, user, password, output_dir="output"):
        self.ip = ip
        self.user = user
        self.password = password
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        self.script_dir = Path(__file__).parent.resolve()
        self.hw_passwd_bin = self.script_dir / "hw_passwd"
        self._ensure_hw_passwd()

    def _ensure_hw_passwd(self):
        """Usa el descifrador nativo en Python para hashes $1/$2 (no requiere compilar C++)."""
        return

    def login(self):
        """Inicia sesión en la interfaz web del router Huawei."""
        print(f"📡 Conectando y autenticando en el módem (http://{self.ip})...")
        token_url = f"http://{self.ip}/asp/GetRandCount.asp"
        try:
            with self.opener.open(urllib.request.Request(token_url, data=b""), timeout=7) as r:
                cnt = r.read().decode("utf-8", errors="ignore").strip().lstrip("\ufeff")
        except Exception as e:
            raise ConnectionError(f"No fue posible conectar con el router en http://{self.ip}: {e}")

        pwd_b64 = base64.b64encode(self.password.encode()).decode()
        login_data = urllib.parse.urlencode({
            "UserName": self.user,
            "PassWord": pwd_b64,
            "x.X_HW_Token": cnt
        }).encode()

        req = urllib.request.Request(f"http://{self.ip}/login.cgi", data=login_data)
        req.add_header("Cookie", "body:Language:spanish:id=-1")
        with self.opener.open(req, timeout=7) as r:
            resp = r.read().decode("utf-8", errors="ignore")
            if "login.cgi" in resp and "txt_Password" in resp:
                raise ValueError("Credenciales inválidas. Verifica usuario y contraseña.")
        print("✅ Autenticación exitosa en el módem.")

    def download_config(self):
        """Descarga el archivo de configuración cifrado del módem."""
        print("📥 Solicitando archivo de respaldo de configuración (hw_ctree.xml)...")
        cfg_url = f"http://{self.ip}/html/ssmp/cfgfile/cfgfile.asp"
        with self.opener.open(cfg_url, timeout=7) as r:
            cfg_html = r.read().decode("utf-8", errors="ignore")

        m = re.search(r"name=[\"\x27]onttoken[\"\x27]\s+value=[\"\x27]([a-f0-9]+)[\"\x27]", cfg_html)
        if not m:
            raise RuntimeError("No se pudo obtener el token de respaldo (onttoken) desde cfgfile.asp.")
        onttoken = m.group(1)

        try:
            self.opener.open(f"http://{self.ip}/html/ssmp/common/StartFileLoad.asp", timeout=5)
        except Exception:
            pass

        post_data = urllib.parse.urlencode({"x.X_HW_Token": onttoken}).encode()
        url_down = f"http://{self.ip}/html/ssmp/cfgfile/cfgfiledown.cgi?&RequestFile=html/ssmp/cfgfile/cfgfile.asp"
        req_down = urllib.request.Request(url_down, data=post_data)
        with self.opener.open(req_down, timeout=15) as r:
            raw_bytes = r.read()

        raw_path = self.output_dir / "hw_ctree_encrypted.xml"
        with open(raw_path, "wb") as f:
            f.write(raw_bytes)
        print(f"✅ Archivo cifrado recibido ({len(raw_bytes):,} bytes) -> {raw_path}")
        return raw_bytes

    def decrypt_ctree(self, raw_bytes):
        """Descifra el contenedor Type-1 AES-256-CBC de Huawei con KDF SHA-256."""
        print("🔓 Descifrando contenedor Type-1 AES-256-CBC con KDF SHA-256 (8,192 rondas)...")
        if len(raw_bytes) < 48:
            raise ValueError("El archivo de configuración es demasiado pequeño o está corrupto.")

        header = raw_bytes[:8]
        if header[:4] != b"\x01\x00\x00\x00":
            raise ValueError(f"Formato no reconocido o no soportado (Encabezado: {header.hex()}). Se esperaba Type-1 (01000000).")

        payload = raw_bytes[8:]
        iv = payload[:16]
        ciphertext = payload[16:-32]

        # KDF oficial: 8,192 rondas SHA-256
        digest = bytearray(32)
        digest[:16] = iv
        for _ in range(8192):
            h = hashlib.sha256()
            h.update(digest)
            h.update(HUAWEI_MASTER_KEY)
            digest = h.digest()

        aes_key = bytes(digest)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plain = decryptor.update(ciphertext) + decryptor.finalize()

        # Recorte de padding según residuo codificado en IV[15]
        lastn = iv[15] & 0x0F
        if lastn != 0:
            plain = plain[: -(16 - lastn)]

        if not plain.startswith(b"\x1f\x8b"):
            raise ValueError("Fallo en el descifrado: Los datos no corresponden a una compresión Gzip válida.")

        xml_bytes = gzip.decompress(plain)
        xml_text = xml_bytes.decode("utf-8", errors="ignore")
        xml_path = self.output_dir / "hw_ctree_decrypted.xml"
        with open(xml_path, "w", encoding="utf-8") as f:
            f.write(xml_text)
        print(f"✅ Configuración XML descifrada exitosamente ({len(xml_text):,} caracteres) -> {xml_path}")
        return xml_text

    def decrypt_value(self, enc_val):
        """Descifra hashes reversibles propietarios $1 y $2 de Huawei en Python puro."""
        if not enc_val or not (enc_val.startswith("$2") or enc_val.startswith("$1")):
            return enc_val
        try:
            res = decrypt_huawei_password_native(enc_val)
            if res != enc_val:
                return res
        except Exception:
            pass
        if self.hw_passwd_bin.exists():
            try:
                proc = subprocess.Popen(
                    [str(self.hw_passwd_bin), "-s", "-d", "-"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                out, _ = proc.communicate(input=enc_val.encode("utf-8"), timeout=5)
                res = out.decode("utf-8", errors="ignore").strip()
                if ":" in res:
                    return res.rsplit(":", 1)[1].strip()
                return res
            except Exception:
                return enc_val
        return enc_val

    def parse_credentials(self, xml_text):
        """Extrae y estructura los parámetros de red y credenciales del XML."""
        print("🔍 Extrayendo parámetros de red, WAN PPPoE y cuentas VoIP SIP...")
        results = {
            "pppoe": {},
            "sip_voip": {},
            "web_admin": [],
            "wifi_networks": []
        }

        # 1. PPPoE WAN
        m_wan = re.search(r"<WANPPPConnectionInstance([^>]+)>", xml_text)
        if m_wan:
            attrs = m_wan.group(1)
            def get_attr(name):
                m = re.search(rf'{name}=[\"\x27]([^\"]+)[\"\x27]', attrs)
                return m.group(1) if m else ""

            user = get_attr("Username")
            p_enc = html.unescape(get_attr("Password"))
            vlan = get_attr("X_HW_VLAN") or "881"
            mtu = get_attr("MaxMRUSize") or "1492"
            service = get_attr("X_HW_SERVICELIST")
            gw = get_attr("DefaultGateway")
            p_dec = self.decrypt_value(p_enc)

            results["pppoe"] = {
                "username": user,
                "password": p_dec,
                "vlan_id": vlan,
                "mtu": mtu,
                "service": service,
                "gateway": gw
            }

        # 2. SIP VoIP (IMS)
        m_sip = re.search(
            r"<SIP\s+[^>]*?AuthUserName=[\"\x27]([^\"]+)[\"\x27]\s+AuthPassword=[\"\x27]([^\"]+)[\"\x27]\s+URI=[\"\x27]([^\"]+)[\"\x27]",
            xml_text
        )
        if m_sip:
            u = m_sip.group(1)
            p_enc = html.unescape(m_sip.group(2))
            uri = m_sip.group(3)
            p_dec = self.decrypt_value(p_enc)

            # Buscar Outbound Proxy o Registrar Server
            m_proxy = re.search(r'OutBoundProxyServer=[\"\x27]([^\"]+)[\"\x27]', xml_text)
            proxy_val = m_proxy.group(1) if m_proxy else "nir8.norte.telmex.net"

            m_registrar = re.search(r'RegistrarServer=[\"\x27]([^\"]+)[\"\x27]', xml_text)
            registrar_val = m_registrar.group(1) if m_registrar else "vims-h.telmex.com"

            results["sip_voip"] = {
                "auth_username": u,
                "auth_password": p_dec,
                "uri": uri,
                "registrar_server": registrar_val,
                "outbound_proxy": proxy_val
            }

        # 3. Usuarios Web Admin
        web_users = re.findall(
            r"<X_HW_WebUserInfoInstance[^>]+UserName=[\"\x27]([^\"]+)[\"\x27][^>]+Password=[\"\x27]([^\"]+)[\"\x27][^>]+UserLevel=[\"\x27]([^\"]+)[\"\x27]",
            xml_text
        )
        for u, p, lvl in web_users:
            p_dec = self.decrypt_value(html.unescape(p))
            results["web_admin"].append({
                "username": u,
                "level": lvl,
                "password": p_dec
            })

        # 4. Redes Wi-Fi PreSharedKey
        wifi_keys = set(re.findall(r"PreSharedKey=[\"\x27]([^\"]+)[\"\x27]", xml_text))
        for k in wifi_keys:
            if k.startswith("$2"):
                k_dec = self.decrypt_value(html.unescape(k))
                if k_dec and k_dec not in results["wifi_networks"]:
                    results["wifi_networks"].append(k_dec)

        # Guardar reportes locales
        json_path = self.output_dir / "credentials.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        md_path = self.output_dir / "credentials.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# 📡 Credenciales Extraídas — Router Huawei ONT\n\n")
            f.write("## 1. Conexión a Internet WAN (PPPoE)\n")
            f.write(f"- **Usuario PPPoE:** `{results['pppoe'].get('username', 'N/A')}`\n")
            f.write(f"- **Contraseña PPPoE:** `{results['pppoe'].get('password', 'N/A')}`\n")
            f.write(f"- **VLAN ID:** `{results['pppoe'].get('vlan_id', '881')}`\n")
            f.write(f"- **MTU:** `{results['pppoe'].get('mtu', '1492')}`\n")
            f.write(f"- **Servicios:** `{results['pppoe'].get('service', 'TR069_VOIP_INTERNET')}`\n\n")

            f.write("## 2. Telefonía Fija VoIP (IMS SIP)\n")
            f.write(f"- **Directorio / URI:** `{results['sip_voip'].get('uri', 'N/A')}`\n")
            f.write(f"- **Usuario SIP (Digest):** `{results['sip_voip'].get('auth_username', 'N/A')}`\n")
            f.write(f"- **Contraseña SIP:** `{results['sip_voip'].get('auth_password', 'N/A')}`\n")
            f.write(f"- **Registrar Server:** `{results['sip_voip'].get('registrar_server', 'vims-h.telmex.com')}`\n")
            f.write(f"- **Outbound Proxy:** `{results['sip_voip'].get('outbound_proxy', 'nir8.norte.telmex.net')}`\n\n")

            f.write("## 3. Acceso Web y Wi-Fi\n")
            for w in results["web_admin"]:
                f.write(f"- **Usuario Web ({w['username']}):** `{w['password']}`\n")
            for k in results["wifi_networks"]:
                f.write(f"- **Clave Wi-Fi:** `{k}`\n")

        print(f"✅ Reportes generados:\n  - {json_path}\n  - {md_path}")
        try:
            import nokia_g1425gh_extractor
            pjsip_path = nokia_g1425gh_extractor.render_asterisk_pjsip_conf(
                results["sip_voip"], output_dir=str(self.output_dir)
            )
            sip_path, ext_path = nokia_g1425gh_extractor.render_asterisk_sip_conf(
                results["sip_voip"], output_dir=str(self.output_dir)
            )
            print(f"  - {pjsip_path}\n  - {sip_path}\n  - {ext_path}")
        except Exception:
            pass
        return results


def main():
    parser = argparse.ArgumentParser(
        description="📡 Extractor y Descifrador Forense de Routers Huawei HG8145V5 / HG8245 (Telmex)"
    )
    parser.add_argument("--ip", default=None, help="IP del router (por defecto detectada automáticamente)")
    parser.add_argument("-u", "--user", default="TELMEX", help="Usuario de acceso web (por defecto: TELMEX)")
    parser.add_argument("-p", "--password", default=None, help="Contraseña web del módem (se solicita de forma segura si se omite)")
    parser.add_argument("--file", default=None, help="Ruta a un archivo hw_ctree.xml local previamente descargado para descifrado offline")
    parser.add_argument("-o", "--out", default="output", help="Directorio de salida para los reportes y configuración descifrada")
    parser.add_argument("--json", action="store_true", help="Imprime únicamente el resultado en formato JSON estructurado")
    args = parser.parse_args()

    if not args.json:
        print("=" * 68)
        print("📡 HUAWEI ONT AUTOMATED CREDENTIAL EXTRACTOR & DECRYPTOR")
        print("   EchoLife HG8145V5 / HG8145V5V3 / HG8245 / EG8145 Series (Telmex)")
        print("=" * 68)

    # Modo Offline
    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"❌ Error: El archivo especificado no existe: {file_path}")
            sys.exit(1)
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        extractor = HuaweiHG8145V5Extractor(ip="127.0.0.1", user="offline", password="", output_dir=args.out)
        try:
            xml_text = extractor.decrypt_ctree(raw_bytes)
            res = extractor.parse_credentials(xml_text)
        except Exception as e:
            print(f"❌ Error al procesar archivo offline: {e}")
            sys.exit(1)
    else:
        # Modo Online (Módem en Red)
        target_ip = args.ip if args.ip else detect_default_gateway()
        if not args.json:
            print(f"[+] Dirección IP de la ONT identificada: {target_ip}")

        password = args.password
        if not password:
            password = getpass.getpass(f"🔑 Ingrese el password web del router ({target_ip}): ")

        extractor = HuaweiHG8145V5Extractor(ip=target_ip, user=args.user, password=password, output_dir=args.out)
        try:
            extractor.login()
            raw_bytes = extractor.download_config()
            xml_text = extractor.decrypt_ctree(raw_bytes)
            res = extractor.parse_credentials(xml_text)
        except Exception as e:
            print(f"❌ Error durante la extracción: {e}")
            sys.exit(1)

    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return

    print("\n" + "=" * 68)
    print("📋 PARÁMETROS CRÍTICOS EXTRAÍDOS:")
    print("=" * 68)
    print(f"  🌐 Usuario WAN PPPoE:    {res['pppoe'].get('username', 'N/A')}")
    print(f"  🔑 Contraseña PPPoE:     {res['pppoe'].get('password', 'N/A')}")
    print(f"  🏷️  VLAN ID (802.1Q):     {res['pppoe'].get('vlan_id', '881')}")
    print(f"  📞 Usuario SIP (Digest): {res['sip_voip'].get('auth_username', 'N/A')}")
    print(f"  🔐 Contraseña SIP:       {res['sip_voip'].get('auth_password', 'N/A')}")
    print(f"  🌐 Servidor Registrar:   {res['sip_voip'].get('registrar_server', 'vims-h.telmex.com')}")
    print("=" * 68)
    print("✨ Proceso completado exitosamente.\n")


if __name__ == "__main__":
    main()
