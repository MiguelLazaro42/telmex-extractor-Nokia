#!/usr/bin/env python3
"""
📞 Gestor y Desactivador de Telefonía VoIP SIP — Huawei ONT (Telmex)
===================================================================
Permite habilitar o deshabilitar quirúrgicamente el servicio VoIP SIP en el
archivo de configuración de la ONT Huawei EchoLife (HG8145V5 / HG8245),
empaquetar el contenedor binario Type-1 y opcionalmente cargarlo en el módem.

Uso principal:
Desactivar el cliente SIP interno de la ONT para registrar directamente
Asterisk, FreePBX o un Softphone (MicroSIP / Zoiper) en el Core IMS de Telmex
sin colisiones de registro Digest ("Registration Failed / Conflict").
"""

import os
import sys
import re
import base64
import getpass
import argparse
import urllib.request
import urllib.parse
import http.cookiejar
import xml.etree.ElementTree as ET
from pathlib import Path

# Importar funciones de empaquetado Type-1
from huawei_config_packer import pack_ctree, verify_pack


def modify_sip_state(input_xml: Path, output_xml: Path, enable: bool = False):
    """Modifica el estado de los perfiles y líneas SIP en el árbol XML."""
    print(f"📖 Leyendo XML de configuración: {input_xml}")
    tree = ET.parse(input_xml)
    root = tree.getroot()

    target_state = "Enabled" if enable else "Disabled"
    voice_profiles_modified = 0
    lines_modified = 0

    for elem in root.iter():
        tag = elem.tag
        if tag == "VoiceProfileInstance" or tag.endswith("VoiceProfileInstance"):
            inst_id = elem.attrib.get("InstanceID", "")
            curr = elem.attrib.get("Enable", "Unknown")
            elem.attrib["Enable"] = target_state
            print(f"  🔍 VoiceProfileInstance (ID={inst_id}): {curr} -> {target_state}")
            voice_profiles_modified += 1

        elif tag == "LineInstance" or tag.endswith("LineInstance"):
            inst_id = elem.attrib.get("InstanceID", "")
            curr = elem.attrib.get("Enable", "Unknown")
            elem.attrib["Enable"] = target_state
            print(f"  🔍 LineInstance (ID={inst_id}): {curr} -> {target_state}")
            lines_modified += 1

    if voice_profiles_modified == 0 and lines_modified == 0:
        raise ValueError("No se encontraron instancias de VoiceProfile o LineInstance en el XML.")

    output_xml.parent.mkdir(parents=True, exist_ok=True)
    tree.write(output_xml, encoding="utf-8", xml_declaration=True)
    print(f"✅ Modificación completada: {voice_profiles_modified} VoiceProfiles y {lines_modified} Líneas.")
    print(f"💾 XML guardado en: {output_xml}")


def upload_config(ip: str, user: str, password: str, config_file: Path):
    """Sube el archivo de configuración cifrado al módem vía web."""
    if not config_file.exists():
        raise FileNotFoundError(f"No existe el archivo de configuración: {config_file}")

    with open(config_file, "rb") as f:
        file_bytes = f.read()

    print(f"📡 Conectando con el módem en http://{ip}...")
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # 1. Obtener token aleatorio
    token_url = f"http://{ip}/asp/GetRandCount.asp"
    with opener.open(urllib.request.Request(token_url, data=b""), timeout=7) as r:
        cnt = r.read().decode("utf-8", errors="ignore").strip().lstrip("\ufeff")

    # 2. Login
    pwd_b64 = base64.b64encode(password.encode()).decode()
    login_data = urllib.parse.urlencode({
        "UserName": user,
        "PassWord": pwd_b64,
        "x.X_HW_Token": cnt
    }).encode()

    req = urllib.request.Request(f"http://{ip}/login.cgi", data=login_data)
    req.add_header("Cookie", "body:Language:spanish:id=-1")
    with opener.open(req, timeout=7) as r:
        resp = r.read().decode("utf-8", errors="ignore")
        if "login.cgi" in resp and "txt_Password" in resp:
            raise ValueError("Error de autenticación: contraseña incorrecta.")
    print("✅ Autenticación exitosa.")

    try:
        opener.open(f"http://{ip}/index.asp", timeout=5)
    except Exception:
        pass

    # 3. Obtener onttoken desde cfgfile.asp
    cfg_url = f"http://{ip}/html/ssmp/cfgfile/cfgfile.asp"
    with opener.open(cfg_url, timeout=7) as r:
        cfg_html = r.read().decode("utf-8", errors="ignore")

    m = re.search(r"name=[\"\x27]onttoken[\"\x27]\s+value=[\"\x27]([a-f0-9]+)[\"\x27]", cfg_html)
    if not m:
        raise RuntimeError("No se pudo obtener el onttoken de subida.")
    onttoken = m.group(1)

    # 4. Construir multipart form-data
    boundary = "----WebKitFormBoundaryHuaweiCfgUpload"
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode())
    body.extend(b'Content-Disposition: form-data; name="x.X_HW_Token"\r\n\r\n')
    body.extend(f"{onttoken}\r\n".encode())

    body.extend(f"--{boundary}\r\n".encode())
    body.extend(b'Content-Disposition: form-data; name="BrowsefilePath"; filename="hw_ctree.xml"\r\n')
    body.extend(b"Content-Type: text/xml\r\n\r\n")
    body.extend(file_bytes)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())

    upload_url = f"http://{ip}/html/ssmp/cfgfile/cfgfileupload.cgi?&RequestFile=html/ssmp/cfgfile/cfgfile.asp"
    req_upload = urllib.request.Request(upload_url, data=bytes(body))
    req_upload.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

    print(f"🚀 Enviando archivo de configuración ({len(file_bytes):,} bytes)...")
    with opener.open(req_upload, timeout=30) as r:
        _ = r.read()

    print("✅ Archivo cargado exitosamente. El módem se está reiniciando (~60 segundos)...")


def main():
    parser = argparse.ArgumentParser(
        description="📞 Gestor de Perfiles SIP VoIP para ONT Huawei (Telmex)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--disable", action="store_true", help="Desactiva los perfiles y líneas SIP en la configuración")
    group.add_argument("--enable", action="store_true", help="Reactiva los perfiles y líneas SIP en la configuración")

    parser.add_argument("--xml", default="output/hw_ctree_decrypted.xml", help="Ruta al XML descifrado")
    parser.add_argument("-o", "--output-bin", default="output/hw_ctree_sip_modified.xml", help="Ruta del paquete Type-1 cifrado")
    parser.add_argument("--template", default="output/hw_ctree_encrypted.xml", help="Plantilla cifrada original para CRC")
    parser.add_argument("--apply", action="store_true", help="Sube la configuración generada al módem y reinicia")
    parser.add_argument("--ip", default=None, help="IP del router")
    parser.add_argument("-u", "--user", default="TELMEX", help="Usuario web del router")
    parser.add_argument("-p", "--password", default=None, help="Contraseña web del módem")
    args = parser.parse_args()

    xml_path = Path(args.xml)
    if not xml_path.exists():
        print(f"❌ Error: No se encontró el archivo XML en {xml_path}")
        print("   Ejecuta primero 'huawei_hg8145v5_extractor.py' para descargar y descifrar la configuración.")
        sys.exit(1)

    temp_xml = xml_path.parent / "hw_ctree_temp_modified.xml"
    out_bin = Path(args.output_bin)
    tmpl_bin = Path(args.template) if Path(args.template).exists() else None

    # Modificar estado
    modify_sip_state(xml_path, temp_xml, enable=args.enable)

    # Empaquetar y verificar
    pack_ctree(temp_xml, out_bin, tmpl_bin)
    verify_pack(out_bin)

    if temp_xml.exists():
        temp_xml.unlink()

    # Cargar al módem si se especificó --apply
    if args.apply:
        ip = args.ip if args.ip else "192.168.1.254"
        password = args.password
        if not password:
            password = getpass.getpass(f"🔑 Ingrese el password del módem ({ip}) para aplicar cambios: ")
        upload_config(ip, args.user, password, out_bin)
    else:
        print("\n[ℹ️] Configuración empaquetada lista.")
        print("    Para cargarla directamente al módem y reiniciar, añade la bandera '--apply':")
        print(f"    python huawei_sip_manager.py {'--disable' if args.disable else '--enable'} --apply")


if __name__ == "__main__":
    main()
