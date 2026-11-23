#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎛️ Lanzador Interactivo Unificado — Telmex ONT Extractor & Gestor VoIP SIP / Asterisk
=====================================================================================
Menú interactivo multiplataforma (Windows / macOS / Linux) invocado automáticamente
por `setup_and_run.bat` y `setup_and_run.sh`.

Permite configurar y cambiar en cualquier momento:
  1. Marca / Modelo de ONT (Huawei HG8145V5 / HG8145V5V3 / HG8245 vs. Nokia G-1425G-H)
  2. Dirección IP del módem (con auto-detección de puerta de enlace predeterminada)
  3. Usuario de administración web (por defecto: TELMEX)
  4. Contraseña del módem (o selección rápida de perfiles preconfigurados)
  5. Carpeta de salida para los reportes y plantillas de Asterisk
"""

import os
import sys
import json
import getpass
from pathlib import Path

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import huawei_hg8145v5_extractor as huawei_ext
import huawei_sip_manager
import nokia_g1425gh_extractor as nokia_ext
import nokia_sip_manager
import nokia_backup


# Perfiles rápidos de tus módems identificados para ahorrar escritura si lo deseas
KNOWN_PRESETS = [
    {
        "label": "Nokia G-1425G-H (SN: ALCLB472FD24)",
        "brand": "NOKIA",
        "model": "Nokia G-1425G-H",
        "ip": "192.168.99.254",
        "user": "TELMEX",
        "password": "sf3h5zkdtA",
        "out_dir": "output_nokia",
    },
    {
        "label": "Huawei HG8145V5 [Etiqueta B4] (INFINITUME69F)",
        "brand": "HUAWEI",
        "model": "Huawei EchoLife HG8145V5",
        "ip": "",  # Auto-detectar
        "user": "TELMEX",
        "password": "mb8HRCJcaE",
        "out_dir": "output_B4",
    },
    {
        "label": "Huawei HG8145V5 [Etiqueta B3] (INFINITUM5A9F)",
        "brand": "HUAWEI",
        "model": "Huawei EchoLife HG8145V5",
        "ip": "",  # Auto-detectar
        "user": "TELMEX",
        "password": "SZBnwDu9b2",
        "out_dir": "output_B3",
    },
    {
        "label": "Huawei HG8145V5V3 Negro (INFINITUM7AB2)",
        "brand": "HUAWEI",
        "model": "Huawei EchoLife HG8145V5V3",
        "ip": "",  # Auto-detectar
        "user": "TELMEX",
        "password": "4c9RqGuNwE",
        "out_dir": "output_7AB2",
    },
]


def _probe_router_brand(ip: str, timeout: float = 3.0) -> tuple:
    """
    Sonda HTTP rápida (GET /) para detectar automáticamente si el módem en `ip`
    es Huawei EchoLife o Nokia GPON Home Gateway sin importar qué IP tenga.
    Devuelve (brand, model_label, detected_ok).
    """
    import urllib.request

    try:
        req = urllib.request.Request(
            f"http://{ip}/",
            headers={"User-Agent": "Mozilla/5.0 (compatible; telmex-launcher)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            html = r.read(32768).decode("utf-8", errors="ignore")
    except Exception:
        html = ""

    # 1. Huella Nokia (pubkey RSA + crypto_page.js / js_glb)
    if "var pubkey" in html and "BEGIN PUBLIC KEY" in html:
        return ("NOKIA", "Nokia G-1425G-H / G-2425G-A (Auto-detectado)", True)

    # 2. Huella Huawei (GetRandCount.asp o marcadores HW en index/login)
    if any(k in html for k in ("GetRandCount.asp", "X_HW_Token", "hw_ctree", "frame.asp", "Cuscss")):
        return ("HUAWEI", "Huawei EchoLife HG8145V5 / HG8145V5V3 (Auto-detectado)", True)

    try:
        req_hw = urllib.request.Request(f"http://{ip}/asp/GetRandCount.asp", data=b"")
        with urllib.request.urlopen(req_hw, timeout=timeout) as r2:
            tok = r2.read(128).decode("utf-8", errors="ignore").strip().lstrip("\ufeff")
            if tok and len(tok) >= 16 and all(c in "0123456789abcdefABCDEF" for c in tok):
                return ("HUAWEI", "Huawei EchoLife HG8145V5 / HG8145V5V3 (Auto-detectado)", True)
    except Exception:
        pass

    return ("HUAWEI", "Huawei EchoLife HG8145V5 / HG8145V5V3", False)


def _auto_sync_brand(state: dict):
    """Sincroniza automáticamente la marca del módem sondeando HTTP en state['ip']."""
    brand, model, ok = _probe_router_brand(state["ip"])
    if ok:
        if state["brand"] != brand:
            print(f"🔎 Módem detectado automáticamente en http://{state['ip']}/ -> [{brand}] {model}")
        state["brand"] = brand
        state["model"] = model
    return ok


def _mask_pwd(pwd: str) -> str:
    if not pwd:
        return "(sin definir — se solicitará al ejecutar)"
    if len(pwd) <= 4:
        return "*" * len(pwd)
    return pwd[:2] + ("*" * (len(pwd) - 4)) + pwd[-2:]


def _prompt(msg: str, default: str = "") -> str:
    val = input(msg).strip()
    return val if val else default


def _pause():
    input("\nPresiona [Enter] para volver al menú principal...")


def _select_model(state: dict):
    print("\n" + "=" * 72)
    print(" 📡 SELECCIÓN DE MARCA Y MODELO DE MÓDEM / ONT")
    print("=" * 72)
    print("  [1] Huawei EchoLife HG8145V5 / HG8145V5V3 / HG8245 / EG8145")
    print("  [2] Nokia G-1425G-H / G-2425G-A (GPON Home Gateway)")
    print("-" * 72)
    print("  ⚡ PERFILES RÁPIDOS GUARDADOS (carga modelo + usuario + contraseña):")
    for idx, preset in enumerate(KNOWN_PRESETS, start=3):
        print(f"  [{idx}] {preset['label']}  (Pass: {preset['password']})")
    print("=" * 72)

    choice = _prompt("Selecciona una opción [1-6]: ", "1")
    if choice == "1":
        state["brand"] = "HUAWEI"
        state["model"] = "Huawei EchoLife HG8145V5 / HG8145V5V3"
    elif choice == "2":
        state["brand"] = "NOKIA"
        state["model"] = "Nokia G-1425G-H"
    elif choice.isdigit() and 3 <= int(choice) < 3 + len(KNOWN_PRESETS):
        p = KNOWN_PRESETS[int(choice) - 3]
        state["brand"] = p["brand"]
        state["model"] = p["model"]
        state["ip"] = p["ip"] or huawei_ext.detect_default_gateway()
        state["user"] = p["user"]
        state["password"] = p["password"]
        state["out_dir"] = p["out_dir"]
        print(f"\n✅ Perfil cargado: {p['label']} -> IP {state['ip']}, salida en '{state['out_dir']}'")


def _configure_credentials(state: dict):
    print("\n" + "=" * 72)
    print(" 🔑 CONFIGURAR IP, USUARIO Y CONTRASEÑA DEL MÓDEM")
    print("=" * 72)
    detected_gw = huawei_ext.detect_default_gateway()
    ip_default = state["ip"] or detected_gw
    state["ip"] = _prompt(
        f"  🌐 Dirección IP del módem [Enter para '{ip_default}', 'auto' para {detected_gw}]: ",
        ip_default,
    )
    if state["ip"].lower() == "auto":
        state["ip"] = detected_gw
    _auto_sync_brand(state)

    state["user"] = _prompt(
        f"  👤 Usuario de acceso web [Enter para '{state['user']}']: ",
        state["user"],
    )

    print("  🔐 Contraseña web del módem:")
    print("     (Escribe la contraseña o deja vacío y presiona Enter para conservar la actual)")
    new_pwd = getpass.getpass("     Contraseña (oculta) [o Enter]: ").strip()
    if not new_pwd:
        # Por si el usuario prefiere escribirla visible o en terminales donde getpass no hace eco
        vis = input("     ¿Deseas escribirla visible? (escríbela aquí o presiona Enter para omitir): ").strip()
        if vis:
            new_pwd = vis
    if new_pwd:
        state["password"] = new_pwd

    state["out_dir"] = _prompt(
        f"  📂 Carpeta de salida [Enter para '{state['out_dir']}']: ",
        state["out_dir"],
    )
    print("\n✅ Parámetros actualizados correctamente.")


def _ensure_password(state: dict) -> str:
    if state["password"]:
        return state["password"]
    pwd = getpass.getpass(f"🔑 Ingresa la contraseña web para {state['user']}@{state['ip']}: ").strip()
    if not pwd:
        pwd = input("🔑 Ingresa la contraseña web (visible): ").strip()
    state["password"] = pwd
    return pwd


def _run_extraction(state: dict):
    _auto_sync_brand(state)
    pwd = _ensure_password(state)
    ip = state["ip"] or huawei_ext.detect_default_gateway()
    user = state["user"]
    out_dir = state["out_dir"]

    print("\n" + "=" * 72)
    print(f" 🚀 EJECUTANDO EXTRACCIÓN EN {state['model']} ({user}@{ip})")
    print("=" * 72)

    if state["brand"] == "HUAWEI":
        extractor = huawei_ext.HuaweiHG8145V5Extractor(
            ip=ip, user=user, password=pwd, output_dir=out_dir
        )
        try:
            extractor.login()
            raw_bytes = extractor.download_config()
            xml_text = extractor.decrypt_ctree(raw_bytes)
            res = extractor.parse_credentials(xml_text)
            print("\n" + "=" * 68)
            print("📋 PARÁMETROS CRÍTICOS EXTRAÍDOS (HUAWEI):")
            print("=" * 68)
            print(f"  🌐 Usuario WAN PPPoE:    {res['pppoe'].get('username', 'N/A')}")
            print(f"  🔑 Contraseña PPPoE:     {res['pppoe'].get('password', 'N/A')}")
            print(f"  🏷️  VLAN ID (802.1Q):     {res['pppoe'].get('vlan_id', '881')}")
            print(f"  📞 Usuario SIP (Digest): {res['sip_voip'].get('auth_username', 'N/A')}")
            print(f"  🔐 Contraseña SIP:       {res['sip_voip'].get('auth_password', 'N/A')}")
            print(f"  🌐 Servidor Registrar:   {res['sip_voip'].get('registrar_server', 'vims-h.telmex.com')}")
            print(f"  🌐 Outbound Proxy:       {res['sip_voip'].get('outbound_proxy', 'nir8.norte.telmex.net')}")
            print("=" * 68)
        except Exception as e:
            print(f"\n❌ Error durante la extracción Huawei: {e}")
    else:
        try:
            rc = nokia_ext.main(["--ip", ip, "-u", user, "-p", pwd, "-o", out_dir])
            if rc == 0:
                print(f"\n✅ Extracción Nokia completada en '{out_dir}/'")
        except Exception as e:
            print(f"\n❌ Error durante la extracción Nokia: {e}")


def _run_sip_action(state: dict, enable: bool):
    _auto_sync_brand(state)
    pwd = _ensure_password(state)
    ip = state["ip"] or huawei_ext.detect_default_gateway()
    user = state["user"]
    out_dir = Path(state["out_dir"])
    action_label = "REACTIVAR (--enable)" if enable else "DESACTIVAR (--disable)"

    print("\n" + "=" * 72)
    print(f" 📞 {action_label} CLIENTE SIP INTERNO EN {state['model']} ({ip})")
    print("=" * 72)

    if state["brand"] == "HUAWEI":
        xml_path = out_dir / "hw_ctree_decrypted.xml"
        if not xml_path.exists():
            print(f"⚠️ No se encontró {xml_path}. Ejecutando primero la extracción...")
            _run_extraction(state)
            if not xml_path.exists():
                return

        temp_xml = out_dir / "hw_ctree_temp_modified.xml"
        out_bin = out_dir / "hw_ctree_sip_modified.xml"
        tmpl_bin = out_dir / "hw_ctree_encrypted.xml"
        try:
            huawei_sip_manager.modify_sip_state(xml_path, temp_xml, enable=enable)
            huawei_sip_manager.pack_ctree(
                temp_xml, out_bin, tmpl_bin if tmpl_bin.exists() else None
            )
            huawei_sip_manager.verify_pack(out_bin)
            if temp_xml.exists():
                temp_xml.unlink()

            confirm = _prompt(
                f"\n¿Deseas subir la configuración modificada al módem Huawei ({ip}) y reiniciarlo ahora? [s/N]: ",
                "n",
            )
            if confirm.lower() in ("s", "si", "sí", "y", "yes"):
                huawei_sip_manager.upload_config(ip, user, pwd, out_bin)
            else:
                print(f"ℹ️ Archivo empaquetado guardado en: {out_bin} (no se subió al módem).")
        except Exception as e:
            print(f"\n❌ Error gestionando SIP en Huawei: {e}")
    else:
        xml_default = str(out_dir / "nokia_ctree_decrypted.xml")
        xml_in = _prompt(f"Ruta al XML de configuración Nokia [{xml_default}]: ", xml_default)
        if not Path(xml_in).exists():
            print(f"❌ No existe el archivo XML: {xml_in}")
            return
        out_cfg = str(out_dir / "nokia_cfg_sip_modified.cfg")
        flag = "--enable" if enable else "--disable"
        confirm = _prompt(
            f"¿Deseas aplicar y subir el contenedor .cfg al Nokia ({ip}) tras empaquetar? [s/N]: ",
            "n",
        )
        argv = [flag, "--xml", xml_in, "-o", out_cfg, "--ip", ip, "-u", user, "-p", pwd]
        if confirm.lower() in ("s", "si", "sí", "y", "yes"):
            argv.append("--apply")
        nokia_sip_manager.main(argv)


def _run_diagnostics(state: dict):
    _auto_sync_brand(state)
    ip = state["ip"] or huawei_ext.detect_default_gateway()
    user = state["user"]
    out_dir = state["out_dir"]

    if state["brand"] == "NOKIA":
        pwd = _ensure_password(state)
        print("\n" + "=" * 72)
        print(f" 🩺 DIAGNÓSTICO DE RED, SIP ALG Y ESTADO VOIP EN NOKIA ({ip})")
        print("=" * 72)
        try:
            nokia_sip_manager.main(["--check-network", "--ip", ip, "-u", user, "-p", pwd, "--out", out_dir])
            print("\n📥 ¿Deseas descargar también el respaldo binario config.cfg del Nokia?")
            dl = _prompt("   Descargar config.cfg a '%s' [s/N]: " % out_dir, "n")
            if dl.lower() in ("s", "si", "sí", "y", "yes"):
                res = nokia_backup.download_nokia_backup(
                    opener=None, ip=ip, output_dir=out_dir, user=user, password=pwd
                )
                print(json.dumps(res, indent=2, ensure_ascii=False))
        except Exception as e:
            print(f"\n❌ Error durante el diagnóstico Nokia en {ip}: {e}")
    else:
        print(f"\n🔎 El módem en {ip} es un HUAWEI ({state['model']}).")
        print("   Ejecutando extracción y descifrado completo de Huawei (hw_ctree.xml + Asterisk)...")
        _run_extraction(state)


def _run_custom_asterisk_generator(state: dict):
    out_dir = state["out_dir"]
    print("\n" + "=" * 72)
    print(" ☎️  GENERADOR MANUAL DE PLANTILLAS ASTERISK (PJSIP / CHAN_SIP)")
    print("=" * 72)
    num = _prompt("  📞 Número telefónico SIP (ej. +525512345678): ", "+5255XXXXXXXX")
    usr = _prompt(f"  👤 AuthUserName SIP [Enter para '{num}']: ", num)
    pwd = _prompt("  🔐 Contraseña SIP (AuthPassword): ", "TU_PASSWORD_SIP_IMS")
    reg = _prompt("  🌐 Servidor Registrar [Enter para 'vims-h.telmex.com']: ", "vims-h.telmex.com")
    prx = _prompt("  🌐 Outbound Proxy [Enter para 'nir8.norte.telmex.net']: ", "nir8.norte.telmex.net")

    sip_data = {
        "directory_number": num,
        "uri": num,
        "auth_username": usr,
        "auth_password": pwd,
        "registrar_server": reg,
        "registrar_server_port": "5060",
        "outbound_proxy": prx,
        "outbound_proxy_port": "5060",
        "port": "5060",
    }
    pjsip_p = nokia_ext.render_asterisk_pjsip_conf(sip_data, output_dir=out_dir)
    sip_p, ext_p = nokia_ext.render_asterisk_sip_conf(sip_data, output_dir=out_dir)
    print("\n✅ Plantillas Asterisk generadas exitosamente:")
    print(f"   - {pjsip_p}")
    print(f"   - {sip_p}")
    print(f"   - {ext_p}")


def main():
    detected_gw = huawei_ext.detect_default_gateway()
    brand, model, _ = _probe_router_brand(detected_gw)
    state = {
        "brand": brand,
        "model": model,
        "ip": detected_gw,
        "user": "TELMEX",
        "password": "",
        "out_dir": "output",
    }

    while True:
        print("\n" + "=" * 72)
        print(" 📡 TELMEX ONT EXTRACTOR & GESTOR SIP / ASTERISK — MENÚ INTERACTIVO")
        print("=" * 72)
        print(f"   • Marca / Modelo actual : [{state['brand']}] {state['model']}")
        print(f"   • Dirección IP objetivo : {state['ip']}")
        print(f"   • Usuario Web           : {state['user']}")
        print(f"   • Contraseña Web        : {_mask_pwd(state['password'])}")
        print(f"   • Carpeta de salida     : {state['out_dir']}/")
        print("-" * 72)
        print("  CONFIGURACIÓN DE OBJETIVO:")
        print("   [1] Cambiar Marca / Modelo (Huawei / Nokia) o Cargar Perfil Rápido")
        print("   [2] Configurar IP, Usuario, Contraseña y Carpeta de Salida")
        print("-" * 72)
        print("  ACCIONES SOBRE EL MÓDEM Y ASTERISK:")
        print("   [3] Extraer Credenciales (PPPoE, Wi-Fi, VoIP SIP) y Generar Config Asterisk")
        print("   [4] Desactivar Cliente SIP Interno en el Módem (--disable para liberar línea)")
        print("   [5] Reactivar Cliente SIP Interno en el Módem (--enable)")
        print("   [6] Diagnóstico de Red / SIP ALG / Descarga de Backup Crudo (Nokia)")
        print("   [7] Generar Plantillas de Asterisk Ingresando Datos SIP Manualmente")
        print("   [0] Salir")
        print("=" * 72)

        opt = _prompt("Selecciona una opción [0-7]: ", "")
        if opt == "1":
            _select_model(state)
        elif opt == "2":
            _configure_credentials(state)
        elif opt == "3":
            _run_extraction(state)
            _pause()
        elif opt == "4":
            _run_sip_action(state, enable=False)
            _pause()
        elif opt == "5":
            _run_sip_action(state, enable=True)
            _pause()
        elif opt == "6":
            _run_diagnostics(state)
            _pause()
        elif opt == "7":
            _run_custom_asterisk_generator(state)
            _pause()
        elif opt == "0":
            print("\n👋 Saliendo del extractor. ¡Hasta luego!")
            break
        else:
            print("\n⚠️ Opción no válida. Elige un número entre 0 y 7.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Interrumpido por el usuario.")
        sys.exit(0)
