#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nokia_sip_manager.py — Gestor de estado SIP para Nokia G-1425G-H (Fase 5).

Microfunciones implementadas:
    MF-5.1a  check_ont_voice_state()       (solo lectura)
    MF-5.2b  toggle_xml_sip_state()         (edición offline del XML de configuración)
    MF-5.2c  upload_nokia_configuration()   (restauración controlada vía usb.cgi?import)
    MF-5.3a  verify_ims_network_reachability() (checklist de red Asterisk/IMS, solo lectura)
"""
import re
import sys
import json
import argparse
import getpass
import uuid
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

import nokia_auth
import nokia_backup
from nokia_g1425gh_extractor import (_get_text, _parse_voice_info, _local_tag,
                                     _parse_wan_pppoe, _extract_block, _fields)

from nokia_config_packer import pack_nokia_configuration, verify_nokia_pack

ACTIVE_STATUSES = ("Enabled", "Up", "Registered", "1")

_VOICE_NODE_TAGS = {"voiceprofile", "voiceprofileinstance", "line", "lineinstance"}

# Formato de número de serie Nokia/Alcatel-Lucent validado por el JS del firmware
# (`isvalidSerialNum`): exactamente 12 caracteres alfanuméricos con prefijo `ALCL`
# (p.ej. `ALCLB472FD24`).
_RE_SERIAL_NUM = re.compile(r"^ALCL[A-Za-z0-9]{8}$")


def check_ont_voice_state(opener=None, ip="192.168.99.254", user="TELMEX",
                          password="", x_sid=None, timeout=10):
    """
    MF-5.1a — Diagnóstico (solo lectura) del cliente SIP interno de la ONT vía voice_info.cgi.

    Si `opener` es None abre su propia sesión (authenticate_nokia) y la cierra SIEMPRE
    con logout_nokia() en `finally`. Si recibe un opener, no toca su ciclo de vida.
    """
    managed = opener is None
    logout_status = None

    if managed:
        opener, _cj = nokia_auth.make_opener()
        opener.add_handler(nokia_auth._Pass2xxErrorProcessor())
        auth = nokia_auth.authenticate_nokia(opener, ip=ip, user=user,
                                             password=password, timeout=timeout)
        if not auth["success"]:
            raise RuntimeError(
                "MF-5.1a: no se pudo autenticar contra %s (status=%s). "
                "No se abrió ninguna sesión que deba cerrarse." % (ip, auth["status"])
            )
        x_sid = auth["x_sid"]

    try:
        status, html = _get_text(opener, ip, "voice_info.cgi", x_sid, timeout)
        if status != 200 or not html:
            raise RuntimeError("MF-5.1a: voice_info.cgi devolvió status=%s" % status)
        v = _parse_voice_info(html)
        line_status = v.get("LineStatus")
        line_status = "" if line_status is None else str(line_status).strip()
        is_active = line_status in ACTIVE_STATUSES

        if is_active:
            msg = ("El cliente SIP interno de la ONT está ACTIVO (LineStatus=%s): puede "
                   "colisionar con el registro de Asterisk; debe desactivarse." % line_status)
        elif line_status == "Disabled":
            msg = ("El cliente SIP interno de la ONT ya se encuentra INACTIVO "
                   "(LineStatus=Disabled): no hay colisión de registro desde el módem.")
        else:
            msg = ("Estado de línea no reconocido (LineStatus=%r); se considera inactivo."
                   % line_status)

        result = {
            "ip": ip,
            "is_active": is_active,
            "line_status": line_status,
            "ph_number": v.get("phNumber"),
            "proxy_ip": v.get("proxyIp"),
            "user_agent_ip": v.get("userAgentIp"),
            "reg_error_code": v.get("regErrorCode"),
            "reg_error_reason": v.get("regErrorReason"),
            "summary_message": msg,
        }
    finally:
        if managed:
            logout_status = nokia_auth.logout_nokia(opener, ip=ip, timeout=timeout)

    result["_session"] = {"self_managed": managed,
                          "logout_status": logout_status if managed else None}
    return result


def toggle_xml_sip_state(input_xml_path, output_xml_path, enable=False):
    """
    MF-5.2b — Edita (offline) el estado `Enable`/`Status` de los nodos de voz
    (`VoiceProfile`, `VoiceProfileInstance`, `Line`, `LineInstance`) de un XML
    de configuración Nokia/TR-104, sin tocar nada más del árbol.

    Equivalente a `modify_sip_state()` de `huawei_sip_manager.py`, pero
    tolerante a los DOS esquemas que usa el firmware Nokia (ver
    `parse_xml_voice_profile()` / MF-4.1b en `nokia_g1425gh_extractor.py`):

      a) Esquema por atributos TR-098/TR-104: el nodo de voz trae el estado
         en su propio atributo `Enable` o `Status` (p.ej.
         `<VoiceProfileInstance Enable="Enabled" ...>` /
         `<LineInstance Status="Enabled" ...>`). Se actualiza ese atributo.
      b) Esquema jerárquico por sub-elementos: el nodo de voz trae un hijo
         directo `<Enable>...</Enable>` o `<Status>...</Status>` con el
         estado como texto (p.ej. `<Line><Enable>Enabled</Enable></Line>`).
         Se actualiza el `.text` de ese hijo; si el nodo padre también tenía
         el atributo `Enable` (ambos esquemas mezclados), se sincroniza
         también.

    Entrada:
        input_xml_path:  ruta al XML de configuración de entrada (plano,
                          descifrado/descomprimido).
        output_xml_path:  ruta donde escribir el XML modificado.
        enable:           True -> "Enabled", False (por defecto) -> "Disabled".

    Salida:
        dict: {"voice_profiles_modified": int, "lines_modified": int,
               "target_state": str, "output_xml_path": str}

    Lanza:
        ValueError si no se encuentra ningún nodo de voz
        (`VoiceProfile`/`VoiceProfileInstance`/`Line`/`LineInstance`) en el XML
        — igual que `modify_sip_state()` en `huawei_sip_manager.py`.
    """
    input_xml_path = Path(input_xml_path)
    output_xml_path = Path(output_xml_path)

    tree = ET.parse(input_xml_path)
    root = tree.getroot()

    target_state = "Enabled" if enable else "Disabled"
    voice_profiles_modified = 0
    lines_modified = 0

    for elem in root.iter():
        local = _local_tag(elem.tag).lower()
        if local not in _VOICE_NODE_TAGS:
            continue

        is_voice_profile = local in ("voiceprofile", "voiceprofileinstance")

        # Esquema (b): ¿tiene hijo directo <Enable> o <Status>?
        state_child = None
        state_child_tag = None
        for child in list(elem):
            ctag = _local_tag(child.tag).lower()
            if ctag in ("enable", "status"):
                state_child = child
                state_child_tag = ctag
                break

        if state_child is not None:
            state_child.text = target_state
            # Si además el propio nodo tenía el atributo homónimo, sincronizarlo.
            attr_name = "Enable" if state_child_tag == "enable" else "Status"
            if attr_name in elem.attrib:
                elem.attrib[attr_name] = target_state
        else:
            # Esquema (a): actualizar el atributo propio (Enable o Status).
            if "Status" in elem.attrib and "Enable" not in elem.attrib:
                elem.attrib["Status"] = target_state
            else:
                elem.attrib["Enable"] = target_state

        if is_voice_profile:
            voice_profiles_modified += 1
        else:
            lines_modified += 1

    if voice_profiles_modified == 0 and lines_modified == 0:
        raise ValueError(
            "toggle_xml_sip_state: no se encontraron nodos VoiceProfile/"
            "VoiceProfileInstance/Line/LineInstance en %s" % input_xml_path
        )

    output_xml_path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(output_xml_path, encoding="utf-8", xml_declaration=True)

    return {
        "voice_profiles_modified": voice_profiles_modified,
        "lines_modified": lines_modified,
        "target_state": target_state,
        "output_xml_path": str(output_xml_path),
    }


def _is_valid_nokia_serial(serial_number):
    """Replica `isvalidSerialNum` del JS del firmware: 12 chars alfanuméricos, prefijo ALCL."""
    return bool(_RE_SERIAL_NUM.match(serial_number or ""))


def upload_nokia_configuration(opener=None, ip="192.168.99.254", cfg_path=None,
                               serial_number=None, user="TELMEX", password="",
                               x_sid=None, timeout=30):
    """
    MF-5.2c — Restauración controlada de un contenedor `config.cfg` Nokia vía
    `POST /usb.cgi?import` (o `?v=import&sl_num=<serial>`), equivalente al
    form nativo `import` de `usb.cgi?backup` (ver MF-2.3 §5b).

    PASO 0 (bloqueo de seguridad OBLIGATORIO, antes de tocar la red):
      1. `cfg_path` debe existir (si no, `FileNotFoundError` propagado de
         `Path.read_bytes()` / `verify_nokia_pack()`, sin abrir ninguna sesión).
      2. `verify_nokia_pack(cfg_path)` debe validar magic + CRC32 del contenedor
         (`ValueError` si falla) — igual chequeo que usa `pack_nokia_configuration()`
         (MF-5.2a) antes de escribir el `.cfg` a disco.
      3. Si se da `serial_number`, debe cumplir el formato `isvalidSerialNum` del
         JS Nokia (12 alfanuméricos, prefijo `ALCL`) o se lanza `ValueError`.

    Solo tras pasar las tres validaciones se abre una sesión (si `opener is None`)
    y se toca la red.

    Entrada:
      - opener:        sesión ya autenticada; si es `None`, se abre una propia con
                        `authenticate_nokia()` y se cierra SIEMPRE con `logout_nokia()`
                        en `finally` (incluso si el router ya no responde tras un
                        posible reinicio).
      - ip:             IP del router Nokia.
      - cfg_path:       ruta al `.cfg` ya empaquetado por `pack_nokia_configuration()`
                        (MF-5.2a) y validado por `verify_nokia_pack()`.
      - serial_number:  número de serie GPON opcional (`sl_num`); si se da, se usa
                        el endpoint `?v=import&sl_num=<serial>` en vez de `?import`.
      - user/password:  credenciales (solo si `opener is None`).
      - x_sid:          X-SID de sesión externa (si `opener` ya viene autenticado).
      - timeout:        timeout HTTP en segundos.

    Salida: dict con `status`, `endpoint`, `cfg_size`, `crc32`, `import_completed`,
            `response_preview`.
    """
    # --- PASO 0: bloqueo de seguridad, SIN tocar la red ----------------------
    cfg_path = Path(cfg_path)
    if not cfg_path.exists():
        raise FileNotFoundError(
            "upload_nokia_configuration: no existe el archivo .cfg: %s" % cfg_path
        )

    verification = verify_nokia_pack(cfg_path)  # ValueError si magic/CRC32 inválidos

    if serial_number is not None and not _is_valid_nokia_serial(serial_number):
        raise ValueError(
            "upload_nokia_configuration: serial_number inválido (%r); se espera el "
            "formato Nokia isvalidSerialNum (12 caracteres alfanuméricos con "
            "prefijo 'ALCL', p.ej. 'ALCLB472FD24')." % serial_number
        )

    cfg_bytes = cfg_path.read_bytes()

    managed = opener is None
    logout_status = None

    try:
        if managed:
            opener, _cj = nokia_auth.make_opener()
            opener.add_handler(nokia_auth._Pass2xxErrorProcessor())
            auth = nokia_auth.authenticate_nokia(opener, ip=ip, user=user,
                                                 password=password, timeout=timeout)
            if not auth["success"]:
                raise RuntimeError(
                    "MF-5.2c: no se pudo autenticar contra %s (status=%s). "
                    "No se abrió ninguna sesión que deba cerrarse." % (ip, auth["status"])
                )
            x_sid = auth["x_sid"]

        # --- csrf_token fresco: GET /usb.cgi?backup -------------------------
        backup_url = "http://%s/usb.cgi?backup" % ip
        bk_headers = {"X-Requested-With": "XMLHttpRequest"}
        if x_sid:
            bk_headers["X-SID"] = x_sid
        bk_req = urllib.request.Request(backup_url, headers=bk_headers)
        with opener.open(bk_req, timeout=timeout) as rb:
            bk_body = rb.read().decode("utf-8", errors="replace")
        csrf_token = nokia_backup._extract_csrf_token(bk_body)
        if not csrf_token:
            raise RuntimeError(
                "MF-5.2c: no se encontró csrf_token en GET /usb.cgi?backup"
            )

        # --- Cuerpo multipart/form-data con boundary limpio ------------------
        boundary = "----NokiaCfgUpload%s" % uuid.uuid4().hex
        parts = []
        parts.append(
            ("--%s\r\n"
             'Content-Disposition: form-data; name="csrf_val"\r\n\r\n'
             "\r\n" % boundary).encode("ascii")
        )
        parts.append(
            ("--%s\r\n"
             'Content-Disposition: form-data; name="csrf_token"\r\n\r\n'
             "%s\r\n" % (boundary, csrf_token)).encode("ascii")
        )
        parts.append(
            ("--%s\r\n"
             'Content-Disposition: form-data; name="filename"; filename="config.cfg"\r\n'
             "Content-Type: application/octet-stream\r\n\r\n" % boundary).encode("ascii")
        )
        parts.append(cfg_bytes)
        parts.append(("\r\n--%s--\r\n" % boundary).encode("ascii"))
        body = b"".join(parts)

        # --- Endpoint de subida (ver MF-2.3 §5b) -----------------------------
        if serial_number is None:
            endpoint = "http://%s/usb.cgi?import" % ip
        else:
            endpoint = "http://%s/usb.cgi?v=import&sl_num=%s" % (ip, serial_number)

        post_headers = {
            "Content-Type": "multipart/form-data; boundary=%s" % boundary,
            "Referer": backup_url,
        }
        if x_sid:
            post_headers["X-SID"] = x_sid
        post_req = urllib.request.Request(
            endpoint, data=body, method="POST", headers=post_headers,
        )

        try:
            with opener.open(post_req, timeout=timeout) as rp:
                status = getattr(rp, "status", rp.getcode())
                raw_resp = rp.read()
        except urllib.error.HTTPError as e:
            status = e.code
            raw_resp = e.read()

        response_text = raw_resp.decode("utf-8", errors="replace")
        import_completed = "Import Completed!" in response_text

        result = {
            "status": status,
            "endpoint": endpoint,
            "cfg_size": len(cfg_bytes),
            "crc32": verification.get("crc32_field"),
            "import_completed": import_completed,
            "response_preview": response_text[:500],
        }
    finally:
        if managed:
            logout_status = nokia_auth.logout_nokia(opener, ip=ip, timeout=timeout)

    result["_session"] = {"self_managed": managed,
                          "logout_status": logout_status if managed else None}
    return result


def _render_network_checklist(ip, registrar_host, proxy_host, voice_state, wan_state, alg_state):
    """Construye el Markdown del checklist de red para Asterisk (MF-5.3a)."""
    def ok(b):
        return "✅" if b else "⚠️"

    dns = wan_state.get("dns_servers") or "(no disponible)"
    voice_ok = not voice_state.get("is_active")
    wan_ok = bool(wan_state.get("connected") and wan_state.get("voip_service"))
    alg_ok = not alg_state.get("sip_alg_enabled")
    lines = [
        "# Checklist de red para Asterisk ↔ IMS Telmex",
        "",
        "Generado por `nokia_sip_manager.py --check-network` (MF-5.3a, solo lectura). Router: `%s`." % ip,
        "",
        "## 1. Resumen de Estado de Interoperabilidad",
        "",
        "| Chequeo | Estado | Detalle |",
        "| :--- | :---: | :--- |",
        "| Cliente SIP interno ONT (`voice_info.cgi`) | %s | LineStatus=`%s`, userAgentIp=`%s`, activo=%s |"
        % (ok(voice_ok), voice_state.get("line_status"), voice_state.get("user_agent_ip"),
           voice_state.get("is_active")),
        "| Conexión WAN VLAN 881 + servicio VOIP + DNS Telmex | %s | ConnectionStatus=`%s`, "
        "IP=`%s`, DNS=`%s`, ServiceList=`%s` |"
        % (ok(wan_ok), wan_state.get("connection_status"), wan_state.get("external_ip"),
           dns, wan_state.get("service_list")),
        "| SIP ALG (`nat_glb.cgi?v=alg`) | %s | SIPEnable=`%s` |"
        % (ok(alg_ok), alg_state.get("sip_enable_raw")),
        "",
    ]
    if voice_state.get("is_active"):
        lines += ["> ⚠️ El cliente SIP interno de la ONT está activo y puede colisionar con el "
                  "registro de Asterisk. Desactívelo (`--disable --apply`).", ""]
    if alg_state.get("sip_alg_enabled"):
        lines += ["> ⚠️ **Recomendación:** el SIP ALG está habilitado. Desmarque la casilla "
                  "\"SIP\" en *Security → DMZ and ALG* (`nat_glb.cgi?v=alg`) para evitar que el "
                  "NAT del Nokia reescriba de forma conflictiva las cabeceras SIP/SDP de Asterisk.", ""]
    lines += [
        "## 2. Configuración de DNS y Ruteo para el Servidor Asterisk",
        "",
        "`%s` (registrar) y `%s` (proxy) son dominios **internos de la red IMS de Telmex**: "
        "solo resuelven a través de los servidores DNS asignados a la WAN VLAN 881 del Nokia "
        "(actualmente: `%s`; típicamente `189.233.12.5` y `189.233.15.2`), o bien usando "
        "`%s` como DNS primario en el host de Asterisk (el router reenvía las consultas)."
        % (registrar_host, proxy_host, dns, ip),
        "",
        "```bash",
        "dig @%s %s +short" % (ip, registrar_host),
        "dig @%s %s +short" % (ip, proxy_host),
        "```",
        "",
        "El tráfico SIP/RTP de Asterisk debe salir por el Nokia (gateway de la LAN) para alcanzar "
        "la VLAN 881 de voz.",
        "",
        "## 3. Comandos de Verificación en Asterisk CLI",
        "",
        "```",
        "pjsip show registrations",
        "pjsip show endpoints",
        "pjsip set logger on",
        "```",
        "",
    ]
    return "\n".join(lines)


def verify_ims_network_reachability(opener=None, ip="192.168.99.254", user="TELMEX",
                                    password="", registrar_host="vims-h.telmex.com",
                                    proxy_host="nir8.norte.telmex.net", output_dir="output",
                                    x_sid=None, timeout=10):
    """
    MF-5.3a — Checklist de red (solo lectura) para Asterisk/IMS Telmex.

    Consulta: estado del cliente SIP interno (MF-5.1a), WAN VLAN 881 (VOIP/DNS) y SIP ALG
    (`nat_glb.cgi?v=alg`, variable `alg_obj`) y escribe `<output_dir>/asterisk_network_checklist.md`.
    Si `opener is None` abre su sesión y la cierra SIEMPRE con logout_nokia() en `finally`.
    """
    managed = opener is None
    logout_status = None

    if managed:
        opener, _cj = nokia_auth.make_opener()
        opener.add_handler(nokia_auth._Pass2xxErrorProcessor())
        auth = nokia_auth.authenticate_nokia(opener, ip=ip, user=user,
                                             password=password, timeout=timeout)
        if not auth["success"]:
            raise RuntimeError(
                "MF-5.3a: no se pudo autenticar contra %s (status=%s). "
                "No se abrió ninguna sesión que deba cerrarse." % (ip, auth["status"])
            )
        x_sid = auth["x_sid"]

    try:
        voice_state = check_ont_voice_state(opener=opener, ip=ip, x_sid=x_sid, timeout=timeout)

        st_cfg, wan_cfg_html = _get_text(opener, ip, "wan_config_glb.cgi", x_sid, timeout)
        st_sts, wan_sts_html = _get_text(opener, ip, "show_wan_status.cgi?ipv4", x_sid, timeout)
        wan = _parse_wan_pppoe(wan_cfg_html, wan_sts_html)
        service_list = wan.get("X_CT_COM_ServiceList") or ""
        wan_state = {
            "vlan": wan.get("VLANIDMark"),
            "connection_status": wan.get("ConnectionStatus"),
            "connected": wan.get("ConnectionStatus") == "Connected",
            "external_ip": wan.get("ExternalIPAddress"),
            "dns_servers": wan.get("DNSServers"),
            "service_list": service_list,
            "voip_service": "VOIP" in service_list.upper(),
            "http_status": {"wan_config_glb": st_cfg, "show_wan_status": st_sts},
        }

        st_alg, alg_html = _get_text(opener, ip, "nat_glb.cgi?v=alg", x_sid, timeout)
        alg = _fields(_extract_block(alg_html or "", "alg_obj") or "")
        sip_enable_raw = alg.get("SIPEnable")
        sip_alg_enabled = str(alg.get("SIPEnable", "")) == "1"
        alg_state = {
            "sip_alg_enabled": sip_alg_enabled,
            "sip_enable_raw": sip_enable_raw,
            "alg": alg,
            "http_status": st_alg,
            "recommendation": (
                "Desmarcar la casilla 'SIP' en Security -> DMZ and ALG (nat_glb.cgi?v=alg) "
                "para evitar que el NAT del Nokia reescriba cabeceras SIP/SDP de Asterisk."
                if sip_alg_enabled else None),
        }

        md = _render_network_checklist(ip, registrar_host, proxy_host,
                                       voice_state, wan_state, alg_state)
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path = out_dir / "asterisk_network_checklist.md"
        md_path.write_text(md, encoding="utf-8")

        result = {
            "voice_state": voice_state,
            "wan_state": wan_state,
            "alg_state": alg_state,
            "checklist_ready": bool(
                not voice_state.get("is_active") and wan_state["connected"]
                and wan_state["voip_service"] and not sip_alg_enabled),
            "checklist_md_path": str(md_path),
        }
    finally:
        if managed:
            logout_status = nokia_auth.logout_nokia(opener, ip=ip, timeout=timeout)

    result["_session"] = {"self_managed": managed,
                          "logout_status": logout_status if managed else None}
    return result


def _build_arg_parser():
    p = argparse.ArgumentParser(description="Gestor SIP Nokia G-1425G-H (Fase 5)")
    p.add_argument("--status", action="store_true",
                   help="MF-5.1a: diagnóstico del cliente SIP interno (solo lectura)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--disable", action="store_true",
                        help="MF-5.2b+MF-5.2a: desactiva SIP en el XML y empaqueta el .cfg (offline)")
    group.add_argument("--enable", action="store_true",
                        help="MF-5.2b+MF-5.2a: reactiva SIP en el XML y empaqueta el .cfg (offline)")
    p.add_argument("--xml", default="output/nokia_ctree_decrypted.xml",
                   help="Ruta al XML de configuración de entrada (--disable/--enable)")
    p.add_argument("-o", "--output-cfg", default="output/nokia_cfg_sip_modified.cfg",
                   help="Ruta del contenedor .cfg de salida (--disable/--enable)")
    p.add_argument("--template", default=None,
                   help="Backup .cfg real opcional para preservar magic/fw_magic (--disable/--enable)")
    p.add_argument("--check-network", action="store_true",
                   help="MF-5.3a: checklist de red para Asterisk/IMS (solo lectura)")
    p.add_argument("--out", default="output",
                   help="Directorio de salida del checklist (--check-network)")
    p.add_argument("--apply", action="store_true",
                   help="MF-5.2c: además de empaquetar, sube el .cfg al router vía "
                        "usb.cgi?import (--disable/--enable). Sin esta bandera, el "
                        "flujo queda 100%% offline.")
    p.add_argument("--serial", default=None,
                   help="Número de serie GPON (formato ALCLxxxxxxxx) para "
                        "usb.cgi?v=import&sl_num=... (MF-5.2c, requiere --apply)")
    p.add_argument("--ip", default="192.168.99.254")
    p.add_argument("-u", "--user", default="TELMEX")
    p.add_argument("-p", "--password", default=None)
    p.add_argument("--timeout", type=int, default=10)
    return p


def main(argv=None):
    args = _build_arg_parser().parse_args(argv)

    if args.disable or args.enable:
        xml_path = Path(args.xml)
        if not xml_path.exists():
            print("ERROR: no se encontró el XML de entrada: %s" % xml_path, file=sys.stderr)
            return 1

        out_cfg_path = Path(args.output_cfg)
        temp_xml = out_cfg_path.parent / "nokia_ctree_temp_modified.xml"

        try:
            toggle_result = toggle_xml_sip_state(xml_path, temp_xml, enable=args.enable)
        except ValueError as e:
            print("ERROR: %s" % e, file=sys.stderr)
            return 1
        print(json.dumps(toggle_result, indent=2, ensure_ascii=False))

        try:
            pack_result = pack_nokia_configuration(
                temp_xml, out_cfg_path,
                template_raw_path=args.template if args.template else None,
            )
        finally:
            if temp_xml.exists():
                temp_xml.unlink()

        print(json.dumps(pack_result, indent=2, ensure_ascii=False))

        if not args.apply:
            print("\n[ℹ️] Configuración %s empaquetada en modo offline (sin subir al "
                  "router; use --apply para subirla)." % ("Disabled" if args.disable else "Enabled"))
            return 0

        password = args.password if args.password is not None else getpass.getpass("Contraseña: ")
        try:
            upload_result = upload_nokia_configuration(
                ip=args.ip, cfg_path=out_cfg_path, serial_number=args.serial,
                user=args.user, password=password, timeout=args.timeout,
            )
        except (FileNotFoundError, ValueError, RuntimeError) as e:
            print("ERROR: %s" % e, file=sys.stderr)
            return 1
        print(json.dumps(upload_result, indent=2, ensure_ascii=False))
        print("\n[%s] Configuración %s subida al router (%s)."
              % ("✅" if upload_result.get("import_completed") else "⚠️",
                 "Disabled" if args.disable else "Enabled",
                 upload_result.get("endpoint")))
        return 0

    if args.check_network:
        password = args.password if args.password is not None else getpass.getpass("Contraseña: ")
        try:
            r = verify_ims_network_reachability(ip=args.ip, user=args.user, password=password,
                                                output_dir=args.out, timeout=args.timeout)
        except RuntimeError as e:
            print("ERROR: %s" % e, file=sys.stderr)
            return 1
        print(json.dumps(r, indent=2, ensure_ascii=False))
        print("\nChecklist: %s (checklist_ready=%s)" % (r["checklist_md_path"], r["checklist_ready"]))
        return 0

    if not args.status:
        print("Indique una acción (--status | --check-network | --disable | --enable).", file=sys.stderr)
        return 2
    password = args.password if args.password is not None else getpass.getpass("Contraseña: ")
    try:
        r = check_ont_voice_state(ip=args.ip, user=args.user, password=password,
                                  timeout=args.timeout)
    except RuntimeError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1
    print(json.dumps(r, indent=2, ensure_ascii=False))
    print("\n" + r["summary_message"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
