#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nokia_g1425gh_extractor.py — Fase 4 (Extracción Estructurada, Reportes y Plantillas Asterisk)

MF-4.1a  collect_web_telemetry(opener, ip)  -> Recolección en modo de SOLO LECTURA de la
          telemetría de red/dispositivo/voz/WLAN/GPON/syslog expuesta directamente por los
          CGIs del Nokia G-1425G-H (sin requerir el backup .cfg ni descifrado alguno).

Este módulo es deliberadamente de solo lectura: no modifica ningún parámetro del router,
no envía ningún `?set`/`?config`/`?import`, y cierra siempre la sesión HTTP que haya abierto
él mismo (si recibe un `opener` ya autenticado de otro llamador, respeta ese ciclo de vida
y NO hace login/logout).

Importa `nokia_auth.py` (Fase 2) para reutilizar: make_opener(), authenticate_nokia(),
logout_nokia(), _Pass2xxErrorProcessor y el envoltorio híbrido RSA+AES
(get_login_challenge/encrypt_post_data) necesario para el único endpoint que exige una
petición cifrada incluso en modo lectura: `log.cgi?vlog_glb`.
"""

import os
import sys
import re
import json
import binascii
import argparse
import getpass
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import nokia_auth


# --------------------------------------------------------------------------- #
#  Helpers HTTP de solo lectura (GET/POST simples sobre el opener autenticado)
# --------------------------------------------------------------------------- #
def _get_text(opener, ip, target, x_sid=None, timeout=10):
    """GET http://<ip>/<target> y devuelve (status, texto_decodificado)."""
    url = "http://%s/%s" % (ip, target.lstrip("/"))
    headers = {"X-Requested-With": "XMLHttpRequest"}
    if x_sid:
        headers["X-SID"] = x_sid
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as r:
            status = getattr(r, "status", r.getcode())
            body = r.read()
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read()
    except Exception as e:  # noqa: BLE001  (timeout / conexión)
        return None, ""
    return status, body.decode("utf-8", errors="replace")


def _post_encrypted(opener, ip, target, plaintext, x_sid=None, timeout=10):
    """
    POST http://<ip>/<target> replicando el flujo real del frontend JS de Nokia.
    Nota importante: en las páginas como `log.cgi`, el hook global `$(document).ajaxSend`
    verifica si `settings.data` contiene `csrf_token`; si no lo contiene (o si el botón
    ya cifró y el hook vuelve a cifrar cuando `log.cgi` hace `encrypt_post_data` antes de
    `$.ajax`), el servidor espera el `csrf_token=<token_real_de_sesion>` (ej.
    `settings.data = 'csrf_token=MHlyCWWZDOaogecD'`) cifrado con `encrypt_post_data`, o bien
    el doble cifrado que produce `#logbtn` + `ajaxSend`. Soportamos ambos automáticamente.
    """
    base_page = target.split("?", 1)[0]
    status, html = _get_text(opener, ip, base_page, x_sid, timeout)
    m = nokia_auth._RE_PUBKEY.search(html or "")
    if not m:
        return None, "", "no se pudo leer var pubkey de %s" % base_page
    pubkey = nokia_auth._normalize_pem(m.group(1))

    # Extraer el csrf_token real de la sesión embebido en el ajaxSend de la página
    m_csrf = re.search(r"csrf_token=([A-Za-z0-9]{8,64})", html or "")
    real_csrf = m_csrf.group(1) if m_csrf else None

    # En log.cgi (#logbtn):
    #   1) getppppostdata = "csrf_token=checkcsrf_token"
    #   2) encryptdata = crypto_page.encrypt_post_data(pubkey, getppppostdata) -> "encrypted=1&ct=...&ck=..."
    #   3) $.ajax({type:'POST', data: encryptdata})
    #   4) El hook $(document).ajaxSend intercepta el POST: como `encryptdata` NO contiene la
    #      subcadena literal "csrf_token", le concatena `&csrf_token=<real_csrf>` y vuelve a
    #      llamar a `crypto_page.encrypt_post_data(pubkey, settings.data)`!
    if plaintext == "csrf_token=checkcsrf_token" and real_csrf:
        inner = nokia_auth.encrypt_post_data(pubkey, plaintext)
        outer_plain = inner + "&csrf_token=" + real_csrf
        body = nokia_auth.encrypt_post_data(pubkey, outer_plain).encode("ascii")
    else:
        if real_csrf and "csrf_token=" not in plaintext:
            plaintext = (plaintext + "&" if plaintext else "") + "csrf_token=" + real_csrf
        body = nokia_auth.encrypt_post_data(pubkey, plaintext).encode("ascii")

    url = "http://%s/%s" % (ip, target.lstrip("/"))
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
               "X-Requested-With": "XMLHttpRequest",
               "Referer": "http://%s/%s" % (ip, base_page.lstrip("/"))}
    if x_sid:
        headers["X-SID"] = x_sid
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with opener.open(req, timeout=timeout) as r:
            status = getattr(r, "status", r.getcode())
            resp = r.read()
    except urllib.error.HTTPError as e:
        status = e.code
        resp = e.read()
    except Exception as e:  # noqa: BLE001
        return None, "", repr(e)
    return status, resp.decode("utf-8", errors="replace"), None


# --------------------------------------------------------------------------- #
#  Mini-parser de literales JS (var x = {...}; / var x = [...];)
# --------------------------------------------------------------------------- #
_FIELD_RE = re.compile(
    r"""["']?([A-Za-z0-9_]+)["']?\s*:\s*(?:'([^']*)'|"([^"]*)"|(-?\d+(?:\.\d+)?))"""
)


def _fields(blob):
    """Extrae pares clave:valor escalares de un fragmento JS (no respeta anidamiento,
    pero conserva la PRIMERA aparición de cada clave, que en los literales del Nokia
    corresponde siempre al nivel superior del objeto)."""
    out = {}
    if not blob:
        return out
    for m in _FIELD_RE.finditer(blob):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else (
            m.group(3) if m.group(3) is not None else m.group(4))
        if key not in out:
            out[key] = val
    return out


def _match_braces(text, start):
    """Devuelve el substring balanceado text[start:...] donde text[start] == '{' o '['."""
    open_c, close_c = text[start], {"{": "}", "[": "]"}[text[start]]
    depth, i = 0, start
    while i < len(text):
        c = text[i]
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1
    return text[start:]


def _extract_block(text, varname):
    """Primer bloque balanceado tras `var <varname> = {` o `var <varname> = [`."""
    m = re.search(r"var\s+" + re.escape(varname) + r"\s*=\s*([\{\[])", text)
    if not m:
        return None
    return _match_braces(text, m.start(1))


def _extract_indexed_object(text, varname):
    """Para literales tipo `var wlan_config = {1:{...}, 2:{...}, ...};` devuelve
    {idx:int -> sub_objeto_balanceado_str}."""
    blob = _extract_block(text, varname)
    if not blob or blob[0] != "{":
        return {}
    inner = blob[1:-1]
    out = {}
    pos = 0
    idx_re = re.compile(r"(\d+)\s*:\s*\{")
    while True:
        im = idx_re.search(inner, pos)
        if not im:
            break
        idx = int(im.group(1))
        sub_start = im.end() - 1
        sub = _match_braces(inner, sub_start)
        out[idx] = sub
        pos = sub_start + len(sub)  # saltar todo el sub-objeto: evita capturar
        # indices anidados (p.ej. psks:{1:{PreSharedKey:...}}) como si fueran
        # entradas de nivel superior.
    return out


def _hex_to_ascii_if_printable(hex_str):
    try:
        raw = binascii.unhexlify(hex_str)
    except (binascii.Error, ValueError):
        return None
    if raw and all(32 <= b < 127 for b in raw):
        return raw.decode("ascii")
    return None


# --------------------------------------------------------------------------- #
#  Parsers por endpoint (uno por página de estado consultada)
# --------------------------------------------------------------------------- #
def _parse_device_status(html):
    dev = _fields(_extract_block(html, "dev_info") or "")
    gpon = _fields(_extract_block(html, "gpon_status") or "")
    device_info = {
        "ModelName": dev.get("ModelName"),
        "ProductClass": dev.get("ProductClass"),
        "Manufacturer": dev.get("Manufacturer"),
        "ManufacturerOUI": dev.get("ManufacturerOUI"),
        "SerialNumber": dev.get("SerialNumber"),
        "HardwareVersion": dev.get("HardwareVersion"),
        "SoftwareVersion": dev.get("SoftwareVersion"),
        "AdditionalSoftwareVersion": dev.get("AdditionalSoftwareVersion"),
        "Chipset": dev.get("X_ASB_COM_Chipset"),
        "ProvisioningCode": dev.get("ProvisioningCode"),
        "UpTime_seconds": dev.get("UpTime"),
        "FirstUseDate": dev.get("FirstUseDate"),
        "gpon_status": {
            "Enable": gpon.get("Enable"),
            "Status": gpon.get("Status"),
            "TXPower": gpon.get("TXPower"),
            "RXPower": gpon.get("RXPower"),
            "TransceiverTemperature": gpon.get("TransceiverTemperature"),
        },
    }
    return device_info


def _parse_wan_pppoe(wan_config_glb_html, show_wan_status_html):
    """
    Combina:
      - wan_config_glb.cgi  -> Username/Password(enmascarada)/VLANIDMark/InterfaceMtu/
                                X_CT_COM_ServiceList/DNSServers/ExternalIPAddress
      - show_wan_status.cgi?ipv4 -> ConnectionStatus/MACAddress/Uptime/RemoteIPAddress
                                     (campos que wan_config_glb.cgi no expone)
    Ambos CGIs listan primero la conexión WAN#1 (VLAN 881, PPPoE VOIP/TR069/INTERNET/OTHER),
    por lo que tomar la PRIMERA coincidencia de cada campo corresponde a esa conexión.
    """
    cfg = _fields(wan_config_glb_html or "")
    status = _fields(show_wan_status_html or "")

    wan_pppoe = {
        "Name": status.get("Name") or cfg.get("Name"),
        "VLANIDMark": cfg.get("VLANIDMark"),
        "Username": cfg.get("Username"),
        "Password_masked": cfg.get("Password"),
        "ConnectionStatus": status.get("ConnectionStatus"),
        "ExternalIPAddress": status.get("ExternalIPAddress") or cfg.get("ExternalIPAddress"),
        "RemoteIPAddress": status.get("RemoteIPAddress"),
        "DNSServers": status.get("DNSServers") or cfg.get("DNSServers"),
        "InterfaceMtu": cfg.get("InterfaceMtu"),
        "X_CT_COM_ServiceList": cfg.get("X_CT_COM_ServiceList"),
        "MACAddress": status.get("MACAddress"),
        "Uptime_seconds": status.get("Uptime"),
        "PPPoEACName": status.get("PPPoEACName"),
        "LastConnectionError": status.get("LastConnectionError"),
    }
    return wan_pppoe


def _parse_voice_info(html):
    voip_cmd_blob = _extract_block(html, "voip_cmd") or ""
    lines_cfg_blob = _extract_block(html, "lines_config") or ""
    user_agent_blob = _extract_block(html, "user_agent") or ""

    voip = _fields(voip_cmd_blob)
    lines = _fields(lines_cfg_blob)
    ua = _fields(user_agent_blob)

    voice_telemetry = {
        "LineStatus": lines.get("Status"),
        "phNumber": voip.get("phNumber") or None,
        "proxyIp": voip.get("proxyIp") or None,
        "regErrorCode": voip.get("regErrorCode"),
        "regErrorReason": voip.get("regErrorReason") or None,
        "userAgentIp": ua.get("userAgentIp"),
    }
    return voice_telemetry


def _parse_wlan_config(html, band_label, enckey=None, enciv=None):
    idx_objs = _extract_indexed_object(html, "wlan_config")
    ssids = []
    for idx in sorted(idx_objs):
        f = _fields(idx_objs[idx])
        psk_match = re.search(r"PreSharedKey\s*:\s*'([^']*)'", idx_objs[idx])
        psk_enc = psk_match.group(1) if psk_match else None
        psk_clear = None
        if psk_enc and enckey and enciv:
            try:
                psk_clear = nokia_auth.aes128_cbc_decrypt_sjcl(enckey, enciv, psk_enc)
            except Exception:
                psk_clear = None
        ssids.append({
            "ssid_index": idx,
            "SSID": f.get("SSID"),
            "BSSID": f.get("BSSID"),
            "Enable": f.get("Enable"),
            "RadioEnabled": f.get("RadioEnabled"),
            "Channel": f.get("Channel"),
            "AutoChannelEnable": f.get("AutoChannelEnable"),
            "Standard": f.get("Standard"),
            "BeaconType": f.get("BeaconType"),
            "WPAAuthenticationMode": f.get("WPAAuthenticationMode"),
            "WPAEncryptionModes": f.get("WPAEncryptionModes"),
            "SSIDAdvertisementEnabled": f.get("SSIDAdvertisementEnabled"),
            "PreSharedKey_encrypted_b64": psk_enc,
            "PreSharedKey_cleartext": psk_clear,
        })
    return {"band": band_label, "ssids": ssids}


def _parse_gpon_config(html):
    f = _fields(_extract_block(html, "gpon_info") or "")
    hexslid = f.get("HexSLID")
    pwd_hex = f.get("Password")
    decoded = _hex_to_ascii_if_printable(pwd_hex) if pwd_hex else None
    return {
        "HexSLID_flag": hexslid,
        "SLID_hex": pwd_hex,
        "SLID_ascii_decoded": decoded,
        "note": "SLID='DEFAULT' (ALU ONU password) segun MF-2.3; no es la clave SIP/PPPoE.",
    }


_LOG_KEYWORDS = re.compile(
    r"(ppp|wan|pppoe|voip|voice|sip|gpon|pon|dhcp|dns|register|auth)", re.IGNORECASE
)


def _summarize_syslog(raw_text, max_lines=80):
    if not raw_text:
        return {"raw_available": False, "relevant_lines": [], "total_lines": 0}
    if "Errorinfo" in raw_text or "invalid parameter in the co" in raw_text.lower():
        return {
            "raw_available": False,
            "relevant_lines": [],
            "total_lines": 0,
            "note": (
                "El router rechazo la peticion cifrada a log.cgi?vlog_glb "
                "('Bad request for invalid parameter in the coookie'), replicando "
                "exactamente el envoltorio RSA+AES y csrf_token literal "
                "('checkcsrf_token') que usa el propio JS del firmware "
                "($(\"#logbtn\").click() en log.cgi). El endpoint exige, ademas del "
                "cifrado, un estado de cookie/sesion no reproducible por un cliente "
                "externo (posible validacion server-side del par sid/lsid frente a un "
                "nonce de pagina que no se expone). No se reintento para evitar activar "
                "el ErrorLimit de la sesion; MF-4.1a continua sin el volcado de syslog."
            ),
        }
    lines = [ln for ln in raw_text.splitlines() if ln.strip()]
    relevant = [ln.strip() for ln in lines if _LOG_KEYWORDS.search(ln)]
    return {
        "raw_available": True,
        "total_lines": len(lines),
        "relevant_line_count": len(relevant),
        "relevant_lines": relevant[-max_lines:],
    }


# --------------------------------------------------------------------------- #
#  MF-4.1a  collect_web_telemetry
# --------------------------------------------------------------------------- #
def collect_web_telemetry(opener=None, ip="192.168.99.254", user="TELMEX",
                           password="", x_sid=None, enckey=None, enciv=None, timeout=10):
    """
    MF-4.1a — Recolección de telemetría web en modo SOLO LECTURA.

    Si `opener` es None, abre su propia sesión con `authenticate_nokia()` y la cierra
    SIEMPRE con `logout_nokia()` en un bloque `finally` (ciclo de vida propio: login ->
    recolección -> logout). Si recibe un `opener` ya autenticado (y opcionalmente `x_sid`),
    reutiliza esa sesión sin tocar su ciclo de vida (no hace login ni logout).

    Endpoints consultados (todos vía GET, excepto log.cgi?vlog_glb que exige POST cifrado):
        device_status.cgi            -> dev_info / gpon_status
        wan_config_glb.cgi           -> parametros de configuracion WAN PPPoE
        show_wan_status.cgi?ipv4    -> estado en vivo de la conexion WAN PPPoE
        voice_info.cgi                -> voip_cmd / lines_config / user_agent
        wlan_config.cgi               -> SSIDs 2.4 GHz (indices 1-4)
        wlan_config.cgi?v=11ac       -> SSIDs 5 GHz (indices 5-10)
        gpon_config.cgi               -> gpon_info (SLID)
        log.cgi?vlog_glb             -> volcado de syslog en vivo (POST cifrado RSA+AES)

    Devuelve `web_telemetry` con las llaves:
        device_info, wan_pppoe, voice_telemetry, wlan_info, gpon_info, system_log_summary
    """
    managed_session = opener is None
    logout_status = None

    if managed_session:
        opener, _cj = nokia_auth.make_opener()
        opener.add_handler(nokia_auth._Pass2xxErrorProcessor())
        auth = nokia_auth.authenticate_nokia(opener, ip=ip, user=user, password=password,
                                              timeout=timeout)
        if not auth["success"]:
            raise RuntimeError(
                "MF-4.1a: no se pudo autenticar contra %s (status=%s). "
                "No se abrió ninguna sesión que deba cerrarse." % (ip, auth["status"])
            )
        x_sid = auth["x_sid"]
        enckey = auth.get("enckey_b64")
        enciv = auth.get("enciv_b64")

    web_telemetry = {
        "ip": ip,
        "device_info": {},
        "wan_pppoe": {},
        "voice_telemetry": {},
        "wlan_info": {"2.4GHz": [], "5GHz": []},
        "gpon_info": {},
        "system_log_summary": {},
        "_endpoints": {},
    }

    try:
        # device_status.cgi
        st, html = _get_text(opener, ip, "device_status.cgi", x_sid, timeout)
        web_telemetry["_endpoints"]["device_status.cgi"] = st
        web_telemetry["device_info"] = _parse_device_status(html)

        # wan_config_glb.cgi + show_wan_status.cgi?ipv4
        st1, wan_cfg_html = _get_text(opener, ip, "wan_config_glb.cgi", x_sid, timeout)
        st2, wan_status_html = _get_text(opener, ip, "show_wan_status.cgi?ipv4", x_sid, timeout)
        web_telemetry["_endpoints"]["wan_config_glb.cgi"] = st1
        web_telemetry["_endpoints"]["show_wan_status.cgi?ipv4"] = st2
        web_telemetry["wan_pppoe"] = _parse_wan_pppoe(wan_cfg_html, wan_status_html)

        # voice_info.cgi
        st, html = _get_text(opener, ip, "voice_info.cgi", x_sid, timeout)
        web_telemetry["_endpoints"]["voice_info.cgi"] = st
        web_telemetry["voice_telemetry"] = _parse_voice_info(html)

        # wlan_config.cgi (2.4GHz) + wlan_config.cgi?v=11ac (5GHz)
        st, html = _get_text(opener, ip, "wlan_config.cgi", x_sid, timeout)
        web_telemetry["_endpoints"]["wlan_config.cgi"] = st
        wl24 = _parse_wlan_config(html, "2.4GHz", enckey=enckey, enciv=enciv)
        st, html = _get_text(opener, ip, "wlan_config.cgi?v=11ac", x_sid, timeout)
        web_telemetry["_endpoints"]["wlan_config.cgi?v=11ac"] = st
        wl5 = _parse_wlan_config(html, "5GHz", enckey=enckey, enciv=enciv)
        web_telemetry["wlan_info"] = {"2.4GHz": wl24["ssids"], "5GHz": wl5["ssids"]}

        # lan_status.cgi?wlan (resumen de interfaz local / hosts conectados, informativo)
        st, lan_status_html = _get_text(opener, ip, "lan_status.cgi?wlan", x_sid, timeout)
        web_telemetry["_endpoints"]["lan_status.cgi?wlan"] = st

        # mapa SSID <-> interfaz ra0..rai4 (var wlan_route, expuesto en wan_config_glb.cgi)
        wlan_route_blob = _extract_block(wan_cfg_html, "wlan_route")
        if wlan_route_blob:
            web_telemetry["wlan_info"]["interface_map"] = [
                _fields(blk) for blk in re.findall(r"\{[^{}]*\}", wlan_route_blob)
            ]

        # gpon_config.cgi
        st, html = _get_text(opener, ip, "gpon_config.cgi", x_sid, timeout)
        web_telemetry["_endpoints"]["gpon_config.cgi"] = st
        web_telemetry["gpon_info"] = _parse_gpon_config(html)

        # log.cgi?vlog_glb (unico endpoint de lectura que exige POST cifrado)
        st, raw_log, err = _post_encrypted(
            opener, ip, "log.cgi?vlog_glb", "csrf_token=checkcsrf_token", x_sid, timeout
        )
        web_telemetry["_endpoints"]["log.cgi?vlog_glb"] = st
        if err:
            web_telemetry["system_log_summary"] = {"raw_available": False, "error": err}
        else:
            web_telemetry["system_log_summary"] = _summarize_syslog(raw_log)

    finally:
        if managed_session:
            logout_status = nokia_auth.logout_nokia(opener, ip=ip, timeout=timeout)
            web_telemetry["_session"] = {"self_managed": True, "logout_status": logout_status}
        else:
            web_telemetry["_session"] = {"self_managed": False}

    return web_telemetry


# --------------------------------------------------------------------------- #
#  Helpers XML genéricos TR-098/TR-104 (tolerantes a los dos esquemas Nokia:
#  sub-elementos XML vs. atributos en el propio nodo)
# --------------------------------------------------------------------------- #
def _local_tag(tag):
    """Quita el namespace Clark-notation ('{uri}Tag' -> 'Tag')."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _elem_fields(elem):
    """
    Combina, en un solo diccionario, los atributos del elemento (esquema TR-098/
    TR-104 por atributos, p.ej. `<SIP ProxyServer="..." .../>`) y el texto de sus
    hijos directos (esquema jerárquico por sub-elementos, p.ej.
    `<SIP><ProxyServer>...</ProxyServer></SIP>`). Los atributos tienen prioridad
    sobre los sub-elementos cuando ambos declaran la misma clave.
    """
    fields = {}
    for child in list(elem):
        ctag = _local_tag(child.tag)
        if ctag not in fields:
            fields[ctag] = (child.text or "").strip()
    fields.update(elem.attrib)  # los atributos del propio nodo tienen prioridad
    return fields


def _iter_by_tag(elem, *names):
    """Itera (en cualquier orden de aparición) todos los descendientes de `elem`
    (inclusive) cuyo nombre de etiqueta local (sin namespace) coincida, sin
    distinguir mayúsculas/minúsculas, con alguno de los `names` dados."""
    names_lower = {n.lower() for n in names}
    for el in elem.iter():
        if _local_tag(el.tag).lower() in names_lower:
            yield el


def _pick(fields, keys, default=None):
    """Devuelve el primer valor no vacío de `fields` cuya clave coincida
    (sin distinguir mayúsculas/minúsculas) con alguno de `keys`, en el orden
    dado; si ninguno existe o todos están vacíos, devuelve `default`."""
    for k in keys:
        for actual_key, v in fields.items():
            if actual_key.lower() == k.lower():
                if v is not None and str(v).strip() != "":
                    return v
    return default


_PENDIENTE = "Pendiente / No disponible en XML"


# --------------------------------------------------------------------------- #
#  MF-4.1b  parse_xml_voice_profile(xml_text)
# --------------------------------------------------------------------------- #
def parse_xml_voice_profile(xml_text):
    """
    MF-4.1b — Analiza un árbol XML de configuración Nokia/Alcatel-Lucent
    (TR-098 / TR-104 `InternetGatewayDevice.Services.VoiceService`) y extrae las
    credenciales y parámetros de registro SIP IMS.

    Tolerante a los DOS esquemas que usa el firmware Nokia:
      - Jerárquico por sub-elementos XML: `<SIP><ProxyServer>x</ProxyServer></SIP>`.
      - De atributos TR-098/TR-104: `<SIP ProxyServer="x" .../>`.
      - Nodos ya aplanados `VoiceProfileInstance` / `LineInstance` usados por
        algunos volcados de configuración, además de los nombres canónicos
        `VoiceProfile` / `Line`.

    Entrada:
        xml_text: cadena XML completa (del backup descomprimido o de --xml).
                   Si es None o cadena vacía, se devuelven únicamente los
                   valores por defecto, marcados como "Pendiente / No
                   disponible en XML".

    Salida (`sip_voip`):
        - Parámetros de perfil: proxy_server, proxy_server_port,
          registrar_server, registrar_server_port, outbound_proxy,
          outbound_proxy_port, user_agent_domain.
        - lines: lista de dicts por cada <Line>/<LineInstance> encontrada:
          instance_id, enable, directory_number, uri, auth_username,
          auth_password.
        - Campos planos de compatibilidad con credentials.json (datos de la
          línea principal, la primera encontrada): auth_username,
          auth_password, uri, directory_number, registrar_server,
          outbound_proxy, proxy_server, port, line_status.
    """
    sip_voip = {
        "proxy_server": None,
        "proxy_server_port": "5060",
        "registrar_server": "vims-h.telmex.com",
        "registrar_server_port": "5060",
        "outbound_proxy": "nir8.norte.telmex.net",
        "outbound_proxy_port": "5060",
        "user_agent_domain": None,
        "lines": [],
        "auth_username": _PENDIENTE,
        "auth_password": _PENDIENTE,
        "uri": _PENDIENTE,
        "directory_number": _PENDIENTE,
        "line_status": _PENDIENTE,
    }
    sip_voip["port"] = sip_voip["proxy_server_port"]

    if not xml_text:
        return sip_voip

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return sip_voip

    # Mapa de padres (ElementTree no lo expone de forma nativa) para poder
    # distinguir un <SIP> a nivel de VoiceProfile de un <SIP> anidado dentro
    # de una <Line> (ambos comparten la misma etiqueta local "SIP").
    parent_map = {child: parent for parent in root.iter() for child in parent}

    def _ancestor_tags(el):
        tags = []
        cur = el
        while cur in parent_map:
            cur = parent_map[cur]
            tags.append(_local_tag(cur.tag).lower())
        return tags

    # --- Nivel VoiceProfile: ProxyServer/RegistrarServer/OutboundProxy/UserAgentDomain ---
    profile_fields = {}
    for vp_el in _iter_by_tag(root, "VoiceProfile", "VoiceProfileInstance"):
        for k, v in _elem_fields(vp_el).items():
            profile_fields.setdefault(k, v)
    for sip_el in _iter_by_tag(root, "SIP"):
        anc = _ancestor_tags(sip_el)
        if "line" in anc or "lineinstance" in anc:
            continue  # SIP de línea, no de perfil; se procesa más abajo
        for k, v in _elem_fields(sip_el).items():
            profile_fields.setdefault(k, v)

    sip_voip["proxy_server"] = _pick(profile_fields, ["ProxyServer"], sip_voip["proxy_server"])
    sip_voip["proxy_server_port"] = _pick(
        profile_fields, ["ProxyServerPort"], sip_voip["proxy_server_port"])
    sip_voip["registrar_server"] = _pick(
        profile_fields, ["RegistrarServer"], sip_voip["registrar_server"])
    sip_voip["registrar_server_port"] = _pick(
        profile_fields, ["RegistrarServerPort"], sip_voip["registrar_server_port"])
    sip_voip["outbound_proxy"] = _pick(
        profile_fields, ["OutboundProxy", "OutBoundProxyServer"], sip_voip["outbound_proxy"])
    sip_voip["outbound_proxy_port"] = _pick(
        profile_fields, ["OutboundProxyPort"], sip_voip["outbound_proxy_port"])
    sip_voip["user_agent_domain"] = _pick(
        profile_fields, ["UserAgentDomain"], sip_voip["user_agent_domain"])
    sip_voip["port"] = sip_voip["proxy_server_port"]

    # --- Nivel Line/LineInstance (+ su propio SIP anidado) ---
    lines = []
    for idx, line_el in enumerate(_iter_by_tag(root, "Line", "LineInstance"), start=1):
        merged = _elem_fields(line_el)
        for sip_el in _iter_by_tag(line_el, "SIP"):
            merged.update(_elem_fields(sip_el))

        lines.append({
            "instance_id": _pick(merged, ["InstanceID"], str(idx)),
            "enable": _pick(merged, ["Enable", "Status"], _PENDIENTE),
            "directory_number": _pick(merged, ["DirectoryNumber"], _PENDIENTE),
            "uri": _pick(merged, ["URI"], _PENDIENTE),
            "auth_username": _pick(merged, ["AuthUserName"], _PENDIENTE),
            "auth_password": _pick(merged, ["AuthPassword"], _PENDIENTE),
        })

    sip_voip["lines"] = lines

    if lines:
        primary = lines[0]
        sip_voip["auth_username"] = primary["auth_username"]
        sip_voip["auth_password"] = primary["auth_password"]
        sip_voip["uri"] = primary["uri"]
        sip_voip["directory_number"] = primary["directory_number"]
        sip_voip["line_status"] = primary["enable"]

    return sip_voip


# --------------------------------------------------------------------------- #
#  MF-4.2a  parse_xml_wan_and_wlan(xml_text)
# --------------------------------------------------------------------------- #
def parse_xml_wan_and_wlan(xml_text):
    """
    MF-4.2a — Extrae del árbol XML de configuración los parámetros de la
    conexión WAN PPPoE, las redes Wi-Fi y las cuentas de administración web
    locales del Nokia G-1425G-H, tolerante a los esquemas de sub-elementos y
    de atributos TR-098/TR-104.

    Nodos procesados (ambos esquemas, por elemento hijo o por atributo):
      - WANPPPConnection / WANPPPConnectionInstance -> pppoe
      - WLANConfiguration / WLANConfigurationInstance -> wifi_networks
      - UserInterface / X_ALU_COM_UserAccount / Account / User /
        X_HW_WebUserInfoInstance -> web_admin

    Entrada:
        xml_text: cadena XML completa. Si es None o vacía, se devuelven los
                   valores por defecto marcados como "Pendiente / No
                   disponible en XML".

    Salida: dict con las secciones `pppoe`, `wifi_networks` y `web_admin`.
    """
    result = {
        "pppoe": {
            "username": _PENDIENTE,
            "password": _PENDIENTE,
            "vlan_id": "881",
            "mtu": "1492",
            "service_list": _PENDIENTE,
            "connection_type": _PENDIENTE,
            "nat_enabled": _PENDIENTE,
        },
        "wifi_networks": [],
        "web_admin": [],
    }

    if not xml_text:
        return result

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return result

    # --- PPPoE (WANPPPConnection / WANPPPConnectionInstance) ---
    ppp_elems = list(_iter_by_tag(root, "WANPPPConnection", "WANPPPConnectionInstance"))
    if ppp_elems:
        fields = _elem_fields(ppp_elems[0])
        pppoe = result["pppoe"]
        pppoe["username"] = _pick(fields, ["Username"], pppoe["username"])
        pppoe["password"] = _pick(fields, ["Password"], pppoe["password"])
        pppoe["vlan_id"] = _pick(
            fields,
            ["X_ALU-COM_VLANID", "VLANIDMark", "X_HW_VLAN", "X_CT-COM_VLANID"],
            pppoe["vlan_id"],
        )
        pppoe["mtu"] = _pick(fields, ["MaxMRUSize", "InterfaceMtu"], pppoe["mtu"])
        pppoe["service_list"] = _pick(
            fields, ["X_CT-COM_ServiceList", "X_HW_SERVICELIST"], pppoe["service_list"])
        pppoe["connection_type"] = _pick(
            fields, ["ConnectionType"], pppoe["connection_type"])
        pppoe["nat_enabled"] = _pick(fields, ["NATEnabled"], pppoe["nat_enabled"])

    # --- WLAN (WLANConfiguration / WLANConfigurationInstance) ---
    wifi_networks = []
    for idx, wlan_el in enumerate(
        _iter_by_tag(root, "WLANConfiguration", "WLANConfigurationInstance"), start=1
    ):
        fields = _elem_fields(wlan_el)
        # Soportar PreSharedKey anidado en <PreSharedKey><PreSharedKey>...</PreSharedKey></PreSharedKey>
        for psk_el in _iter_by_tag(wlan_el, "PreSharedKey", "PreSharedKeyInstance"):
            for k, v in _elem_fields(psk_el).items():
                if v and k not in fields:
                    fields[k] = v
            if psk_el.text and psk_el.text.strip() and not fields.get("PreSharedKey"):
                fields["PreSharedKey"] = psk_el.text.strip()
        wifi_networks.append({
            "ssid_index": _pick(fields, ["InstanceID"], str(idx)),
            "ssid": _pick(fields, ["SSID"], _PENDIENTE),
            "psk": _pick(fields, ["PreSharedKey", "KeyPassphrase"], _PENDIENTE),
            "enable": _pick(fields, ["Enable"], _PENDIENTE),
            "standard": _pick(fields, ["Standard"], _PENDIENTE),
        })
    result["wifi_networks"] = wifi_networks

    # --- Cuentas de administracion web local ---
    web_admin = []
    account_tags = ("Account", "User", "X_ALU_COM_UserAccount", "X_HW_WebUserInfoInstance")
    for acc_el in _iter_by_tag(root, *account_tags):
        fields = _elem_fields(acc_el)
        username = _pick(fields, ["Username", "Name", "User"], None)
        password = _pick(fields, ["Password", "Passwd"], None)
        level = _pick(fields, ["X_HW_UserLevel", "Role", "Level", "AccessLevel"], None)
        if username is None and password is None and level is None:
            continue  # nodo homónimo sin datos de cuenta reales
        web_admin.append({
            "username": username or _PENDIENTE,
            "password": password or _PENDIENTE,
            "level": level or _PENDIENTE,
        })
    result["web_admin"] = web_admin

    return result


# --------------------------------------------------------------------------- #
#  Helpers de "mejor valor disponible" (texto claro > placeholder/mascara)
# --------------------------------------------------------------------------- #
_MASK_PLACEHOLDER = "!!!@@@###$$$^^^&&&***"


def _is_placeholder(value):
    """True si `value` es None, cadena vacía, el marcador `_PENDIENTE` de
    MF-4.1b/4.2a, o la máscara fija `!!!@@@###$$$^^^&&&***` que el firmware
    Nokia devuelve en lugar de contraseñas reales (ver MF-2.3/Fase 3.5)."""
    if value is None:
        return True
    s = str(value).strip()
    return s == "" or s == _PENDIENTE or s == _MASK_PLACEHOLDER


def _first_real(*values):
    """Devuelve el primer valor de `values` que NO sea un placeholder/máscara
    (según `_is_placeholder`). Si ninguno es "real", devuelve el primer valor
    no-None disponible (para que el reporte siga mostrando algo útil en vez de
    `None`); si todos son `None`, devuelve `None`."""
    for v in values:
        if not _is_placeholder(v):
            return v
    for v in values:
        if v is not None:
            return v
    return None


# --------------------------------------------------------------------------- #
#  MF-4.2b  build_unified_reports(web_telemetry, xml_data, output_dir)
# --------------------------------------------------------------------------- #
def build_unified_reports(web_telemetry, xml_data=None, output_dir="output"):
    """
    MF-4.2b — Combina la telemetría web en vivo (`MF-4.1a`, modo de solo lectura
    contra el router) con los datos extraídos del XML de configuración offline
    (`MF-4.1b` + `MF-4.2a`, dict opcional con las llaves `sip_voip`, `pppoe`,
    `wifi_networks`, `web_admin`) y escribe los reportes unificados del proyecto:
    `output/credentials.json` y `output/credentials.md`.

    Para cada campo se prioriza el valor en texto claro disponible (XML o
    telemetría web) sobre los marcadores `"Pendiente / No disponible en XML"`
    o la máscara fija `!!!@@@###$$$^^^&&&***` que el firmware usa para no
    exponer contraseñas reales en las páginas de estado.

    Entrada:
        web_telemetry: dict devuelto por `collect_web_telemetry()` (MF-4.1a).
                        Puede ser `{}`/`None` si solo se dispone del XML.
        xml_data: dict opcional con `{"sip_voip": ..., "pppoe": ..., "wifi_networks": ...,
                   "web_admin": ...}` (salida combinada de `parse_xml_voice_profile()` +
                   `parse_xml_wan_and_wlan()`). `None` si no se cuenta con el XML.
        output_dir: directorio donde escribir `credentials.json`/`credentials.md`.

    Salida: dict `credentials` con las llaves `device_info`, `pppoe`, `sip_voip`,
            `wifi_networks`, `web_admin` y `_paths` (rutas de los dos archivos
            escritos), que es el mismo diccionario volcado a `credentials.json`.
    """
    web_telemetry = web_telemetry or {}
    xml_data = xml_data or {}

    dev = web_telemetry.get("device_info", {}) or {}
    gpon_status = dev.get("gpon_status", {}) or {}
    gpon_info = web_telemetry.get("gpon_info", {}) or {}
    wan = web_telemetry.get("wan_pppoe", {}) or {}
    voice = web_telemetry.get("voice_telemetry", {}) or {}
    wlan = web_telemetry.get("wlan_info", {}) or {}

    xml_pppoe = xml_data.get("pppoe", {}) or {}
    xml_sip = xml_data.get("sip_voip", {}) or {}
    xml_wifi = xml_data.get("wifi_networks", []) or []
    xml_web_admin = xml_data.get("web_admin", []) or []

    # --- 1. Identidad del equipo y estado GPON ---
    device_info = {
        "model_name": _first_real(dev.get("ModelName"), "G-1425G-H"),
        "product_class": dev.get("ProductClass"),
        "manufacturer": dev.get("Manufacturer"),
        "manufacturer_oui": dev.get("ManufacturerOUI"),
        "serial_number": dev.get("SerialNumber"),
        "hardware_version": dev.get("HardwareVersion"),
        "software_version": dev.get("SoftwareVersion"),
        "provisioning_code": dev.get("ProvisioningCode"),
        "gpon_status": gpon_status.get("Status"),
        "gpon_enable": gpon_status.get("Enable"),
        "slid_ascii": gpon_info.get("SLID_ascii_decoded"),
        "slid_hex": gpon_info.get("SLID_hex"),
    }

    # --- 2. Conexion WAN PPPoE ---
    pppoe_password = _first_real(xml_pppoe.get("password"), wan.get("Password_masked"))
    pppoe = {
        "vlan_id": _first_real(xml_pppoe.get("vlan_id"), wan.get("VLANIDMark"), "881"),
        "username": _first_real(xml_pppoe.get("username"), wan.get("Username")),
        "password": pppoe_password,
        "password_is_masked": pppoe_password == _MASK_PLACEHOLDER,
        "mtu": _first_real(xml_pppoe.get("mtu"), wan.get("InterfaceMtu"), "1492"),
        "service_list": _first_real(xml_pppoe.get("service_list"), wan.get("X_CT_COM_ServiceList")),
        "connection_status": wan.get("ConnectionStatus"),
        "external_ip": wan.get("ExternalIPAddress"),
        "dns_servers": wan.get("DNSServers"),
        "mac_address": wan.get("MACAddress"),
    }

    # --- 3. Telefonia Fija VoIP (IMS SIP Telmex) ---
    sip_voip = {
        "line_status_ont": voice.get("LineStatus"),
        "directory_number": _first_real(
            xml_sip.get("directory_number"), voice.get("phNumber"), _PENDIENTE),
        "uri": _first_real(xml_sip.get("uri"), _PENDIENTE),
        "auth_username": _first_real(xml_sip.get("auth_username"), _PENDIENTE),
        "auth_password": _first_real(xml_sip.get("auth_password"), _PENDIENTE),
        "registrar_server": _first_real(xml_sip.get("registrar_server"), "vims-h.telmex.com"),
        "registrar_server_port": _first_real(xml_sip.get("registrar_server_port"), "5060"),
        "outbound_proxy": _first_real(
            xml_sip.get("outbound_proxy"), voice.get("proxyIp"), "nir8.norte.telmex.net"),
        "outbound_proxy_port": _first_real(xml_sip.get("outbound_proxy_port"), "5060"),
        "proxy_server": xml_sip.get("proxy_server"),
        "user_agent_ip": voice.get("userAgentIp"),
        "reg_error_code": voice.get("regErrorCode"),
        "reg_error_reason": voice.get("regErrorReason"),
    }

    # --- 4. Redes Wi-Fi (texto claro, MF-4.1a) + Acceso Web (XML, MF-4.2a) ---
    wifi_networks = []
    for band_label, key in (("2.4GHz", "2.4GHz"), ("5GHz", "5GHz")):
        for s in (wlan.get(key) or []):
            wifi_networks.append({
                "band": band_label,
                "ssid": s.get("SSID"),
                "bssid": s.get("BSSID"),
                "channel": s.get("Channel"),
                "enable": s.get("Enable"),
                "wpa_mode": s.get("WPAAuthenticationMode"),
                "psk_cleartext": _first_real(s.get("PreSharedKey_cleartext"), _PENDIENTE),
            })
    if not wifi_networks and xml_wifi:
        for w in xml_wifi:
            wifi_networks.append({
                "band": None,
                "ssid": w.get("ssid"),
                "bssid": None,
                "channel": None,
                "enable": w.get("enable"),
                "wpa_mode": None,
                "psk_cleartext": _first_real(w.get("psk"), _PENDIENTE),
            })

    web_admin = list(xml_web_admin)

    credentials = {
        "device_info": device_info,
        "pppoe": pppoe,
        "sip_voip": sip_voip,
        "wifi_networks": wifi_networks,
        "web_admin": web_admin,
    }

    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "credentials.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(credentials, fh, indent=2, ensure_ascii=False)

    md_path = os.path.join(output_dir, "credentials.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(_render_credentials_markdown(credentials))

    credentials["_paths"] = {"json": json_path, "md": md_path}
    return credentials


def _render_credentials_markdown(c):
    """Genera el contenido Markdown de `credentials.md` con las 4 secciones de
    MF-4.2b (Identidad/GPON, WAN PPPoE, VoIP SIP, Wi-Fi + Acceso Web)."""
    dev = c["device_info"]
    pppoe = c["pppoe"]
    sip = c["sip_voip"]
    wifi = c["wifi_networks"]
    admin = c["web_admin"]

    def nz(v, default="N/D"):
        return v if v is not None and str(v).strip() != "" else default

    lines = []
    lines.append("# 📡 Credenciales Extraídas — Nokia G-1425G-H (Telmex)\n")

    lines.append("## 1. Identidad del Equipo y Estado GPON\n")
    lines.append("| Campo | Valor |")
    lines.append("| :--- | :--- |")
    lines.append("| Modelo | `%s` |" % nz(dev.get("model_name")))
    lines.append("| Fabricante (OUI) | `%s` (`%s`) |" % (
        nz(dev.get("manufacturer")), nz(dev.get("manufacturer_oui"))))
    lines.append("| Número de Serie (GPON) | `%s` |" % nz(dev.get("serial_number")))
    lines.append("| Firmware (SoftwareVersion) | `%s` |" % nz(dev.get("software_version")))
    lines.append("| Hardware | `%s` |" % nz(dev.get("hardware_version")))
    lines.append("| ProvisioningCode | `%s` |" % nz(dev.get("provisioning_code")))
    lines.append("| Estado GPON | `%s` |" % nz(dev.get("gpon_status")))
    lines.append("| SLID (clave ONU de fábrica, no es la clave SIP/PPPoE) | `%s` (hex `%s`) |\n" % (
        nz(dev.get("slid_ascii")), nz(dev.get("slid_hex"))))

    lines.append("## 2. Conexión WAN PPPoE (VLAN %s)\n" % nz(pppoe.get("vlan_id"), "881"))
    lines.append("| Campo | Valor |")
    lines.append("| :--- | :--- |")
    lines.append("| Usuario PPPoE | `%s` |" % nz(pppoe.get("username")))
    pwd_display = nz(pppoe.get("password"))
    if pppoe.get("password_is_masked"):
        pwd_display += "  _(⚠️ enmascarada por el router; no es la contraseña real — usa `--xml`)_"
    lines.append("| Contraseña PPPoE | `%s` |" % pwd_display)
    lines.append("| VLAN ID | `%s` |" % nz(pppoe.get("vlan_id"), "881"))
    lines.append("| MTU | `%s` |" % nz(pppoe.get("mtu"), "1492"))
    lines.append("| IP Pública | `%s` |" % nz(pppoe.get("external_ip")))
    lines.append("| Servidores DNS | `%s` |" % nz(pppoe.get("dns_servers")))
    lines.append("| Estado de conexión | `%s` |" % nz(pppoe.get("connection_status")))
    lines.append("| Lista de servicios | `%s` |\n" % nz(pppoe.get("service_list")))

    lines.append("## 3. Telefonía Fija VoIP (IMS SIP Telmex)\n")
    lines.append("| Campo | Valor |")
    lines.append("| :--- | :--- |")
    lines.append("| Estado de línea en ONT | `%s` |" % nz(sip.get("line_status_ont")))
    lines.append("| URI / Número | `%s` |" % nz(sip.get("uri")))
    lines.append("| AuthUserName | `%s` |" % nz(sip.get("auth_username")))
    lines.append("| AuthPassword | `%s` |" % nz(sip.get("auth_password")))
    lines.append("| RegistrarServer | `%s:%s` |" % (
        nz(sip.get("registrar_server")), nz(sip.get("registrar_server_port"), "5060")))
    lines.append("| OutboundProxy | `%s:%s` |" % (
        nz(sip.get("outbound_proxy")), nz(sip.get("outbound_proxy_port"), "5060")))
    lines.append("| UserAgentIP | `%s` |\n" % nz(sip.get("user_agent_ip")))

    lines.append("## 4. Redes Inalámbricas Wi-Fi y Acceso Web\n")
    lines.append("### 4.1 Wi-Fi (2.4 GHz / 5 GHz)\n")
    lines.append("| Banda | SSID | BSSID | Canal | Estado | Clave WPA (`PreSharedKey_cleartext`) |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for w in wifi:
        estado = "Activo" if str(w.get("enable")) == "1" else "Inactivo"
        lines.append("| %s | `%s` | `%s` | %s | %s | `%s` |" % (
            nz(w.get("band")), nz(w.get("ssid")), nz(w.get("bssid")),
            nz(w.get("channel")), estado, nz(w.get("psk_cleartext"))))
    if not wifi:
        lines.append("| _(sin datos)_ | | | | | |")
    lines.append("")

    lines.append("### 4.2 Cuentas de Acceso Web\n")
    if admin:
        lines.append("| Usuario | Contraseña | Nivel |")
        lines.append("| :--- | :--- | :--- |")
        for a in admin:
            lines.append("| `%s` | `%s` | `%s` |" % (
                nz(a.get("username")), nz(a.get("password")), nz(a.get("level"))))
    else:
        lines.append(
            "_No se encontraron cuentas de administración web en los datos disponibles "
            "(requiere el XML de configuración vía `--xml`)._"
        )

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
#  MF-4.3a  render_asterisk_pjsip_conf(sip_data, output_dir)
# --------------------------------------------------------------------------- #
def render_asterisk_pjsip_conf(sip_data, output_dir="output"):
    """
    MF-4.3a — Genera `output/asterisk_pjsip_telmex.conf`, una plantilla PJSIP
    (`res_pjsip`, stack moderno de Asterisk) lista para registrar un Asterisk
    contra la red IMS de Telmex con las credenciales SIP extraídas por
    `build_unified_reports()` (MF-4.2b). Si `sip_data` aún contiene los
    marcadores "Pendiente" (p. ej. porque no se dispone del XML descifrado),
    se usan placeholders explícitos y se agrega un aviso en los comentarios.

    Entrada:
        sip_data: dict `sip_voip` (de `build_unified_reports()` o equivalente)
                   con, al menos, `directory_number`, `auth_username`,
                   `auth_password`, `registrar_server`, `outbound_proxy`.
        output_dir: directorio de salida.

    Salida: ruta del archivo `output/asterisk_pjsip_telmex.conf` escrito.
    """
    sip_data = sip_data or {}

    numero = sip_data.get("directory_number")
    if _is_placeholder(numero):
        numero = "+5255XXXXXXXX"

    auth_user = sip_data.get("auth_username")
    if _is_placeholder(auth_user):
        auth_user = numero

    auth_pass = sip_data.get("auth_password")
    pendiente = _is_placeholder(sip_data.get("auth_username")) or \
        _is_placeholder(sip_data.get("auth_password")) or \
        _is_placeholder(sip_data.get("directory_number"))
    if _is_placeholder(auth_pass):
        auth_pass = "TU_PASSWORD_SIP_IMS"

    registrar = sip_data.get("registrar_server") or "vims-h.telmex.com"
    outbound = sip_data.get("outbound_proxy") or "nir8.norte.telmex.net"

    aviso = ""
    if pendiente:
        aviso = (
            "; ⚠️  AVISO: uno o más de (numero SIP / AuthUserName / AuthPassword) aun no\n"
            ";     se han extraido en texto claro (ver MF-4.1b, requiere el XML descifrado\n"
            ";     del backup .cfg, pendiente en Fase 3.5/5). Sustituye manualmente los\n"
            ";     placeholders '+5255XXXXXXXX' y 'TU_PASSWORD_SIP_IMS' por los valores\n"
            ";     reales de tu cuenta SIP IMS de Telmex antes de usar esta plantilla.\n;\n"
        )

    content = (
        "; ===========================================================================\n"
        "; asterisk_pjsip_telmex.conf -- Plantilla PJSIP (res_pjsip) para registrar un\n"
        "; Asterisk contra la red IMS de Telmex. Generada por MF-4.3a\n"
        "; (nokia_g1425gh_extractor.py :: render_asterisk_pjsip_conf).\n"
        ";\n"
        "{aviso}"
        "; Numero / URI SIP .... {numero}\n"
        "; AuthUserName ........ {auth_user}\n"
        "; RegistrarServer ..... {registrar}:5060\n"
        "; OutboundProxy ....... {outbound}:5060\n"
        "; ===========================================================================\n"
        "\n"
        "[transport-udp]\n"
        "type=transport\n"
        "protocol=udp\n"
        "bind=0.0.0.0:5060\n"
        "\n"
        "; --- Registro activo hacia el registrar IMS de Telmex ---------------------\n"
        "[telmex-ims]\n"
        "type=registration\n"
        "outbound_auth=telmex-auth\n"
        "server_uri=sip:{registrar}:5060\n"
        "client_uri=sip:{auth_user}@{registrar}:5060\n"
        "contact_user={numero}\n"
        "outbound_proxy=sip:{outbound}:5060\\;lr\n"
        "retry_interval=60\n"
        "expiration=3600\n"
        "\n"
        "; --- Credenciales de autenticacion Digest ----------------------------------\n"
        "[telmex-auth]\n"
        "type=auth\n"
        "auth_type=userpass\n"
        "username={auth_user}\n"
        "password={auth_pass}\n"
        "\n"
        "; --- Direccion de contacto (AOR) -------------------------------------------\n"
        "[telmex-aor]\n"
        "type=aor\n"
        "contact=sip:{registrar}:5060\n"
        "outbound_proxy=sip:{outbound}:5060\\;lr\n"
        "qualify_frequency=30\n"
        "\n"
        "; --- Endpoint: codecs, contexto de entrada y opciones de NAT ---------------\n"
        "[telmex-endpoint]\n"
        "type=endpoint\n"
        "transport=transport-udp\n"
        "context=from-telmex\n"
        "disallow=all\n"
        "allow=alaw,ulaw\n"
        "outbound_auth=telmex-auth\n"
        "aors=telmex-aor\n"
        "from_domain={registrar}\n"
        "from_user={numero}\n"
        "outbound_proxy=sip:{outbound}:5060\\;lr\n"
        "direct_media=no\n"
        "dtmf_mode=rfc4733\n"
        "rtp_symmetric=yes\n"
        "force_rport=yes\n"
        "rewrite_contact=yes\n"
        "\n"
        "; --- Identificacion de trafico entrante desde el proxy IMS ------------------\n"
        "[telmex-identify]\n"
        "type=identify\n"
        "endpoint=telmex-endpoint\n"
        "match={outbound}\n"
    ).format(aviso=aviso, numero=numero, auth_user=auth_user, auth_pass=auth_pass,
             registrar=registrar, outbound=outbound)

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "asterisk_pjsip_telmex.conf")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return out_path


# --------------------------------------------------------------------------- #
#  MF-4.3b  render_asterisk_sip_conf(sip_data, output_dir)
# --------------------------------------------------------------------------- #
def render_asterisk_sip_conf(sip_data, output_dir="output"):
    """
    MF-4.3b — Genera la plantilla complementaria para el driver clásico
    `chan_sip` de Asterisk (`output/asterisk_sip_legacy_telmex.conf`) y un
    ejemplo básico de plan de marcado (`output/asterisk_extensions_sample.conf`)
    con un contexto `[from-telmex]` para llamadas entrantes y
    `[salientes-telmex]` para llamadas salientes nacionales/celulares a 10
    dígitos. Usa los mismos placeholders explícitos que MF-4.3a cuando
    `sip_data` aún contiene marcadores "Pendiente".

    Entrada:
        sip_data: dict `sip_voip` (de `build_unified_reports()` o equivalente).
        output_dir: directorio de salida.

    Salida: tupla `(ruta_sip_conf, ruta_extensions_conf)`.
    """
    sip_data = sip_data or {}

    numero = sip_data.get("directory_number")
    if _is_placeholder(numero):
        numero = "+5255XXXXXXXX"

    auth_user = sip_data.get("auth_username")
    if _is_placeholder(auth_user):
        auth_user = numero

    auth_pass = sip_data.get("auth_password")
    pendiente = _is_placeholder(sip_data.get("auth_username")) or \
        _is_placeholder(sip_data.get("auth_password")) or \
        _is_placeholder(sip_data.get("directory_number"))
    if _is_placeholder(auth_pass):
        auth_pass = "TU_PASSWORD_SIP_IMS"

    registrar = sip_data.get("registrar_server") or "vims-h.telmex.com"
    outbound = sip_data.get("outbound_proxy") or "nir8.norte.telmex.net"

    aviso = ""
    if pendiente:
        aviso = (
            "; ⚠️  AVISO: uno o más de (numero SIP / AuthUserName / AuthPassword) aun no\n"
            ";     se han extraido en texto claro (ver MF-4.1b). Sustituye manualmente los\n"
            ";     placeholders '+5255XXXXXXXX' y 'TU_PASSWORD_SIP_IMS' por los valores\n"
            ";     reales de tu cuenta SIP IMS de Telmex antes de usar esta plantilla.\n;\n"
        )

    sip_conf = (
        "; ===========================================================================\n"
        "; asterisk_sip_legacy_telmex.conf -- Plantilla chan_sip (driver SIP clasico)\n"
        "; para registrar un Asterisk contra la red IMS de Telmex. Generada por MF-4.3b\n"
        "; (nokia_g1425gh_extractor.py :: render_asterisk_sip_conf).\n"
        ";\n"
        "{aviso}"
        "; Numero SIP .......... {numero}\n"
        "; AuthUserName ........ {auth_user}\n"
        "; RegistrarServer ..... {registrar}:5060\n"
        "; OutboundProxy ....... {outbound}:5060\n"
        "; ===========================================================================\n"
        "\n"
        "[general]\n"
        "context=from-telmex\n"
        "allowguest=no\n"
        "bindaddr=0.0.0.0\n"
        "bindport=5060\n"
        "disallow=all\n"
        "allow=alaw\n"
        "allow=ulaw\n"
        "qualify=yes\n"
        "nat=force_rport,comedia\n"
        "\n"
        "; --- Registro activo hacia el registrar IMS de Telmex ---------------------\n"
        "register => {auth_user}:{auth_pass}@{registrar}/{numero}\n"
        "\n"
        "; --- Peer / cuenta SIP IMS de Telmex ---------------------------------------\n"
        "[telmex-ims]\n"
        "type=peer\n"
        "host={outbound}\n"
        "outboundproxy={outbound}\n"
        "fromdomain={registrar}\n"
        "fromuser={auth_user}\n"
        "username={auth_user}\n"
        "secret={auth_pass}\n"
        "defaultuser={auth_user}\n"
        "context=from-telmex\n"
        "insecure=port,invite\n"
        "nat=force_rport,comedia\n"
        "qualify=yes\n"
        "disallow=all\n"
        "allow=alaw\n"
        "allow=ulaw\n"
        "dtmfmode=rfc4733\n"
        "canreinvite=no\n"
    ).format(aviso=aviso, numero=numero, auth_user=auth_user, auth_pass=auth_pass,
             registrar=registrar, outbound=outbound)

    extensions_conf = (
        "; ===========================================================================\n"
        "; asterisk_extensions_sample.conf -- Ejemplo de plan de marcado para la cuenta\n"
        "; SIP IMS de Telmex. Generado por MF-4.3b (render_asterisk_sip_conf).\n"
        "; Ajusta el destino interno (PJSIP/100 o SIP/100) a tu propia extension.\n"
        "; ===========================================================================\n"
        "\n"
        "[from-telmex]\n"
        "; Llamadas entrantes desde la red IMS de Telmex hacia el numero {numero}\n"
        "exten => {numero},1,NoOp(Llamada entrante Telmex a {numero})\n"
        " same => n,Dial(PJSIP/100,20)\n"
        " same => n,Hangup()\n"
        "\n"
        "exten => s,1,NoOp(Llamada entrante Telmex sin numero de destino explicito)\n"
        " same => n,Dial(PJSIP/100,20)\n"
        " same => n,Hangup()\n"
        "\n"
        "[salientes-telmex]\n"
        "; Llamadas salientes nacionales/celulares a 10 digitos via la cuenta de Telmex\n"
        "exten => _XXXXXXXXXX,1,NoOp(Llamada saliente Telmex a ${{EXTEN}})\n"
        " same => n,Dial(PJSIP/telmex-endpoint/sip:${{EXTEN}}@{registrar},60)\n"
        " same => n,Hangup()\n"
    ).format(numero=numero, registrar=registrar)

    os.makedirs(output_dir, exist_ok=True)
    sip_path = os.path.join(output_dir, "asterisk_sip_legacy_telmex.conf")
    with open(sip_path, "w", encoding="utf-8") as fh:
        fh.write(sip_conf)

    ext_path = os.path.join(output_dir, "asterisk_extensions_sample.conf")
    with open(ext_path, "w", encoding="utf-8") as fh:
        fh.write(extensions_conf)

    return sip_path, ext_path


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def _build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="nokia_g1425gh_extractor.py",
        description=(
            "📡 Nokia G-1425G-H (Telmex) — Telemetría web de solo lectura (MF-4.1a), "
            "parseo offline del XML de configuración (MF-4.1b/MF-4.2a), reportes "
            "unificados (MF-4.2b) y plantillas Asterisk PJSIP/chan_sip (MF-4.3a/MF-4.3b)."
        ),
    )
    parser.add_argument(
        "command", nargs="?", default="all", choices=["telemetry", "all"],
        help=(
            "'telemetry': solo ejecuta MF-4.1a y guarda web_telemetry.json. "
            "'all' (por defecto): telemetría (o --offline) + reportes + plantillas Asterisk."
        ),
    )
    parser.add_argument("--ip", default="192.168.99.254", help="IP del router Nokia")
    parser.add_argument("-u", "--user", default="TELMEX", help="Usuario de acceso web (por defecto: TELMEX)")
    parser.add_argument("-p", "--password", default=None,
                         help="Contraseña web del router (se solicita de forma segura si se omite)")
    parser.add_argument("--xml", default=None,
                         help="Ruta a un XML de configuración ya descifrado (MF-4.1b/MF-4.2a)")
    parser.add_argument("--sip-user", default=None, help="AuthUserName SIP a usar/forzar en los reportes y plantillas")
    parser.add_argument("--sip-pass", default=None, help="AuthPassword SIP a usar/forzar en los reportes y plantillas")
    parser.add_argument("--sip-number", default=None, help="Numero/directory_number SIP a usar/forzar")
    parser.add_argument("-o", "--out", default="output", help="Directorio de salida (por defecto: output)")
    parser.add_argument("--json", action="store_true", help="Imprime el resultado en formato JSON")
    parser.add_argument(
        "--offline", action="store_true",
        help="Reutiliza output/web_telemetry.json ya existente sin reconectar al router",
    )
    return parser


def main(argv=None):
    args = _build_arg_parser().parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    web_telemetry_path = os.path.join(args.out, "web_telemetry.json")

    def _ask_password():
        pwd = args.password
        if not pwd:
            pwd = getpass.getpass("🔑 Password web Nokia (%s): " % args.ip)
        return pwd

    # --- modo "telemetry": unicamente MF-4.1a ---
    if args.command == "telemetry" and not args.offline:
        telemetry = collect_web_telemetry(
            opener=None, ip=args.ip, user=args.user, password=_ask_password())
        with open(web_telemetry_path, "w", encoding="utf-8") as fh:
            json.dump(telemetry, fh, indent=2, ensure_ascii=False)
        if args.json:
            print(json.dumps(telemetry, indent=2, ensure_ascii=False))
        else:
            print("MF-4.1a collect_web_telemetry() -> %s" % web_telemetry_path)
            print("logout status: %s" % telemetry.get("_session", {}).get("logout_status"))
        return

    # --- modo "all" (o "telemetry --offline"): telemetria + reportes + Asterisk ---
    if args.offline:
        if not os.path.exists(web_telemetry_path):
            print("❌ --offline requiere que %s ya exista (ejecuta antes 'telemetry')." % web_telemetry_path)
            sys.exit(1)
        with open(web_telemetry_path, "r", encoding="utf-8") as fh:
            web_telemetry = json.load(fh)
        if not args.json:
            print("ℹ️  --offline: reutilizando %s (sin reconectar al router)." % web_telemetry_path)
    else:
        web_telemetry = collect_web_telemetry(
            opener=None, ip=args.ip, user=args.user, password=_ask_password())
        with open(web_telemetry_path, "w", encoding="utf-8") as fh:
            json.dump(web_telemetry, fh, indent=2, ensure_ascii=False)

    if args.command == "telemetry":
        # 'telemetry --offline': solo reimprime/confirma la telemetria ya guardada.
        if args.json:
            print(json.dumps(web_telemetry, indent=2, ensure_ascii=False))
        else:
            print("MF-4.1a collect_web_telemetry() -> %s (desde --offline)" % web_telemetry_path)
        return

    xml_data = None
    if args.xml:
        xml_path = Path(args.xml)
        if not xml_path.exists():
            print("❌ El XML indicado en --xml no existe: %s" % xml_path)
            sys.exit(1)
        with open(xml_path, "r", encoding="utf-8", errors="replace") as fh:
            xml_text = fh.read()
        wan_wlan = parse_xml_wan_and_wlan(xml_text)
        xml_data = {
            "sip_voip": parse_xml_voice_profile(xml_text),
            "pppoe": wan_wlan["pppoe"],
            "wifi_networks": wan_wlan["wifi_networks"],
            "web_admin": wan_wlan["web_admin"],
        }

    if args.sip_user or args.sip_pass or args.sip_number:
        xml_data = xml_data or {}
        sip_voip = dict(xml_data.get("sip_voip") or parse_xml_voice_profile(None))
        if args.sip_number:
            sip_voip["directory_number"] = args.sip_number
            sip_voip["uri"] = "sip:%s@%s" % (
                args.sip_number, sip_voip.get("registrar_server") or "vims-h.telmex.com")
        if args.sip_user:
            sip_voip["auth_username"] = args.sip_user
        if args.sip_pass:
            sip_voip["auth_password"] = args.sip_pass
        xml_data["sip_voip"] = sip_voip

    credentials = build_unified_reports(web_telemetry, xml_data=xml_data, output_dir=args.out)
    pjsip_path = render_asterisk_pjsip_conf(credentials["sip_voip"], output_dir=args.out)
    sip_path, ext_path = render_asterisk_sip_conf(credentials["sip_voip"], output_dir=args.out)

    if args.json:
        print(json.dumps(credentials, indent=2, ensure_ascii=False))
        return

    paths = credentials["_paths"]
    print("MF-4.2b build_unified_reports()        -> %s" % paths["json"])
    print("                                           %s" % paths["md"])
    print("MF-4.3a render_asterisk_pjsip_conf()    -> %s" % pjsip_path)
    print("MF-4.3b render_asterisk_sip_conf()      -> %s" % sip_path)
    print("                                           %s" % ext_path)


if __name__ == "__main__":
    main()
