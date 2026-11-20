#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_xml_parsers.py — Validación unitaria de MF-4.1b (`parse_xml_voice_profile`) y
MF-4.2a (`parse_xml_wan_and_wlan`) en `nokia_g1425gh_extractor.py`.

Usa dos XML sintéticos realistas tipo TR-098/TR-104 Nokia/Alcatel-Lucent:
  - XML_ELEMENTOS: esquema jerárquico por sub-elementos XML
                    (`<ProxyServer>x</ProxyServer>`).
  - XML_ATRIBUTOS: esquema de atributos TR-098/TR-104 (`<SIP ProxyServer="x" .../>`),
                    incluyendo los nodos ya aplanados `VoiceProfileInstance` /
                    `LineInstance` / `WANPPPConnectionInstance` /
                    `WLANConfigurationInstance`.

No requiere red ni acceso al router: valida únicamente el parseo de cadenas XML
en memoria. Ejecutar con:  python3 -m pytest tests/test_xml_parsers.py -v
                      o:    python3 tests/test_xml_parsers.py
"""

import json
import os
import shutil
import sys
import tempfile

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from nokia_g1425gh_extractor import (  # noqa: E402
    parse_xml_voice_profile,
    parse_xml_wan_and_wlan,
    build_unified_reports,
    render_asterisk_pjsip_conf,
    render_asterisk_sip_conf,
)


# --------------------------------------------------------------------------- #
#  XML sintético #1 — esquema jerárquico por sub-elementos XML
# --------------------------------------------------------------------------- #
XML_ELEMENTOS = """<?xml version="1.0" encoding="UTF-8"?>
<InternetGatewayDevice>
  <Services>
    <VoiceService InstanceID="1">
      <VoiceProfile InstanceID="1">
        <SIP>
          <ProxyServer>nir8.norte.telmex.net</ProxyServer>
          <ProxyServerPort>5060</ProxyServerPort>
          <RegistrarServer>vims-h.telmex.com</RegistrarServer>
          <RegistrarServerPort>5060</RegistrarServerPort>
          <OutboundProxy>nir8.norte.telmex.net</OutboundProxy>
          <OutboundProxyPort>5060</OutboundProxyPort>
          <UserAgentDomain>vims-h.telmex.com</UserAgentDomain>
        </SIP>
        <Line InstanceID="1">
          <Enable>Enabled</Enable>
          <DirectoryNumber>+525512345678</DirectoryNumber>
          <SIP>
            <AuthUserName>+525512345678</AuthUserName>
            <AuthPassword>ElemPass123</AuthPassword>
            <URI>sip:+525512345678@vims-h.telmex.com</URI>
          </SIP>
        </Line>
      </VoiceProfile>
    </VoiceService>
  </Services>
  <WANDevice>
    <WANConnectionDevice>
      <WANPPPConnection InstanceID="1">
        <Username>E03005LALCLB472FD24@prodigyweb.com.mx</Username>
        <Password>PppoePassElem</Password>
        <X_ALU-COM_VLANID>881</X_ALU-COM_VLANID>
        <MaxMRUSize>1492</MaxMRUSize>
        <X_CT-COM_ServiceList>VOIP,TR069,INTERNET,OTHER</X_CT-COM_ServiceList>
        <ConnectionType>IP_Routed</ConnectionType>
        <NATEnabled>1</NATEnabled>
      </WANPPPConnection>
    </WANConnectionDevice>
  </WANDevice>
  <LANDevice>
    <WLANConfiguration InstanceID="1">
      <SSID>SITAI</SSID>
      <PreSharedKey>Sitai10925</PreSharedKey>
      <Enable>1</Enable>
      <Standard>n</Standard>
    </WLANConfiguration>
    <WLANConfiguration InstanceID="5">
      <SSID>SITAI_5G</SSID>
      <KeyPassphrase>Sitai10925</KeyPassphrase>
      <Enable>1</Enable>
      <Standard>ac</Standard>
    </WLANConfiguration>
  </LANDevice>
  <UserInterface>
    <X_ALU_COM_UserAccount>
      <Username>admin</Username>
      <Password>AdminPassElem</Password>
      <Level>1</Level>
    </X_ALU_COM_UserAccount>
    <X_ALU_COM_UserAccount>
      <Username>TELMEX</Username>
      <Password>sf3h5zkdtA</Password>
      <Level>0</Level>
    </X_ALU_COM_UserAccount>
  </UserInterface>
</InternetGatewayDevice>
"""


# --------------------------------------------------------------------------- #
#  XML sintético #2 — esquema de atributos TR-098/TR-104 (nodos aplanados)
# --------------------------------------------------------------------------- #
XML_ATRIBUTOS = """<?xml version="1.0" encoding="UTF-8"?>
<X_TR069_Config>
  <VoiceService InstanceID="1">
    <VoiceProfileInstance InstanceID="1"
        ProxyServer="nir8.norte.telmex.net" ProxyServerPort="5060"
        RegistrarServer="vims-h.telmex.com" RegistrarServerPort="5060"
        OutBoundProxyServer="nir8.norte.telmex.net" OutboundProxyPort="5060"
        UserAgentDomain="vims-h.telmex.com">
      <LineInstance InstanceID="1" Enable="Enabled" DirectoryNumber="+525587654321">
        <SIP AuthUserName="+525587654321" AuthPassword="AttrPass456"
             URI="sip:+525587654321@vims-h.telmex.com"/>
      </LineInstance>
    </VoiceProfileInstance>
  </VoiceService>
  <WANPPPConnectionInstance InstanceID="1"
      Username="E03005LALCLB472FD24@prodigyweb.com.mx" Password="PppoePassAttr"
      VLANIDMark="881" InterfaceMtu="1492"
      X_CT-COM_ServiceList="VOIP,TR069,INTERNET,OTHER"
      ConnectionType="IP_Routed" NATEnabled="1"/>
  <WLANConfigurationInstance InstanceID="1" SSID="SITAI" PreSharedKey="Sitai10925"
      Enable="1" Standard="n"/>
  <WLANConfigurationInstance InstanceID="5" SSID="SITAI_5G" KeyPassphrase="Sitai10925"
      Enable="1" Standard="ac"/>
  <X_HW_WebUserInfoInstance Username="admin" Password="AdminPassAttr"
      X_HW_UserLevel="1"/>
  <X_HW_WebUserInfoInstance Username="TELMEX" Password="sf3h5zkdtA" X_HW_UserLevel="0"/>
</X_TR069_Config>
"""


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("  OK  " + msg)


# --------------------------------------------------------------------------- #
#  MF-4.1b — parse_xml_voice_profile
# --------------------------------------------------------------------------- #
def test_parse_xml_voice_profile_elementos():
    print("\n[MF-4.1b] esquema por sub-elementos XML")
    sip = parse_xml_voice_profile(XML_ELEMENTOS)

    _check(sip["proxy_server"] == "nir8.norte.telmex.net", "proxy_server")
    _check(sip["proxy_server_port"] == "5060", "proxy_server_port")
    _check(sip["registrar_server"] == "vims-h.telmex.com", "registrar_server")
    _check(sip["registrar_server_port"] == "5060", "registrar_server_port")
    _check(sip["outbound_proxy"] == "nir8.norte.telmex.net", "outbound_proxy")
    _check(sip["outbound_proxy_port"] == "5060", "outbound_proxy_port")
    _check(sip["user_agent_domain"] == "vims-h.telmex.com", "user_agent_domain")
    _check(sip["port"] == "5060", "port (alias raiz)")

    _check(len(sip["lines"]) == 1, "lines: una linea detectada")
    line = sip["lines"][0]
    _check(line["instance_id"] == "1", "lines[0].instance_id")
    _check(line["enable"] == "Enabled", "lines[0].enable")
    _check(line["directory_number"] == "+525512345678", "lines[0].directory_number")
    _check(line["uri"] == "sip:+525512345678@vims-h.telmex.com", "lines[0].uri")
    _check(line["auth_username"] == "+525512345678", "lines[0].auth_username")
    _check(line["auth_password"] == "ElemPass123", "lines[0].auth_password")

    # Campos planos raiz (linea principal) compatibles con credentials.json
    _check(sip["auth_username"] == "+525512345678", "root.auth_username")
    _check(sip["auth_password"] == "ElemPass123", "root.auth_password")
    _check(sip["uri"] == "sip:+525512345678@vims-h.telmex.com", "root.uri")
    _check(sip["directory_number"] == "+525512345678", "root.directory_number")
    _check(sip["line_status"] == "Enabled", "root.line_status")


def test_parse_xml_voice_profile_atributos():
    print("\n[MF-4.1b] esquema de atributos TR-098/TR-104 (nodos aplanados)")
    sip = parse_xml_voice_profile(XML_ATRIBUTOS)

    _check(sip["proxy_server"] == "nir8.norte.telmex.net", "proxy_server")
    _check(sip["proxy_server_port"] == "5060", "proxy_server_port")
    _check(sip["registrar_server"] == "vims-h.telmex.com", "registrar_server")
    _check(sip["registrar_server_port"] == "5060", "registrar_server_port")
    _check(sip["outbound_proxy"] == "nir8.norte.telmex.net", "outbound_proxy (OutBoundProxyServer)")
    _check(sip["outbound_proxy_port"] == "5060", "outbound_proxy_port")
    _check(sip["user_agent_domain"] == "vims-h.telmex.com", "user_agent_domain")
    _check(sip["port"] == "5060", "port (alias raiz)")

    _check(len(sip["lines"]) == 1, "lines: una linea detectada (LineInstance)")
    line = sip["lines"][0]
    _check(line["instance_id"] == "1", "lines[0].instance_id")
    _check(line["enable"] == "Enabled", "lines[0].enable (atributo Enable)")
    _check(line["directory_number"] == "+525587654321", "lines[0].directory_number")
    _check(line["uri"] == "sip:+525587654321@vims-h.telmex.com", "lines[0].uri")
    _check(line["auth_username"] == "+525587654321", "lines[0].auth_username")
    _check(line["auth_password"] == "AttrPass456", "lines[0].auth_password")

    _check(sip["auth_username"] == "+525587654321", "root.auth_username")
    _check(sip["auth_password"] == "AttrPass456", "root.auth_password")
    _check(sip["line_status"] == "Enabled", "root.line_status")


def test_parse_xml_voice_profile_vacio():
    print("\n[MF-4.1b] entrada vacia / None -> valores por defecto")
    for xml_text in (None, ""):
        sip = parse_xml_voice_profile(xml_text)
        _check(sip["lines"] == [], "lines vacia")
        _check(sip["auth_username"] == "Pendiente / No disponible en XML", "auth_username default")
        _check(sip["auth_password"] == "Pendiente / No disponible en XML", "auth_password default")
        _check(sip["registrar_server"] == "vims-h.telmex.com", "registrar_server default")
        _check(sip["outbound_proxy"] == "nir8.norte.telmex.net", "outbound_proxy default")
        _check(sip["proxy_server_port"] == "5060", "proxy_server_port default")


# --------------------------------------------------------------------------- #
#  MF-4.2a — parse_xml_wan_and_wlan
# --------------------------------------------------------------------------- #
def test_parse_xml_wan_and_wlan_elementos():
    print("\n[MF-4.2a] esquema por sub-elementos XML")
    data = parse_xml_wan_and_wlan(XML_ELEMENTOS)

    pppoe = data["pppoe"]
    _check(pppoe["username"] == "E03005LALCLB472FD24@prodigyweb.com.mx", "pppoe.username")
    _check(pppoe["password"] == "PppoePassElem", "pppoe.password")
    _check(pppoe["vlan_id"] == "881", "pppoe.vlan_id")
    _check(pppoe["mtu"] == "1492", "pppoe.mtu")
    _check(pppoe["service_list"] == "VOIP,TR069,INTERNET,OTHER", "pppoe.service_list")
    _check(pppoe["connection_type"] == "IP_Routed", "pppoe.connection_type")
    _check(pppoe["nat_enabled"] == "1", "pppoe.nat_enabled")

    wifi = data["wifi_networks"]
    _check(len(wifi) == 2, "wifi_networks: 2 SSIDs detectados")
    ssid_by_name = {w["ssid"]: w for w in wifi}
    _check("SITAI" in ssid_by_name, "SSID 'SITAI' detectado")
    _check(ssid_by_name["SITAI"]["psk"] == "Sitai10925", "SSID 'SITAI'.psk (PreSharedKey)")
    _check(ssid_by_name["SITAI"]["enable"] == "1", "SSID 'SITAI'.enable")
    _check(ssid_by_name["SITAI"]["standard"] == "n", "SSID 'SITAI'.standard")
    _check("SITAI_5G" in ssid_by_name, "SSID 'SITAI_5G' detectado")
    _check(ssid_by_name["SITAI_5G"]["psk"] == "Sitai10925", "SSID 'SITAI_5G'.psk (KeyPassphrase)")

    admin = data["web_admin"]
    _check(len(admin) == 2, "web_admin: 2 cuentas detectadas")
    by_user = {a["username"]: a for a in admin}
    _check(by_user["admin"]["password"] == "AdminPassElem", "web_admin['admin'].password")
    _check(by_user["admin"]["level"] == "1", "web_admin['admin'].level")
    _check(by_user["TELMEX"]["password"] == "sf3h5zkdtA", "web_admin['TELMEX'].password")


def test_parse_xml_wan_and_wlan_atributos():
    print("\n[MF-4.2a] esquema de atributos TR-098/TR-104 (nodos aplanados)")
    data = parse_xml_wan_and_wlan(XML_ATRIBUTOS)

    pppoe = data["pppoe"]
    _check(pppoe["username"] == "E03005LALCLB472FD24@prodigyweb.com.mx", "pppoe.username")
    _check(pppoe["password"] == "PppoePassAttr", "pppoe.password")
    _check(pppoe["vlan_id"] == "881", "pppoe.vlan_id (VLANIDMark)")
    _check(pppoe["mtu"] == "1492", "pppoe.mtu (InterfaceMtu)")
    _check(pppoe["service_list"] == "VOIP,TR069,INTERNET,OTHER", "pppoe.service_list")
    _check(pppoe["connection_type"] == "IP_Routed", "pppoe.connection_type")
    _check(pppoe["nat_enabled"] == "1", "pppoe.nat_enabled")

    wifi = data["wifi_networks"]
    _check(len(wifi) == 2, "wifi_networks: 2 SSIDs detectados (WLANConfigurationInstance)")
    ssid_by_name = {w["ssid"]: w for w in wifi}
    _check(ssid_by_name["SITAI"]["psk"] == "Sitai10925", "SSID 'SITAI'.psk (PreSharedKey)")
    _check(ssid_by_name["SITAI_5G"]["psk"] == "Sitai10925", "SSID 'SITAI_5G'.psk (KeyPassphrase)")

    admin = data["web_admin"]
    _check(len(admin) == 2, "web_admin: 2 cuentas detectadas (X_HW_WebUserInfoInstance)")
    by_user = {a["username"]: a for a in admin}
    _check(by_user["admin"]["password"] == "AdminPassAttr", "web_admin['admin'].password")
    _check(by_user["admin"]["level"] == "1", "web_admin['admin'].level (X_HW_UserLevel)")
    _check(by_user["TELMEX"]["password"] == "sf3h5zkdtA", "web_admin['TELMEX'].password")


def test_parse_xml_wan_and_wlan_vacio():
    print("\n[MF-4.2a] entrada vacia / None -> valores por defecto")
    for xml_text in (None, ""):
        data = parse_xml_wan_and_wlan(xml_text)
        _check(data["pppoe"]["username"] == "Pendiente / No disponible en XML", "pppoe.username default")
        _check(data["pppoe"]["vlan_id"] == "881", "pppoe.vlan_id default")
        _check(data["pppoe"]["mtu"] == "1492", "pppoe.mtu default")
        _check(data["wifi_networks"] == [], "wifi_networks vacia")
        _check(data["web_admin"] == [], "web_admin vacia")


# --------------------------------------------------------------------------- #
#  Fixture — `web_telemetry` sintetico tipo MF-4.1a (recorte minimo realista)
# --------------------------------------------------------------------------- #
WEB_TELEMETRY_FIXTURE = {
    "ip": "192.168.99.254",
    "device_info": {
        "ModelName": "G-1425G-H",
        "Manufacturer": "ALCATEL-LUCENT",
        "ManufacturerOUI": "E03005",
        "SerialNumber": "ALCLB472FD24",
        "HardwareVersion": "3TN00990ADAA",
        "SoftwareVersion": "3TN00702IJMI00",
        "ProvisioningCode": "TELMEX",
        "gpon_status": {"Enable": "0", "Status": "Up"},
    },
    "wan_pppoe": {
        "VLANIDMark": "881",
        "Username": "E03005LALCLB472FD24@prodigyweb.com.mx",
        "Password_masked": "!!!@@@###$$$^^^&&&***",
        "ConnectionStatus": "Connected",
        "ExternalIPAddress": "189.238.92.11",
        "DNSServers": "189.233.12.5,189.233.15.2",
        "InterfaceMtu": "1492",
        "X_CT_COM_ServiceList": "VOIP,TR069,INTERNET,OTHER",
        "MACAddress": "e0:3d:a6:d0:bd:54",
    },
    "voice_telemetry": {
        "LineStatus": "Disabled",
        "phNumber": None,
        "proxyIp": None,
        "regErrorCode": "0",
        "regErrorReason": None,
        "userAgentIp": "189.238.92.11",
    },
    "wlan_info": {
        "2.4GHz": [{
            "SSID": "SITAI", "BSSID": "e0:3d:a6:d0:bd:59", "Enable": "1",
            "Channel": "6", "WPAAuthenticationMode": "PSKAuthentication",
            "PreSharedKey_encrypted_b64": "3NQG3ZyKDNt9qQnxgqmR0w==",
            "PreSharedKey_cleartext": "Sitai10925",
        }],
        "5GHz": [{
            "SSID": "SITAI", "BSSID": "e0:3d:a6:d0:bd:5d", "Enable": "1",
            "Channel": "100", "WPAAuthenticationMode": "PSKAuthentication",
            "PreSharedKey_encrypted_b64": "3NQG3ZyKDNt9qQnxgqmR0w==",
            "PreSharedKey_cleartext": "Sitai10925",
        }],
    },
    "gpon_info": {
        "HexSLID_flag": "0",
        "SLID_hex": "44454641554C54",
        "SLID_ascii_decoded": "DEFAULT",
    },
    "system_log_summary": {"raw_available": False},
    "_endpoints": {},
    "_session": {"self_managed": True, "logout_status": 200},
}


def _xml_data_from(xml_text):
    """Combina parse_xml_voice_profile() + parse_xml_wan_and_wlan() en el dict
    `xml_data` que espera `build_unified_reports()` (MF-4.2b)."""
    wan_wlan = parse_xml_wan_and_wlan(xml_text)
    return {
        "sip_voip": parse_xml_voice_profile(xml_text),
        "pppoe": wan_wlan["pppoe"],
        "wifi_networks": wan_wlan["wifi_networks"],
        "web_admin": wan_wlan["web_admin"],
    }


# --------------------------------------------------------------------------- #
#  MF-4.2b — build_unified_reports
# --------------------------------------------------------------------------- #
def test_build_unified_reports_con_xml():
    print("\n[MF-4.2b] build_unified_reports() con web_telemetry + xml_data (XML_ELEMENTOS)")
    tmp_dir = tempfile.mkdtemp(prefix="nokia_mf42b_")
    try:
        xml_data = _xml_data_from(XML_ELEMENTOS)
        creds = build_unified_reports(WEB_TELEMETRY_FIXTURE, xml_data=xml_data, output_dir=tmp_dir)

        _check(creds["device_info"]["model_name"] == "G-1425G-H", "device_info.model_name")
        _check(creds["device_info"]["serial_number"] == "ALCLB472FD24", "device_info.serial_number")
        _check(creds["device_info"]["gpon_status"] == "Up", "device_info.gpon_status")

        pppoe = creds["pppoe"]
        _check(pppoe["username"] == "E03005LALCLB472FD24@prodigyweb.com.mx", "pppoe.username")
        _check(pppoe["password"] == "PppoePassElem", "pppoe.password (texto claro del XML, no la mascara)")
        _check(pppoe["password_is_masked"] is False, "pppoe.password_is_masked == False")
        _check(pppoe["vlan_id"] == "881", "pppoe.vlan_id")
        _check(pppoe["external_ip"] == "189.238.92.11", "pppoe.external_ip (de web_telemetry)")

        sip = creds["sip_voip"]
        _check(sip["auth_username"] == "+525512345678", "sip_voip.auth_username (del XML)")
        _check(sip["auth_password"] == "ElemPass123", "sip_voip.auth_password (del XML)")
        _check(sip["uri"] == "sip:+525512345678@vims-h.telmex.com", "sip_voip.uri (del XML)")
        _check(sip["line_status_ont"] == "Disabled", "sip_voip.line_status_ont (de web_telemetry)")
        _check(sip["registrar_server"] == "vims-h.telmex.com", "sip_voip.registrar_server")

        wifi = creds["wifi_networks"]
        _check(len(wifi) == 2, "wifi_networks: 2 SSIDs (de web_telemetry, con PSK en claro)")
        _check(all(w["psk_cleartext"] == "Sitai10925" for w in wifi), "wifi_networks[*].psk_cleartext")

        admin = creds["web_admin"]
        _check(len(admin) == 2, "web_admin: 2 cuentas (del XML)")

        json_path = os.path.join(tmp_dir, "credentials.json")
        md_path = os.path.join(tmp_dir, "credentials.md")
        _check(os.path.exists(json_path), "credentials.json escrito en disco")
        _check(os.path.exists(md_path), "credentials.md escrito en disco")
        _check(creds["_paths"]["json"] == json_path, "_paths.json")

        with open(json_path, "r", encoding="utf-8") as fh:
            reloaded = json.load(fh)
        _check(reloaded["sip_voip"]["auth_username"] == "+525512345678", "credentials.json: sip_voip.auth_username")

        with open(md_path, "r", encoding="utf-8") as fh:
            md_text = fh.read()
        _check("## 1. Identidad del Equipo y Estado GPON" in md_text, "credentials.md: seccion 1")
        _check("## 2. Conexión WAN PPPoE" in md_text, "credentials.md: seccion 2")
        _check("## 3. Telefonía Fija VoIP" in md_text, "credentials.md: seccion 3")
        _check("## 4. Redes Inalámbricas Wi-Fi y Acceso Web" in md_text, "credentials.md: seccion 4")
        _check("ElemPass123" in md_text, "credentials.md: contiene AuthPassword en claro")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_build_unified_reports_sin_xml():
    print("\n[MF-4.2b] build_unified_reports() solo con web_telemetry (sin --xml)")
    tmp_dir = tempfile.mkdtemp(prefix="nokia_mf42b_")
    try:
        creds = build_unified_reports(WEB_TELEMETRY_FIXTURE, xml_data=None, output_dir=tmp_dir)

        pppoe = creds["pppoe"]
        _check(pppoe["password"] == "!!!@@@###$$$^^^&&&***", "pppoe.password == mascara (sin XML disponible)")
        _check(pppoe["password_is_masked"] is True, "pppoe.password_is_masked == True")

        sip = creds["sip_voip"]
        _check(sip["auth_username"] == "Pendiente / No disponible en XML", "sip_voip.auth_username pendiente")
        _check(sip["auth_password"] == "Pendiente / No disponible en XML", "sip_voip.auth_password pendiente")
        _check(sip["registrar_server"] == "vims-h.telmex.com", "sip_voip.registrar_server (default operador)")

        _check(creds["web_admin"] == [], "web_admin vacio sin XML")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# --------------------------------------------------------------------------- #
#  MF-4.3a — render_asterisk_pjsip_conf
# --------------------------------------------------------------------------- #
def test_render_asterisk_pjsip_conf_con_datos_reales():
    print("\n[MF-4.3a] render_asterisk_pjsip_conf() con credenciales SIP reales")
    tmp_dir = tempfile.mkdtemp(prefix="nokia_mf43a_")
    try:
        xml_data = _xml_data_from(XML_ATRIBUTOS)
        creds = build_unified_reports(WEB_TELEMETRY_FIXTURE, xml_data=xml_data, output_dir=tmp_dir)
        out_path = render_asterisk_pjsip_conf(creds["sip_voip"], output_dir=tmp_dir)

        _check(out_path == os.path.join(tmp_dir, "asterisk_pjsip_telmex.conf"), "ruta de salida esperada")
        _check(os.path.exists(out_path), "archivo .conf escrito en disco")

        with open(out_path, "r", encoding="utf-8") as fh:
            content = fh.read()

        for seccion in ("[transport-udp]", "[telmex-ims]", "[telmex-auth]", "[telmex-aor]",
                        "[telmex-endpoint]", "[telmex-identify]"):
            _check(seccion in content, "contiene seccion %s" % seccion)

        _check("username=+525587654321" in content, "auth username real (XML_ATRIBUTOS)")
        _check("password=AttrPass456" in content, "auth password real (XML_ATRIBUTOS)")
        _check("contact_user=+525587654321" in content, "contact_user == numero real")
        _check("server_uri=sip:vims-h.telmex.com:5060" in content, "server_uri con registrar real")
        _check("outbound_proxy=sip:nir8.norte.telmex.net:5060\\;lr" in content, "outbound_proxy con ';lr' escapado")
        _check("TU_PASSWORD_SIP_IMS" not in content, "no quedan placeholders cuando hay datos reales")
        _check("AVISO" not in content, "no hay aviso de 'Pendiente' cuando hay datos reales")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_render_asterisk_pjsip_conf_sin_datos():
    print("\n[MF-4.3a] render_asterisk_pjsip_conf() sin datos (placeholders + aviso)")
    tmp_dir = tempfile.mkdtemp(prefix="nokia_mf43a_")
    try:
        creds = build_unified_reports(WEB_TELEMETRY_FIXTURE, xml_data=None, output_dir=tmp_dir)
        out_path = render_asterisk_pjsip_conf(creds["sip_voip"], output_dir=tmp_dir)
        with open(out_path, "r", encoding="utf-8") as fh:
            content = fh.read()

        _check("+5255XXXXXXXX" in content, "placeholder de numero SIP presente")
        _check("TU_PASSWORD_SIP_IMS" in content, "placeholder de password SIP presente")
        _check("AVISO" in content, "aviso de datos pendientes presente")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# --------------------------------------------------------------------------- #
#  MF-4.3b — render_asterisk_sip_conf
# --------------------------------------------------------------------------- #
def test_render_asterisk_sip_conf():
    print("\n[MF-4.3b] render_asterisk_sip_conf() con credenciales SIP reales")
    tmp_dir = tempfile.mkdtemp(prefix="nokia_mf43b_")
    try:
        xml_data = _xml_data_from(XML_ELEMENTOS)
        creds = build_unified_reports(WEB_TELEMETRY_FIXTURE, xml_data=xml_data, output_dir=tmp_dir)
        sip_path, ext_path = render_asterisk_sip_conf(creds["sip_voip"], output_dir=tmp_dir)

        _check(sip_path == os.path.join(tmp_dir, "asterisk_sip_legacy_telmex.conf"), "ruta sip.conf esperada")
        _check(ext_path == os.path.join(tmp_dir, "asterisk_extensions_sample.conf"), "ruta extensions.conf esperada")
        _check(os.path.exists(sip_path), "sip_legacy_telmex.conf escrito en disco")
        _check(os.path.exists(ext_path), "extensions_sample.conf escrito en disco")

        with open(sip_path, "r", encoding="utf-8") as fh:
            sip_content = fh.read()
        _check("[telmex-ims]" in sip_content, "contiene peer [telmex-ims]")
        _check("register => +525512345678:ElemPass123@vims-h.telmex.com/+525512345678" in sip_content,
               "linea register => con credenciales reales")
        _check("secret=ElemPass123" in sip_content, "secret == auth_password real")

        with open(ext_path, "r", encoding="utf-8") as fh:
            ext_content = fh.read()
        _check("[from-telmex]" in ext_content, "contiene contexto [from-telmex]")
        _check("[salientes-telmex]" in ext_content, "contiene contexto [salientes-telmex]")
        _check("exten => +525512345678,1,NoOp" in ext_content, "exten de entrada con numero real")
        _check("exten => _XXXXXXXXXX,1,NoOp" in ext_content, "patron de 10 digitos para llamadas salientes")
        _check("${EXTEN}" in ext_content, "variable ${EXTEN} sin corromper por el formateo")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


_ALL_TESTS = [
    test_parse_xml_voice_profile_elementos,
    test_parse_xml_voice_profile_atributos,
    test_parse_xml_voice_profile_vacio,
    test_parse_xml_wan_and_wlan_elementos,
    test_parse_xml_wan_and_wlan_atributos,
    test_parse_xml_wan_and_wlan_vacio,
    test_build_unified_reports_con_xml,
    test_build_unified_reports_sin_xml,
    test_render_asterisk_pjsip_conf_con_datos_reales,
    test_render_asterisk_pjsip_conf_sin_datos,
    test_render_asterisk_sip_conf,
]


if __name__ == "__main__":
    fallos = 0
    for test_fn in _ALL_TESTS:
        try:
            test_fn()
        except AssertionError as e:
            fallos += 1
            print("  FALLO  %s: %s" % (test_fn.__name__, e))
    print("\n%d/%d pruebas pasaron" % (len(_ALL_TESTS) - fallos, len(_ALL_TESTS)))
    sys.exit(1 if fallos else 0)
