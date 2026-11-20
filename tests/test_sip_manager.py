#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_sip_manager.py — Validación unitaria de MF-5.2b
(`toggle_xml_sip_state`) en `nokia_sip_manager.py`.

Reutiliza los dos esquemas XML sintéticos TR-098/TR-104 Nokia/Alcatel-Lucent
de `tests/test_xml_parsers.py` (jerárquico por sub-elementos y de atributos
aplanados) para verificar que `toggle_xml_sip_state()`:

  1. Cambia correctamente `Enabled` <-> `Disabled` en ambos esquemas, sin
     alterar `AuthUserName`, `AuthPassword`, `URI` ni `WANPPPConnection`
     (verificado reutilizando `parse_xml_voice_profile()` — MF-4.1b).
  2. Lanza `ValueError` si el XML no contiene nodos de voz.
  3. Se integra con `pack_nokia_configuration()` (MF-5.2a) y el resultado
     pasa `verify_nokia_pack()`.

No requiere red ni acceso al router. Ejecutar con:
    python3 -m unittest tests/test_sip_manager.py -v
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from nokia_g1425gh_extractor import parse_xml_voice_profile  # noqa: E402
from nokia_sip_manager import (  # noqa: E402
    toggle_xml_sip_state,
    upload_nokia_configuration,
    verify_ims_network_reachability,
)
import nokia_config_packer as packer  # noqa: E402


# --------------------------------------------------------------------------- #
#  XML sintético #1 — esquema jerárquico por sub-elementos XML
#  (idéntico en estructura a XML_ELEMENTOS de tests/test_xml_parsers.py)
# --------------------------------------------------------------------------- #
XML_ELEMENTOS = """<?xml version="1.0" encoding="UTF-8"?>
<InternetGatewayDevice>
  <Services>
    <VoiceService InstanceID="1">
      <VoiceProfile InstanceID="1">
        <Enable>Enabled</Enable>
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
</InternetGatewayDevice>
"""


# --------------------------------------------------------------------------- #
#  XML sintético #2 — esquema de atributos TR-098/TR-104 (nodos aplanados)
#  (idéntico en estructura a XML_ATRIBUTOS de tests/test_xml_parsers.py)
# --------------------------------------------------------------------------- #
XML_ATRIBUTOS = """<?xml version="1.0" encoding="UTF-8"?>
<X_TR069_Config>
  <VoiceService InstanceID="1">
    <VoiceProfileInstance InstanceID="1" Enable="Enabled"
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
</X_TR069_Config>
"""


XML_SIN_VOZ = """<?xml version="1.0" encoding="UTF-8"?>
<X_TR069_Config>
  <WANPPPConnectionInstance InstanceID="1"
      Username="user@prodigyweb.com.mx" Password="PppoePass"
      VLANIDMark="881" InterfaceMtu="1492"/>
</X_TR069_Config>
"""


def _read(path):
    return Path(path).read_text(encoding="utf-8")


class TestToggleXmlSipStateSubelementos(unittest.TestCase):
    """Esquema jerárquico por sub-elementos (<Enable>Enabled</Enable>)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.in_xml = Path(self.tmp.name) / "in.xml"
        self.in_xml.write_text(XML_ELEMENTOS, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_disable_then_enable_roundtrip(self):
        out1 = Path(self.tmp.name) / "disabled.xml"
        result = toggle_xml_sip_state(self.in_xml, out1, enable=False)

        self.assertEqual(result["target_state"], "Disabled")
        self.assertEqual(result["voice_profiles_modified"], 1)
        self.assertEqual(result["lines_modified"], 1)
        self.assertEqual(result["output_xml_path"], str(out1))

        sip = parse_xml_voice_profile(_read(out1))
        self.assertEqual(sip["line_status"], "Disabled")
        # Datos de credenciales/URI intactos.
        self.assertEqual(sip["auth_username"], "+525512345678")
        self.assertEqual(sip["auth_password"], "ElemPass123")
        self.assertEqual(sip["uri"], "sip:+525512345678@vims-h.telmex.com")

        out2 = Path(self.tmp.name) / "enabled.xml"
        result2 = toggle_xml_sip_state(out1, out2, enable=True)
        self.assertEqual(result2["target_state"], "Enabled")

        sip2 = parse_xml_voice_profile(_read(out2))
        self.assertEqual(sip2["line_status"], "Enabled")
        self.assertEqual(sip2["auth_username"], "+525512345678")
        self.assertEqual(sip2["auth_password"], "ElemPass123")
        self.assertEqual(sip2["uri"], "sip:+525512345678@vims-h.telmex.com")

    def test_wanppp_connection_not_touched(self):
        out = Path(self.tmp.name) / "disabled.xml"
        toggle_xml_sip_state(self.in_xml, out, enable=False)
        text = _read(out)
        self.assertIn("<Username>E03005LALCLB472FD24@prodigyweb.com.mx</Username>", text)
        self.assertIn("<Password>PppoePassElem</Password>", text)


class TestToggleXmlSipStateAtributos(unittest.TestCase):
    """Esquema de atributos TR-098/TR-104 (VoiceProfileInstance/LineInstance)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.in_xml = Path(self.tmp.name) / "in.xml"
        self.in_xml.write_text(XML_ATRIBUTOS, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_disable_then_enable_roundtrip(self):
        out1 = Path(self.tmp.name) / "disabled.xml"
        result = toggle_xml_sip_state(self.in_xml, out1, enable=False)

        self.assertEqual(result["target_state"], "Disabled")
        self.assertEqual(result["voice_profiles_modified"], 1)
        self.assertEqual(result["lines_modified"], 1)

        sip = parse_xml_voice_profile(_read(out1))
        self.assertEqual(sip["line_status"], "Disabled")
        self.assertEqual(sip["auth_username"], "+525587654321")
        self.assertEqual(sip["auth_password"], "AttrPass456")
        self.assertEqual(sip["uri"], "sip:+525587654321@vims-h.telmex.com")

        out2 = Path(self.tmp.name) / "enabled.xml"
        result2 = toggle_xml_sip_state(out1, out2, enable=True)
        self.assertEqual(result2["target_state"], "Enabled")

        sip2 = parse_xml_voice_profile(_read(out2))
        self.assertEqual(sip2["line_status"], "Enabled")
        self.assertEqual(sip2["auth_username"], "+525587654321")
        self.assertEqual(sip2["auth_password"], "AttrPass456")
        self.assertEqual(sip2["uri"], "sip:+525587654321@vims-h.telmex.com")

    def test_wanppp_connection_instance_not_touched(self):
        out = Path(self.tmp.name) / "disabled.xml"
        toggle_xml_sip_state(self.in_xml, out, enable=False)
        text = _read(out)
        self.assertIn('Username="E03005LALCLB472FD24@prodigyweb.com.mx"', text)
        self.assertIn('Password="PppoePassAttr"', text)


class TestToggleXmlSipStateErrors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_raises_value_error_without_voice_nodes(self):
        in_xml = Path(self.tmp.name) / "sin_voz.xml"
        in_xml.write_text(XML_SIN_VOZ, encoding="utf-8")
        out_xml = Path(self.tmp.name) / "out.xml"
        with self.assertRaises(ValueError):
            toggle_xml_sip_state(in_xml, out_xml, enable=False)


class TestIntegrationToggleAndPack(unittest.TestCase):
    """MF-5.2b + MF-5.2a: el XML modificado se empaqueta y verifica."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_toggle_then_pack_then_verify(self):
        in_xml = Path(self.tmp.name) / "in.xml"
        in_xml.write_text(XML_ELEMENTOS, encoding="utf-8")

        toggled_xml = Path(self.tmp.name) / "toggled.xml"
        toggle_result = toggle_xml_sip_state(in_xml, toggled_xml, enable=False)
        self.assertEqual(toggle_result["target_state"], "Disabled")

        out_cfg = Path(self.tmp.name) / "out.cfg"
        pack_result = packer.pack_nokia_configuration(toggled_xml, out_cfg)
        self.assertTrue(pack_result["crc32_ok"])

        verify_result = packer.verify_nokia_pack(out_cfg)
        self.assertTrue(verify_result["crc32_ok"])


XML_PARA_EMPAQUETAR = """<?xml version="1.0" encoding="UTF-8"?>
<InternetGatewayDevice>
  <Services>
    <VoiceService InstanceID="1">
      <VoiceProfile InstanceID="1">
        <Enable>Disabled</Enable>
        <Line InstanceID="1">
          <Enable>Disabled</Enable>
          <SIP>
            <AuthUserName>+525512345678</AuthUserName>
            <AuthPassword>ElemPass123</AuthPassword>
          </SIP>
        </Line>
      </VoiceProfile>
    </VoiceService>
  </Services>
</InternetGatewayDevice>
"""


# --------------------------------------------------------------------------- #
#  MockOpener — doble de prueba en memoria del OpenerDirector de urllib.
#  NUNCA toca la red: solo responde según la URL/método de la Request.
# --------------------------------------------------------------------------- #
class _FakeHttpResponse:
    def __init__(self, body, status=200):
        self._body = body
        self.status = status

    def read(self):
        return self._body

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class MockOpener:
    """
    Simula el `opener` autenticado que usan `nokia_backup.py`/`nokia_sip_manager.py`:
      - GET  .../usb.cgi?backup       -> HTML con un csrf_token embebido.
      - POST .../usb.cgi?import(...)  -> "Import Completed!" (o la respuesta dada).
    Registra CADA llamada en `self.requests` para poder aseverar que
    `upload_nokia_configuration()` NUNCA llama a la red cuando debe abortar
    en el PASO 0 (bloqueo de seguridad).
    """

    def __init__(self, csrf_token="TESTCSRFTOKEN0001", import_response=b"Import Completed!"):
        self.requests = []
        self.csrf_token = csrf_token
        self.import_response = import_response
        self.last_import_body = None

    def open(self, req, timeout=None):
        method = req.get_method()
        url = req.full_url
        data = req.data
        self.requests.append({
            "method": method,
            "url": url,
            "data": data,
            "headers": dict(req.header_items()),
        })

        if method == "GET" and "usb.cgi?backup" in url:
            html = ('<html><input type="hidden" name="csrf_token" '
                    'value="%s"></html>' % self.csrf_token)
            return _FakeHttpResponse(html.encode("utf-8"))

        if method == "POST" and ("usb.cgi?import" in url or "v=import" in url):
            self.last_import_body = data
            return _FakeHttpResponse(self.import_response)

        raise AssertionError("MockOpener: petición inesperada %s %s" % (method, url))


class TestUploadNokiaConfigurationSecurityGate(unittest.TestCase):
    """MF-5.2c — PASO 0: el bloqueo de seguridad debe abortar ANTES de tocar la red."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        xml_path = Path(self.tmp.name) / "in.xml"
        xml_path.write_text(XML_PARA_EMPAQUETAR, encoding="utf-8")
        self.valid_cfg = Path(self.tmp.name) / "valid.cfg"
        packer.pack_nokia_configuration(xml_path, self.valid_cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_cfg_file_raises_before_network(self):
        mock_opener = MockOpener()
        missing_cfg = Path(self.tmp.name) / "no_existe.cfg"
        with self.assertRaises(FileNotFoundError):
            upload_nokia_configuration(opener=mock_opener, cfg_path=missing_cfg,
                                       x_sid="SID-TEST")
        self.assertEqual(len(mock_opener.requests), 0)

    def test_corrupted_cfg_raises_value_error_before_network(self):
        corrupt_cfg = Path(self.tmp.name) / "corrupt.cfg"
        raw = bytearray(self.valid_cfg.read_bytes())
        # Altera 1 bit en medio del payload (después del header de 20 bytes).
        raw[25] ^= 0x01
        corrupt_cfg.write_bytes(bytes(raw))

        mock_opener = MockOpener()
        with self.assertRaises(ValueError):
            upload_nokia_configuration(opener=mock_opener, cfg_path=corrupt_cfg,
                                       x_sid="SID-TEST")
        self.assertEqual(len(mock_opener.requests), 0)

    def test_invalid_serial_number_raises_before_network(self):
        mock_opener = MockOpener()
        for bad_serial in ("NOTVALID1234", "ALCL123", "alclb472fd24extra", ""):
            with self.subTest(bad_serial=bad_serial):
                with self.assertRaises(ValueError):
                    upload_nokia_configuration(opener=mock_opener, cfg_path=self.valid_cfg,
                                               serial_number=bad_serial, x_sid="SID-TEST")
        self.assertEqual(len(mock_opener.requests), 0)


class TestUploadNokiaConfigurationHappyPath(unittest.TestCase):
    """MF-5.2c — flujo exitoso con MockOpener (sin red real)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        xml_path = Path(self.tmp.name) / "in.xml"
        xml_path.write_text(XML_PARA_EMPAQUETAR, encoding="utf-8")
        self.valid_cfg = Path(self.tmp.name) / "valid.cfg"
        self.pack_result = packer.pack_nokia_configuration(xml_path, self.valid_cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def _multipart_text(self, mock_opener):
        post_reqs = [r for r in mock_opener.requests if r["method"] == "POST"]
        self.assertEqual(len(post_reqs), 1)
        body = post_reqs[0]["data"]
        # Los bytes del .cfg (binarios) pueden no decodificar en UTF-8 estricto;
        # se usa 'replace' solo para inspeccionar los campos de texto del multipart.
        return body.decode("latin-1")

    def test_upload_without_serial_hits_import_endpoint(self):
        mock_opener = MockOpener()
        result = upload_nokia_configuration(opener=mock_opener, ip="192.168.99.254",
                                            cfg_path=self.valid_cfg, x_sid="SID-TEST")

        self.assertEqual(result["endpoint"], "http://192.168.99.254/usb.cgi?import")
        self.assertTrue(result["import_completed"])
        self.assertEqual(result["cfg_size"], self.valid_cfg.stat().st_size)
        self.assertEqual(result["crc32"], self.pack_result["crc32_field"])

        # Debe haber hecho exactamente GET backup (csrf) + POST import.
        methods = [r["method"] for r in mock_opener.requests]
        self.assertEqual(methods, ["GET", "POST"])

        text = self._multipart_text(mock_opener)
        self.assertIn('name="csrf_val"', text)
        self.assertIn('name="csrf_token"', text)
        self.assertIn(mock_opener.csrf_token, text)
        self.assertIn('name="filename"; filename="config.cfg"', text)
        self.assertIn("Content-Type: application/octet-stream", text)

    def test_upload_with_valid_serial_hits_v_import_endpoint(self):
        mock_opener = MockOpener()
        serial = "ALCLB472FD24"
        result = upload_nokia_configuration(opener=mock_opener, ip="192.168.99.254",
                                            cfg_path=self.valid_cfg, serial_number=serial,
                                            x_sid="SID-TEST")

        self.assertEqual(result["endpoint"],
                         "http://192.168.99.254/usb.cgi?v=import&sl_num=%s" % serial)
        self.assertTrue(result["import_completed"])

        post_req = [r for r in mock_opener.requests if r["method"] == "POST"][0]
        self.assertIn("v=import&sl_num=%s" % serial, post_req["url"])

    def test_import_not_completed_is_reported_false(self):
        mock_opener = MockOpener(import_response=b"Import Failed!")
        result = upload_nokia_configuration(opener=mock_opener, cfg_path=self.valid_cfg,
                                            x_sid="SID-TEST")
        self.assertFalse(result["import_completed"])
        self.assertIn("Import Failed!", result["response_preview"])

    def test_unmanaged_opener_does_not_logout(self):
        """Si se pasa un opener externo, upload_nokia_configuration() no debe cerrar
        la sesión (eso es responsabilidad de quien la abrió)."""
        mock_opener = MockOpener()
        result = upload_nokia_configuration(opener=mock_opener, cfg_path=self.valid_cfg,
                                            x_sid="SID-TEST")
        self.assertEqual(result["_session"], {"self_managed": False, "logout_status": None})
        # Ningún request de logout (login.cgi?out) debe haberse disparado.
        self.assertFalse(any("login.cgi" in r["url"] for r in mock_opener.requests))


class NetworkMockOpener:
    """MockOpener en memoria para MF-5.3a (solo GET; cualquier otro método falla)."""

    def __init__(self, sip_enable=1, line_status="Disabled"):
        self.requests = []
        self.sip_enable = sip_enable
        self.line_status = line_status

    def open(self, req, timeout=None):
        url = req.full_url
        self.requests.append({"method": req.get_method(), "url": url})
        if req.get_method() != "GET":
            raise AssertionError("MF-5.3a debe ser solo lectura: %s %s" % (req.get_method(), url))
        if "voice_info.cgi" in url:
            body = ("var voip_cmd = {phNumber:'', proxyIp:'', regErrorCode:'0', regErrorReason:''};"
                    "var lines_config = {Status:'%s'};"
                    "var user_agent = {userAgentIp:'189.238.92.11'};" % self.line_status)
        elif "wan_config_glb.cgi" in url:
            body = ("var wan = {VLANIDMark:881, X_CT_COM_ServiceList:'VOIP,TR069,INTERNET,OTHER',"
                    "DNSServers:'189.233.12.5,189.233.15.2', ExternalIPAddress:'189.238.92.11'};")
        elif "show_wan_status.cgi" in url:
            body = ("var st = {ConnectionStatus:'Connected', ExternalIPAddress:'189.238.92.11',"
                    "DNSServers:'189.233.12.5,189.233.15.2'};")
        elif "nat_glb.cgi?v=alg" in url:
            body = ("var alg_obj = { H323Enable:1, TFTPEnable:1, SIPEnable:%d, RTSPEnable:1 };"
                    % self.sip_enable)
        else:
            raise AssertionError("petición inesperada %s" % url)
        return _FakeHttpResponse(body.encode("utf-8"))


class TestVerifyImsNetworkReachability(unittest.TestCase):
    """MF-5.3a — checklist de red (solo lectura) con opener simulado."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sip_alg_enabled_adds_recommendation(self):
        mock = NetworkMockOpener(sip_enable=1)
        r = verify_ims_network_reachability(opener=mock, x_sid="SID", output_dir=self.tmp)
        self.assertTrue(r["alg_state"]["sip_alg_enabled"])
        self.assertFalse(r["checklist_ready"])
        self.assertTrue(r["wan_state"]["connected"])
        self.assertTrue(r["wan_state"]["voip_service"])
        self.assertFalse(r["voice_state"]["is_active"])
        self.assertEqual(r["_session"], {"self_managed": False, "logout_status": None})
        md = Path(r["checklist_md_path"]).read_text(encoding="utf-8")
        self.assertIn("Security → DMZ and ALG", md)
        self.assertIn("189.233.12.5", md)
        self.assertIn("pjsip show registrations", md)
        self.assertIn("pjsip set logger on", md)
        self.assertTrue(all(q["method"] == "GET" for q in mock.requests))
        self.assertFalse(any("login.cgi" in q["url"] for q in mock.requests))

    def test_sip_alg_disabled_no_recommendation(self):
        mock = NetworkMockOpener(sip_enable=0)
        r = verify_ims_network_reachability(opener=mock, x_sid="SID", output_dir=self.tmp)
        self.assertFalse(r["alg_state"]["sip_alg_enabled"])
        self.assertIsNone(r["alg_state"]["recommendation"])
        self.assertTrue(r["checklist_ready"])
        md = Path(r["checklist_md_path"]).read_text(encoding="utf-8")
        self.assertNotIn("Recomendación", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
