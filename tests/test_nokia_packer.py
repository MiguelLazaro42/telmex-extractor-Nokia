#!/usr/bin/env python3
"""
Pruebas unitarias — Fase 5, MF-5.1b (build_cfg_header_and_crc) y
MF-5.2a (pack_nokia_configuration / verify_nokia_pack) de nokia_config_packer.py.

Ejecutar desde la raíz del repo:
    python3 -m unittest tests/test_nokia_packer.py -v
"""

import os
import sys
import struct
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import nokia_backup  # noqa: E402
import nokia_config_packer as packer  # noqa: E402

REAL_BACKUP = REPO_ROOT / "output" / "nokia_backup_raw.cfg"

# Header real de output/nokia_backup_raw.cfg (20 bytes), verificado a mano:
# magic=0x00123123, compressed_size=137526, crc32=0x9bf0704f,
# uncompressed_size+1=1286772 (uncompressed_len=1286771), fw_magic=0xfffffffe
EXPECTED_REAL_HEADER_HEX = (
    "23 31 12 00 36 19 02 00 4f 70 f0 9b 74 a2 13 00 fe ff ff ff"
)
EXPECTED_REAL_COMPRESSED_SIZE = 137526
EXPECTED_REAL_CRC32 = 0x9bf0704f
EXPECTED_REAL_UNCOMPRESSED_LEN = 1286771
EXPECTED_REAL_FW_MAGIC = 0xfffffffe


@unittest.skipUnless(REAL_BACKUP.exists(), "requiere output/nokia_backup_raw.cfg (backup real)")
class TestRealBackupVerification(unittest.TestCase):
    """Validaciones contra el backup real capturado del router (MF-3.1/3.2)."""

    def test_verify_nokia_pack_on_real_backup(self):
        result = packer.verify_nokia_pack(REAL_BACKUP)
        self.assertTrue(result["crc32_ok"])
        self.assertEqual(result["magic"], "0x123123")
        self.assertEqual(result["compressed_size_field"], EXPECTED_REAL_COMPRESSED_SIZE)
        self.assertEqual(result["crc32_field"], "0x%08x" % EXPECTED_REAL_CRC32)
        self.assertTrue(result["compressed_size_matches_payload"])
        self.assertTrue(result["crc32_valid"])

    def test_verify_nokia_pack_accepts_bytes_too(self):
        raw = REAL_BACKUP.read_bytes()
        result = packer.verify_nokia_pack(raw)
        self.assertTrue(result["crc32_ok"])

    def test_build_cfg_header_and_crc_reconstructs_real_header_bit_for_bit(self):
        raw = REAL_BACKUP.read_bytes()
        payload = raw[20:]
        self.assertEqual(len(payload), EXPECTED_REAL_COMPRESSED_SIZE)

        header_bytes, meta = packer.build_cfg_header_and_crc(
            payload,
            uncompressed_len=EXPECTED_REAL_UNCOMPRESSED_LEN,
            fw_magic=EXPECTED_REAL_FW_MAGIC,
        )

        expected_header = bytes.fromhex(EXPECTED_REAL_HEADER_HEX.replace(" ", ""))
        self.assertEqual(len(header_bytes), 20)
        self.assertEqual(header_bytes, expected_header)
        self.assertEqual(header_bytes, raw[:20])

        self.assertEqual(meta["compressed_size"], EXPECTED_REAL_COMPRESSED_SIZE)
        self.assertEqual(meta["crc32"], EXPECTED_REAL_CRC32)
        self.assertEqual(meta["uncompressed_size_plus_1"], EXPECTED_REAL_UNCOMPRESSED_LEN + 1)
        self.assertEqual(meta["fw_magic"], EXPECTED_REAL_FW_MAGIC)
        self.assertEqual(meta["magic"], 0x00123123)
        self.assertEqual(meta["header_len"], 20)

    def test_build_cfg_header_and_crc_extended_40b_variant(self):
        payload = b"\x01\x02\x03\x04" * 4
        header_bytes, meta = packer.build_cfg_header_and_crc(
            payload, uncompressed_len=10, fw_magic=0xfffffffe, extended_40b=True
        )
        self.assertEqual(len(header_bytes), 40)
        vals = struct.unpack("<10I", header_bytes)
        self.assertEqual(vals[0], 0x00123123)
        self.assertEqual(vals[1], 0)
        self.assertEqual(vals[2], len(payload))
        self.assertEqual(vals[3], 0)
        self.assertEqual(meta["header_len"], 40)
        self.assertTrue(meta["extended_40b"])


class TestPackRoundTrip(unittest.TestCase):
    """Round-trip completo: XML -> pack -> verify -> unpack -> XML idéntico."""

    SAMPLE_XML = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<InternetGatewayDevice>\n"
        "  <VoiceService>\n"
        "    <VoiceProfile>\n"
        "      <Line>\n"
        '        <SIP AuthUserName="+525512345678" '
        'AuthPassword="TestPassword123" '
        'ProxyServer="vims-h.telmex.com" '
        'RegistrarServer="vims-h.telmex.com"/>\n'
        "      </Line>\n"
        "    </VoiceProfile>\n"
        "  </VoiceService>\n"
        "</InternetGatewayDevice>\n"
    )

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.xml_path = Path(self.tmpdir.name) / "sample.xml"
        self.xml_path.write_text(self.SAMPLE_XML, encoding="utf-8")
        self.cfg_path = Path(self.tmpdir.name) / "packed.cfg"

    def test_pack_nokia_configuration_roundtrip_zlib_mode(self):
        result = packer.pack_nokia_configuration(self.xml_path, self.cfg_path)
        self.assertTrue(result["crc32_ok"])
        self.assertTrue(result["crc32_valid"])
        self.assertTrue(result["compressed_size_matches_payload"])

        raw = self.cfg_path.read_bytes()
        unpacked = nokia_backup.unpack_and_decrypt_config(raw)
        self.assertTrue(unpacked["success"], msg=unpacked.get("reason"))
        self.assertEqual(unpacked["method"], "zlib-directo")

        xml_bytes = self.SAMPLE_XML.encode("utf-8")

        # unpack_and_decrypt_config no devuelve el XML directamente salvo que
        # se le pase out_path; lo volvemos a invocar con out_path para
        # comparar bytes exactos.
        out_xml_path = Path(self.tmpdir.name) / "recovered.xml"
        unpacked2 = nokia_backup.unpack_and_decrypt_config(raw, out_path=str(out_xml_path))
        self.assertTrue(unpacked2["success"])
        recovered = out_xml_path.read_bytes()
        self.assertEqual(recovered, xml_bytes)
        self.assertEqual(unpacked2["xml_len"], len(xml_bytes))
        self.assertTrue(unpacked2["xml_len_matches_header"])

    def test_pack_nokia_configuration_with_cipher_hook(self):
        # cipher_hook trivial (XOR) solo para validar que el payload final
        # (post-hook) es el que se usa para CRC32/compressed_size.
        key = 0x5A

        def xor_hook(data: bytes) -> bytes:
            return bytes(b ^ key for b in data)

        result = packer.pack_nokia_configuration(
            self.xml_path, self.cfg_path, cipher_hook=xor_hook
        )
        self.assertTrue(result["crc32_ok"])

        raw = self.cfg_path.read_bytes()
        payload = raw[20:]
        import zlib
        compressed = zlib.compress(self.SAMPLE_XML.encode("utf-8"), 9)
        expected_payload = bytes(b ^ key for b in compressed)
        self.assertEqual(payload, expected_payload)


class TestCorruptionDetection(unittest.TestCase):
    SAMPLE_XML = "<root><a>1</a></root>"

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.xml_path = Path(self.tmpdir.name) / "sample.xml"
        self.xml_path.write_text(self.SAMPLE_XML, encoding="utf-8")
        self.cfg_path = Path(self.tmpdir.name) / "packed.cfg"
        packer.pack_nokia_configuration(self.xml_path, self.cfg_path)
        self.good_bytes = self.cfg_path.read_bytes()

    def _flip_bit(self, data: bytes, byte_offset: int, bit: int = 0) -> bytes:
        buf = bytearray(data)
        buf[byte_offset] ^= (1 << bit)
        return bytes(buf)

    def test_detects_1bit_corruption_in_payload(self):
        # El payload empieza en el byte 20 (fin del header de 20 bytes).
        corrupted = self._flip_bit(self.good_bytes, 20 + 2)
        with self.assertRaises(ValueError):
            packer.verify_nokia_pack(corrupted)

    def test_detects_1bit_corruption_in_header_crc_field(self):
        # El campo CRC32 ocupa los bytes [8:12) del header.
        corrupted = self._flip_bit(self.good_bytes, 8)
        with self.assertRaises(ValueError):
            packer.verify_nokia_pack(corrupted)

    def test_detects_1bit_corruption_in_header_size_field(self):
        # compressed_size ocupa los bytes [4:8).
        corrupted = self._flip_bit(self.good_bytes, 4)
        with self.assertRaises(ValueError):
            packer.verify_nokia_pack(corrupted)

    def test_uncorrupted_file_still_verifies(self):
        result = packer.verify_nokia_pack(self.good_bytes)
        self.assertTrue(result["crc32_ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
