#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test thedroidgeek Nokia cfg format against our file."""
import os, sys, zlib, binascii, struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "..", "output", "nokia_backup_raw.cfg")
data = open(RAW, "rb").read()

KEY = bytes.fromhex("3DA373D7DC822E2A470DEC37896E80D72C49B31629DDC997354B840391779EA4")
IV  = bytes.fromhex("D0E6DCCDA74A00DF760FC08511CB05EA")
print("key len:", len(KEY), "iv len:", len(IV))

hdr = data[:20]
payload = data[20:]
magic   = struct.unpack("<I", hdr[0:4])[0]
clen    = struct.unpack("<I", hdr[4:8])[0]
crc     = struct.unpack("<I", hdr[8:12])[0]
ulen    = struct.unpack("<I", hdr[12:16])[0]
fwmagic = struct.unpack("<I", hdr[16:20])[0]
print("magic   : 0x%06x (expect 0x123123)" % magic)
print("clen    :", clen, " actual payload:", len(payload))
print("crc hdr : 0x%08x" % crc)
print("ulen    :", ulen, " => xml bytes =", ulen - 1)
print("fw_magic: 0x%08x" % fwmagic)
print("=" * 60)

crc_payload = binascii.crc32(payload) & 0xffffffff
print("CRC32(payload as-is)      : 0x%08x  match=%s" % (crc_payload, crc_payload == crc))

def summarize(label, out):
    if out is None:
        print("  %-28s: FAIL" % label); return False
    head = out[:4].hex()
    ok = head.startswith("789c") or head.startswith("78da") or head.startswith("7801") or head.startswith("785e") or head.startswith("1f8b")
    crc_o = binascii.crc32(out) & 0xffffffff
    print("  %-28s: head=%s crc=0x%08x crcmatch=%s zlibmagic=%s len=%d" % (
        label, head, crc_o, crc_o == crc, ok, len(out)))
    return ok

def aes_dec(mode_name, buf):
    try:
        if mode_name == "CBC":
            cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
        elif mode_name == "CFB":
            cipher = Cipher(algorithms.AES(KEY), modes.CFB(IV))
        elif mode_name == "OFB":
            cipher = Cipher(algorithms.AES(KEY), modes.OFB(IV))
        elif mode_name == "CTR":
            cipher = Cipher(algorithms.AES(KEY), modes.CTR(IV))
        d = cipher.decryptor()
        return d.update(buf) + d.finalize()
    except Exception as e:
        print("   aes_dec err", mode_name, e)
        return None

print("=" * 60)
print("[A] Decrypt WHOLE FILE (header+payload) then look for magic 0x123123")
# thedroidgeek: if magic not found, AES-decrypt the file. Our file IS block-aligned?
print("  file len %% 16 =", len(data) % 16)
for m in ("CBC",):
    if len(data) % 16 == 0:
        out = aes_dec(m, data)
        print("  whole-file %s first16: %s" % (m, out[:16].hex() if out else None))

print("=" * 60)
print("[B] payload length %% 16 =", len(payload) % 16)
print("[B] Stream modes over full payload (offset 20):")
for m in ("CTR", "CFB", "OFB"):
    out = aes_dec(m, payload)
    summarize("payload %s" % m, out)

print("=" * 60)
print("[C] CBC over block-aligned prefix of payload, leave 6-byte tail:")
blk = (len(payload) // 16) * 16
out = aes_dec("CBC", payload[:blk])
if out is not None:
    out_full = out + payload[blk:]
    summarize("payload[:blk] CBC + tail", out_full)
    # try zlib on it
    try:
        dec = zlib.decompress(out_full)
        print("  zlib OK len=%d" % len(dec), dec[:80])
    except Exception as e:
        print("  zlib fail:", e)
