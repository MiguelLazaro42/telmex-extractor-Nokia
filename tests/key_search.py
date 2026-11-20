#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Broad candidate-key search for the Telmex G-1425G-H config.cfg inner payload.

We KNOW (verified): legacy container magic 0x123123, 20-byte LE header,
CRC32(payload)=0x9bf0704f matches, uncompressed=1286772. The inner stored
payload is 137526 bytes, entropy 7.998, len%16=6 (NOT block-aligned => if AES,
a STREAM mode: CTR/CFB/OFB; whole-payload CBC/ECB impossible).

Discriminator: the format compresses with zlib (zlib.decompress on unpack),
so a correctly decrypted payload MUST begin with a zlib header:
  78 01 / 78 9c / 78 da / 78 5e   (or gzip 1f 8b).

Run: .venv/bin/python -I tests/key_search.py
"""
import os, sys, zlib, hashlib, struct, binascii, itertools
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "..", "output", "nokia_backup_raw.cfg")
data = open(RAW, "rb").read()
payload = data[20:]
CRC = 0x9bf0704f

ZLIB_HEADS = (b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e", b"\x1f\x8b")

SERIAL = "ALCLB472FD24"
SER_HEX = "b472fd24"           # 8 hex after stripping ALCL (rajkosto style)
PKCS_PW = "S23l7nZm47XyMGs6y6oJpN9CR4nbfIZHJ4VRwp7HcdV6o2YvUmeNYFlz08Otwz78"
DG_KEY = bytes.fromhex("3DA373D7DC822E2A470DEC37896E80D72C49B31629DDC997354B840391779EA4")
DG_IV  = bytes.fromhex("D0E6DCCDA74A00DF760FC08511CB05EA")

def norm_key(kb):
    """Return list of (keylen, keybytes) for 16/24/32 from a raw byte source."""
    out = []
    for L in (16, 24, 32):
        if len(kb) >= L:
            out.append((L, kb[:L]))
        else:
            out.append((L, (kb * (L // len(kb) + 1))[:L]))
    return out

# ---- Build candidate (key, iv, label) list --------------------------------
candidates = []  # (label, keybytes, ivbytes)

def add_keyvariants(label, src_bytes, ivs):
    for L, kb in norm_key(src_bytes):
        for ivlabel, iv in ivs:
            candidates.append(("%s|k%d|%s" % (label, L, ivlabel), kb, iv))

ZIV = b"\x00" * 16
ivs_common = [("zeroIV", ZIV), ("dgIV", DG_IV)]

# droidgeek key itself (already known to fail in stream modes, include for completeness)
candidates.append(("dgkey|k32|dgIV", DG_KEY, DG_IV))
candidates.append(("dgkey|k32|zeroIV", DG_KEY, ZIV))

# string-derived keys
str_sources = {
    "serial":       SERIAL.encode(),
    "serial_lc":    SERIAL.lower().encode(),
    "serhex":       SER_HEX.encode(),
    "ALCL":         b"ALCL",
    "NOKA":         b"NOKA",
    "TELMEX":       b"TELMEX",
    "pkcspw":       PKCS_PW.encode(),
    "serial+telmex": (SERIAL + "TELMEX").encode(),
}
for name, s in str_sources.items():
    add_keyvariants("raw:" + name, s, ivs_common)
    add_keyvariants("md5:" + name, hashlib.md5(s).digest(), ivs_common)
    add_keyvariants("sha256:" + name, hashlib.sha256(s).digest(), ivs_common)
    # md5 doubled -> 32 bytes
    add_keyvariants("md5x2:" + name, hashlib.md5(s).digest() * 2, ivs_common)

# PBKDF2 of the fixed password with various salts
salts = {
    "key10": b"key10",
    "empty": b"",
    "serial": SERIAL.encode(),
    "payload8": payload[:8],
    "payload16": payload[:16],
    "dgIV": DG_IV,
}
for sname, salt in salts.items():
    for iters in (10, 100, 1000):
        dk = hashlib.pbkdf2_hmac("sha256", PKCS_PW.encode(), salt, iters, dklen=48)
        candidates.append(("pbkdf2:%s:%d|split" % (sname, iters), dk[:32], dk[16:32] if False else dk[32:48]))
        candidates.append(("pbkdf2:%s:%d|zeroIV" % (sname, iters), dk[:32], ZIV))

# ---- Test each candidate in stream modes (len not aligned) + aligned block --
def decrypt(mode, key, iv, buf):
    try:
        if mode == "CTR":
            c = Cipher(algorithms.AES(key), modes.CTR(iv))
        elif mode == "CFB":
            c = Cipher(algorithms.AES(key), modes.CFB(iv))
        elif mode == "OFB":
            c = Cipher(algorithms.AES(key), modes.OFB(iv))
        elif mode == "CBC":
            c = Cipher(algorithms.AES(key), modes.CBC(iv))
        elif mode == "ECB":
            c = Cipher(algorithms.AES(key), modes.ECB())
        d = c.decryptor()
        return d.update(buf) + d.finalize()
    except Exception:
        return None

blk = (len(payload) // 16) * 16
hits = []
tested = 0
for label, key, iv in candidates:
    # stream modes over full payload
    for mode in ("CTR", "CFB", "OFB"):
        out = decrypt(mode, key, iv, payload)
        tested += 1
        if out and out[:2] in ZLIB_HEADS:
            hits.append((label, mode, out))
            print("HIT", label, mode, out[:4].hex())
    # CBC/ECB over aligned prefix
    for mode in ("CBC", "ECB"):
        out = decrypt(mode, key, iv, payload[:blk])
        tested += 1
        if out and out[:2] in ZLIB_HEADS:
            hits.append((label + "+alignedtail", mode, out))
            print("HIT", label, mode, out[:4].hex())

print("tested combos:", tested, "candidates:", len(candidates))
print("hits:", len(hits))

# ---- Also: maybe payload has a small prefix then aligned CBC ----------------
print("=" * 60)
print("[*] Trying prefix-stripped CBC (prefix 1..32), droidgeek + pbkdf2 keys...")
test_keys = [("dgkey", DG_KEY, DG_IV)]
dk = hashlib.pbkdf2_hmac("sha256", PKCS_PW.encode(), b"", 10, dklen=48)
test_keys.append(("pbkdf2empty", dk[:32], dk[32:48]))
for pfx in range(0, 33):
    body = payload[pfx:]
    bl = (len(body) // 16) * 16
    if bl == 0:
        continue
    for label, key, iv in test_keys:
        # use first 16 bytes after prefix as IV too (common pattern)
        for ivlabel, ivv in (("fixedIV", iv), ("zeroIV", ZIV)):
            out = decrypt("CBC", key, ivv, body[:bl])
            if out and out[:2] in ZLIB_HEADS:
                print("PREFIX HIT pfx=%d %s %s" % (pfx, label, ivlabel), out[:4].hex())
        # prefix bytes AS iv
        if pfx == 16:
            out = decrypt("CBC", key, payload[:16], body[:bl])
            if out and out[:2] in ZLIB_HEADS:
                print("PREFIX-AS-IV HIT pfx=16 %s" % label, out[:4].hex())

print("done.")
