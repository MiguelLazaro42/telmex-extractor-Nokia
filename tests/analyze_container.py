#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Forensic / cryptanalysis sandbox for MF-3.2 (analyze_container_format).

Goal: identify the exact byte transformation that turns the 137,526-byte payload
of output/nokia_backup_raw.cfg (Alcatel-Lucent/Nokia '#1' container) into a
decompressible stream yielding ~1,286,772 bytes of XML, and verify the header
checksum 0x9bf0704f.

Run:  .venv/bin/python -I tests/analyze_container.py
"""
import os, sys, zlib, gzip, bz2, lzma, struct, io, binascii

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "..", "output", "nokia_backup_raw.cfg")

data = open(RAW, "rb").read()
hdr = data[:20]
payload = data[20:]

print("file size      :", len(data))
print("header (20B)   :", hdr.hex())
magic   = hdr[0:2]
h_rest  = struct.unpack("<H", hdr[2:4])[0]
h_plen  = struct.unpack("<I", hdr[4:8])[0]
h_cksum = struct.unpack("<I", hdr[8:12])[0]
h_ulen  = struct.unpack("<I", hdr[12:16])[0]
h_flags = struct.unpack("<I", hdr[16:20])[0]
print("magic          :", magic, magic.hex())
print("hdr_rest(2:4)  :", h_rest)
print("payload_len    :", h_plen, "(actual payload bytes: %d)" % len(payload))
print("checksum(8:12) : 0x%08x" % h_cksum)
print("uncompr_len    :", h_ulen, "(0x%08x)" % h_ulen)
print("flags(16:20)   : 0x%08x" % h_flags)
print("payload %%16     :", len(payload) % 16)
print("payload[0:16]  :", payload[:16].hex())
print("=" * 70)

# ---- entropy of payload (sanity: high entropy => compressed or encrypted) ----
from math import log2
from collections import Counter
c = Counter(payload)
n = len(payload)
ent = -sum((v/n) * log2(v/n) for v in c.values())
print("payload entropy: %.4f bits/byte (8.0 = random/compressed/encrypted)" % ent)
print("=" * 70)

ZLIB_MAGICS = {b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e"}
GZIP_MAGIC  = b"\x1f\x8b"

def try_decompress(buf):
    """Return (method, out) if buf decompresses to ~h_ulen bytes, else None."""
    attempts = []
    # zlib (with header)
    attempts.append(("zlib", lambda b: zlib.decompress(b)))
    # raw deflate (no header)
    attempts.append(("deflate_raw", lambda b: zlib.decompressobj(-15).decompress(b)))
    attempts.append(("gzip", lambda b: gzip.decompress(b)))
    attempts.append(("lzma", lambda b: lzma.decompress(b)))
    attempts.append(("bz2", lambda b: bz2.decompress(b)))
    for name, fn in attempts:
        try:
            out = fn(buf)
            if len(out) > 1000:
                return (name, out)
        except Exception:
            pass
    return None

# ---- Stateless per-byte transforms --------------------------------------
def t_identity(b):   return b
def t_not(b):        return bytes((~x) & 0xff for x in b)
def t_nibswap(b):    return bytes(((x << 4) | (x >> 4)) & 0xff for x in b)
def t_bitrev(b):
    def r(x):
        y = 0
        for i in range(8):
            y = (y << 1) | ((x >> i) & 1)
        return y
    return bytes(r(x) for x in b)
def t_rol(b, n):     return bytes(((x << n) | (x >> (8 - n))) & 0xff for x in b)
def t_ror(b, n):     return bytes(((x >> n) | (x << (8 - n))) & 0xff for x in b)
def t_xor(b, k):     return bytes(x ^ k for x in b)

TRANSFORMS = [("identity", t_identity), ("NOT", t_not),
              ("nibswap", t_nibswap), ("bitrev", t_bitrev)]
for n in range(1, 8):
    TRANSFORMS.append(("ROL%d" % n, lambda b, n=n: t_rol(b, n)))
for k in range(256):
    TRANSFORMS.append(("XOR%02x" % k, lambda b, k=k: t_xor(b, k)))

# quick 2-byte magic prefilter, then full decompress
print("[*] Scanning stateless byte transforms (magic prefilter + decompress)...")
found = []
for name, fn in TRANSFORMS:
    head = fn(payload[:2])
    is_zlib = head in ZLIB_MAGICS
    is_gzip = head == GZIP_MAGIC
    cand = is_zlib or is_gzip or name in ("identity", "NOT", "nibswap", "bitrev") or name.startswith("ROL")
    if head in ZLIB_MAGICS or head == GZIP_MAGIC:
        print("  magic hit: %-10s -> head %s" % (name, head.hex()))
    # Only full-decompress if magic matches (cheap) to keep runtime sane
    if is_zlib or is_gzip:
        full = fn(payload)
        res = try_decompress(full)
        if res:
            print("  *** DECOMPRESSED via %s -> %s (%d bytes)" % (name, res[0], len(res[1])))
            found.append((name, res[0], res[1]))

if not found:
    print("  no stateless transform produced a zlib/gzip magic that decompressed.")

print("=" * 70)
print("[*] Also testing raw-deflate (no magic) under NOT / identity / nibswap...")
for name, fn in [("identity", t_identity), ("NOT", t_not), ("nibswap", t_nibswap), ("bitrev", t_bitrev)]:
    full = fn(payload)
    try:
        out = zlib.decompressobj(-15).decompress(full)
        if len(out) > 1000:
            print("  *** raw-deflate via %s -> %d bytes" % (name, len(out)))
            found.append((name + "+rawdeflate", "deflate_raw", out))
    except Exception as e:
        pass

print("=" * 70)
if found:
    for name, method, out in found:
        print("WINNER:", name, method, "ulen match:", len(out) == h_ulen)
        print("  head:", out[:120])
        print("  crc32   of out: 0x%08x" % (zlib.crc32(out) & 0xffffffff))
        print("  adler32 of out: 0x%08x" % (zlib.adler32(out) & 0xffffffff))
        print("  header checksum: 0x%08x" % h_cksum)
else:
    print("No winner among stateless transforms. Need positional/keyed analysis.")
