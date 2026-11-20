#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validación de compatibilidad bit-a-bit de nokia_auth.py con el frontend JS
(sjcl.mode.cbc.encrypt + sjcl.codec.base64url + JSEncrypt RSA PKCS#1 v1.5).

Sin node: se valida contra OpenSSL (referencia estándar) + round-trip RSA.
Como el análisis de sjcl.js prueba que su CBC usa PKCS#7 estándar y su
base64url es urlsafe-sin-padding, igualar a OpenSSL == igualar a sjcl/JSEncrypt.
"""
import os, sys, base64, subprocess, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nokia_auth as na

OK = "\033[32mOK\033[0m"
FAIL = "\033[31mFAIL\033[0m"
fails = 0

def check(name, cond, detail=""):
    global fails
    print(f"  [{OK if cond else FAIL}] {name}" + (f"  {detail}" if detail and not cond else ""))
    if not cond:
        fails += 1

print("== 1) base64url_escape (crypto_page) ==")
# '+'->'-', '/'->'_', '='->'.'
check("escape map", na.b64url_escape("ab+c/d==") == "ab-c_d..")
check("sin cambios en A-Za-z0-9", na.b64url_escape("Zz09") == "Zz09")

print("== 2) sjcl.codec.base64 vs base64url (fromBits) ==")
v16 = bytes(range(16))
# sjcl.base64.fromBits -> estándar con '='
check("base64 estándar con '='", na.sjcl_base64(v16) == base64.b64encode(v16).decode())
# sjcl.base64url.fromBits = base64.fromBits(a,1,1) -> urlsafe, SIN '='
exp_url = base64.urlsafe_b64encode(v16).decode().rstrip('=')
check("base64url urlsafe sin '='", na.sjcl_base64url(v16) == exp_url, na.sjcl_base64url(v16))
check("base64url 16B -> 22 chars sin padding", len(na.sjcl_base64url(v16)) == 22 and '=' not in na.sjcl_base64url(v16))

print("== 3) PKCS#7 == sjcl.mode.cbc (padval = 16-(len%16), bloque completo si múltiplo) ==")
check("pad de 5 bytes -> +11x0x0b", na._pkcs7_pad(b"ABCDE")[-11:] == bytes([11])*11)
check("pad de 16 bytes -> +16x0x10 (bloque completo)", na._pkcs7_pad(b"A"*16)[-16:] == bytes([16])*16 and len(na._pkcs7_pad(b"A"*16)) == 32)
check("pad de 0 bytes -> 16x0x10", na._pkcs7_pad(b"")==bytes([16])*16)

print("== 4) AES-128-CBC(nokia) == OpenSSL (PKCS#7 estándar) ==")
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
iv  = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
for label, pt in [("len=11", b"hello world"),
                  ("len=16 (múltiplo exacto)", b"ABCDEFGHIJKLMNOP"),
                  ("len=49 (como aesinfo)", b"A"*49),
                  ("len=0 (vacío)", b"")]:
    mine = na.aes128_cbc_encrypt_sjcl(key, iv, pt)
    # OpenSSL con PKCS#7 por defecto (sin -nopad)
    p = subprocess.run(
        ["openssl", "enc", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex()],
        input=pt, capture_output=True)
    check(f"AES-CBC {label}", mine == p.stdout, f"mine={mine.hex()} ossl={p.stdout.hex()}")

print("== 5) RSA-1024 PKCS#1 v1.5 (nokia) round-trip con OpenSSL (== JSEncrypt) ==")
with tempfile.TemporaryDirectory() as d:
    priv = os.path.join(d, "priv.pem"); pub = os.path.join(d, "pub.pem")
    subprocess.run(["openssl", "genrsa", "-out", priv, "1024"], capture_output=True, check=True)
    subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub], capture_output=True, check=True)
    pub_pem = open(pub).read()
    msg = b"sw5lXg== bQ2k/j==  (simulacro aesinfo 'key iv')"
    ck_b64 = na.rsa_pkcs1v15_b64(pub_pem, msg)
    ck_raw = base64.b64decode(ck_b64)
    check("ciphertext RSA = 128 bytes (1024-bit)", len(ck_raw) == 128)
    # Descifrar con la privada via OpenSSL -> debe volver el mensaje original
    dec = subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", priv],
                         input=ck_raw, capture_output=True)
    check("round-trip PKCS#1 v1.5 descifra igual", dec.stdout == msg, f"got={dec.stdout!r}")
    # base64url_escape deja ck con '.' en el padding
    ck_esc = na.b64url_escape(ck_b64)
    check("ck escapado usa '.' por '=' (si había padding)", ('=' not in ck_esc) and ('+' not in ck_esc) and ('/' not in ck_esc))

print("== 6) Pubkey REAL del dispositivo: parse + modulus vía OpenSSL ==")
# PEM tal como lo reconstruye _normalize_pem a partir del literal JS del HTML
raw_js = ("-----BEGIN PUBLIC KEY-----\\\n"
          "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD7nE9L38HvcuWPLgmCFrEwfVVe\\\n"
          "4pbDLciv/c0DMyymkRb1T/dYsC9cTR4kWxLK/qfnWzPTmCfOEHDvEa9qNmupnNy7\\\n"
          "OP68cZs+JJAKXBncf5aI3H2hMpE0SVqThATtLz/SlfVlvFSEfx0Lf+w1pPN+aE6+\\\n"
          "8ri48nVMfCE2gDrlqQIDAQAB\\\n"
          "-----END PUBLIC KEY-----")
pem = na._normalize_pem(raw_js)
from cryptography.hazmat.primitives.serialization import load_pem_public_key
pk = load_pem_public_key(pem.encode())
nums = pk.public_numbers()
check("pubkey carga como RSA-1024", pk.key_size == 1024)
check("exponente público = 65537", nums.e == 65537)
# Cifrar con la pubkey real y comprobar tamaño (no podemos descifrar: no hay priv)
ct = na.rsa_pkcs1v15_b64(pem, b"test")
check("cifra con pubkey real -> 128 bytes", len(base64.b64decode(ct)) == 128)

print("== 7) encrypt_post_data: formato y determinismo con key/iv fijos ==")
fixed_key = bytes.fromhex("aa"*16); fixed_iv = bytes.fromhex("bb"*16)
body = na.encrypt_post_data(pem, "&username=TELMEX&password=x", aeskey=fixed_key, iv=fixed_iv)
check("prefijo 'encrypted=1&ct=...&ck=...'", body.startswith("encrypted=1&ct=") and "&ck=" in body)
# ct es determinista (AES fijo); ck NO (padding RSA aleatorio) -> sólo validamos ct
ct2 = na.encrypt_post_data(pem, "&username=TELMEX&password=x", aeskey=fixed_key, iv=fixed_iv)
ct_a = body.split("&ck=")[0].split("&ct=")[1]
ct_b = ct2.split("&ck=")[0].split("&ct=")[1]
check("ct determinista con key/iv fijos", ct_a == ct_b)
check("ct sin '=' ni '+' ni '/' (base64url)", all(c not in ct_a for c in "=+/"))

print()
if fails:
    print(f"\033[31m{fails} comprobacion(es) FALLARON\033[0m"); sys.exit(1)
print("\033[32mTODAS las comprobaciones pasaron — cripto Python == frontend JS\033[0m")
