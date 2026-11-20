#!/usr/bin/env python3
"""
📦 Huawei ONT Configuration Packer & Signer (Type-1 Container)
==============================================================
Empaqueta y cifra archivos de configuración XML (hw_ctree.xml)
en el formato de contenedor binario oficial Type-1 AES-256-CBC de Huawei,
con KDF SHA-256 de 8,192 iteraciones y firma de integridad HMAC-SHA256.
"""

import os
import sys
import gzip
import struct
import hashlib
import hmac
import argparse
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("❌ Falta la librería 'cryptography'. Instálala ejecutando: pip install cryptography")
    sys.exit(1)

HUAWEI_MASTER_KEY = b"hex:13395537D2730554A176799F6D56A239"


def pack_ctree(xml_path: Path, output_path: Path, template_raw_path: Path = None) -> Path:
    """Empaqueta un XML en el contenedor binario Type-1 de Huawei."""
    print(f"📄 Leyendo archivo XML: {xml_path}")
    with open(xml_path, "r", encoding="utf-8") as f:
        xml_text = f.read()

    # 1. Comprimir en GZIP estándar nivel 9
    plain = gzip.compress(xml_text.encode("utf-8"), compresslevel=9)
    rem = len(plain) % 16

    # 2. Generar Vector de Inicialización (IV) de 16 bytes
    # Regla de padding Huawei: IV[15] codifica en su nibble bajo el residuo del padding
    iv = bytearray(os.urandom(16))
    iv[15] = (iv[15] & 0xF0) | rem
    iv = bytes(iv)

    # 3. Padding a múltiplo de bloque AES (16 bytes)
    if rem != 0:
        pad_len = 16 - rem
        plain_padded = plain + (b"\x00" * pad_len)
    else:
        plain_padded = plain

    # 4. Derivación de Clave (KDF): 8,192 rondas SHA-256
    print("🔑 Derivando clave AES-256 con 8,192 rondas SHA-256...")
    digest = bytearray(32)
    digest[:16] = iv
    for _ in range(8192):
        h = hashlib.sha256()
        h.update(digest)
        h.update(HUAWEI_MASTER_KEY)
        digest = h.digest()
    aes_key = bytes(digest)

    # 5. Cifrado AES-256-CBC
    print(f"🔒 Cifrando bloque ({len(plain_padded):,} bytes)...")
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plain_padded) + encryptor.finalize()

    # 6. Cálculo de HMAC-SHA256 (32 bytes)
    tag = hmac.new(aes_key, ciphertext, hashlib.sha256).digest()

    # 7. Encabezado Type-1 (01 00 00 00 [4 bytes CRC / ID])
    if template_raw_path and Path(template_raw_path).exists():
        with open(template_raw_path, "rb") as f:
            header = f.read(8)
            if not header.startswith(b"\x01\x00\x00\x00"):
                header = b"\x01\x00\x00\x00\xd9\x71\x01\xc3"
    else:
        header = b"\x01\x00\x00\x00\xd9\x71\x01\xc3"

    full_payload = header + iv + ciphertext + tag
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(full_payload)

    print(f"✅ Paquete Type-1 generado exitosamente: {output_path} ({len(full_payload):,} bytes)")
    return output_path


def verify_pack(pack_path: Path):
    """Verifica que un paquete Type-1 cumpla con la estructura criptográfica e integridad."""
    print(f"🧪 Verificando integridad del paquete {pack_path}...")
    with open(pack_path, "rb") as f:
        raw = f.read()

    header = raw[:8]
    if header[:4] != b"\x01\x00\x00\x00":
        raise ValueError("Header no es Type-1")

    payload = raw[8:]
    iv = payload[:16]
    ciphertext = payload[16:-32]
    expected_hmac = payload[-32:]

    digest = bytearray(32)
    digest[:16] = iv
    for _ in range(8192):
        h = hashlib.sha256()
        h.update(digest)
        h.update(HUAWEI_MASTER_KEY)
        digest = h.digest()

    aes_key = bytes(digest)
    calc_hmac = hmac.new(aes_key, ciphertext, hashlib.sha256).digest()
    if calc_hmac != expected_hmac:
        raise ValueError("Fallo de integridad: HMAC-SHA256 no coincide.")

    print("✅ HMAC-SHA256 verificado correctamente.")


def main():
    parser = argparse.ArgumentParser(description="Empacador y Firmador de Contenedores Type-1 para Huawei ONT")
    parser.add_argument("xml_file", help="Ruta al archivo XML descomprimido a empaquetar")
    parser.add_argument("-o", "--output", default="hw_ctree_packed.xml", help="Ruta del archivo cifrado de salida")
    parser.add_argument("-t", "--template", default=None, help="Archivo cifrado original para copiar encabezado CRC exacto")
    args = parser.parse_args()

    pack_ctree(Path(args.xml_file), Path(args.output), Path(args.template) if args.template else None)
    verify_pack(Path(args.output))


if __name__ == "__main__":
    main()
