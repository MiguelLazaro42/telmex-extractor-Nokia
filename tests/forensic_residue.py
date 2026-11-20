#!/usr/bin/env python3
"""MF-3.4 — Analisis forense del residuo de 6 bytes y estructura de bloques.
Uso: .venv/bin/python -I tests/forensic_residue.py
"""
import binascii, struct, zlib, sys, os

RAW = os.path.join(os.path.dirname(__file__), "..", "output", "nokia_backup_raw.cfg")

def hexdump(b, base=0):
    out = []
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hx = " ".join(f"{x:02x}" for x in chunk)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out.append(f"  {base+i:08x}: {hx:<47}  {asc}")
    return "\n".join(out)

def main():
    with open(RAW, "rb") as f:
        data = f.read()
    print(f"[*] Archivo: {len(data)} bytes")
    magic, comp_size, crc, unc_size, fw = struct.unpack("<IIIII", data[:20])
    print(f"    magic=0x{magic:08x} comp_size={comp_size} crc=0x{crc:08x} unc+1={unc_size} fw=0x{fw:08x}")
    payload = data[20:]
    print(f"[*] Payload: {len(payload)} bytes")
    print(f"    CRC32 recomputado = 0x{binascii.crc32(payload)&0xffffffff:08x} (header dice 0x{crc:08x})")

    # Estructura de bloques
    for bs in (16, 8):
        q, r = divmod(len(payload), bs)
        print(f"    len%{bs} = {r}  ({q} bloques completos de {bs}B + {r}B residuo)")

    print("\n[*] PRIMEROS 32 bytes del payload:")
    print(hexdump(payload[:32], 0))
    print("\n[*] ULTIMOS 32 bytes del payload:")
    print(hexdump(payload[-32:], len(payload)-32))

    print("\n[*] ULTIMOS 6 bytes (el residuo):")
    tail6 = payload[-6:]
    print("    hex:", tail6.hex(), " dec:", list(tail6))

    # (a) Hipotesis: residuo = cola de stream zlib en claro.
    # zlib stream termina: [deflate final] + Adler-32 (4B big-endian).
    # Si los ULTIMOS 4 bytes fueran Adler-32, serian el checksum del XML descomprimido.
    print("\n[*] Hipotesis zlib-tail (ultimos 4B = Adler-32 big-endian):")
    adler_be = struct.unpack(">I", tail6[-4:])[0]
    adler_le = struct.unpack("<I", tail6[-4:])[0]
    print(f"    ultimos4 BE = 0x{adler_be:08x} ({adler_be})")
    print(f"    ultimos4 LE = 0x{adler_le:08x} ({adler_le})")
    print(f"    2 bytes previos al adler = {tail6[:2].hex()}")

    # (b) Hipotesis: residuo = IV/salt/cabecera AL INICIO (primeros 6).
    print("\n[*] PRIMEROS 6 bytes (por si el residuo fuese prefijo):")
    head6 = payload[:6]
    print("    hex:", head6.hex(), " dec:", list(head6))

    # Entropia por segmentos: inicio, medio, final (para ver si hay zona en claro)
    import math
    def ent(b):
        if not b: return 0.0
        from collections import Counter
        c = Counter(b); n = len(b)
        return -sum((v/n)*math.log2(v/n) for v in c.values())
    print("\n[*] Entropia por segmentos (1024B):")
    print(f"    primeros 1024 : {ent(payload[:1024]):.4f}")
    print(f"    medio    1024 : {ent(payload[len(payload)//2:len(payload)//2+1024]):.4f}")
    print(f"    ultimos  1024 : {ent(payload[-1024:]):.4f}")
    print(f"    primeros 32   : {ent(payload[:32]):.4f}")
    print(f"    ultimos  32   : {ent(payload[-32:]):.4f}")

    # Zona en claro al final? buscar ascii imprimible en cola
    tail64 = payload[-64:]
    printable = sum(1 for x in tail64 if 32 <= x < 127)
    print(f"    % imprimible en ultimos 64B: {printable}/64")

    # Intento: ¿y si los ultimos 6 bytes NO estan cifrados y son fin de deflate?
    # Probar descomprimir los 8595 bloques (AES) es imposible sin clave; pero
    # podemos ver si el stream COMPLETO del payload (asumiendo que NO esta cifrado,
    # solo los 6 finales fueran residuo) arroja algo. Ya sabemos que no.
    print("\n[*] zlib/gzip/raw-deflate directo sobre payload:")
    for name, fn in [("zlib", lambda b: zlib.decompress(b)),
                     ("raw-deflate", lambda b: zlib.decompressobj(-15).decompress(b)),
                     ("gzip", lambda b: zlib.decompress(b, 16+15))]:
        try:
            r = fn(payload); print(f"    {name}: OK ({len(r)}B)!!!")
        except Exception as e:
            print(f"    {name}: {type(e).__name__}: {e}")

if __name__ == "__main__":
    main()
