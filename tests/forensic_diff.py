#!/usr/bin/env python3
"""MF-3.4 — Diff diferencial entre dos backups consecutivos.
Revela modo de cifrado (ECB / CBC / stream) y offset de inicio.
Uso: .venv/bin/python -I tests/forensic_diff.py
"""
import struct, binascii, os

D = os.path.join(os.path.dirname(__file__), "..", "output")
A = os.path.join(D, "nokia_backup_raw.cfg")
B = os.path.join(D, "nokia_backup_raw_2.cfg")

def hdr(data):
    return struct.unpack("<IIIII", data[:20])

def main():
    a = open(A, "rb").read(); b = open(B, "rb").read()
    print(f"[*] A={len(a)}B  B={len(b)}B  (diff {len(a)-len(b)}B)")
    ha = hdr(a); hb = hdr(b)
    names = ["magic", "comp_size", "crc32", "unc_size+1", "fw_magic"]
    print("\n[*] HEADERS (20B, uint32 LE):")
    print(f"    {'campo':<12} {'A':>12} {'B':>12}  igual?")
    for n, va, vb in zip(names, ha, hb):
        print(f"    {n:<12} 0x{va:08x}={va:<10} 0x{vb:08x}={vb:<10} {'SI' if va==vb else 'NO <<<'}")

    pa = a[20:]; pb = b[20:]
    print(f"\n[*] Payloads: A={len(pa)}B  B={len(pb)}B")
    print(f"    CRC32(A)=0x{binascii.crc32(pa)&0xffffffff:08x}  header dice 0x{ha[2]:08x}")
    print(f"    CRC32(B)=0x{binascii.crc32(pb)&0xffffffff:08x}  header dice 0x{hb[2]:08x}")

    # Primer byte que difiere
    n = min(len(pa), len(pb))
    first = next((i for i in range(n) if pa[i] != pb[i]), None)
    print(f"\n[*] Primer byte distinto en payload: offset {first}")
    if first is not None:
        lo = max(0, first-4)
        print(f"    A[{lo}:{first+12}] = {pa[lo:first+12].hex()}")
        print(f"    B[{lo}:{first+12}] = {pb[lo:first+12].hex()}")
    # Cuantos bytes iniciales son identicos
    print(f"    => {first} bytes iniciales IDENTICOS, luego divergen")

    # Analisis por bloques de 16B: cuales bloques son identicos
    bs = 16
    nb = n // bs
    same = [i for i in range(nb) if pa[i*bs:(i+1)*bs] == pb[i*bs:(i+1)*bs]]
    diff = [i for i in range(nb) if pa[i*bs:(i+1)*bs] != pb[i*bs:(i+1)*bs]]
    print(f"\n[*] Bloques de 16B: {nb} total | iguales={len(same)} | distintos={len(diff)}")
    if same:
        print(f"    bloques iguales (idx): primeros={same[:8]} ... ultimos={same[-8:]}")
    # ¿Hay islas de bloques iguales DESPUES del primer diff? -> patron ECB o stream realineado
    if first is not None:
        fb = first // bs
        same_after = [i for i in same if i > fb]
        print(f"    bloque del primer diff = {fb}; bloques iguales DESPUES de ese = {len(same_after)}")
        if same_after:
            print(f"        -> islas iguales post-divergencia: {same_after[:20]}")

    # Tramo final: ¿la cola larga es identica? (indicaria plaintext comun + stream alineado)
    # comparar desde el final hacia atras
    m = min(len(pa), len(pb))
    tail_same = 0
    while tail_same < m and pa[-1-tail_same] == pb[-1-tail_same]:
        tail_same += 1
    print(f"\n[*] Bytes IDENTICOS contando desde el FINAL: {tail_same}")

    # Mapa de densidad: % de bytes iguales en ventanas de 4096
    print("\n[*] % bytes iguales por ventana de 4096B:")
    win = 4096
    line = []
    for i in range(0, n, win):
        seg_a = pa[i:i+win]; seg_b = pb[i:i+win]
        eq = sum(1 for x, y in zip(seg_a, seg_b) if x == y)
        pct = 100.0*eq/len(seg_a)
        line.append(f"{pct:4.0f}")
    print("    " + " ".join(line))
    print("    (si cerca de 0 tras el primer diff => CBC/stream con plaintext corrido;")
    print("     si hay 100 intercalados => ECB o stream con keystream estatico y plaintext igual)")

if __name__ == "__main__":
    main()
