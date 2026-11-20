#!/usr/bin/env python3
"""
📦 Nokia G-1425G-H ONT Configuration Packer & Verifier (config.cfg Container)
==============================================================================
Equivalente a `huawei_config_packer.py` pero para el contenedor binario
propietario Alcatel-Lucent/Nokia `config.cfg` (magic `0x00123123`, header de
20 bytes: magic/compressed_size/crc32/uncompressed_size+1/fw_magic, los 5
campos `uint32` little-endian).

Implementa:
  - MF-5.1b: build_cfg_header_and_crc()  -> construye y valida la cabecera.
  - MF-5.2a: pack_nokia_configuration()  -> comprime (zlib) + empaqueta + verifica.
  - verify_nokia_pack()                  -> verificación de integridad standalone.

Reutiliza `analyze_container_format()` de `nokia_backup.py` para no duplicar
el parseo forense del contenedor.
"""

import sys
import zlib
import struct
import binascii
import argparse
from pathlib import Path

import nokia_backup  # noqa: E402  (mismo repo: analyze_container_format, magics)

_MAGIC_LEGACY = nokia_backup._MAGIC_LEGACY   # 0x00123123
_MAGIC_NEW = nokia_backup._MAGIC_NEW         # 0x00124126
_FW_MAGIC_DEFAULT = 0xFFFFFFFE


# ======================================================================
# MF-5.1b — build_cfg_header_and_crc
# ======================================================================

def build_cfg_header_and_crc(payload_bytes, uncompressed_len,
                              fw_magic=_FW_MAGIC_DEFAULT,
                              magic=_MAGIC_LEGACY, extended_40b=False):
    """
    MF-5.1b — Construye la cabecera binaria del contenedor Nokia `config.cfg`.

    Entrada:
      - payload_bytes:     bytes finales que irán después de la cabecera
                            (comprimidos, o comprimidos+cifrados si se usó
                            cipher_hook). El CRC32 y compressed_size se
                            calculan sobre ESTOS bytes, igual que el firmware.
      - uncompressed_len:  longitud en bytes del XML plano original (antes
                            de comprimir). El campo de header guarda +1.
      - fw_magic:          uint32 LE, por defecto 0xFFFFFFFE (observado en
                            el backup real). Se debe preservar del template
                            original cuando se re-empaqueta un backup real.
      - magic:             uint32 LE del contenedor, 0x00123123 (legacy) por
                            defecto; también soporta 0x00124126 (new/40B).
      - extended_40b:      si True, empaqueta la variante de 40 bytes
                            (`<10I`, cada campo seguido de un uint32 = 0).

    Salida: tupla (header_bytes, metadata_dict).
    """
    crc32 = binascii.crc32(payload_bytes) & 0xFFFFFFFF
    compressed_size = len(payload_bytes)
    uncompressed_size_plus_1 = uncompressed_len + 1

    if not extended_40b:
        header_bytes = struct.pack(
            "<5I", magic, compressed_size, crc32, uncompressed_size_plus_1, fw_magic
        )
    else:
        header_bytes = struct.pack(
            "<10I",
            magic, 0,
            compressed_size, 0,
            crc32, 0,
            uncompressed_size_plus_1, 0,
            fw_magic, 0,
        )

    metadata = {
        "magic": magic,
        "magic_hex": "0x%08x" % magic,
        "compressed_size": compressed_size,
        "crc32": crc32,
        "crc32_hex": "0x%08x" % crc32,
        "uncompressed_len": uncompressed_len,
        "uncompressed_size_plus_1": uncompressed_size_plus_1,
        "fw_magic": fw_magic,
        "fw_magic_hex": "0x%08x" % fw_magic,
        "header_len": 40 if extended_40b else 20,
        "extended_40b": extended_40b,
    }
    return header_bytes, metadata


# ======================================================================
# verify_nokia_pack
# ======================================================================

def verify_nokia_pack(cfg_path_or_bytes):
    """
    Verifica que un contenedor Nokia `config.cfg` tenga una cabecera válida
    y que el CRC32 declarado coincida con el payload almacenado.

    Entrada: ruta (str/Path) o bytes crudos del .cfg.
    Salida:  dict de verificación (incluye el diagnóstico de
             analyze_container_format() más 'crc32_ok': True) si todo es
             correcto.
    Lanza:   ValueError si el magic es desconocido, si compressed_size no
             coincide con el payload real, o si el CRC32 no verifica.
    """
    if isinstance(cfg_path_or_bytes, (str, Path)):
        raw = Path(cfg_path_or_bytes).read_bytes()
    else:
        raw = bytes(cfg_path_or_bytes)

    diag = nokia_backup.analyze_container_format(raw)

    if not diag.get("magic_known"):
        raise ValueError(
            "verify_nokia_pack: magic desconocido (%s); no es un contenedor "
            "Nokia cfg reconocible (se esperaba 0x00123123 o 0x00124126)."
            % diag.get("magic")
        )

    if not diag.get("compressed_size_matches_payload"):
        raise ValueError(
            "verify_nokia_pack: compressed_size del header (%s) no coincide "
            "con el tamaño real del payload (%s)."
            % (diag.get("compressed_size_field"), diag.get("payload_actual_len"))
        )

    if not diag.get("crc32_valid"):
        raise ValueError(
            "verify_nokia_pack: CRC32 inválido. Header=%s Calculado=%s"
            % (diag.get("crc32_field"), diag.get("crc32_calc"))
        )

    diag["crc32_ok"] = True
    return diag


# ======================================================================
# MF-5.2a — pack_nokia_configuration
# ======================================================================

def pack_nokia_configuration(xml_path, output_cfg_path, template_raw_path=None,
                              cipher_hook=None, compresslevel=9):
    """
    MF-5.2a — Empaqueta un XML de configuración en el contenedor `config.cfg`
    de Nokia (equivalente a `pack_ctree()` de Huawei, pero en formato
    magic+CRC32+zlib propio de Alcatel-Lucent/Nokia).

    Pasos:
      1. Lee xml_path (UTF-8) -> xml_bytes; uncompressed_len = len(xml_bytes).
      2. Si template_raw_path existe, preserva su magic/fw_magic originales
         (primeros 20 bytes del backup real que se está re-empaquetando).
      3. compressed_bytes = zlib.compress(xml_bytes, compresslevel).
      4. payload_bytes = cipher_hook(compressed_bytes) si se da, si no,
         payload_bytes = compressed_bytes (modo zlib estándar Nokia, el
         mismo que usa `unpack_and_decrypt_config()` vía su intento 1).
      5. header = build_cfg_header_and_crc(payload_bytes, uncompressed_len, fw_magic).
      6. Escribe header+payload en output_cfg_path y corre verify_nokia_pack().

    Entrada:
      - xml_path:            ruta al XML plano a empaquetar.
      - output_cfg_path:     ruta del .cfg de salida.
      - template_raw_path:   .cfg real opcional del que copiar magic/fw_magic.
      - cipher_hook:         callable(compressed_bytes) -> encrypted_bytes,
                              opcional. None => contenedor zlib sin cifrar.
      - compresslevel:       nivel de compresión zlib (0-9), 9 por defecto.

    Salida: dict de verificación de verify_nokia_pack() sobre el archivo escrito.
    """
    xml_path = Path(xml_path)
    output_cfg_path = Path(output_cfg_path)

    print(f"📄 Leyendo archivo XML: {xml_path}")
    xml_text = xml_path.read_text(encoding="utf-8")
    xml_bytes = xml_text.encode("utf-8")
    uncompressed_len = len(xml_bytes)

    magic = _MAGIC_LEGACY
    fw_magic = _FW_MAGIC_DEFAULT
    if template_raw_path and Path(template_raw_path).exists():
        tpl_header = Path(template_raw_path).read_bytes()[:20]
        if len(tpl_header) == 20:
            tpl_magic, _csize, _crc, _ulen1, tpl_fw = struct.unpack("<5I", tpl_header)
            if tpl_magic in (_MAGIC_LEGACY, _MAGIC_NEW):
                magic = tpl_magic
                fw_magic = tpl_fw
                print(f"🔖 Preservando magic={hex(magic)} / fw_magic={hex(fw_magic)} de la plantilla {template_raw_path}")

    print(f"🗜️  Comprimiendo XML con zlib (nivel {compresslevel}, {uncompressed_len:,} bytes)...")
    compressed_bytes = zlib.compress(xml_bytes, compresslevel)

    if cipher_hook is not None:
        print("🔒 Aplicando cipher_hook sobre el payload comprimido...")
        payload_bytes = cipher_hook(compressed_bytes)
    else:
        payload_bytes = compressed_bytes

    header_bytes, meta = build_cfg_header_and_crc(
        payload_bytes, uncompressed_len, fw_magic=fw_magic, magic=magic
    )

    output_cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_cfg_path, "wb") as f:
        f.write(header_bytes)
        f.write(payload_bytes)

    total_len = len(header_bytes) + len(payload_bytes)
    print(f"✅ Contenedor Nokia generado: {output_cfg_path} ({total_len:,} bytes; "
          f"compressed_size={meta['compressed_size']:,}, crc32={meta['crc32_hex']})")

    verification = verify_nokia_pack(output_cfg_path)
    print("🧪 verify_nokia_pack() OK: magic %s, CRC32 %s, compressed_size coincide."
          % (verification["magic"], verification["crc32_field"]))
    return verification


def main():
    parser = argparse.ArgumentParser(
        description="Empaquetador y Verificador de Contenedores config.cfg para Nokia ONT"
    )
    parser.add_argument("xml_file", nargs="?", default=None,
                         help="Ruta al archivo XML descomprimido a empaquetar")
    parser.add_argument("-o", "--output", default="nokia_config_packed.cfg",
                         help="Ruta del archivo .cfg de salida")
    parser.add_argument("-t", "--template", default=None,
                         help="Backup .cfg real original para copiar magic/fw_magic exactos")
    parser.add_argument("--verify", default=None, metavar="CFG_FILE",
                         help="Solo verifica un .cfg existente (no empaqueta) y termina")
    args = parser.parse_args()

    if args.verify:
        verification = verify_nokia_pack(Path(args.verify))
        print(f"✅ {args.verify}: contenedor válido (magic={verification['magic']}, "
              f"crc32={verification['crc32_field']}, "
              f"compressed_size={verification['compressed_size_field']})")
        return

    if not args.xml_file:
        parser.error("se requiere xml_file (o usa --verify CFG_FILE)")

    pack_nokia_configuration(
        Path(args.xml_file), Path(args.output),
        Path(args.template) if args.template else None,
    )


if __name__ == "__main__":
    main()
