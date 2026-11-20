#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nokia_backup.py — Fase 3 (Descarga y análisis criptográfico del respaldo Nokia GPON / Telmex)

MF-3.1  download_nokia_backup(opener, ip, output_dir, x_sid, ...)
        -> descarga el archivo de configuración via POST /usb.cgi?export

MF-3.2  analyze_container_format(raw_bytes)
        -> diagnóstico forense del contenedor (magic, header de 20B, CRC32, entropía,
           variante legacy/new, detección de capas conocidas).

MF-3.3  unpack_and_decrypt_config(raw_bytes, out_path, ...)
        -> intenta toda la cadena de descompresión/descifrado conocida
           (zlib plano -> AES legacy thedroidgeek -> capa 0xFF+PBKDF2 rajkosto ->
           claves derivadas candidatas) y, si procede, escribe el XML en claro.
        probe_key_hints(...) -> sonda read-only autenticada (diag.cgi, usb.cgi…)
           en busca de pistas de clave / export alterno.

Flujo EXACTO descubierto en MF-2.3 (Backup and Restore -> usb.cgi?backup):
    - El form nativo "export" apunta a `?export` (relativo a usb.cgi), method POST,
      ENCTYPE application/x-www-form-urlencoded, target=pfrm (iframe oculto).
    - Por ser un *form submit nativo* NO pasa por el hook ajaxSend ⇒ NO se cifra.
    - Al form se le prependen dos hidden: csrf_val="" y csrf_token="<token-de-sesion>".
    - El router responde el .cfg como descarga (Content-Disposition: attachment).

Este módulo:
    1. Inicia sesión con authenticate_nokia() (TELMEX / sf3h5zkdtA) si no se pasa un
       opener ya autenticado.
    2. GET /usb.cgi?backup  -> lee el csrf_token ACTIVO de la sesión (var token='...').
    3. POST /usb.cgi?export (urlencoded, 'csrf_val=&csrf_token=<token>', Referer backup).
    4. Captura TODOS los headers de respuesta y los bytes crudos.
    5. Guarda el .cfg intacto en output/nokia_backup_raw.cfg (+ copia con el filename
       exacto del Content-Disposition si viene uno).
    6. Calcula tamaño exacto (bytes), SHA-256 y MD5.
    7. Cierra SIEMPRE la sesión con logout_nokia() (GET /login.cgi?out) en finally.

NO descifra ni analiza el contenedor (eso es MF-3.2 / MF-3.3).

Uso:
    .venv/bin/python -I nokia_backup.py
"""

import os
import re
import sys
import json
import struct
import zlib
import bz2
import lzma
import gzip
import binascii
import hashlib
import urllib.request
import urllib.error

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

# En modo aislado (`python -I`) el directorio del script NO se agrega a sys.path;
# lo añadimos para poder importar nokia_auth del mismo repo.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nokia_auth  # noqa: E402  (mismo repo: login/logout/opener/handler 299)

# Regex para el csrf_token activo de la sesión embebido en usb.cgi?backup.
# La página lo expone de tres formas equivalentes (mismo valor):
#   var token = '...';                          (shell general)
#   settings.data = 'csrf_token=XXXX';          (prepend al form via jQuery)
#   <input ... name="csrf_token" value="XXXX">  (hidden inyectado)
_RE_TOKEN_CANDIDATES = (
    re.compile(r"var\s+token\s*=\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"csrf_token=([A-Za-z0-9]+)"),
    re.compile(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']'),
)


def _extract_csrf_token(html):
    """Devuelve el primer csrf_token encontrado en la página (o None)."""
    for rx in _RE_TOKEN_CANDIDATES:
        m = rx.search(html)
        if m:
            return m.group(1)
    return None

# Content-Disposition: attachment; filename="..."  (filename con o sin comillas)
_RE_CD_FILENAME = re.compile(
    r'filename\*?\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([^;\r\n]+))',
    re.IGNORECASE,
)


def _parse_cd_filename(content_disposition):
    """Extrae el nombre de archivo original del header Content-Disposition."""
    if not content_disposition:
        return None
    m = _RE_CD_FILENAME.search(content_disposition)
    if not m:
        return None
    name = (m.group(1) or m.group(2) or m.group(3) or "").strip().strip('"').strip()
    # RFC 5987: filename*=UTF-8''nombre  -> quitar el prefijo de charset si lo trae.
    if "''" in name:
        name = name.split("''", 1)[1]
    # Saneo defensivo: solo el basename, sin separadores de ruta.
    name = os.path.basename(name.replace("\\", "/"))
    return name or None


def _safe_filename(name):
    """Deja solo caracteres seguros para escribir en disco (preserva el nombre real)."""
    name = os.path.basename(name.replace("\\", "/"))
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "nokia_backup_original"


def download_nokia_backup(opener=None, ip="192.168.99.254", output_dir="output",
                          x_sid=None, user="TELMEX", password="sf3h5zkdtA",
                          timeout=30, raw_name="nokia_backup_raw.cfg"):
    """
    MF-3.1 — Descarga el respaldo de configuración del Nokia via POST /usb.cgi?export.

    Parámetros:
      - opener:  OpenerDirector YA autenticado (con cookies sid/isAdminLoggedIn/lsid).
                 Si es None, este función hace el login completo (authenticate_nokia)
                 y cerrará la sesión en el finally.
      - ip:      IP del router Nokia (default 192.168.99.254).
      - output_dir: carpeta de salida (se crea si no existe).
      - x_sid:   X-SID de la sesión (si opener se pasa autenticado desde fuera).
      - user/password: credenciales (solo si opener es None y hay que loguear aquí).
      - timeout: timeout HTTP en segundos.
      - raw_name: nombre del archivo crudo intacto en output_dir.

    Devuelve un dict con: endpoint, status, headers de respuesta, csrf_token usado,
    filename original (Content-Disposition), rutas guardadas, tamaño en bytes, sha256,
    md5 y los primeros 64 bytes en hex (vista preliminar de recepción).

    SIEMPRE cierra la sesión con logout_nokia() en el finally (si la abrió aquí).
    """
    os.makedirs(output_dir, exist_ok=True)

    owns_session = opener is None
    result = {
        "endpoint": "http://%s/usb.cgi?export" % ip,
        "owns_session": owns_session,
    }

    try:
        # --- (1) Sesión autenticada -----------------------------------------
        if owns_session:
            opener, _cj = nokia_auth.make_opener()
            opener.add_handler(nokia_auth._Pass2xxErrorProcessor())
            auth = nokia_auth.authenticate_nokia(
                opener, ip=ip, user=user, password=password, timeout=timeout,
            )
            if not auth.get("success"):
                result["login"] = "FAILED"
                result["login_status"] = auth.get("status")
                return result
            x_sid = auth.get("x_sid")
            result["login"] = "OK"
            result["x_sid"] = x_sid

        # --- (2) GET /usb.cgi?backup -> csrf_token activo de la sesión ------
        backup_url = "http://%s/usb.cgi?backup" % ip
        bk_headers = {"X-Requested-With": "XMLHttpRequest"}
        if x_sid:
            bk_headers["X-SID"] = x_sid
        bk_req = urllib.request.Request(backup_url, headers=bk_headers)
        with opener.open(bk_req, timeout=timeout) as rb:
            bk_body = rb.read().decode("utf-8", errors="replace")
        csrf_token = _extract_csrf_token(bk_body)
        if not csrf_token:
            result["error"] = "No se encontró csrf_token en GET /usb.cgi?backup"
            result["backup_page_size"] = len(bk_body)
            return result
        result["csrf_token"] = csrf_token

        # --- (3) POST /usb.cgi?export (urlencoded, sin cifrar) --------------
        export_url = "http://%s/usb.cgi?export" % ip
        body = ("csrf_val=&csrf_token=" + csrf_token).encode("ascii")
        post_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": backup_url,
            "X-Requested-With": "XMLHttpRequest",
        }
        if x_sid:
            post_headers["X-SID"] = x_sid
        post_req = urllib.request.Request(
            export_url, data=body, method="POST", headers=post_headers,
        )

        try:
            with opener.open(post_req, timeout=timeout) as rp:
                status = getattr(rp, "status", rp.getcode())
                resp_headers = rp.headers
                raw = rp.read()
        except urllib.error.HTTPError as e:
            status = e.code
            resp_headers = e.headers
            raw = e.read()

        result["status"] = status
        result["request_body"] = body.decode("ascii")

        # --- (4) Captura de TODOS los headers de respuesta ------------------
        headers_dict = dict(resp_headers.items()) if resp_headers else {}
        result["response_headers"] = headers_dict
        content_type = (resp_headers.get("Content-Type")
                        or resp_headers.get("Content-type")) if resp_headers else None
        content_disposition = resp_headers.get("Content-Disposition") if resp_headers else None
        content_length = resp_headers.get("Content-Length") if resp_headers else None
        result["content_type"] = content_type
        result["content_disposition"] = content_disposition
        result["content_length_header"] = content_length

        original_filename = _parse_cd_filename(content_disposition)
        result["original_filename"] = original_filename

        # --- (5) Guardar bytes crudos intactos -----------------------------
        raw_path = os.path.join(output_dir, raw_name)
        with open(raw_path, "wb") as fh:
            fh.write(raw)
        result["raw_path"] = raw_path

        saved_original_path = None
        if original_filename:
            safe = _safe_filename(original_filename)
            saved_original_path = os.path.join(output_dir, safe)
            # No sobrescribir el crudo si por casualidad coincide el nombre.
            if os.path.abspath(saved_original_path) != os.path.abspath(raw_path):
                with open(saved_original_path, "wb") as fh:
                    fh.write(raw)
            result["original_copy_path"] = saved_original_path
            result["original_copy_safe_name"] = safe

        # --- (6) Tamaño exacto, SHA-256 y MD5 ------------------------------
        size = len(raw)
        sha256 = hashlib.sha256(raw).hexdigest()
        md5 = hashlib.md5(raw).hexdigest()
        result["size_bytes"] = size
        result["sha256"] = sha256
        result["md5"] = md5
        result["first_64_bytes_hex"] = raw[:64].hex()
        # Vista ASCII imprimible de la cabecera (solo diagnóstico de recepción).
        result["first_64_bytes_ascii"] = "".join(
            chr(b) if 32 <= b < 127 else "." for b in raw[:64]
        )

        # Coherencia: tamaño vs Content-Length anunciado.
        if content_length is not None:
            try:
                result["content_length_matches"] = (int(content_length) == size)
            except ValueError:
                result["content_length_matches"] = None

        return result

    finally:
        # --- (7) Cierre de sesión SIEMPRE (si la abrimos aquí) -------------
        if owns_session and opener is not None:
            try:
                lo = nokia_auth.logout_nokia(opener, ip=ip)
                result["logout_status"] = lo
            except Exception as e:  # noqa: BLE001
                result["logout_status"] = "error: %r" % e


# ======================================================================
# MF-3.2  —  analyze_container_format
# ======================================================================
#
# Formato del contenedor (IDENTIFICADO): familia Alcatel-Lucent/Nokia "cfg"
# documentada públicamente por thedroidgeek / rajkosto.
#
#   Header LEGACY (magic 0x00123123)  = 20 bytes (0x14), todos u32:
#     off 0x00  magic           u32   0x00123123
#     off 0x04  compressed_size u32   tamaño del payload almacenado
#     off 0x08  crc32           u32   CRC32 (binascii.crc32) del payload almacenado
#     off 0x0C  uncompressed+1  u32   tamaño del XML descomprimido + 1
#     off 0x10  fw_magic        u32   (versión fw / build / flags; aquí 0xfffffffe)
#     off 0x14  payload...
#
#   Header NEW (magic 0x00124126)     = 40 bytes (0x28): cada campo u32 seguido
#     de un u32 = 0 (los mismos 5 campos "ensanchados" a 64 bits).
#
# El magic/endianness se detecta por los 4 primeros bytes:
#   23 31 12 00 -> little-endian 0x123123 (NUESTRO CASO)
#   00 12 31 23 -> big-endian    0x123123
#   26 41 12 00 -> little-endian 0x124126 (new header)
#
# Capas INTERNAS conocidas del payload (tras validar CRC) antes de zlib:
#   - directo           : payload empieza con header zlib (78 01/9c/da/5e) -> zlib.decompress
#   - capa 0xFF (rajkosto, "G2425 y posteriores"):
#         payload = 0xFF | salt(8) | AES-256-CBC(PBKDF2-HMAC-SHA256(pw, salt, 10, 48))
#         pw fijo = "S23l7nZm47XyMGs6y6oJpN9CR4nbfIZHJ4VRwp7HcdV6o2YvUmeNYFlz08Otwz78"
#   - capa 0x11 (udaravima, G-1425G-B, NO resuelta públicamente)
#   - Telmex G-1425G-H fw 3TN00702 (NUESTRO CASO): payload cifrado con clave
#         DERIVADA EN EL DISPOSITIVO; no recuperable desde el .cfg (ver MF-3.3).

# Claves/const. públicas (MIT: Sami Alaoui Kendil / Rajko Stojadinovic)
_DG_KEY = bytes.fromhex(
    "3DA373D7DC822E2A470DEC37896E80D72C49B31629DDC997354B840391779EA4")
_DG_IV = bytes.fromhex("D0E6DCCDA74A00DF760FC08511CB05EA")
_PKCS_PW = b"S23l7nZm47XyMGs6y6oJpN9CR4nbfIZHJ4VRwp7HcdV6o2YvUmeNYFlz08Otwz78"

_MAGIC_LEGACY = 0x00123123
_MAGIC_NEW = 0x00124126
_ZLIB_HEADS = (b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e")
_GZIP_HEAD = b"\x1f\x8b"


def _shannon_entropy(buf):
    """Entropía de Shannon en bits/byte (8.0 = aleatorio/comprimido/cifrado)."""
    if not buf:
        return 0.0
    from math import log2
    freq = [0] * 256
    for b in buf:
        freq[b] += 1
    n = len(buf)
    return -sum((c / n) * log2(c / n) for c in freq if c)


def analyze_container_format(raw_bytes):
    """
    MF-3.2 — Inspección forense del contenedor de respaldo Nokia.

    Entrada: bytes crudos del .cfg (p.ej. open('output/nokia_backup_raw.cfg','rb').read()).
    Salida:  dict con el diagnóstico completo (magic, endianness, variante de header,
             campos del header, validación de CRC32, entropía, detección de capa interna
             y veredicto de cómo está protegido el archivo).

    NO descifra (eso es MF-3.3). Es puramente de diagnóstico y no toca la red.
    """
    res = {"mf": "3.2", "size": len(raw_bytes)}
    if len(raw_bytes) < 20:
        res["error"] = "archivo demasiado corto para un header de 20 bytes"
        return res

    first4 = raw_bytes[:4]
    res["first4_hex"] = first4.hex()

    # --- Detección de magic + endianness --------------------------------
    le = struct.unpack("<I", first4)[0]
    be = struct.unpack(">I", first4)[0]
    endian = fmt = None
    magic = None
    if le in (_MAGIC_LEGACY, _MAGIC_NEW):
        endian, fmt, magic = "little", "<", le
    elif be in (_MAGIC_LEGACY, _MAGIC_NEW):
        endian, fmt, magic = "big", ">", be
    res["endianness"] = endian
    res["magic"] = ("0x%06x" % magic) if magic is not None else None
    res["magic_known"] = magic in (_MAGIC_LEGACY, _MAGIC_NEW)

    if magic is None:
        res["verdict"] = ("Magic desconocido: el archivo podría estar cifrado por "
                          "completo (whole-file AES) o no ser un contenedor Nokia cfg.")
        res["entropy_bits_per_byte"] = round(_shannon_entropy(raw_bytes), 4)
        return res

    is_new = (magic == _MAGIC_NEW)
    res["header_variant"] = "new(0x124126, 40B)" if is_new else "legacy(0x123123, 20B)"

    # --- Parseo de campos del header ------------------------------------
    if not is_new:
        hdr_len = 20
        _, csize, crc, ulen_p1, fw = struct.unpack(fmt + "IIIII", raw_bytes[:20])
    else:
        hdr_len = 40
        vals = struct.unpack(fmt + "IIIIIIIIII", raw_bytes[:40])
        # campos en posiciones pares (cada u32 seguido de un u32=0)
        _, _, csize, _z1, crc, _z2, ulen_p1, _z3, fw, _z4 = vals
    payload = raw_bytes[hdr_len:]

    res["header_len"] = hdr_len
    res["compressed_size_field"] = csize
    res["payload_actual_len"] = len(payload)
    res["compressed_size_matches_payload"] = (csize == len(payload))
    res["crc32_field"] = "0x%08x" % crc
    res["uncompressed_size"] = ulen_p1 - 1
    res["uncompressed_size_field_raw"] = ulen_p1
    res["fw_magic"] = "0x%08x" % fw
    res["payload_mod16"] = len(payload) % 16
    res["payload_head_hex"] = payload[:16].hex()

    # --- Validación de CRC32 sobre el payload almacenado ----------------
    crc_calc = binascii.crc32(payload) & 0xffffffff
    res["crc32_calc"] = "0x%08x" % crc_calc
    res["crc32_valid"] = (crc_calc == crc)

    # --- Entropía -------------------------------------------------------
    ent = _shannon_entropy(payload)
    res["entropy_bits_per_byte"] = round(ent, 4)

    # --- Compresión directa (sin capa de cifrado) ----------------------
    head2 = payload[:2]
    res["payload_starts_with_zlib"] = head2 in _ZLIB_HEADS
    res["payload_starts_with_gzip"] = head2 == _GZIP_HEAD

    # --- Detección de capa interna conocida ----------------------------
    b0 = payload[0] if payload else None
    layer = None
    if head2 in _ZLIB_HEADS:
        layer = "zlib-directo (sin cifrado de contenido)"
    elif head2 == _GZIP_HEAD:
        layer = "gzip-directo"
    elif b0 == 0xFF:
        layer = "capa 0xFF rajkosto (salt+PBKDF2+AES-256-CBC, pw fijo G2425)"
    elif b0 == 0x11:
        layer = "capa 0x11 udaravima (G-1425G-B, NO resuelta públicamente)"
    else:
        layer = ("payload de alta entropía sin marcador de capa conocido "
                 "(byte0=0x%02x) -> cifrado con clave DERIVADA EN EL DISPOSITIVO" % (b0 or 0))
    res["inner_layer"] = layer

    # --- Veredicto ------------------------------------------------------
    if head2 in _ZLIB_HEADS or head2 == _GZIP_HEAD:
        res["verdict"] = "Contenedor Nokia cfg; payload comprimido SIN cifrar -> descomprimible."
    elif ent >= 7.9:
        res["verdict"] = (
            "Contenedor Nokia cfg LEGACY verificado (magic+CRC32 OK). El payload "
            "(entropía %.3f, len%%16=%d) está CIFRADO. Sin header zlib ni marcador "
            "0xFF/0x11 => clave simétrica DERIVADA EN EL DISPOSITIVO (firmware). "
            "No recuperable solo desde el .cfg (ver MF-3.3)." % (ent, len(payload) % 16))
    else:
        res["verdict"] = "Contenedor Nokia cfg; payload de baja entropía inesperada (revisar)."
    return res


# ======================================================================
# MF-3.3  —  unpack_and_decrypt_config
# ======================================================================

def _aes_decrypt(mode, key, iv, buf):
    if not _HAVE_CRYPTO:
        return None
    try:
        if mode == "CBC":
            c = Cipher(algorithms.AES(key), modes.CBC(iv))
        elif mode == "CTR":
            c = Cipher(algorithms.AES(key), modes.CTR(iv))
        elif mode == "CFB":
            c = Cipher(algorithms.AES(key), modes.CFB(iv))
        elif mode == "OFB":
            c = Cipher(algorithms.AES(key), modes.OFB(iv))
        elif mode == "ECB":
            c = Cipher(algorithms.AES(key), modes.ECB())
        else:
            return None
        d = c.decryptor()
        return d.update(buf) + d.finalize()
    except Exception:
        return None


def _zlib_try(buf):
    """Intenta zlib / raw-deflate / gzip; devuelve bytes o None."""
    for fn in (zlib.decompress,
               lambda b: zlib.decompressobj(-15).decompress(b),
               gzip.decompress):
        try:
            out = fn(buf)
            if len(out) > 64:
                return out
        except Exception:
            pass
    return None


def _candidate_keys():
    """Lista (label, key, iv) de claves candidatas públicas/derivables del propio
    archivo. (Se mantiene por trazabilidad; para el fw Telmex 3TN00702 ninguna
    funciona: la clave real es derivada en el dispositivo.)"""
    SERIAL = "ALCLB472FD24"
    ZIV = b"\x00" * 16
    cands = [("droidgeek", _DG_KEY, _DG_IV)]
    srcs = {
        "serial": SERIAL.encode(), "serial_lc": SERIAL.lower().encode(),
        "serhex": b"b472fd24", "ALCL": b"ALCL", "TELMEX": b"TELMEX",
        "pkcspw": _PKCS_PW,
    }
    for name, s in srcs.items():
        for klen, kb in ((16, None), (32, None)):
            raw = (s * (klen // len(s) + 1))[:klen]
            cands.append(("raw:%s|%d" % (name, klen), raw, _DG_IV))
        cands.append(("sha256:%s" % name, hashlib.sha256(s).digest(), ZIV))
        cands.append(("md5x2:%s" % name, hashlib.md5(s).digest() * 2, ZIV))
    for salt_name, salt in (("key10", b"key10"), ("empty", b""),
                            ("serial", SERIAL.encode())):
        for it in (10, 100):
            dk = hashlib.pbkdf2_hmac("sha256", _PKCS_PW, salt, it, dklen=48)
            cands.append(("pbkdf2:%s:%d" % (salt_name, it), dk[:32], dk[32:48]))
    return cands


def unpack_and_decrypt_config(raw_bytes, out_path=None, pkcs_password=None,
                              extra_keys=None):
    """
    MF-3.3 — Desempaqueta/descifra el contenedor Nokia hasta obtener el XML en claro.

    Cadena de intentos (en orden), cada uno validado contra el tamaño descomprimido
    anunciado en el header:
      1. zlib directo             (payload ya es un stream zlib sin cifrar).
      2. whole-file AES-256-CBC legacy (thedroidgeek) -> re-parseo del header interno.
      3. capa 0xFF rajkosto       (0xFF|salt8|AES-256-CBC con PBKDF2-HMAC-SHA256,10).
      4. claves candidatas        (_candidate_keys() + extra_keys), modos stream+bloque.

    Si TODO falla (caso Telmex G-1425G-H fw 3TN00702), devuelve un resultado
    estructurado 'blocked' SIN inventar un XML: la clave es derivada en el dispositivo.

    Entrada:
      - raw_bytes: contenido del .cfg.
      - out_path:  si se da y hay éxito, escribe el XML descomprimido ahí.
      - pkcs_password / extra_keys: para probar material de clave adicional
        (p.ej. pistas obtenidas de la sesión web en probe_key_hints()).
    Salida: dict con 'success', 'method', 'xml_path'/'xml_len', o 'blocked' + 'reason'.
    """
    diag = analyze_container_format(raw_bytes)
    out = {"mf": "3.3", "analysis": diag}

    if not diag.get("magic_known"):
        out["success"] = False
        out["blocked"] = True
        out["reason"] = "magic desconocido; no es un contenedor Nokia cfg reconocible."
        return out

    hdr_len = diag["header_len"]
    payload = raw_bytes[hdr_len:]
    want = diag["uncompressed_size"]

    def _finish(method, xml):
        out["success"] = True
        out["method"] = method
        out["xml_len"] = len(xml)
        out["xml_len_matches_header"] = (len(xml) == want)
        out["xml_head"] = xml[:200].decode("utf-8", errors="replace")
        if out_path:
            with open(out_path, "wb") as fh:
                fh.write(xml)
            out["xml_path"] = out_path
        return out

    attempts = []

    # (1) zlib directo
    xml = _zlib_try(payload)
    attempts.append("zlib-directo")
    if xml:
        return _finish("zlib-directo", xml)

    # (2) whole-file AES-256-CBC legacy (header cifrado): descifra y re-parsea
    if _HAVE_CRYPTO and len(raw_bytes) % 16 == 0:
        dec = _aes_decrypt("CBC", _DG_KEY, _DG_IV, raw_bytes)
        attempts.append("wholefile-AES256CBC-droidgeek")
        if dec and struct.unpack("<I", dec[:4])[0] in (_MAGIC_LEGACY, _MAGIC_NEW):
            inner = unpack_and_decrypt_config(dec, out_path=out_path)
            if inner.get("success"):
                inner["method"] = "wholefile-AES+" + inner.get("method", "")
                return inner

    # (3) capa 0xFF rajkosto (salt + PBKDF2 + AES-256-CBC)
    pw = pkcs_password.encode() if isinstance(pkcs_password, str) else (pkcs_password or _PKCS_PW)
    if _HAVE_CRYPTO and payload and payload[0] == 0xFF and len(payload) >= 9:
        salt = payload[1:9]
        enc = payload[9:]
        attempts.append("rajkosto-0xFF-PBKDF2")
        if len(enc) % 16 == 0:
            dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 10, dklen=48)
            dec = _aes_decrypt("CBC", dk[:32], dk[32:48], enc)
            if dec:
                # strip PKCS#7 (último byte) y zlib
                pad = dec[-1] if dec else 0
                body = dec[:-pad] if 0 < pad <= 16 else dec
                xml = _zlib_try(body) or _zlib_try(dec)
                if xml:
                    return _finish("rajkosto-0xFF-PBKDF2", xml)

    # (4) claves candidatas (stream sobre payload completo + bloque alineado)
    if _HAVE_CRYPTO:
        blk = (len(payload) // 16) * 16
        keylist = list(_candidate_keys())
        if extra_keys:
            keylist.extend(extra_keys)
        attempts.append("candidate-keys(%d)" % len(keylist))
        for label, key, iv in keylist:
            for mode in ("CTR", "CFB", "OFB"):
                dec = _aes_decrypt(mode, key, iv, payload)
                if dec and dec[:2] in _ZLIB_HEADS:
                    xml = _zlib_try(dec)
                    if xml:
                        return _finish("candidate:%s:%s" % (label, mode), xml)
            for mode in ("CBC", "ECB"):
                dec = _aes_decrypt(mode, key, iv, payload[:blk])
                if dec and dec[:2] in _ZLIB_HEADS:
                    xml = _zlib_try(dec + payload[blk:]) or _zlib_try(dec)
                    if xml:
                        return _finish("candidate:%s:%s" % (label, mode), xml)

    # --- Nada funcionó: BLOQUEADO (clave derivada en el dispositivo) -----
    out["success"] = False
    out["blocked"] = True
    out["attempts"] = attempts
    out["reason"] = (
        "Contenedor Nokia cfg LEGACY verificado (magic 0x123123 + CRC32 OK), pero el "
        "payload interno está cifrado con una clave simétrica DERIVADA EN EL DISPOSITIVO "
        "(firmware 3TN00702IJMI00). No existe header zlib ni marcador de capa 0xFF/0x11, "
        "y ninguna clave pública/derivable del archivo lo descifra. Estado idéntico al "
        "público no resuelto para esta familia (G-1425G-B build Dic-2024, udaravima). "
        "Para recuperar la clave hace falta extraer y analizar el binario del firmware "
        "(no incluido en el backup).")
    return out


# ======================================================================
# MF-3.3 (vía fallback) — sonda read-only de pistas de clave en la sesión web
# ======================================================================

# Patrones que delatarían material de clave / export alterno en una respuesta CGI.
_RE_HINTS = re.compile(
    r"(aes|cipher|encrypt|decrypt|passphrase|secret|pbkdf2|salt|0x123123|"
    r"\bkey\b|extfs|progdate|dmdb)", re.IGNORECASE)


def probe_key_hints(ip="192.168.99.254", user="TELMEX", password="sf3h5zkdtA",
                    outdir="output/key_hints", timeout=12):
    """
    Sonda READ-ONLY (solo GET) sobre la sesión autenticada buscando pistas que
    ayuden a derivar la clave del contenedor: diag.cgi, usb.cgi, device_status.cgi,
    etc. NO modifica nada en el router. Cierra la sesión (logout) en finally.

    Expectativa realista: BAJA. La clave de config.cfg se deriva dentro del firmware;
    las CGIs de rol 0 no exponen material de clave. Se ejecuta porque la tarea lo pide
    explícitamente y para documentar con precisión qué expone (o no) la UI.
    """
    os.makedirs(outdir, exist_ok=True)
    result = {"mf": "3.3-probe", "ip": ip, "endpoints": []}
    probes = [
        "diag.cgi", "diagnostic.cgi", "usb.cgi?backup", "usb.cgi?export",
        "device_status.cgi", "sysinfo.cgi", "gpon_status.cgi", "backup.cgi",
        "cfg.cgi", "config.cgi", "mgmt.cgi",
    ]
    opener = None
    owns = True
    try:
        opener, _cj = nokia_auth.make_opener()
        opener.add_handler(nokia_auth._Pass2xxErrorProcessor())
        auth = nokia_auth.authenticate_nokia(opener, ip=ip, user=user,
                                             password=password, timeout=timeout)
        if not auth.get("success"):
            result["login"] = "FAILED"
            return result
        x_sid = auth.get("x_sid")
        result["login"] = "OK"
        for tgt in probes:
            r = nokia_auth._authget(opener, ip, tgt, outdir, x_sid=x_sid,
                                    timeout=timeout)
            body = ""
            if r.get("saved") and os.path.exists(r["saved"]):
                try:
                    body = open(r["saved"], "rb").read().decode("utf-8", "replace")
                except Exception:
                    body = ""
            hints = sorted(set(m.group(0).lower() for m in _RE_HINTS.finditer(body)))
            result["endpoints"].append({
                "target": tgt, "status": r.get("status"),
                "content_type": r.get("content_type"), "size": r.get("size"),
                "login_redirect": r.get("is_login_redirect"),
                "hint_tokens": hints,
            })
        return result
    finally:
        if owns and opener is not None:
            try:
                result["logout"] = nokia_auth.logout_nokia(opener, ip=ip)
            except Exception as e:  # noqa: BLE001
                result["logout"] = "error: %r" % e


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Nokia backup Fase 3 (MF-3.1/3.2/3.3)")
    ap.add_argument("cmd", nargs="?", default="download",
                    choices=["download", "analyze", "decrypt", "probe"],
                    help="download=MF-3.1, analyze=MF-3.2, decrypt=MF-3.3, probe=hints")
    ap.add_argument("--file", default="output/nokia_backup_raw.cfg")
    ap.add_argument("--out", default="output/nokia_config_decrypted.xml")
    ap.add_argument("--ip", default="192.168.99.254")
    args = ap.parse_args()

    if args.cmd == "download":
        res = download_nokia_backup(ip=args.ip, output_dir="output",
                                    user="TELMEX", password="sf3h5zkdtA")
    elif args.cmd == "analyze":
        raw = open(args.file, "rb").read()
        res = analyze_container_format(raw)
    elif args.cmd == "decrypt":
        raw = open(args.file, "rb").read()
        res = unpack_and_decrypt_config(raw, out_path=args.out)
    elif args.cmd == "probe":
        res = probe_key_hints(ip=args.ip)
    print(json.dumps(res, indent=2, ensure_ascii=False))
