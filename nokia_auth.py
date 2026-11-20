#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nokia_auth.py — Fase 2 (Autenticación Web Nokia GPON / Telmex "Beacon")

MF-2.1  get_login_challenge(opener, ip)   -> lee pubkey/nonce/csrf_token de GET /
MF-2.2  (NO en este archivo todavía)      -> POST /login.cgi

Helpers criptográficos que replican BIT A BIT el frontend JS del módem
(js_glb/crypto_page.js + js_glb/sjcl.js + jsencrypt.min.js):

    - b64url_escape()           == crypto_page.base64url_escape  ('+'->'-' '/'->'_' '='->'.')
    - sjcl_base64()             == sjcl.codec.base64.fromBits     (base64 estándar con '=')
    - sjcl_base64url()          == sjcl.codec.base64url.fromBits  (urlsafe, SIN '=')
    - aes128_cbc_encrypt_sjcl() == sjcl.mode.cbc.encrypt          (AES-128-CBC + PKCS#7)
    - rsa_pkcs1v15_b64()        == JSEncrypt.encrypt              (RSA-1024 PKCS#1 v1.5 -> base64)
    - encrypt_post_data()       == crypto_page.encrypt_post_data  ('encrypted=1&ct=..&ck=..')

Backend cripto: librería `cryptography` (pyca). NO envía ningún POST de login.
"""

import os
import re
import base64
import http.cookiejar
import urllib.request
import urllib.error

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

BLOCK = 16  # AES block size (bytes)


# --------------------------------------------------------------------------- #
#  Codecs — réplica exacta de sjcl.codec.* y crypto_page.base64url_escape
# --------------------------------------------------------------------------- #
def b64url_escape(b64: str) -> str:
    """crypto_page.base64url_escape: '+'->'-', '/'->'_', '='->'.' (NO estándar: '.' por '=')."""
    return b64.replace('+', '-').replace('/', '_').replace('=', '.')


def sjcl_base64(data: bytes) -> str:
    """sjcl.codec.base64.fromBits(a): base64 estándar CON relleno '=' (alfabeto +/)."""
    return base64.b64encode(data).decode('ascii')


def sjcl_base64url(data: bytes) -> str:
    """sjcl.codec.base64url.fromBits(a) = base64.fromBits(a,1,1): urlsafe ('-_') y SIN '='."""
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


# --------------------------------------------------------------------------- #
#  AES-128-CBC con PKCS#7  ==  sjcl.mode.cbc.encrypt
# --------------------------------------------------------------------------- #
def _pkcs7_pad(data: bytes) -> bytes:
    """
    Relleno idéntico a sjcl.mode.cbc.encrypt:
        padval = 16 - (len % 16)   (incluye bloque completo de 0x10 cuando len%16==0)
    = PKCS#7 estándar.
    """
    padval = BLOCK - (len(data) % BLOCK)
    return data + bytes([padval]) * padval


def aes128_cbc_encrypt_sjcl(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-128-CBC(key, iv, PKCS7(plaintext)) -> ciphertext crudo. key/iv = 16 bytes."""
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("AES-128: key e iv deben ser de 16 bytes")
    padded = _pkcs7_pad(plaintext)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def _pkcs7_unpad(data: bytes) -> bytes:
    """
    Quita el relleno PKCS#7 exactamente como lo valida sjcl.mode.cbc.decrypt
    (lanza 'pkcs#5 padding corrupt' si el relleno no es consistente).
    """
    if not data or (len(data) % BLOCK) != 0:
        raise ValueError("PKCS#7: longitud de texto cifrado inválida (no múltiplo de 16)")
    padval = data[-1]
    if padval < 1 or padval > BLOCK or data[-padval:] != bytes([padval]) * padval:
        raise ValueError("PKCS#7 padding corrupt")
    return data[:-padval]


def aes128_cbc_decrypt_sjcl(enckey, enciv, ciphertext_b64):
    """
    Réplica EXACTA de crypto_page.aes_decrypt(sid, ciphertext):

        key = sjcl.codec.base64.toBits(enckey)     # base64 ESTÁNDAR (con '=')
        iv  = sjcl.codec.base64.toBits(enciv)
        ct  = sjcl.codec.base64.toBits(ciphertext)
        pt  = sjcl.mode.cbc.decrypt(aes(key), ct, iv)   # AES-128-CBC + validación PKCS#7
        return sjcl.codec.utf8String.fromBits(pt)

    Parámetros:
      - `enckey` / `enciv`: la clave/IV efímeras generadas por el cliente para el login
        (las mismas `dec_key`/`dec_iv` guardadas en localStorage ligadas al X-SID).
        Se aceptan como str base64 estándar (como las guarda el JS) o como `bytes` de 16.
      - `ciphertext_b64`: respuesta del router en base64 estándar.

    Devuelve el texto plano descifrado como `str` (UTF-8).
    """
    def _to16(v):
        if isinstance(v, (bytes, bytearray)):
            b = bytes(v)
        else:
            b = base64.b64decode(v)
        if len(b) != 16:
            raise ValueError("AES-128: enckey/enciv deben decodificar a 16 bytes")
        return b

    key = _to16(enckey)
    iv = _to16(enciv)
    ct = base64.b64decode(ciphertext_b64)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    pt = _pkcs7_unpad(padded)
    return pt.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- #
#  RSA-1024 PKCS#1 v1.5  ==  JSEncrypt.encrypt
# --------------------------------------------------------------------------- #
def rsa_pkcs1v15_b64(pubkey_pem: str, message: bytes) -> str:
    """
    RSA PKCS#1 v1.5 (type 2) como JSEncrypt.encrypt, devuelto en base64 ESTÁNDAR
    (con '='), igual que JSEncrypt antes de pasar por base64url_escape.
    """
    pub = load_pem_public_key(pubkey_pem.encode('ascii'))
    ct = pub.encrypt(message, asym_padding.PKCS1v15())
    return base64.b64encode(ct).decode('ascii')


# --------------------------------------------------------------------------- #
#  Envoltorio híbrido  ==  crypto_page.encrypt / encrypt_post_data
# --------------------------------------------------------------------------- #
def encrypt_body(pubkey_pem: str, plaintext: str, aeskey: bytes = None, iv: bytes = None):
    """
    Réplica de crypto_page.encrypt():
        aeskey/iv = 128 bits efímeros  (parametrizables aquí para pruebas deterministas)
        ct = base64url( AES-128-CBC(aeskey, iv, utf8(plaintext)) )        [urlsafe, sin '=']
        ck = base64url_escape( RSA( base64(aeskey)+' '+base64(iv) ) )     [base64 con '.' por '=']
    Devuelve dict {ct, ck, aeskey, iv}.
    """
    import os
    if aeskey is None:
        aeskey = os.urandom(16)
    if iv is None:
        iv = os.urandom(16)

    pt = plaintext.encode('utf-8')                     # sjcl.codec.utf8String.toBits
    ct_raw = aes128_cbc_encrypt_sjcl(aeskey, iv, pt)
    ct = sjcl_base64url(ct_raw)

    aesinfo = sjcl_base64(aeskey) + ' ' + sjcl_base64(iv)   # "<b64 key> <b64 iv>"
    ck = b64url_escape(rsa_pkcs1v15_b64(pubkey_pem, aesinfo.encode('ascii')))

    return {"ct": ct, "ck": ck, "aeskey": aeskey, "iv": iv}


def encrypt_post_data(pubkey_pem: str, plaintext: str, aeskey: bytes = None, iv: bytes = None) -> str:
    """crypto_page.encrypt_post_data: 'encrypted=1&ct=<ct>&ck=<ck>'."""
    p = encrypt_body(pubkey_pem, plaintext, aeskey, iv)
    return "encrypted=1&ct=" + p["ct"] + "&ck=" + p["ck"]


# --------------------------------------------------------------------------- #
#  MF-2.1  get_login_challenge
# --------------------------------------------------------------------------- #
_RE_PUBKEY = re.compile(
    r"var\s+pubkey\s*=\s*'(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)",
    re.DOTALL,
)
_RE_NONCE = re.compile(r'var\s+nonce\s*=\s*"([^"]+)"')
_RE_TOKEN = re.compile(r'var\s+token\s*=\s*"([^"]+)"')
_RE_OPERATOR = re.compile(r'var\s+operatorCheck\s*=\s*"([^"]*)"')
_RE_WINNAME = re.compile(r"window\.name\s*=\s*'([^']*)'")


def _normalize_pem(raw: str) -> str:
    r"""
    El PEM en el HTML viene como literal JS con continuaciones de línea '\' + salto real.
    Reconstruye un PEM limpio: elimina los backslashes de continuación y normaliza líneas.
    """
    # Quita el backslash de continuación justo antes de cada salto de línea.
    cleaned = raw.replace('\\\r\n', '\n').replace('\\\n', '\n').replace('\\', '')
    lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]
    return "\n".join(lines) + "\n"


def make_opener():
    """Crea un OpenerDirector con CookieJar (mismo patrón que el extractor Huawei)."""
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    opener.addheaders = [("User-Agent", "Mozilla/5.0 (compatible; nokia-extractor)")]
    return opener, cj


def get_login_challenge(opener, ip="192.168.99.254", timeout=8):
    """
    MF-2.1 — GET / y extracción determinista del desafío de login.

    Devuelve dict:
        {
          "pubkey":        <PEM RSA-1024 limpio>,
          "nonce":         <base64, 32 bytes, anti-replay>,
          "csrf_token":    <16 chars, var token>,
          "operatorCheck": <"MXXT" = Telmex>,
          "window_name":   <"Bell">,
          "cookies":       {"lang": "spa", ...},   # cookies iniciales del CookieJar
          "html_size":     <int>,
          "status":        <int HTTP>,
        }
    NO envía ningún POST a /login.cgi.
    """
    url = "http://%s/" % ip
    req = urllib.request.Request(url)
    with opener.open(req, timeout=timeout) as r:
        status = getattr(r, "status", r.getcode())
        html = r.read().decode("utf-8", errors="replace")

    def _need(regex, label):
        m = regex.search(html)
        if not m:
            raise ValueError("MF-2.1: no se pudo extraer %s de GET /" % label)
        return m.group(1)

    pubkey = _normalize_pem(_need(_RE_PUBKEY, "pubkey"))
    nonce = _need(_RE_NONCE, "nonce")
    csrf_token = _need(_RE_TOKEN, "csrf_token (var token)")

    m_op = _RE_OPERATOR.search(html)
    m_wn = _RE_WINNAME.search(html)

    # Cookies iniciales desde el CookieJar asociado al opener (si lo hay).
    cookies = {}
    for handler in getattr(opener, "handlers", []):
        cj = getattr(handler, "cookiejar", None)
        if cj is not None:
            for c in cj:
                cookies[c.name] = c.value

    return {
        "pubkey": pubkey,
        "nonce": nonce,
        "csrf_token": csrf_token,
        "operatorCheck": m_op.group(1) if m_op else None,
        "window_name": m_wn.group(1) if m_wn else None,
        "cookies": cookies,
        "html_size": len(html.encode("utf-8")),
        "status": status,
    }


def build_login_plaintext(username, password, nonce, csrf_token, enckey_b64, enciv_b64):
    """
    Construye el `postdata` en texto plano EXACTO del submit() de la página
    (para MF-2.2; aquí NO se envía). Nota: el JS antepone un '&' inicial.
        &username=..&password=<encodeURIComponent>&csrf_token=..&nonce=..
        &enckey=<b64url_escape>&enciv=<b64url_escape>
    `enckey_b64`/`enciv_b64` son base64 ESTÁNDAR (como base64.fromBits), luego escapados.
    """
    import urllib.parse
    # encodeURIComponent(password): urllib.parse.quote con el mismo safe set que JS.
    pw = urllib.parse.quote(password, safe="!~*'()")
    return ("&username=" + username +
            "&password=" + pw +
            "&csrf_token=" + csrf_token +
            "&nonce=" + nonce +
            "&enckey=" + b64url_escape(enckey_b64) +
            "&enciv=" + b64url_escape(enciv_b64))


# --------------------------------------------------------------------------- #
#  MF-2.2  authenticate_nokia  (POST /login.cgi — un intento limpio)
# --------------------------------------------------------------------------- #
class _Pass2xxErrorProcessor(urllib.request.HTTPErrorProcessor):
    """
    HTTPErrorProcessor que NO convierte en error ningún 2xx, incluido el
    HTTP 299 propietario de Nokia (que no es 200..206). Deja pasar la
    respuesta intacta para poder leer headers (X-SID, Set-Cookie) y body.
    """
    def http_response(self, request, response):
        code = response.code
        if 200 <= code < 300:
            return response
        return super().http_response(request, response)

    https_response = http_response


def _collect_cookies(opener):
    """Devuelve {nombre: valor} de todas las cookies del CookieJar del opener."""
    cookies = {}
    for handler in getattr(opener, "handlers", []):
        cj = getattr(handler, "cookiejar", None)
        if cj is not None:
            for c in cj:
                cookies[c.name] = c.value
    return cookies


def authenticate_nokia(opener, ip="192.168.99.254", user="TELMEX",
                       password="", timeout=10, save_html_path=None):
    """
    MF-2.2 — UN intento limpio de login contra http://<ip>/login.cgi.

    Replica bit a bit el submit() del HTML:
      1. GET / fresco  -> pubkey/nonce/csrf_token nuevos (get_login_challenge).
      2. dec_key/dec_iv = 16 bytes aleatorios c/u -> base64 ESTÁNDAR (con '=').
         (clave/IV con que el ROUTER cifrará sus respuestas; se guardan sin escapar).
      3. postdata = &username=..&password=<encodeURIComponent>&csrf_token=..&nonce=..
                    &enckey=<b64url_escape(dec_key)>&enciv=<b64url_escape(dec_iv)>
      4. body = encrypt_post_data(pubkey, postdata)  -> 'encrypted=1&ct=..&ck=..'
      5. POST /login.cgi (application/x-www-form-urlencoded).
      6. Éxito  <=>  HTTP 299 + header X-SID.
      7. GET / inmediato (como window.top.location='/') para confirmar la interfaz
         autenticada y guardar el HTML.

    Devuelve dict con todo el material de sesión y diagnóstico.
    """
    # --- (1) Reto fresco -----------------------------------------------------
    ch = get_login_challenge(opener, ip, timeout=timeout)
    pubkey = ch["pubkey"]
    nonce = ch["nonce"]
    csrf_token = ch["csrf_token"]

    # --- (2) Clave/IV efímeras del cliente (para descifrar respuestas) --------
    dec_key = os.urandom(16)
    dec_iv = os.urandom(16)
    dec_key_b64 = sjcl_base64(dec_key)   # base64 estándar CON '=' (== base64.fromBits)
    dec_iv_b64 = sjcl_base64(dec_iv)

    # --- (3) postdata en claro (idéntico al submit() del HTML) ----------------
    postdata = build_login_plaintext(
        user, password, nonce, csrf_token, dec_key_b64, dec_iv_b64
    )

    # --- (4) Envoltorio híbrido RSA+AES efímero -------------------------------
    body = encrypt_post_data(pubkey, postdata).encode("ascii")

    # --- (5) POST /login.cgi --------------------------------------------------
    login_url = "http://%s/login.cgi" % ip
    req = urllib.request.Request(
        login_url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    status = None
    resp_headers = None
    resp_body = b""
    try:
        with opener.open(req, timeout=timeout) as r:
            status = getattr(r, "status", r.getcode())
            resp_headers = r.headers
            resp_body = r.read()
    except urllib.error.HTTPError as e:
        # Blindaje extra por si el opener trae el HTTPErrorProcessor por defecto
        # y la versión de Python decide tratar 299 como error.
        if e.code == 299:
            status = e.code
            resp_headers = e.headers
            resp_body = e.read()
        else:
            raise

    x_sid = resp_headers.get("X-SID") if resp_headers else None
    set_cookie = resp_headers.get_all("Set-Cookie") if resp_headers else None
    success = (status == 299 and bool(x_sid))

    result = {
        "status": status,
        "success": success,
        "x_sid": x_sid,
        "set_cookie_header": set_cookie,
        "cookies_after_login": _collect_cookies(opener),
        "enckey_b64": dec_key_b64,   # base64 estándar: para aes128_cbc_decrypt_sjcl
        "enciv_b64": dec_iv_b64,
        "login_response_headers": dict(resp_headers.items()) if resp_headers else {},
        "login_response_size": len(resp_body),
        "authenticated_html": None,
        "authenticated_status": None,
        "authenticated_html_size": 0,
        "looks_authenticated": None,
    }

    if not success:
        # Fallo: el router devuelve HTML de error (con conteo de intentos).
        result["login_response_body_preview"] = resp_body[:400].decode(
            "utf-8", errors="replace"
        )
        return result

    # --- (7) GET / autenticado (como window.top.location = '/') ---------------
    # La sesión se sostiene por la(s) cookie(s) que el CookieJar ya capturó del
    # Set-Cookie del 299; además re-presentamos X-SID como header por si el
    # firmware lo exige en peticiones autenticadas.
    get_req = urllib.request.Request("http://%s/" % ip, headers={"X-SID": x_sid})
    with opener.open(get_req, timeout=timeout) as r2:
        auth_status = getattr(r2, "status", r2.getcode())
        auth_html = r2.read().decode("utf-8", errors="replace")

    # Heurística: ¿seguimos viendo el formulario de login o ya es la UI interna?
    # (OJO: la UI interna TAMBIÉN declara `var pubkey` para cifrar CGIs, así que
    #  ese marcador no sirve; usamos el formulario de login vs. el menú/iframe.)
    is_login_page = (
        ("function submit()" in auth_html and 'id=username' in auth_html)
        or ("loginform" in auth_html)
    )
    is_internal_ui = ('name="mainFrame"' in auth_html) or ("menu.cgi" in auth_html)
    result["authenticated_status"] = auth_status
    result["authenticated_html"] = auth_html
    result["authenticated_html_size"] = len(auth_html.encode("utf-8"))
    result["looks_authenticated"] = (not is_login_page) and is_internal_ui

    if save_html_path:
        os.makedirs(os.path.dirname(save_html_path), exist_ok=True)
        with open(save_html_path, "w", encoding="utf-8") as fh:
            fh.write(auth_html)
        result["saved_html_path"] = save_html_path

    return result


# --------------------------------------------------------------------------- #
#  MF-2.3  map_authenticated_endpoints  (sesión YA autenticada)
# --------------------------------------------------------------------------- #
def logout_nokia(opener, ip="192.168.99.254", timeout=8):
    """GET /login.cgi?out — cierra la sesión para no dejarla colgada en el router."""
    req = urllib.request.Request("http://%s/login.cgi?out" % ip)
    try:
        with opener.open(req, timeout=timeout) as r:
            return getattr(r, "status", r.getcode())
    except urllib.error.HTTPError as e:
        return e.code


def _authget(opener, ip, target, outdir, x_sid=None, timeout=12):
    """
    GET http://<ip>/<target> con la sesión del opener. Guarda el cuerpo en
    outdir/cgi/<nombre-saneado> y devuelve un dict con status/headers/tamaño/preview.
    `target` puede incluir query string (p.ej. 'usb.cgi?backup').
    """
    url = "http://%s/%s" % (ip, target.lstrip("/"))
    headers = {"X-Requested-With": "XMLHttpRequest"}
    if x_sid:
        headers["X-SID"] = x_sid
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as r:
            status = getattr(r, "status", r.getcode())
            body = r.read()
            hdrs = dict(r.headers.items())
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read()
        hdrs = dict(e.headers.items())
    except Exception as e:  # noqa: BLE001  (timeout / conn reset en sondas negativas)
        return {"target": target, "status": None, "error": repr(e),
                "size": 0, "saved": None, "content_type": None, "preview": ""}

    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target) or "root"
    cgidir = os.path.join(outdir, "cgi")
    os.makedirs(cgidir, exist_ok=True)
    path = os.path.join(cgidir, safe)
    with open(path, "wb") as fh:
        fh.write(body)

    ctype = hdrs.get("Content-type") or hdrs.get("Content-Type", "")
    text = body.decode("utf-8", errors="replace")
    return {
        "target": target,
        "status": status,
        "content_type": ctype,
        "size": len(body),
        "saved": path,
        "preview": text[:300],
        "is_login_redirect": ("loginform" in text or "function submit()" in text
                              or "/reg.html" in text[:500]),
    }


def _parse_menu_nodes(js_text):
    """
    Convierte el objeto JS `var all_nodes = {...}` de menu.cgi a estructura Python.
    Estrategia: transformar el literal JS a JSON (comillas en claves name/target/nodes,
    quitar comas colgantes) y json.loads; si falla, cae a un parser por regex.
    Devuelve (sections, flat_rows, unique_targets).
    """
    import json as _json
    m = re.search(r"var\s+all_nodes\s*=\s*(\{.*\})\s*;?\s*$", js_text, re.DOTALL)
    blob = m.group(1) if m else js_text
    sections = []
    try:
        j = re.sub(r'([{\[,]\s*)(name|target|nodes)(\s*:)', r'\1"\2"\3', blob)
        j = re.sub(r',(\s*[}\]])', r'\1', j)          # comas colgantes
        obj = _json.loads(j)
        for sec in obj.get("nodes", []):
            srow = {"name": sec.get("name"), "target": sec.get("target"),
                    "children": [{"name": c.get("name"), "target": c.get("target")}
                                 for c in sec.get("nodes", [])]}
            sections.append(srow)
    except Exception:
        # Fallback por regex: pares name/target contiguos.
        pairs = re.findall(r'name\s*:\s*"([^"]+)"\s*,\s*target\s*:\s*("?[^",}\s]+"?)',
                           blob)
        sections = [{"name": "(regex)", "target": None,
                     "children": [{"name": n, "target": t.strip('"')} for n, t in pairs]}]

    flat, targets = [], []
    for sec in sections:
        for c in sec["children"]:
            flat.append((sec["name"], c["name"], c["target"]))
            t = c["target"]
            if isinstance(t, str) and t.endswith("cgi") or (isinstance(t, str) and ".cgi" in t):
                if t not in targets:
                    targets.append(t)
    return sections, flat, targets


# CGIs de voz/VoIP a sondear aunque NO aparezcan en el menú de adminRole=0.
_VOICE_PROBES = [
    "voice.cgi", "voip.cgi", "sip.cgi", "voice_config.cgi", "voice_glb.cgi",
    "voice_advanced.cgi", "voice_setting.cgi", "voice_line.cgi", "voip_glb.cgi",
    "voice_basic.cgi", "voice_sip.cgi",
]


def map_authenticated_endpoints(opener, ip="192.168.99.254", outdir="/tmp/nokia_recon",
                                x_sid=None, fetch_menu_targets=True,
                                probe_voice=True, skip_destructive=True, timeout=12):
    """
    MF-2.3 — Mapeo de endpoints con una sesión YA autenticada.

    `opener` debe traer las cookies de sesión (sid/isAdminLoggedIn/lsid) que deja
    authenticate_nokia(). NO inicia sesión ni cierra sesión (eso lo hace el driver,
    para garantizar UN único ciclo login→map→logout limpio).

    Pasos:
      1. GET /menu.cgi  -> guarda menu.cgi.js y parsea all_nodes.nodes[] (árbol).
      2. GET /device_status.cgi -> dev_info (modelo, serial, firmware, GPON SN…).
      3. GET de cada target .cgi del menú (salvo reboot si skip_destructive).
      4. Sondas de endpoints de voz ocultos (probe_voice).

    Devuelve dict estructurado con el árbol, filas planas, dispositivo y resultados GET.
    """
    os.makedirs(outdir, exist_ok=True)
    result = {"ip": ip, "menu_sections": [], "menu_flat": [], "menu_targets": [],
              "device": {}, "fetched": {}, "voice_probes": {}}

    # (1) menu.cgi
    menu = _authget(opener, ip, "menu.cgi", outdir, x_sid, timeout)
    try:
        with open(menu["saved"], "rb") as fh:
            menu_js = fh.read().decode("utf-8", errors="replace")
    except Exception:
        menu_js = ""
    sections, flat, targets = _parse_menu_nodes(menu_js)
    result["menu_sections"] = sections
    result["menu_flat"] = flat
    result["menu_targets"] = targets
    # copia canónica legible
    with open(os.path.join(outdir, "menu.cgi.js"), "w", encoding="utf-8") as fh:
        fh.write(menu_js)

    # (2) device_status.cgi -> dev_info
    dev = _authget(opener, ip, "device_status.cgi", outdir, x_sid, timeout)
    result["fetched"]["device_status.cgi"] = {k: dev[k] for k in
                                              ("status", "size", "content_type", "saved")}
    try:
        with open(dev["saved"], "rb") as fh:
            dev_html = fh.read().decode("utf-8", errors="replace")
        mdev = re.search(r"var\s+dev_info\s*=\s*(\{.*?\})\s*;", dev_html, re.DOTALL)
        if mdev:
            raw = mdev.group(1)
            fields = dict(re.findall(r'"?([A-Za-z0-9_]+)"?\s*:\s*"([^"]*)"', raw))
            result["device"] = {
                "ModelName": fields.get("ModelName"),
                "ProductClass": fields.get("ProductClass"),
                "Manufacturer": fields.get("Manufacturer"),
                "ManufacturerOUI": fields.get("ManufacturerOUI"),
                "SerialNumber": fields.get("SerialNumber"),
                "HardwareVersion": fields.get("HardwareVersion"),
                "SoftwareVersion": fields.get("SoftwareVersion"),
                "AdditionalSoftwareVersion": fields.get("AdditionalSoftwareVersion"),
                "Chipset": fields.get("X_ASB_COM_Chipset"),
                "ProvisioningCode": fields.get("ProvisioningCode"),
                "FirstUseDate": fields.get("FirstUseDate"),
            }
    except Exception as e:  # noqa: BLE001
        result["device"] = {"parse_error": repr(e)}

    # (3) resto de targets del menú
    if fetch_menu_targets:
        for t in targets:
            base = t.split("?", 1)[0]
            if t in ("menu.cgi", "device_status.cgi"):
                continue
            if skip_destructive and base in ("reboot.cgi",):
                result["fetched"][t] = {"status": "skipped", "reason": "destructive(GET-only page, omitido por precaución)"}
                continue
            r = _authget(opener, ip, t, outdir, x_sid, timeout)
            result["fetched"][t] = {k: r.get(k) for k in
                                    ("status", "size", "content_type", "saved",
                                     "is_login_redirect")}

    # (4) sondas de voz ocultas
    if probe_voice:
        for p in _VOICE_PROBES:
            if p in targets:
                continue
            r = _authget(opener, ip, p, outdir, x_sid, timeout)
            result["voice_probes"][p] = {k: r.get(k) for k in
                                         ("status", "size", "content_type",
                                          "is_login_redirect", "error")}

    return result


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) > 1 and sys.argv[1] == "login":
        # MF-2.2 — UN intento limpio de login (ojo: ErrorLimit=4).
        opener, cj = make_opener()
        # Sustituir el HTTPErrorProcessor por defecto por el que deja pasar 2xx/299.
        opener.add_handler(_Pass2xxErrorProcessor())
        res = authenticate_nokia(
            opener,
            ip="192.168.99.254",
            user="TELMEX",
            password="sf3h5zkdtA",
            save_html_path="/tmp/nokia_recon/authenticated_index.html",
        )
        printable = dict(res)
        html = printable.pop("authenticated_html", None)
        if html is not None:
            printable["authenticated_html_head"] = html[:1200]
        print(json.dumps(printable, indent=2, ensure_ascii=False))

    elif len(sys.argv) > 1 and sys.argv[1] == "map":
        # MF-2.3 — ciclo limpio: login -> map_authenticated_endpoints -> logout.
        opener, cj = make_opener()
        opener.add_handler(_Pass2xxErrorProcessor())
        auth = authenticate_nokia(
            opener, ip="192.168.99.254", user="TELMEX", password="sf3h5zkdtA",
            save_html_path="/tmp/nokia_recon/authenticated_index.html",
        )
        if not auth["success"]:
            print(json.dumps({"login": "FAILED", "status": auth["status"]},
                             indent=2, ensure_ascii=False))
            sys.exit(1)
        print("LOGIN OK  status=%s  x_sid=%s" % (auth["status"], auth["x_sid"]))
        try:
            mp = map_authenticated_endpoints(
                opener, ip="192.168.99.254", outdir="/tmp/nokia_recon",
                x_sid=auth["x_sid"],
            )
        finally:
            lo = logout_nokia(opener, ip="192.168.99.254")
            print("LOGOUT GET /login.cgi?out -> %s" % lo)
        print(json.dumps(mp, indent=2, ensure_ascii=False))

    else:
        opener, cj = make_opener()
        ch = get_login_challenge(opener, "192.168.99.254")
        out = dict(ch)
        out["pubkey"] = out["pubkey"].replace("\n", "\\n")
        print(json.dumps(out, indent=2, ensure_ascii=False))
