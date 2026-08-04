#!/usr/bin/env python3
"""Reverse proxy from Ctrlable Pro (HA ingress) to DALI bridge admin UIs.

A DALI bridge runs its own admin web UI on the LAN (default :8099, HTTP basic
auth). Reaching it from Ctrlable Pro otherwise means leaving the UI, knowing the
bridge's IP, and typing a second set of credentials. This add-on puts that UI in
the sidebar instead:

  • Ingress does the authentication — if you are in Ctrlable Pro, you are in.
  • The bridge's basic-auth credentials live in the add-on options and are
    injected upstream, so no browser password prompt ever appears in the panel.
  • Several bridges are supported (multi-gateway sites); / is a picker and each
    bridge is proxied under /b/<index>/.

Stdlib only, on purpose: the add-on image is then a base image plus python3, so
it builds locally on every arch the Supervisor targets without wheels.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

log = logging.getLogger("dali-proxy")

# Upstream is a small admin UI on the LAN. Long enough for a bridge that is busy
# talking to the DALI bus, short enough that a dead bridge fails visibly.
TIMEOUT = 15
PROBE_TIMEOUT = 3

BRIDGES: list[dict[str, Any]] = []


# ── config ───────────────────────────────────────────────────────────────────
def load_bridges() -> list[dict[str, Any]]:
    """Bridges come from the add-on options, via run.sh, as a JSON array."""
    raw = os.environ.get("DALI_PROXY_BRIDGES", "[]")
    try:
        items = json.loads(raw)
    except ValueError:
        log.error("bridges option is not valid JSON — starting with none")
        return []
    out = []
    for i, b in enumerate(items if isinstance(items, list) else []):
        host = str(b.get("host", "")).strip()
        if not host:
            log.warning("bridge #%d has no host — skipped", i)
            continue
        out.append({
            "name": str(b.get("name") or host).strip(),
            "host": host,
            "port": int(b.get("port") or 8099),
            # admin/admin is the bridge's own factory default; matching it here
            # means a stock bridge works with stock add-on options.
            "username": str(b.get("username") or "admin"),
            "password": str(b.get("password") or "admin"),
        })
    return out


def _auth_header(b: dict[str, Any]) -> str:
    token = base64.b64encode(f"{b['username']}:{b['password']}".encode()).decode()
    return f"Basic {token}"


# ── HTML rewriting ───────────────────────────────────────────────────────────
# The bridge UI is a single self-contained page whose script calls absolute
# paths (fetch('/api/status')). Absolute paths escape the ingress prefix, so
# they are rewritten to relative ones and anchored with <base>. Doing it here as
# well as in the bridge keeps already-deployed bridges (0.2.x/0.3.x) working.
_ABS_FETCH = re.compile(r"""(fetch\(\s*['"])/(api/)""")
_HEAD_OPEN = re.compile(r"<head[^>]*>", re.I)


def rewrite_html(body: bytes, base: str, switcher: str) -> bytes:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    text = _ABS_FETCH.sub(r"\1\2", text)
    m = _HEAD_OPEN.search(text)
    if m:
        text = text[:m.end()] + f'<base href="{base}">' + text[m.end():]
    if switcher and "</header>" in text:
        text = text.replace("</header>", switcher + "</header>", 1)
    return text.encode("utf-8")


def _switcher(prefix: str, index: int) -> str:
    """A link back to the picker, dropped into the bridge UI's own header.

    Only meaningful with more than one bridge — with a single one the picker is
    skipped entirely, and a link to it would be a dead end.
    """
    if len(BRIDGES) < 2:
        return ""
    name = BRIDGES[index]["name"]
    return (
        f'<span style="margin-left:auto;display:flex;gap:8px;align-items:center">'
        f'<span style="font-size:11px;color:#8B95A3">{_esc(name)}</span>'
        f'<a href="{prefix}/" style="font-size:11px;color:#4C8DFF;text-decoration:none;'
        f'border:1px solid #262E38;border-radius:20px;padding:2px 8px">All bridges</a>'
        f'</span>'
    )


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


# ── pages ────────────────────────────────────────────────────────────────────
_PICKER = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>DALI bridges</title><style>
:root{--bg:#0F1216;--surface:#161A20;--line:#262E38;--txt:#E6EAF0;--muted:#8B95A3;--brand:#4C8DFF;--ok:#3FBF7F;--err:#E06666}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px system-ui,sans-serif}
header{padding:14px 20px;background:var(--surface);border-bottom:1px solid var(--line)}
h1{font-size:16px;margin:0}main{max-width:720px;margin:0 auto;padding:18px}
a.card{display:block;text-decoration:none;color:inherit;background:var(--surface);border:1px solid var(--line);
border-radius:10px;padding:14px 16px;margin-bottom:12px}
a.card:hover{border-color:var(--brand)}
.name{font-size:15px;margin-bottom:4px}.meta{font-size:12px;color:var(--muted)}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--muted);margin-right:7px}
.dot.on{background:var(--ok)}.dot.off{background:var(--err)}
.empty{color:var(--muted);background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px}
</style></head><body>
<header><h1>DALI bridges</h1></header>
<main id=list></main>
<script>
const PREFIX=__PREFIX__;
async function load(){
  const r=await fetch(PREFIX+'/_status');const bs=await r.json();
  const el=document.getElementById('list');
  if(!bs.length){el.innerHTML='<div class=empty>No bridges configured. Add one in this add-on\\u2019s Configuration tab.</div>';return}
  el.innerHTML=bs.map(b=>`<a class=card href="${PREFIX}/b/${b.index}/">
    <div class=name><span class="dot ${b.ok?'on':'off'}"></span>${b.name}</div>
    <div class=meta>${b.host}:${b.port} \\u2014 ${b.ok?('reachable \\u00b7 '+(b.buses??'?')+' bus(es) \\u00b7 v'+(b.version??'?')):(b.error||'unreachable')}</div>
  </a>`).join('')}
load();setInterval(load,10000);
</script></body></html>"""

_ERROR = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>DALI bridge unavailable</title><style>
body{margin:0;background:#0F1216;color:#E6EAF0;font:14px system-ui,sans-serif}
main{max-width:620px;margin:60px auto;padding:0 18px}
.card{background:#161A20;border:1px solid #262E38;border-radius:10px;padding:20px}
h1{font-size:16px;margin:0 0 10px}p{color:#8B95A3;line-height:1.5}code{color:#E6EAF0}
a{color:#4C8DFF}
</style></head><body><main><div class=card>
<h1>__TITLE__</h1><p>__BODY__</p><p><a href="__PREFIX__/">Back to bridges</a></p>
</div></main></body></html>"""


def error_page(title: str, body: str, prefix: str) -> bytes:
    return (_ERROR.replace("__TITLE__", _esc(title))
                  .replace("__BODY__", body)
                  .replace("__PREFIX__", prefix)).encode()


# ── probing ──────────────────────────────────────────────────────────────────
def probe(index: int) -> dict[str, Any]:
    """Ask one bridge for /api/status so the picker can show live state."""
    b = BRIDGES[index]
    out = {"index": index, "name": b["name"], "host": b["host"], "port": b["port"],
           "ok": False, "error": ""}
    url = f"http://{b['host']}:{b['port']}/api/status"
    req = urllib.request.Request(url, headers={"Authorization": _auth_header(b)})
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        out.update(ok=True, version=data.get("version"), buses=data.get("bus_count"))
    except urllib.error.HTTPError as exc:
        # 401 here is a configuration mistake, not a dead bridge — say which.
        out["error"] = ("wrong username or password" if exc.code == 401
                        else f"HTTP {exc.code}")
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        out["error"] = getattr(exc, "reason", None) and str(exc.reason) or "unreachable"
    except ValueError:
        out["error"] = "unexpected response"
    return out


# ── request handling ─────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ctrlable-dali-proxy"

    # BaseHTTPRequestHandler logs to stderr in its own format; route it through
    # logging so add-on log level applies.
    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("%s %s", self.address_string(), fmt % args)

    # ── helpers ──
    @property
    def prefix(self) -> str:
        """Ingress mounts us under a per-session path; links must carry it."""
        return self.headers.get("X-Ingress-Path", "").rstrip("/")

    def _send(self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── routes ──
    def do_GET(self) -> None:
        self._route()

    def do_HEAD(self) -> None:
        self._route()

    def do_POST(self) -> None:
        self._route()

    def do_PUT(self) -> None:
        self._route()

    def do_DELETE(self) -> None:
        self._route()

    def _route(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path in ("/healthz", "/health"):
            self._send(200, b'{"ok":true}', "application/json")
            return
        if path == "/_status":
            with ThreadPoolExecutor(max_workers=max(1, len(BRIDGES))) as pool:
                results = list(pool.map(probe, range(len(BRIDGES)))) if BRIDGES else []
            self._send(200, json.dumps(results).encode(), "application/json")
            return
        if path in ("", "/"):
            # One bridge is the common case: go straight in rather than making
            # someone click through a list of one.
            if len(BRIDGES) == 1:
                self._redirect(f"{self.prefix}/b/0/")
            else:
                page = _PICKER.replace("__PREFIX__", json.dumps(self.prefix))
                self._send(200, page.encode())
            return
        m = re.match(r"^/b/(\d+)(/.*)?$", path)
        if m:
            self._proxy(int(m.group(1)), m.group(2) or "/")
            return
        self._send(404, error_page("Not found", "No such page on this add-on.",
                                   self.prefix))

    def _proxy(self, index: int, rest: str) -> None:
        if index >= len(BRIDGES):
            self._send(404, error_page(
                "Unknown bridge",
                "That bridge is not in this add-on’s configuration.", self.prefix))
            return
        b = BRIDGES[index]
        query = urllib.parse.urlparse(self.path).query
        url = f"http://{b['host']}:{b['port']}{rest}" + (f"?{query}" if query else "")

        body = None
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            body = self.rfile.read(length)

        headers = {"Authorization": _auth_header(b)}
        for h in ("Content-Type", "Accept"):
            if self.headers.get(h):
                headers[h] = self.headers[h]

        req = urllib.request.Request(url, data=body, method=self.command,
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                status, payload = resp.status, resp.read()
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                # Swallow WWW-Authenticate: a browser prompt inside the ingress
                # iframe cannot be satisfied (and would leak that this is basic
                # auth at all). Point at the fix instead.
                self._send(502, error_page(
                    "Bridge rejected the credentials",
                    f"The bridge at <code>{_esc(b['host'])}:{b['port']}</code> did not "
                    "accept the username and password set for it in this add-on’s "
                    "Configuration tab. A factory-default bridge uses "
                    "<code>admin</code> / <code>admin</code>.", self.prefix))
                return
            status, payload = exc.code, exc.read()
            ctype = exc.headers.get("Content-Type", "text/plain")
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            reason = _esc(str(getattr(exc, "reason", exc)))
            self._send(502, error_page(
                "Bridge unreachable",
                f"Could not reach <code>{_esc(b['host'])}:{b['port']}</code> "
                f"({reason}). Check that the bridge is running and that its admin "
                "UI port is correct.", self.prefix))
            return

        if ctype.startswith("text/html"):
            payload = rewrite_html(payload, f"{self.prefix}/b/{index}/",
                                   _switcher(self.prefix, index))
        self._send(status, payload, ctype)


def main() -> None:
    global BRIDGES
    logging.basicConfig(
        level=getattr(logging, os.environ.get("DALI_PROXY_LOG", "INFO").upper(), logging.INFO),
        format="%(levelname)s %(message)s")
    BRIDGES = load_bridges()
    port = int(os.environ.get("DALI_PROXY_PORT", "8098"))
    if BRIDGES:
        for i, b in enumerate(BRIDGES):
            log.info("bridge %d: %s (%s:%s)", i, b["name"], b["host"], b["port"])
    else:
        log.warning("no bridges configured — add one in the Configuration tab")
    ThreadingHTTPServer.allow_reuse_address = True
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    log.info("listening on :%d", port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
