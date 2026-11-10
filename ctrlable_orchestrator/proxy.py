#!/usr/bin/env python3
"""Reverse proxy from Ctrlable Pro (HA ingress) to the Ctrlable Orchestrator.

The orchestrator (the appliance provisioner) serves its web UI on the site LAN,
usually on the same Proxmox host as Ctrlable Pro, on :8000. Reaching it
otherwise means leaving Ctrlable Pro and knowing the orchestrator's IP — which,
as this very appliance proved, CHANGES when the box moves sites. This add-on
puts that UI in the sidebar and finds the orchestrator itself:

  • AUTO-DISCOVERY — no IP to enter. The add-on runs on the host network, so it
    scans its own /24 for a service answering GET /api/whoami with
    {"service":"ctrlable-orchestrator"} and proxies that. (Set `host` in the
    options only to pin one explicitly.)
  • Ingress mounts us under a per-session path; the orchestrator's SPA was built
    with relative asset/API URLs, so injecting one <base href> is all it needs
    to resolve everything under that prefix.

Stdlib only, on purpose: the image is a base image plus python3, so it builds on
every arch the Supervisor targets without wheels or a compiler.
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("orch-proxy")

TIMEOUT = 30            # upstream requests — a build log can stream a while
PROBE_TIMEOUT = 1.0     # per-host discovery probe
DISCOVERY_TTL = 300     # re-verify the cached orchestrator at most this often

PINNED_HOST = os.environ.get("ORCH_HOST", "").strip()
PORT = int(os.environ.get("ORCH_PORT", "8000") or "8000")

_HEAD_OPEN = re.compile(r"<head[^>]*>", re.I)
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailers", "transfer-encoding", "upgrade", "content-length",
               "content-encoding"}


# ── discovery ─────────────────────────────────────────────────────────────────
class Discovery:
    """Finds and remembers the orchestrator's host:port."""
    def __init__(self) -> None:
        self._host: str | None = None
        self._checked = 0.0
        self._lock = threading.Lock()

    def _own_ipv4(self) -> str | None:
        """This container's primary LAN IP (host_network), via the usual
        connect-a-UDP-socket trick — no packet is actually sent."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))     # TEST-NET-1, guaranteed off-link
            return s.getsockname()[0]
        except OSError:
            return None
        finally:
            s.close()

    def _is_orchestrator(self, host: str) -> bool:
        url = f"http://{host}:{PORT}/api/whoami"
        try:
            with urllib.request.urlopen(url, timeout=PROBE_TIMEOUT) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            return data.get("service") == "ctrlable-orchestrator"
        except Exception:                   # noqa: BLE001 — any failure = not it
            return False

    def _scan(self) -> str | None:
        if PINNED_HOST:
            return PINNED_HOST if self._is_orchestrator(PINNED_HOST) else None
        ip = self._own_ipv4()
        if not ip:
            log.warning("could not determine own IP; cannot auto-discover")
            return None
        a, b, c, own = ip.split(".")
        base = f"{a}.{b}.{c}"
        candidates = [f"{base}.{n}" for n in range(1, 255) if str(n) != own]
        log.info("scanning %s.0/24 for the orchestrator (/api/whoami) ...", base)
        with ThreadPoolExecutor(max_workers=64) as pool:
            for host, ok in zip(candidates, pool.map(self._is_orchestrator, candidates)):
                if ok:
                    log.info("found orchestrator at %s:%s", host, PORT)
                    return host
        log.warning("no orchestrator found on %s.0/24", base)
        return None

    def host(self, force: bool = False) -> str | None:
        with self._lock:
            now = time.time()
            if (self._host and not force
                    and now - self._checked < DISCOVERY_TTL
                    and self._is_orchestrator(self._host)):
                return self._host
            found = self._scan()
            if found:
                self._host, self._checked = found, now
            elif self._host and self._is_orchestrator(self._host):
                self._checked = now            # scan missed it but it's still up
            else:
                self._host = None
            return self._host


DISCOVERY = Discovery()


# ── pages ───────────────────────────────────────────────────────────────────
_NOT_FOUND = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Orchestrator not found</title><style>
body{margin:0;background:#0F1216;color:#E6EAF0;font:14px system-ui,sans-serif}
main{max-width:620px;margin:60px auto;padding:0 18px}
.card{background:#161A20;border:1px solid #262E38;border-radius:10px;padding:20px}
h1{font-size:16px;margin:0 0 10px}p{color:#8B95A3;line-height:1.5}code{color:#E6EAF0}
a{color:#4C8DFF}
</style></head><body><main><div class=card>
<h1>Orchestrator not found on the network</h1>
<p>This add-on scanned the site LAN but did not find a Ctrlable Orchestrator
(a service answering <code>/api/whoami</code> on port __PORT__).</p>
<p>Check that the orchestrator is running, or set <code>host</code> in this
add-on's Configuration tab to pin it. Then <a href="">retry</a>.</p>
</div></main></body></html>"""


# ── request handling ──────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ctrlable-orch-proxy"

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    @property
    def prefix(self) -> str:
        return self.headers.get("X-Ingress-Path", "").rstrip("/")

    def _send(self, status, body, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):    self._route()
    def do_HEAD(self):   self._route()
    def do_POST(self):   self._route()
    def do_PUT(self):    self._route()
    def do_DELETE(self): self._route()
    def do_PATCH(self):  self._route()

    def _route(self):
        if self.path in ("/healthz",):
            self._send(200, b'{"ok":true}', "application/json")
            return
        host = DISCOVERY.host()
        if not host:
            self._send(503, _NOT_FOUND.replace("__PORT__", str(PORT)).encode())
            return
        self._proxy(host)

    def _proxy(self, host: str):
        url = f"http://{host}:{PORT}{self.path}"
        body = None
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            body = self.rfile.read(length)

        # Pass request headers through (notably Authorization: the SPA's JWT),
        # minus hop-by-hop and the rewritten Host.
        fwd = {}
        for k, v in self.headers.items():
            if k.lower() in _HOP_BY_HOP or k.lower() == "host":
                continue
            fwd[k] = v

        req = urllib.request.Request(url, data=body, method=self.command, headers=fwd)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                status = resp.status
                payload = resp.read()
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
                passthru = {k: v for k, v in resp.headers.items()
                            if k.lower() not in _HOP_BY_HOP and k.lower() != "content-type"}
        except urllib.error.HTTPError as exc:
            status = exc.code
            payload = exc.read()
            ctype = exc.headers.get("Content-Type", "text/plain")
            passthru = {}
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            # The cached orchestrator went away — drop it so the next request
            # rediscovers, and tell the user.
            DISCOVERY.host(force=True)
            reason = str(getattr(exc, "reason", exc))
            self._send(502, (f"<pre>orchestrator at {host}:{PORT} unreachable: "
                             f"{reason}</pre>").encode())
            return

        if ctype.startswith("text/html"):
            payload = self._inject_base(payload)
        self._send(status, payload, ctype, passthru)

    def _inject_base(self, body: bytes) -> bytes:
        """Anchor the SPA's relative URLs under the ingress prefix."""
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return body
        base = f"{self.prefix}/" if self.prefix else "/"
        if "<base " in text.lower():
            return body
        m = _HEAD_OPEN.search(text)
        if m:
            text = text[:m.end()] + f'<base href="{base}">' + text[m.end():]
        return text.encode("utf-8")


def main():
    logging.basicConfig(
        level=getattr(logging, os.environ.get("ORCH_LOG", "INFO").upper(), logging.INFO),
        format="%(levelname)s %(message)s")
    port = int(os.environ.get("ORCH_PROXY_PORT", "8099"))
    # Warm discovery at startup so the first click is fast (best effort).
    try:
        host = DISCOVERY.host(force=True)
        log.info("orchestrator: %s", f"{host}:{PORT}" if host else "not found yet (will retry on first request)")
    except Exception as exc:                 # noqa: BLE001
        log.warning("initial discovery failed: %s", exc)
    ThreadingHTTPServer.allow_reuse_address = True
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    log.info("listening on :%d", port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
