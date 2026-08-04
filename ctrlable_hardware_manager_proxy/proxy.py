"""Ingress proxy: serves the Ctrlable Hardware Manager panel inside Ctrlable Pro.

stdlib only, matching the manager it fronts -- nothing to pin, nothing to audit,
and no dependency that can break a released addon.

Two things this has to get right:

  AUTHENTICATION. Home Assistant authenticates the person before ingress reaches
  this addon, so asking again would be friction with no security gain. The proxy
  holds a service key and presents it upstream on the user's behalf. The key is
  never sent to the browser and never appears in a URL. With no key configured the
  proxy simply forwards, and the manager shows its own login -- which is the honest
  fallback rather than a silent failure.

  INGRESS PATHS. HA serves the addon under a generated prefix like
  /api/hassio_ingress/<token>/. Absolute links in the page would escape it and hit
  Home Assistant itself, so the prefix is stripped on the way in and re-applied to
  the handful of root-absolute URLs the panel emits on the way out.
"""

import http.server
import os
import socketserver
import sys
import urllib.error
import urllib.parse
import urllib.request

MANAGER_URL = os.environ.get("MANAGER_URL", "").rstrip("/")
SERVICE_KEY = os.environ.get("SERVICE_KEY", "").strip()
PORT = int(os.environ.get("INGRESS_PORT", "8099"))

# Headers that describe THIS hop and must not be replayed upstream.
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailers", "transfer-encoding", "upgrade", "host",
       "content-length", "accept-encoding"}


# Every fetch() in the panel is root-absolute -- fetch("/health"), fetch("/zones").
# Under ingress the page lives at /api/hassio_ingress/<token>/, so those resolve
# against the ORIGIN and hit Home Assistant itself rather than this add-on. HA
# answers with something that is not the panel's JSON, and the first symptom is a
# parse error on whichever card polls first.
#
# Patching fetch once is what fixes all of them, including any added later. The
# alternative -- rewriting fetch("/ in the HTML -- would work today and silently
# miss a call written with different quoting tomorrow.
#
# Left/right of the boundary matters: only paths starting with a single "/" are
# rewritten, so "//cdn..." and absolute URLs are untouched, and a path already
# carrying the prefix is not doubled.
INGRESS_SHIM = """<script>
(function(){
  var P = "__PREFIX__";
  if(!P) return;
  function fix(u){
    if(typeof u !== "string") return u;
    if(u.charAt(0) !== "/" || u.charAt(1) === "/") return u;
    if(u.indexOf(P + "/") === 0) return u;
    return P + u;
  }
  var f = window.fetch;
  if(f) window.fetch = function(u, o){ return f.call(this, fix(u), o); };
  var xo = window.XMLHttpRequest && window.XMLHttpRequest.prototype.open;
  if(xo) window.XMLHttpRequest.prototype.open = function(m, u){
    arguments[1] = fix(u);
    return xo.apply(this, arguments);
  };
})();
</script>"""


def ingress_prefix(headers):
    """The path HA is serving this addon under, if any."""
    return (headers.get("X-Ingress-Path") or "").rstrip("/")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ctrlable-hardware-manager-proxy"

    def log_message(self, fmt, *a):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % a))

    def _relay(self, method):
        prefix = ingress_prefix(self.headers)
        path = self.path
        if prefix and path.startswith(prefix):
            path = path[len(prefix):] or "/"

        body = None
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n > 0:
            body = self.rfile.read(n)

        req = urllib.request.Request(MANAGER_URL + path, data=body, method=method)
        for k, v in self.headers.items():
            if k.lower() not in HOP:
                req.add_header(k, v)
        # Presented on the user's behalf. HA already established who they are; this
        # is what saves them a second login. Never exposed to the browser.
        if SERVICE_KEY:
            req.add_header("X-Ctrlable-Key", SERVICE_KEY)

        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                self._respond(r.status, r.headers, r.read(), prefix)
        except urllib.error.HTTPError as exc:
            self._respond(exc.code, exc.headers, exc.read(), prefix)
        except Exception as exc:                                   # noqa: BLE001
            msg = ("<h2>Cannot reach the hardware manager</h2>"
                   "<p><code>%s</code> did not respond.</p><p><code>%s</code></p>"
                   "<p>Check <b>manager_url</b> in this addon's configuration.</p>"
                   % (MANAGER_URL, str(exc).replace("<", "&lt;")))
            self._respond(502, {"Content-Type": "text/html; charset=utf-8"},
                          msg.encode(), prefix)

    def _respond(self, code, headers, payload, prefix):
        ctype = ""
        try:
            ctype = headers.get("Content-Type", "") or ""
        except Exception:                                          # noqa: BLE001
            pass

        if prefix and "text/html" in ctype:
            # Only root-absolute URLs the panel actually emits. A blanket rewrite
            # would also mangle content -- the panel legitimately displays strings
            # like "/etc/pulse/system.pa", and turning those into ingress paths
            # would corrupt what it is showing.
            text = payload.decode("utf-8", "replace")
            for attr in ('action="', 'href="', 'src="'):
                text = text.replace(attr + "/", attr + prefix + "/")
            text = INGRESS_SHIM.replace("__PREFIX__", prefix) + text
            payload = text.encode()

        out = []
        for k, v in (headers.items() if hasattr(headers, "items") else headers.items()):
            lk = k.lower()
            if lk in HOP or lk == "content-length":
                continue
            if lk == "location" and prefix and v.startswith("/"):
                v = prefix + v
            if lk == "set-cookie" and prefix:
                # The manager sets Path=/; under ingress that cookie would be sent
                # to Home Assistant itself rather than back here.
                v = v.replace("Path=/", "Path=" + prefix + "/")
            out.append((k, v))

        self.send_response(code)
        for k, v in out:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._relay("GET")

    def do_POST(self):
        self._relay("POST")

    def do_HEAD(self):
        self._relay("HEAD")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    sys.stderr.write("ctrlable-hardware-manager proxy on :%d -> %s (service key: %s)\n"
                     % (PORT, MANAGER_URL, "set" if SERVICE_KEY else "NOT set"))
    Server(("0.0.0.0", PORT), Handler).serve_forever()
