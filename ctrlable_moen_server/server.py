#!/usr/bin/env python3
"""A Pusher server for the house, so the Moen showers don't need Moen's.

WHY (Pinecrest, 2026-11-15). Moen runs every U by Moen shower, every copy of
its app and our integration on ONE shared Pusher app. Pusher caps that app's
messages per day. When Moen's whole fleet uses the day's allowance, Pusher
refuses every message for everyone until 00:00 UTC (7 pm ET): commands from
the app and from Ctrlable Pro fail, and the showers' own reports stop too.
On 11-14 it ran out at 17:35 ET, on 11-15 at 13:40 ET.

WHAT THIS IS. The parts of Pusher protocol 7 the showers and clients use:
connect (pusher:connection_established), subscribe / unsubscribe, ping/pong,
and client events (client-*) relayed to every OTHER socket on the channel.
Private-channel auth is accepted without checking: this listens on the LAN
only, and the channels are the showers' own random ids.

WHERE THE SHOWERS COME FROM. A DNS entry on the router points the Pusher
host name (ws-us2.pusher.com) at this machine. The showers then connect here
on 80 (ws) or 443 (wss). For 443 this presents its own certificate, which the
showers will only accept if they don't check it. That is THE question; every
TLS refusal is logged with the reason the shower gave, e.g.
  tls REFUSED from 10.1.8.77: TLSV1_ALERT_UNKNOWN_CA  (= the shower checks)

    moen_local_pusher.py [--tls-port 443 --cert c.pem --key k.pem] [--port 80]

Logs one line per event to stdout. No payloads beyond the event name and
the channel's first 8 characters, except --verbose.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import itertools
import json
import os
import random
import ssl
import struct
import time

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ACTIVITY_TIMEOUT = 120
VERBOSE = False


def log(msg: str) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%S ") + msg, flush=True)


def short(channel: str | None) -> str:
    c = channel or ""
    for p in ("private-", "presence-"):
        if c.startswith(p):
            return p + c[len(p):len(p) + 8]
    return c[:16]


# ── WebSocket framing (RFC 6455, text frames only, no extensions) ────────────
class Closed(Exception):
    pass


async def read_frame(r: asyncio.StreamReader) -> tuple[int, bytes]:
    head = await r.readexactly(2)
    fin_op, ln = head
    op = fin_op & 0x0F
    masked = ln & 0x80
    n = ln & 0x7F
    if n == 126:
        n = struct.unpack("!H", await r.readexactly(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", await r.readexactly(8))[0]
    if n > 1 << 20:
        raise Closed("frame too large")
    mask = await r.readexactly(4) if masked else b""
    data = await r.readexactly(n)
    if masked:
        data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
    return op, data


def frame(op: int, data: bytes) -> bytes:
    n = len(data)
    if n < 126:
        h = struct.pack("!BB", 0x80 | op, n)
    elif n < 1 << 16:
        h = struct.pack("!BBH", 0x80 | op, 126, n)
    else:
        h = struct.pack("!BBQ", 0x80 | op, 127, n)
    return h + data


# ── the hub ──────────────────────────────────────────────────────────────────
class Conn:
    ids = itertools.count(1)

    def __init__(self, w: asyncio.StreamWriter, peer: str, tls: bool):
        self.w = w
        self.peer = peer
        self.tls = tls
        self.socket_id = f"{random.randint(100000, 999999)}.{next(Conn.ids)}"
        self.channels: set[str] = set()
        self.lock = asyncio.Lock()

    async def send(self, msg: dict) -> None:
        async with self.lock:
            self.w.write(frame(0x1, json.dumps(msg, separators=(",", ":")).encode()))
            await self.w.drain()

    async def send_raw(self, op: int, data: bytes) -> None:
        async with self.lock:
            self.w.write(frame(op, data))
            await self.w.drain()


class Hub:
    def __init__(self):
        self.channels: dict[str, set[Conn]] = {}
        self.counts = {"connections": 0, "relayed": 0, "tls_refused": 0}

    async def handle(self, conn: Conn, msg: dict) -> None:
        ev = msg.get("event")
        data = msg.get("data")
        if isinstance(data, str) and ev and ev.startswith("pusher:"):
            try:
                data = json.loads(data)
            except ValueError:
                pass
        if ev == "pusher:ping":
            await conn.send({"event": "pusher:pong", "data": "{}"})
        elif ev == "pusher:pong":
            pass
        elif ev == "pusher:subscribe":
            ch = (data or {}).get("channel")
            if not ch:
                return
            self.channels.setdefault(ch, set()).add(conn)
            conn.channels.add(ch)
            log(f"subscribe {conn.peer} {short(ch)} ({len(self.channels[ch])} on it)")
            await conn.send({"event": "pusher_internal:subscription_succeeded", "channel": ch, "data": "{}"})
        elif ev == "pusher:unsubscribe":
            ch = (data or {}).get("channel")
            self.leave(conn, ch)
        elif ev and ev.startswith("client-"):
            ch = msg.get("channel")
            if ch not in conn.channels:
                await conn.send({"event": "pusher:error",
                                 "data": {"code": None, "message": "Client event rejected - not subscribed"}})
                return
            # Pusher delivers a client event's data as a JSON string.
            out = {"event": ev, "channel": ch,
                   "data": data if isinstance(data, str) else json.dumps(data, separators=(",", ":"))}
            others = [c for c in self.channels.get(ch, ()) if c is not conn]
            self.counts["relayed"] += 1
            log(f"relay {ev} {short(ch)} from {conn.peer} to {len(others)}"
                + (f" {out['data'][:300]}" if VERBOSE else ""))
            for c in others:
                try:
                    await c.send(out)
                except Exception:
                    pass
        else:
            log(f"ignored event {ev!r} from {conn.peer}")

    def leave(self, conn: Conn, ch: str | None) -> None:
        if ch in conn.channels:
            conn.channels.discard(ch)
            s = self.channels.get(ch)
            if s:
                s.discard(conn)
                if not s:
                    del self.channels[ch]

    def gone(self, conn: Conn) -> None:
        for ch in list(conn.channels):
            self.leave(conn, ch)


HUB = Hub()


async def serve_conn(r: asyncio.StreamReader, w: asyncio.StreamWriter, tls_ctx: ssl.SSLContext | None) -> None:
    peer = (w.get_extra_info("peername") or ("?",))[0]
    if tls_ctx is not None:
        try:
            await asyncio.wait_for(w.start_tls(tls_ctx), 15)
        except ssl.SSLError as e:
            HUB.counts["tls_refused"] += 1
            log(f"tls REFUSED from {peer}: {e.reason or e}")
            w.close()
            return
        except (OSError, asyncio.TimeoutError, ConnectionError) as e:
            HUB.counts["tls_refused"] += 1
            log(f"tls REFUSED from {peer}: hung up during the handshake ({type(e).__name__}), "
                "most likely rejecting the certificate")
            w.close()
            return
        log(f"tls ok from {peer} ({w.get_extra_info('ssl_object').version()})")
    try:
        req = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 15)
    except Exception as e:
        if tls_ctx is not None:
            # TLS 1.3: the server finishes first, so a client that rejects
            # the certificate hangs up only now, before sending a request.
            HUB.counts["tls_refused"] += 1
            log(f"tls REFUSED from {peer}: closed before sending a request ({type(e).__name__}), "
                "most likely rejecting the certificate")
        w.close()
        return
    lines = req.decode("latin-1").split("\r\n")
    path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else ""
    hdr = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:] if l)}
    key = hdr.get("sec-websocket-key")
    shown = path.split("?")[0]
    parts = shown.split("/")
    if len(parts) >= 3 and parts[1] == "app":
        shown = f"/app/{hashlib.sha256(parts[2].encode()).hexdigest()[:8]}"
    if not key or "websocket" not in hdr.get("upgrade", "").lower():
        log(f"http {lines[0].split(' ')[0]} {shown} from {peer} (not a websocket) -> 404")
        w.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await w.drain()
        w.close()
        return
    accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
    w.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
    await w.drain()
    conn = Conn(w, peer, tls_ctx is not None)
    HUB.counts["connections"] += 1
    log(f"connect {peer} {'wss' if conn.tls else 'ws'} {shown} ua={hdr.get('user-agent', '-')[:40]} "
        f"socket {conn.socket_id}")
    await conn.send({"event": "pusher:connection_established",
                     "data": json.dumps({"socket_id": conn.socket_id, "activity_timeout": ACTIVITY_TIMEOUT})})
    why = "closed"
    try:
        while True:
            op, data = await asyncio.wait_for(read_frame(r), ACTIVITY_TIMEOUT * 2)
            if op == 0x8:
                await conn.send_raw(0x8, data[:2])
                break
            if op == 0x9:
                await conn.send_raw(0xA, data)
                continue
            if op != 0x1:
                continue
            try:
                msg = json.loads(data)
            except ValueError:
                continue
            if isinstance(msg, dict):
                await HUB.handle(conn, msg)
    except asyncio.TimeoutError:
        why = "idle"
    except (asyncio.IncompleteReadError, ConnectionError, Closed, OSError) as e:
        why = type(e).__name__
    finally:
        HUB.gone(conn)
        log(f"disconnect {peer} socket {conn.socket_id} ({why})")
        try:
            w.close()
        except Exception:
            pass


async def main_async(a) -> None:
    servers = []
    for port in a.port:
        bind = a.plain_bind or a.bind
        servers.append(await asyncio.start_server(lambda r, w: serve_conn(r, w, None), bind, port))
        log(f"listening ws  {bind}:{port}")
    if a.tls_port:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.cert, a.key)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1   # old embedded TLS stacks
        except (ValueError, ssl.SSLError):
            pass
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        servers.append(await asyncio.start_server(lambda r, w: serve_conn(r, w, ctx), a.bind, a.tls_port))
        log(f"listening wss {a.bind}:{a.tls_port}")
    await asyncio.gather(*(s.serve_forever() for s in servers))


def main() -> None:
    global VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default=os.environ.get("MLP_BIND", "0.0.0.0"))
    ap.add_argument("--port", type=int, action="append", default=None)
    ap.add_argument("--plain-bind", default=None,
                    help="address for the unencrypted port(s) only, e.g. 127.0.0.1 so just this box uses it")
    ap.add_argument("--tls-port", type=int, default=None)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    a.port = a.port if a.port is not None else [80]
    VERBOSE = a.verbose
    asyncio.run(main_async(a))


if __name__ == "__main__":
    main()
