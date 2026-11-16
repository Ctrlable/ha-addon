# Ctrlable Shower Server

Keeps U by Moen smart showers under Ctrlable Pro's control when Moen's cloud
stops passing messages.

## Why

Every U by Moen shower, every copy of the Moen app and the Ctrlable U by Moen
integration send their messages through one shared Pusher account that Moen
pays for. It allows a fixed number of messages per day across all Moen
customers. When it runs out, often in the afternoon (US Eastern), nobody can
turn a shower on or off from an app until the count resets at 00:00 UTC
(7 pm Eastern). The showers' own wall panels keep working.

This add-on is a small Pusher server on the site. The showers and Ctrlable Pro
talk to it instead, so their messages never leave the building and no quota
applies.

## Setting it up

1. **Install and start this add-on.** It needs port 443 on this box free.
2. **U by Moen integration:** Settings → Devices & services → U by Moen →
   Configure. Set *House server address* to `ws://127.0.0.1:8478`.
3. **DNS on the site's router:** add a DNS record so `ws-us2.pusher.com`
   points to this box's LAN address. On a UniFi gateway: Settings → DNS
   records (or Policy Engine → DNS), type *Host (A)*.
4. **Make the showers reconnect:** power-cycle them, or wait. They look up the
   address only when they reconnect.

The add-on log then shows each shower connecting:

```
tls ok from 10.1.8.77 (TLSv1.2)
connect 10.1.8.77 wss /app/2974f0c3 ua=WMSDK socket 170557.2
subscribe 10.1.8.77 private-8263194e (2 on it)
```

and every command as it is passed on:

```
relay client-state-desired private-8263194e from 127.0.0.1 to 1
```

## What changes for the owner

- Ctrlable Pro controls the showers on site with no daily limit, and remote
  control goes through Ctrlable Pro's own remote access.
- **The Moen app no longer controls the showers** (at home or away): they no
  longer listen to Moen's cloud. The wall panels work as always.
- If this box is down, the showers can't be controlled remotely until it is
  back. Removing the DNS record returns everything to Moen's cloud the next
  time the showers reconnect.

## Troubleshooting

| Log line | Meaning |
|---|---|
| `tls REFUSED from <shower>` | That shower rejected this server's certificate. Remove the DNS record. |
| No `connect` lines from the showers | DNS record missing, or the showers have not reconnected yet. |
| `relay ... to 0` from 127.0.0.1 | A command went out but no shower is connected. |
