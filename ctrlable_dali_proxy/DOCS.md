# Ctrlable DALI Bridge

Puts the DALI bridge's admin web UI in the Ctrlable Pro sidebar.

A DALI bridge serves its own admin UI on the LAN (status, MQTT and driver
configuration, bus naming, software updates) on port `8099`, behind HTTP basic
auth. This add-on proxies that UI through Ctrlable Pro's ingress, so:

- it appears as a **DALI Bridge** sidebar panel — no separate IP to remember,
- being signed in to Ctrlable Pro is enough — the add-on holds the bridge
  credentials and attaches them upstream, so no second password prompt appears,
- several bridges can be listed at once, which is what multi-gateway sites need.

## Configuration

```yaml
bridges:
  - name: "Main Hall"
    host: "10.1.8.45"
    port: 8099
    username: "admin"
    password: "admin"
  - name: "Annex"
    host: "10.1.8.46"
    port: 8099
    username: "admin"
    password: "admin"
log_level: info
```

| Option | Description |
| --- | --- |
| `bridges[].name` | Label shown in the picker and in the bridge UI header. |
| `bridges[].host` | Bridge IP or hostname on the LAN. |
| `bridges[].port` | Admin UI port. `8099` unless it was changed on the bridge. |
| `bridges[].username` | Bridge admin user. Factory default `admin`. |
| `bridges[].password` | Bridge admin password. Factory default `admin`. |
| `log_level` | `debug` \| `info` \| `warning` \| `error`. |

A factory-fresh bridge answers to **`admin` / `admin`**, which is what the
default options assume. Change it on the bridge (its **Configuration → Admin
UI** card), then set the same values here.

With one bridge configured the panel opens it directly. With more than one, the
panel shows a picker with live reachability, and each bridge UI carries an
**All bridges** link back to it.

## How it works

Ingress requests arrive under a per-session path; the proxy rewrites the bridge
page to stay inside it (a `<base>` tag, plus relative API paths for bridges
older than 0.3.5, which emitted absolute ones). Everything else is passed
through unchanged, including the bridge's own JSON API.

Direct LAN access to the proxy is disabled by default. Map host port `8098` in
the **Network** section if you want to reach it without Ctrlable Pro — note the
proxy does not authenticate on that path, so only do it on a trusted network.

## Troubleshooting

**"Bridge unreachable"** — the bridge is off, the IP changed, or the admin UI
port differs. Check the bridge with `systemctl status dali-bridge` on its host.

**"Bridge rejected the credentials"** — the username/password here do not match
the bridge. If the bridge password was forgotten, it is `webui_user` /
`webui_pass` in the bridge's `config.yaml`.

**Panel is blank** — check the add-on log; with no bridges configured it starts
and says so, and the picker offers to send you to the Configuration tab.
