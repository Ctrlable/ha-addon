# Ctrlable Orchestrator

Puts the Ctrlable Orchestrator (the appliance provisioner) in the Ctrlable Pro
sidebar, reachable from anywhere Ctrlable Pro is — on the LAN, or remotely
through the portal tunnel — without knowing the orchestrator's IP.

## Auto-discovery

Leave **host** blank (the default). The add-on runs on the host network and
scans the site LAN for the orchestrator (a service answering
`GET /api/whoami` with `{"service":"ctrlable-orchestrator"}`), then proxies it
through ingress. Because discovery is by signature, not by address, the panel
keeps working even after the appliance moves to a different site and its IP
changes.

Set **host** (and **port**, default `8000`) only to pin a specific orchestrator
— for example on a multi-subnet site where the scan can't see it.

```yaml
host: ""        # blank = auto-discover
port: 8000
log_level: info
```

## Signing in

The panel shows the orchestrator's own login. Being in Ctrlable Pro gets you to
it; the orchestrator still asks for its admin credentials the first time (your
browser remembers them for the panel afterwards).
