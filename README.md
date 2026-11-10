# Ctrlable Home Assistant Add-ons

[![Add repository to HA](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FCtrlable%2Fha-addon)

## Add-ons in this repository

### [Ctrlable Agent](./ctrlable)

Connects your Home Assistant to the Ctrlable remote management platform via a secure WireGuard VPN tunnel.

### [Ctrlable DALI Bridge](./ctrlable_dali_proxy)

Puts the admin UI of one or more DALI bridges in the sidebar, through ingress —
no separate IP to remember and no second password prompt.

### [Ctrlable Orchestrator](./ctrlable_orchestrator)

Puts the Ctrlable Orchestrator (appliance provisioner) in the sidebar, through
ingress. Auto-discovers the orchestrator on the site LAN — no IP to enter, and
it keeps working after the appliance moves sites and its IP changes.

**Installation:** Click the button above, or manually add `https://github.com/Ctrlable/ha-addon` as a custom repository in HA.
