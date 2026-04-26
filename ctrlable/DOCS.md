# Ctrlable Agent

Connects your Home Assistant instance to the [Ctrlable](https://portal.ctrlable.com) remote management platform via a secure WireGuard VPN tunnel.

## Installation

1. In Home Assistant, go to **Settings → Add-ons → Add-on Store**
2. Click the **⋮** menu (top right) → **Repositories**
3. Add: `https://github.com/Ctrlable/ha-addon`
4. Find **Ctrlable Agent** in the store and click **Install**

## Setup

1. In the **Configuration** tab, paste your enrollment token from the Ctrlable portal
   - Portal → Devices → Generate Enrollment Token
2. Click **Save**, then click **Start**
3. The device will appear online in the portal within ~60 seconds

## Configuration

| Option | Description |
|---|---|
| `enrollment_token` | One-time token from the Ctrlable portal (consumed on first start) |

## How it works

- On first start: enrolls with the Ctrlable API, configures a WireGuard tunnel, and saves credentials to `/data/`
- On subsequent starts: reconnects the existing tunnel automatically — no token needed again
- Sends a heartbeat to the portal every 60 seconds to report online status

## Support

[portal.ctrlable.com](https://portal.ctrlable.com)
