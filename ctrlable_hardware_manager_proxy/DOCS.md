# Ctrlable Hardware Manager

Puts the hardware manager panel inside Ctrlable Pro, so provisioning lives next to
everything else rather than on a separate address nobody remembers.

## What it manages

- **USB topology** — controllers, hubs and routes, with each device's physical
  route (`C1P2H1P3` = card 1, port 2, hub 1, port 3) and where it currently
  resolves to. Add, name and remove ports; generate the udev rules and slot
  declarations a new hub needs.
- **Audio zones** — sinks, filters, per-zone EQ, crossover and channel modes.
- **Inputs** — microphones and line inputs, their capture jacks, and routing any
  of them live into any set of rooms.
- **Voice assistants** and **snapcast clients** — service state, boot state, and
  which snapserver each client talks to.

## Setup

1. Set **manager_url** to where the manager is reachable, e.g.
   `http://192.168.1.50:8080`.
2. Set **service_key** to the key from the manager's `auth.conf`
   (`service_key:` line). This lets the addon authenticate on your behalf, so you
   do not sign in twice — Home Assistant has already established who you are.
3. Start the addon and open **Hardware** in the sidebar.

Leaving **service_key** empty is supported: the panel then shows its own login and
you sign in with the manager's own credentials.

## A note on the default password

The manager ships with `admin` / `admin` and will keep warning you until it is
changed. That default exists so you can get in the first time, not as a resting
state — anyone who can reach the manager can change what plays in every room, or
open a microphone in one. Change it from the panel before you rely on this.
