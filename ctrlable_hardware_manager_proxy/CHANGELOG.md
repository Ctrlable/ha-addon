# 0.1.0

First release.

- Serves the Ctrlable Hardware Manager panel inside Ctrlable Pro over ingress
- Authenticates upstream with a service key, so Home Assistant's own login is
  enough and there is no second password prompt
- Falls back to the manager's own login when no key is configured
- Not exposed on a host port: the manager already listens on the LAN, and a second
  door would only add one that bypasses Home Assistant's authentication

# 0.1.1

- Renamed to **Ctrlable Hardware Manager Proxy**, and published to the Ctrlable
  Store under `ctrlable_hardware_manager_proxy`.

  0.1.0 registered as `ctrlable_hardware_manager`, which is the LXC — the manager
  runs as a container with an agent on the Proxmox host and is not installable
  through Home Assistant at all. Listing it as an add-on offered something that
  could not be installed.
