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

# 0.1.2

- **Fixed: the panel could not talk to the manager through ingress.** Every fetch
  in the panel is root-absolute — `fetch("/health")`, `fetch("/zones")` — so under
  ingress they resolved against the origin and hit Home Assistant instead of this
  add-on. HA answered with something that was not the panel's JSON and the first
  card to poll reported a parse error. All 38 calls were affected; the host health
  card was simply the first one visible.

  The add-on now injects a small shim that patches `fetch` and `XMLHttpRequest` to
  carry the ingress prefix. Patching once covers every call, including ones added
  later — rewriting the HTML would have worked today and silently missed a call
  written with different quoting tomorrow.

- Releases now sync into `Ctrlable/ha-addon` automatically, so the copy users
  install cannot drift from the one the store gets.
