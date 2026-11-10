#!/usr/bin/with-contenv bashio
# ============================================================
# Ctrlable Orchestrator proxy — startup
# ============================================================
# Supervisor writes the Configuration tab to /data/options.json.
# host is normally blank -> the proxy auto-discovers the orchestrator on the
# site LAN by its /api/whoami signature. Set host only to pin one explicitly.
# ============================================================

export ORCH_HOST="$(jq -r '.host // ""' /data/options.json)"
export ORCH_PORT="$(jq -r '.port // 8000' /data/options.json)"
export ORCH_PROXY_PORT="8099"
export ORCH_LOG="$(jq -r '.log_level // "info"' /data/options.json)"

if [ -n "${ORCH_HOST}" ]; then
  bashio::log.info "Ctrlable Orchestrator proxy starting (pinned to ${ORCH_HOST}:${ORCH_PORT})"
else
  bashio::log.info "Ctrlable Orchestrator proxy starting (auto-discovery on the site LAN)"
fi

exec python3 /app/proxy.py
