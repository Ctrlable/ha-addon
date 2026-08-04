#!/usr/bin/with-contenv bashio
# ============================================================
# Ctrlable DALI Bridge proxy — startup
# ============================================================
# Supervisor writes the Configuration tab to /data/options.json.
# The bridge credentials go options.json -> env -> proxy.py and
# never reach the browser: the proxy attaches them upstream.
# ============================================================

BRIDGES="$(jq -c '.bridges // []' /data/options.json)"
export DALI_PROXY_BRIDGES="${BRIDGES}"
export DALI_PROXY_PORT="8098"
export DALI_PROXY_LOG="$(jq -r '.log_level // "info"' /data/options.json)"

bashio::log.info "Ctrlable DALI Bridge proxy starting"
bashio::log.info "Configured bridges: $(jq 'length' <<< "${BRIDGES}")"

exec python3 /app/proxy.py
