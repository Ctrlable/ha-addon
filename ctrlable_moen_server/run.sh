#!/usr/bin/with-contenv bashio
# ============================================================
# Ctrlable Shower Server: startup
# ============================================================
# The certificate is made once and kept in /data, so it stays
# the same across restarts and updates. The showers accept it
# without checking who signed it (tested 2026-11-15).
# ============================================================

CERT=/data/cert.pem
KEY=/data/key.pem
if [ ! -s "${CERT}" ] || [ ! -s "${KEY}" ]; then
  bashio::log.info "Making this server's certificate"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=ws-us2.pusher.com" \
    -addext "subjectAltName=DNS:ws-us2.pusher.com,DNS:*.pusher.com" \
    -keyout "${KEY}" -out "${CERT}" 2>/dev/null
  chmod 600 "${KEY}"
fi

LOCAL_PORT="$(bashio::config 'local_port')"
ARGS=(--tls-port 443 --cert "${CERT}" --key "${KEY}"
      --port "${LOCAL_PORT}" --plain-bind 127.0.0.1)
if bashio::config.true 'verbose'; then
  ARGS+=(--verbose)
fi

bashio::log.info "Showers: wss on port 443. Ctrlable Pro: ws://127.0.0.1:${LOCAL_PORT}"
exec python3 -W ignore::DeprecationWarning /app/server.py "${ARGS[@]}"
