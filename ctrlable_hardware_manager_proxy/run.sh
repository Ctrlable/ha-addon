#!/usr/bin/with-contenv bashio
set -euo pipefail

MANAGER_URL="$(bashio::config 'manager_url')"
SERVICE_KEY="$(bashio::config 'service_key')"
VERIFY_TLS="$(bashio::config 'verify_tls')"

if [ -z "${MANAGER_URL}" ]; then
  bashio::log.fatal "manager_url is not set."
  bashio::log.fatal "Set it to where the Hardware Manager is reachable on your"
  bashio::log.fatal "network, for example http://192.168.1.50:8080, in this"
  bashio::log.fatal "add-on's Configuration tab."
  bashio::exit.nok
fi

bashio::log.info "Ctrlable Hardware Manager -> ${MANAGER_URL}"

if [ -z "${SERVICE_KEY}" ]; then
  bashio::log.warning "No service_key set. The panel will ask for the manager's"
  bashio::log.warning "own login instead of using this Home Assistant session."
fi

export MANAGER_URL SERVICE_KEY VERIFY_TLS
exec python3 -u /app/proxy.py
