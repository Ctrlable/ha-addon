#!/usr/bin/env bash
set -e

DATA_DIR="/data"
CREDS_FILE="$DATA_DIR/ctrlable.conf"
WG_DIR="/etc/wireguard"
ENROLL_URL="https://portal.ctrlable.com/v1/enroll"
API_BASE="https://portal.ctrlable.com/api/v1"

info()  { echo "[ctrlable] $1"; }
warn()  { echo "[ctrlable] WARN: $1"; }
die()   { echo "[ctrlable] ERROR: $1" >&2; exit 1; }

# ── JSON helper ───────────────────────────────────────────────────────────────
json_get() {
    field="$1"; json="$2"
    python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('$field',''))" <<< "$json"
}

# ── base64 decode ─────────────────────────────────────────────────────────────
b64decode() { base64 -d 2>/dev/null; }

# ── Heartbeat loop ────────────────────────────────────────────────────────────
run_heartbeat() {
    info "Starting heartbeat loop (every 60s)"
    while true; do
        RX=0; TX=0
        DUMP=$(wg show "$WG_IFACE" dump 2>/dev/null | tail -1) || true
        if [ -n "$DUMP" ]; then
            RX=$(awk '{print $6}' <<< "$DUMP") || RX=0
            TX=$(awk '{print $7}' <<< "$DUMP") || TX=0
        fi
        curl -s --max-time 10 -X POST "$API_BASE/devices/$DEVICE_ID/heartbeat" \
            -H "Content-Type: application/json" \
            -H "X-Device-Token: $DEVICE_TOKEN" \
            -d "{\"rx_bytes\":${RX:-0},\"tx_bytes\":${TX:-0}}" \
            >/dev/null 2>&1 || true
        sleep 60
    done
}

# ── Bring up tunnel ───────────────────────────────────────────────────────────
bring_up_tunnel() {
    mkdir -p "$WG_DIR"
    wg-quick down "$WG_IFACE" 2>/dev/null || true
    wg-quick up "$WG_DIR/$WG_IFACE.conf"
    info "Tunnel up on $WG_IFACE ($TUNNEL_IP)"
}

# ── Already enrolled — reconnect ──────────────────────────────────────────────
if [ -f "$CREDS_FILE" ]; then
    info "Found existing enrollment — reconnecting"
    # shellcheck source=/dev/null
    source "$CREDS_FILE"
    if [ -f "$WG_DIR/$WG_IFACE.conf" ]; then
        bring_up_tunnel
        run_heartbeat
        exit 0
    else
        warn "WireGuard config missing — re-enrolling"
    fi
fi

# ── First run — enroll ────────────────────────────────────────────────────────
ENROLLMENT_TOKEN=$(python3 -c "import json; print(json.load(open('/data/options.json')).get('enrollment_token',''))" 2>/dev/null) || ENROLLMENT_TOKEN=""
[ -z "$ENROLLMENT_TOKEN" ] && die "enrollment_token is not set. Open the add-on Configuration tab and paste your token."

info "Enrolling with Ctrlable..."

# Detect MAC from first non-loopback interface on the host (we share host_network)
IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
[ -z "$IFACE" ] && IFACE="eth0"
MAC=$(cat /sys/class/net/"$IFACE"/address 2>/dev/null || echo "00:00:00:00:00:00")
MAC=$(echo "$MAC" | tr '[:lower:]' '[:upper:]')
HN=$(hostname 2>/dev/null || echo "homeassistant")

RESPONSE=$(curl -sk --max-time 30 -X POST "$ENROLL_URL" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$ENROLLMENT_TOKEN\",\"mac_address\":\"$MAC\",\"platform\":\"haos_addon\",\"hostname\":\"$HN\"}") \
    || die "Enrollment request failed — check network connectivity"

if echo "$RESPONSE" | grep -q '"detail"'; then
    DETAIL=$(json_get "detail" "$RESPONSE")
    die "Enrollment rejected: $DETAIL"
fi

DEVICE_ID=$(json_get "device_id" "$RESPONSE")
TUNNEL_IP=$(json_get "tunnel_ip" "$RESPONSE")
WG_IFACE=$(json_get "interface" "$RESPONSE")
DEVICE_TOKEN=$(json_get "device_token" "$RESPONSE")
WG_B64=$(json_get "wg_config" "$RESPONSE")

[ -z "$DEVICE_ID" ] && die "Unexpected server response: $RESPONSE"

info "Enrolled — Device ID: $DEVICE_ID  Tunnel IP: $TUNNEL_IP"

# Decode and write WireGuard config
WG_CONF=$(b64decode <<< "$WG_B64")
[ -z "$WG_CONF" ] && die "Failed to decode WireGuard config"

mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"
echo "$WG_CONF" > "$WG_DIR/$WG_IFACE.conf"
chmod 600 "$WG_DIR/$WG_IFACE.conf"

# Save credentials to /data (persists across restarts)
mkdir -p "$DATA_DIR" && chmod 700 "$DATA_DIR"
cat > "$CREDS_FILE" << EOF
DEVICE_ID=$DEVICE_ID
DEVICE_TOKEN=$DEVICE_TOKEN
TUNNEL_IP=$TUNNEL_IP
WG_IFACE=$WG_IFACE
API_BASE=$API_BASE
EOF
chmod 600 "$CREDS_FILE"

# Also save to /ssl/ctrlable for cross-add-on access
mkdir -p /ssl/ctrlable && chmod 700 /ssl/ctrlable
cp "$CREDS_FILE" /ssl/ctrlable/ctrlable.conf

info "Credentials saved"

# Bring up WireGuard tunnel
bring_up_tunnel

# Start heartbeat
run_heartbeat
