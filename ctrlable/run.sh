#!/usr/bin/env bash
set -e

DATA_DIR="/data"
CREDS_FILE="$DATA_DIR/ctrlable.conf"
WG_DIR="/etc/wireguard"
ENROLL_URL="https://portal.ctrlable.com/v1/enroll"
API_BASE="https://portal.ctrlable.com/api/v1"

info()  { echo "[ctrlable] $1"; }
warn()  { echo "[ctrlable] WARN: $1"; }
die()   {
    echo "[ctrlable] ERROR: $1" >&2
    echo "[ctrlable] Add-on stopped. Fix the issue and restart."
    sleep infinity
}

# ── JSON helper ───────────────────────────────────────────────────────────────
json_get() {
    field="$1"; json="$2"
    python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('$field',''))" <<< "$json"
}

b64decode() { base64 -d 2>/dev/null; }

# ── LAN detection ─────────────────────────────────────────────────────────────
detect_lan_iface() {
    # Default route interface, excluding WireGuard interfaces
    ip route show | awk '/^default/ && !/wg[0-9]/{print $5; exit}'
}

detect_lan_subnet() {
    local iface="$1"
    # The directly-connected subnet on this interface
    ip route show dev "$iface" 2>/dev/null \
        | awk '/proto kernel/ && /scope link/{print $1; exit}'
}

# ── NAT masquerade ────────────────────────────────────────────────────────────
setup_nat() {
    local lan_iface="$1"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    # Remove stale rule if it exists, then add fresh
    iptables -t nat -D POSTROUTING -s 10.10.0.0/16 -o "$lan_iface" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o "$lan_iface" -j MASQUERADE
    info "NAT masquerade enabled: VPN → $lan_iface"
}

teardown_nat() {
    local lan_iface="$1"
    iptables -t nat -D POSTROUTING -s 10.10.0.0/16 -o "$lan_iface" -j MASQUERADE 2>/dev/null || true
}

# ── Heartbeat loop ────────────────────────────────────────────────────────────
run_heartbeat() {
    info "Starting heartbeat loop (every 60s)"
    local lan_registered=0
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

        # Register LAN on first successful heartbeat iteration (connectivity confirmed)
        if [ "$lan_registered" = "0" ] && [ -n "${LAN_SUBNET:-}" ]; then
            REG=$(curl -s --max-time 10 \
                -X POST "$API_BASE/devices/$DEVICE_ID/lan" \
                -H "Content-Type: application/json" \
                -H "X-Device-Token: $DEVICE_TOKEN" \
                -d "{\"lan_subnet\":\"$LAN_SUBNET\",\"lan_access_enabled\":true}" \
                2>&1) || true
            if [ -n "$REG" ] && ! echo "$REG" | grep -q '"detail"'; then
                info "LAN access registered: $LAN_SUBNET"
                lan_registered=1
            else
                warn "LAN registration failed: ${REG:-no response} — retrying next cycle"
            fi
        fi

        sleep 60
    done
}

# ── Bring up tunnel ───────────────────────────────────────────────────────────
bring_up_tunnel() {
    local conf_src="$DATA_DIR/$WG_IFACE.conf"
    mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"
    cp "$conf_src" "$WG_DIR/$WG_IFACE.conf"
    chmod 600 "$WG_DIR/$WG_IFACE.conf"
    wg-quick down "$WG_IFACE" 2>/dev/null || true
    wg-quick up "$WG_DIR/$WG_IFACE.conf"
    info "Tunnel up on $WG_IFACE ($TUNNEL_IP)"

    # Set up LAN NAT if we have a LAN interface
    if [ -n "${LAN_IFACE:-}" ]; then
        setup_nat "$LAN_IFACE"
    fi
}

# ── Read token from options ───────────────────────────────────────────────────
ENROLLMENT_TOKEN=$(python3 -c "import json; print(json.load(open('/data/options.json')).get('enrollment_token',''))" 2>/dev/null) || ENROLLMENT_TOKEN=""

# ── Check if already enrolled ────────────────────────────────────────────────
if [ -f "$CREDS_FILE" ]; then
    source "$CREDS_FILE"

    if [ -n "$ENROLLMENT_TOKEN" ] && [ "$ENROLLMENT_TOKEN" != "${USED_TOKEN:-}" ]; then
        info "New enrollment token detected — clearing previous enrollment"
        [ -n "${LAN_IFACE:-}" ] && teardown_nat "$LAN_IFACE" || true
        wg-quick down "$WG_IFACE" 2>/dev/null || true
        rm -f "$CREDS_FILE" "$DATA_DIR/$WG_IFACE.conf" "$WG_DIR/$WG_IFACE.conf"
        unset DEVICE_ID DEVICE_TOKEN TUNNEL_IP WG_IFACE LAN_IFACE LAN_SUBNET
    else
        info "Reconnecting existing enrollment (Device: $DEVICE_ID)"
        if [ -f "$DATA_DIR/$WG_IFACE.conf" ]; then
            # Re-detect LAN on every startup (may have changed)
            CURRENT_LAN_IFACE=$(detect_lan_iface)
            CURRENT_LAN_SUBNET=""
            if [ -n "$CURRENT_LAN_IFACE" ]; then
                CURRENT_LAN_SUBNET=$(detect_lan_subnet "$CURRENT_LAN_IFACE")
            fi
            LAN_IFACE="$CURRENT_LAN_IFACE"
            LAN_SUBNET="$CURRENT_LAN_SUBNET"

            bring_up_tunnel
            run_heartbeat  # LAN registration happens inside first heartbeat iteration
            exit 0
        else
            die "WireGuard config missing. Paste a new enrollment token in the Configuration tab and restart."
        fi
    fi
fi

# ── Detect LAN (first enrollment) ────────────────────────────────────────────
LAN_IFACE=$(detect_lan_iface)
LAN_SUBNET=""
if [ -n "$LAN_IFACE" ]; then
    LAN_SUBNET=$(detect_lan_subnet "$LAN_IFACE")
    if [ -n "$LAN_SUBNET" ]; then
        info "LAN detected: $LAN_SUBNET on $LAN_IFACE"
    fi
fi

# ── Enroll ────────────────────────────────────────────────────────────────────
[ -z "$ENROLLMENT_TOKEN" ] && die "enrollment_token is not set. Open the add-on Configuration tab and paste your token."

info "Enrolling with Ctrlable..."

IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
[ -z "$IFACE" ] && IFACE="eth0"
MAC=$(cat /sys/class/net/"$IFACE"/address 2>/dev/null || echo "00:00:00:00:00:00")
MAC=$(echo "$MAC" | tr '[:lower:]' '[:upper:]')
HN=$(hostname 2>/dev/null || echo "homeassistant")

# Build JSON payload — include lan_subnet if detected
if [ -n "$LAN_SUBNET" ]; then
    PAYLOAD="{\"token\":\"$ENROLLMENT_TOKEN\",\"mac_address\":\"$MAC\",\"platform\":\"haos_addon\",\"hostname\":\"$HN\",\"lan_subnet\":\"$LAN_SUBNET\"}"
else
    PAYLOAD="{\"token\":\"$ENROLLMENT_TOKEN\",\"mac_address\":\"$MAC\",\"platform\":\"haos_addon\",\"hostname\":\"$HN\"}"
fi

RESPONSE=$(curl -sk --max-time 30 -X POST "$ENROLL_URL" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD") \
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
[ -n "$LAN_SUBNET" ] && info "LAN access enabled for $LAN_SUBNET"

WG_CONF=$(b64decode <<< "$WG_B64")
[ -z "$WG_CONF" ] && die "Failed to decode WireGuard config"

# Save WireGuard config to /data/
echo "$WG_CONF" > "$DATA_DIR/$WG_IFACE.conf"
chmod 600 "$DATA_DIR/$WG_IFACE.conf"

# Save credentials
mkdir -p "$DATA_DIR" && chmod 700 "$DATA_DIR"
cat > "$CREDS_FILE" << EOF
DEVICE_ID=$DEVICE_ID
DEVICE_TOKEN=$DEVICE_TOKEN
TUNNEL_IP=$TUNNEL_IP
WG_IFACE=$WG_IFACE
LAN_IFACE=$LAN_IFACE
LAN_SUBNET=$LAN_SUBNET
API_BASE=$API_BASE
USED_TOKEN=$ENROLLMENT_TOKEN
EOF
chmod 600 "$CREDS_FILE"

mkdir -p /ssl/ctrlable && chmod 700 /ssl/ctrlable
cp "$CREDS_FILE" /ssl/ctrlable/ctrlable.conf

info "Credentials saved"

bring_up_tunnel
run_heartbeat
