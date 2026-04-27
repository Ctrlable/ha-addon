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
    local subnet

    # First try: directly-connected kernel route
    subnet=$(ip route show dev "$iface" 2>/dev/null \
        | awk '/proto kernel/ && /scope link/{print $1; exit}')

    # Fallback: derive network from interface IP + prefix length
    if [ -z "$subnet" ]; then
        local addr
        addr=$(ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet /{print $2; exit}')
        if [ -n "$addr" ]; then
            subnet=$(python3 -c \
                "import ipaddress; print(ipaddress.IPv4Interface('$addr').network)" \
                2>/dev/null) || subnet=""
        fi
    fi

    echo "$subnet"
}

# ── NAT masquerade ────────────────────────────────────────────────────────────
setup_nat() {
    local lan_iface="$1"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    if command -v nft >/dev/null 2>&1; then
        # FORWARD: insert into DOCKER-USER so rules run before HAOS policy drop
        # Remove any stale ctrlable rules first
        nft -a list chain ip filter DOCKER-USER 2>/dev/null \
            | awk '/ctrlable/{print $NF}' \
            | while read -r h; do
                nft delete rule ip filter DOCKER-USER handle "$h" 2>/dev/null || true
              done
        nft insert rule ip filter DOCKER-USER \
            comment \"ctrlable\" \
            ip daddr 10.10.0.0/16 iif "$lan_iface" ct state related,established accept \
            2>/dev/null || true
        nft insert rule ip filter DOCKER-USER \
            comment \"ctrlable\" \
            ip saddr 10.10.0.0/16 oif "$lan_iface" accept \
            2>/dev/null || true
        # POSTROUTING: masquerade VPN source IPs going to LAN
        nft add table ip ctrlnat 2>/dev/null || true
        nft add chain ip ctrlnat postrouting \
            '{ type nat hook postrouting priority srcnat; }' 2>/dev/null || true
        nft flush chain ip ctrlnat postrouting 2>/dev/null || true
        nft add rule ip ctrlnat postrouting \
            ip saddr 10.10.0.0/16 oif "$lan_iface" masquerade
        info "NAT masquerade enabled (nft): VPN → $lan_iface"
    else
        iptables -t nat -D POSTROUTING -s 10.10.0.0/16 -o "$lan_iface" -j MASQUERADE 2>/dev/null || true
        iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o "$lan_iface" -j MASQUERADE \
            || warn "iptables NAT setup failed — LAN forwarding may not work"
        info "NAT masquerade enabled (iptables): VPN → $lan_iface"
    fi
}

teardown_nat() {
    local lan_iface="$1"
    nft delete table ip ctrlnat 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 10.10.0.0/16 -o "$lan_iface" -j MASQUERADE 2>/dev/null || true
}

# ── LAN registration ──────────────────────────────────────────────────────────
# Returns 0 on success, 1 on failure. Prints result via info/warn.
do_lan_register() {
    [ -z "${LAN_SUBNET:-}" ] && return 1
    local TMPF="/tmp/ctrlable_lan_reg"
    local HTTP_CODE BODY CURL_ERR
    HTTP_CODE=$(curl -skS --max-time 15 \
        -w "%{http_code}" -o "$TMPF" \
        -X POST "$API_BASE/devices/$DEVICE_ID/lan" \
        -H "Content-Type: application/json" \
        -H "X-Device-Token: $DEVICE_TOKEN" \
        -d "{\"lan_subnet\":\"$LAN_SUBNET\",\"lan_access_enabled\":true}" \
        2>"$TMPF.err") || HTTP_CODE="ERR"
    BODY=$(cat "$TMPF" 2>/dev/null) || BODY=""
    CURL_ERR=$(cat "$TMPF.err" 2>/dev/null) || CURL_ERR=""
    rm -f "$TMPF" "$TMPF.err" 2>/dev/null || true
    if [ "$HTTP_CODE" = "200" ]; then
        info "LAN access registered: $LAN_SUBNET"
        return 0
    else
        warn "LAN registration: HTTP $HTTP_CODE curl_err=${CURL_ERR:0:120} body=${BODY:0:120} — retrying"
        return 1
    fi
}

# ── Heartbeat loop ────────────────────────────────────────────────────────────
run_heartbeat() {
    info "Starting heartbeat loop (every 60s)"
    local lan_registered="${1:-0}"
    while true; do
        RX=0; TX=0
        DUMP=$(wg show "$WG_IFACE" dump 2>/dev/null | tail -1) || true
        if [ -n "$DUMP" ]; then
            RX=$(awk '{print $6}' <<< "$DUMP") || RX=0
            TX=$(awk '{print $7}' <<< "$DUMP") || TX=0
        fi
        HB_ERRF="/tmp/ctrlable_hb_err"
        HB_CODE=$(curl -skS --max-time 10 \
            -w "%{http_code}" -o /dev/null \
            -X POST "$API_BASE/devices/$DEVICE_ID/heartbeat" \
            -H "Content-Type: application/json" \
            -H "X-Device-Token: $DEVICE_TOKEN" \
            -d "{\"rx_bytes\":${RX:-0},\"tx_bytes\":${TX:-0}}" \
            2>"$HB_ERRF") || HB_CODE="ERR"
        if [ "$HB_CODE" != "200" ]; then
            HB_ERR=$(cat "$HB_ERRF" 2>/dev/null) || HB_ERR=""
            warn "Heartbeat: HTTP $HB_CODE err=${HB_ERR:0:120}"
        fi
        rm -f "$HB_ERRF" 2>/dev/null || true

        # Retry LAN registration if the initial attempt failed
        if [ "$lan_registered" = "0" ] && [ -n "${LAN_SUBNET:-}" ]; then
            do_lan_register && lan_registered=1
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

    if [ -n "${LAN_IFACE:-}" ]; then
        setup_nat "$LAN_IFACE"
    fi

    # Connectivity probe — diagnose routing issues before first API call
    PROBE_ERR=$(curl -skS --max-time 5 -o /dev/null \
        -w "HTTP %{http_code}" \
        "https://portal.ctrlable.com/" \
        2>&1) || true
    info "Portal probe: $PROBE_ERR"
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
            # Re-detect LAN on every startup (interface/subnet may have changed)
            LAN_IFACE=$(detect_lan_iface)
            LAN_SUBNET=""
            if [ -n "$LAN_IFACE" ]; then
                LAN_SUBNET=$(detect_lan_subnet "$LAN_IFACE")
                [ -n "$LAN_SUBNET" ] && info "LAN detected: $LAN_SUBNET on $LAN_IFACE"
            fi

            bring_up_tunnel

            # Register LAN immediately; heartbeat loop will retry if this fails
            LAN_OK=0
            [ -n "$LAN_SUBNET" ] && do_lan_register && LAN_OK=1

            run_heartbeat "$LAN_OK"
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

# Register LAN immediately; heartbeat loop will retry if this fails
LAN_OK=0
[ -n "$LAN_SUBNET" ] && do_lan_register && LAN_OK=1

run_heartbeat "$LAN_OK"
