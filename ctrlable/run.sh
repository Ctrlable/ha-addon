#!/usr/bin/env bash
set -e

ADDON_VERSION="8"
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
        nft add table ip ctrlnat 2>/dev/null || true

        # FORWARD: own chain in ctrlnat — does not depend on DOCKER-USER
        nft add chain ip ctrlnat forward \
            '{ type filter hook forward priority filter; }' 2>/dev/null || true
        nft flush chain ip ctrlnat forward 2>/dev/null || true
        nft add rule ip ctrlnat forward \
            iifname "$WG_IFACE" oifname "$lan_iface" accept 2>/dev/null || true
        nft add rule ip ctrlnat forward \
            iifname "$lan_iface" oifname "$WG_IFACE" ct state related,established accept \
            2>/dev/null || true

        # POSTROUTING: masquerade VPN source IPs going to LAN
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
    nft flush chain ip filter DOCKER-USER 2>/dev/null || true
    nft delete table ip ctrlnat 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 10.10.0.0/16 -o "$lan_iface" -j MASQUERADE 2>/dev/null || true
}

# ── Proxy NETMAP (prerouting: proxy_subnet → real LAN subnet) ─────────────────
setup_netmap() {
    local proxy="$1" lan="$2" iface="$3"
    if command -v nft >/dev/null 2>&1; then
        local a b c lan_hex
        a=$(printf '%s' "$lan" | cut -d. -f1)
        b=$(printf '%s' "$lan" | cut -d. -f2)
        c=$(printf '%s' "$lan" | cut -d. -f3)
        lan_hex=$(printf "0x%02x%02x%02x00" "$a" "$b" "$c")
        nft add table ip ctrlnat 2>/dev/null || true
        nft add chain ip ctrlnat prerouting \
            '{ type nat hook prerouting priority dstnat; }' 2>/dev/null || true
        nft flush chain ip ctrlnat prerouting 2>/dev/null || true
        if nft add rule ip ctrlnat prerouting \
            iifname "\"$iface\"" ip daddr "$proxy" \
            dnat ip to ip daddr and 0x000000ff or "$lan_hex" 2>/dev/null; then
            info "Proxy NETMAP: $proxy → $lan (nft)"
            return 0
        fi
    fi
    if iptables -t nat -L PREROUTING -n >/dev/null 2>&1; then
        iptables -t nat -D PREROUTING -i "$iface" -d "$proxy" -j NETMAP --to "$lan" 2>/dev/null || true
        if iptables -t nat -A PREROUTING -i "$iface" -d "$proxy" -j NETMAP --to "$lan" 2>/dev/null; then
            info "Proxy NETMAP: $proxy → $lan (iptables)"
            return 0
        fi
    fi
    warn "Proxy NETMAP setup failed — overlapping subnets may not route correctly"
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
        # Apply proxy NETMAP rules if server assigned a proxy subnet
        local PROXY_SUBNET
        PROXY_SUBNET=$(printf '%s' "$BODY" | tr -d ' \t' | grep -o '"proxy_subnet":"[^"]*"' | cut -d'"' -f4) || PROXY_SUBNET=""
        if [ -n "$PROXY_SUBNET" ] && [ -n "${WG_IFACE:-}" ]; then
            setup_netmap "$PROXY_SUBNET" "$LAN_SUBNET" "$WG_IFACE"
        fi
        return 0
    else
        warn "LAN registration: HTTP $HTTP_CODE curl_err=${CURL_ERR:0:120} body=${BODY:0:120} — retrying"
        return 1
    fi
}

# ── LAN candidate discovery (all directly-connected subnets, excluding WG/lo) ──
detect_all_lan_subnets_json() {
    local routes candidates="" first=1 out='['
    routes=$(ip -4 route show scope link 2>/dev/null) || \
        routes=$(ip route show scope link 2>/dev/null) || routes=""
    while IFS= read -r line; do
        subnet=$(echo "$line" | awk '{print $1}')
        iface=$(echo "$line" | grep -o 'dev [^ ]*' | awk '{print $2}')
        { [ -z "$subnet" ] || [ -z "$iface" ]; } && continue
        echo "$iface" | grep -qE '^(lo|wg)' && continue
        echo "$subnet" | grep -q '/' || continue
        echo "$subnet" | grep -q '^127\.' && continue
        case ",$candidates," in *,"$subnet",*) continue ;; esac
        candidates="${candidates:+$candidates,}$subnet"
        [ "$first" = "1" ] && first=0 || out="${out},"
        out="${out}\"${subnet}\""
    done <<< "$routes"
    printf '%s]' "$out"
}

# ── Supervisor API self-update (HAOS only) ────────────────────────────────────
supervisor_self_update() {
    local token="${SUPERVISOR_TOKEN:-}"
    [ -z "$token" ] && return 1
    local code
    code=$(curl -sSL --max-time 30 \
        -w "%{http_code}" -o /dev/null \
        -X POST "http://supervisor/addons/self/update" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" 2>/dev/null) || code="ERR"
    if [ "$code" = "200" ]; then
        info "Self-update triggered via Supervisor API — addon will restart"
        return 0
    fi
    warn "Supervisor self-update failed: HTTP $code"
    return 1
}

# ── LAN scanner ───────────────────────────────────────────────────────────────
# Reads ARP table, probes each live host for open ports, POSTs results to server.
SCAN_PORTS_CSV="22,23,80,443,554,1883,3000,4200,5000,7080,8080,8123,8443,8888,9090,9443"

scan_lan() {
    [ -z "${DEVICE_TOKEN:-}" ] || [ -z "${DEVICE_ID:-}" ] && return 0

    # Build JSON array of discovered devices from ARP table
    local devices_json=""
    while IFS= read -r line; do
        local ip mac
        ip=$(printf '%s' "$line" | awk '{print $1}')
        mac=$(printf '%s' "$line" | awk '{print $4}')
        # Skip header, incomplete entries, and the loopback/WG tunnel range
        [ "$ip" = "IP" ] && continue
        [ "$mac" = "00:00:00:00:00:00" ] && continue
        [ -z "$ip" ] || [ -z "$mac" ] && continue
        printf '%s' "$ip" | grep -qE '^10\.10\.' && continue

        # Probe ports in parallel (background nc jobs)
        local open_ports=""
        local pids=""
        local tmpdir
        tmpdir=$(mktemp -d /tmp/ctrlscan_XXXXXX)
        for port in $(printf '%s' "$SCAN_PORTS_CSV" | tr ',' ' '); do
            (
                nc -z -w1 "$ip" "$port" 2>/dev/null && printf '%s' "$port" > "$tmpdir/$port"
            ) &
            pids="$pids $!"
        done
        # Wait for all probes (max 3s guard)
        for pid in $pids; do wait "$pid" 2>/dev/null || true; done

        local ports_arr="["
        local pfirst=1
        for f in "$tmpdir"/*; do
            [ -f "$f" ] || continue
            local p; p=$(cat "$f")
            [ "$pfirst" = "1" ] && pfirst=0 || ports_arr="${ports_arr},"
            ports_arr="${ports_arr}${p}"
        done
        ports_arr="${ports_arr}]"
        rm -rf "$tmpdir"

        # Sanitize hostname (avoid breaking JSON)
        local hn
        hn=$(getent hosts "$ip" 2>/dev/null | awk '{print $2}' | head -1 | tr -d '"\\') || hn=""
        mac_clean=$(printf '%s' "$mac" | tr -d '"\\')

        [ -n "$devices_json" ] && devices_json="${devices_json},"
        devices_json="${devices_json}{\"ip_address\":\"${ip}\",\"mac_address\":\"${mac_clean}\",\"hostname\":\"${hn}\",\"open_ports\":${ports_arr}}"
    done < /proc/net/arp

    [ -z "$devices_json" ] && return 0

    curl -sk --max-time 30 \
        -X POST "$API_BASE/discovery/report" \
        -H "Content-Type: application/json" \
        -H "X-Device-Token: $DEVICE_TOKEN" \
        -d "{\"scan_type\":\"arp_nc\",\"devices\":[${devices_json}]}" \
        > /dev/null 2>&1 || true
}

# ── Heartbeat loop ────────────────────────────────────────────────────────────
run_heartbeat() {
    info "Starting heartbeat loop (every 60s, LAN scan every 5 min)"
    local lan_registered="${1:-0}"
    local hb_count=0
    while true; do
        RX=0; TX=0
        DUMP=$(wg show "$WG_IFACE" dump 2>/dev/null | tail -1) || true
        if [ -n "$DUMP" ]; then
            RX=$(awk '{print $6}' <<< "$DUMP") || RX=0
            TX=$(awk '{print $7}' <<< "$DUMP") || TX=0
        fi

        LAN_JSON=$(detect_all_lan_subnets_json)

        HB_TMPF="/tmp/ctrlable_hb"
        HB_CODE=$(curl -skS --max-time 10 \
            -w "%{http_code}" -o "$HB_TMPF" \
            -X POST "$API_BASE/devices/$DEVICE_ID/heartbeat" \
            -H "Content-Type: application/json" \
            -H "X-Device-Token: $DEVICE_TOKEN" \
            -d "{\"rx_bytes\":${RX:-0},\"tx_bytes\":${TX:-0},\"agent_version\":\"${ADDON_VERSION}\",\"lan_candidates\":${LAN_JSON}}" \
            2>"$HB_TMPF.err") || HB_CODE="ERR"
        if [ "$HB_CODE" = "200" ]; then
            HB_BODY=$(cat "$HB_TMPF" 2>/dev/null | tr -d ' \t') || HB_BODY=""

            # Handle server-side commands
            HB_CMD=$(printf '%s' "$HB_BODY" | grep -o '"command":"[^"]*"' | cut -d'"' -f4) || HB_CMD=""
            if [ "$HB_CMD" = "self_update" ]; then
                info "Server requested self-update"
                supervisor_self_update || true
            fi

            # Update scan ports if server sent a new list
            HB_PORTS=$(printf '%s' "$HB_BODY" | grep -o '"scan_ports":\[[^]]*\]' | sed 's/"scan_ports"://' | tr -d '[]" ') || HB_PORTS=""
            [ -n "$HB_PORTS" ] && SCAN_PORTS_CSV="$HB_PORTS"

            # Apply NETMAP if server returned a proxy_subnet we haven't set up yet
            HB_PROXY=$(printf '%s' "$HB_BODY" | grep -o '"proxy_subnet":"[^"]*"' | cut -d'"' -f4) || HB_PROXY=""
            HB_LAN=$(printf '%s' "$HB_BODY" | grep -o '"lan_subnet":"[^"]*"' | cut -d'"' -f4) || HB_LAN=""
            if [ -n "$HB_PROXY" ] && [ -n "$HB_LAN" ] && [ -n "${WG_IFACE:-}" ]; then
                # Recreate if missing or if old non-conntrack form (ip daddr set) is in place
                _PROXY_BASE="${HB_PROXY%/*}"
                if ! nft list chain ip ctrlnat prerouting 2>/dev/null | grep -q "dnat.*$_PROXY_BASE" && \
                   ! iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "$HB_PROXY"; then
                    setup_netmap "$HB_PROXY" "$HB_LAN" "$WG_IFACE"
                fi
            fi
        else
            HB_ERR=$(cat "$HB_TMPF.err" 2>/dev/null) || HB_ERR=""
            warn "Heartbeat: HTTP $HB_CODE err=${HB_ERR:0:120}"
        fi
        rm -f "$HB_TMPF" "$HB_TMPF.err" 2>/dev/null || true

        # Retry LAN registration if the initial attempt failed
        if [ "$lan_registered" = "0" ] && [ -n "${LAN_SUBNET:-}" ]; then
            do_lan_register && lan_registered=1
        fi

        # LAN scan every 5th heartbeat (~5 min); first scan on iteration 1 (after 60s)
        hb_count=$(( hb_count + 1 ))
        if [ $(( hb_count % 5 )) -eq 1 ]; then
            scan_lan || true
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
    # HAOS manages its own DNS resolver; strip the DNS line so wg-quick never
    # calls resolvconf (which conflicts with HAOS and breaks DNS resolution).
    sed -i '/^[[:space:]]*DNS[[:space:]]*=/d' "$WG_DIR/$WG_IFACE.conf"
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
