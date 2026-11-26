#!/bin/bash
# Set up WiFi AP for MITM probing
# Run this first, then run mitm_probe.py separately

IFACE="${1:-wlp5s0}"
AP_IP="192.168.44.1"
SSID="NintendoWiFi"
CHANNEL=6

set -e

echo "[*] Setting up AP on $IFACE..."

# Stop NM from managing the interface
nmcli device disconnect "$IFACE" 2>/dev/null || true
sleep 1
nmcli device set "$IFACE" managed no 2>/dev/null || true
sleep 1

# Configure IP
ip addr flush dev "$IFACE"
ip addr add "$AP_IP/24" dev "$IFACE"
ip link set "$IFACE" up
sleep 1

# Create hostapd config
HOSTAPD_CONF=$(mktemp /tmp/hostapd_mitm_XXXX.conf)
cat > "$HOSTAPD_CONF" <<EOF
interface=$IFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
EOF

# Create dnsmasq config
DNSMASQ_CONF=$(mktemp /tmp/dnsmasq_mitm_XXXX.conf)
cat > "$DNSMASQ_CONF" <<EOF
interface=$IFACE
bind-interfaces
dhcp-range=192.168.44.10,192.168.44.50,255.255.255.0,12h
dhcp-option=6,$AP_IP
dhcp-option=3,$AP_IP
address=/#/$AP_IP
log-dhcp
log-queries
EOF

# Start hostapd in background
echo "[*] Starting hostapd (SSID: $SSID)..."
hostapd "$HOSTAPD_CONF" &
HOSTAPD_PID=$!
sleep 2

if ! kill -0 $HOSTAPD_PID 2>/dev/null; then
    echo "[!] hostapd failed to start"
    exit 1
fi

# Start dnsmasq
echo "[*] Starting dnsmasq..."
dnsmasq -C "$DNSMASQ_CONF" --no-daemon --log-facility=- &
DNSMASQ_PID=$!
sleep 1

if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
    echo "[!] dnsmasq failed to start"
    kill $HOSTAPD_PID 2>/dev/null
    exit 1
fi

echo "[+] AP '$SSID' running on $IFACE ($AP_IP)"
echo "[+] hostapd PID: $HOSTAPD_PID"
echo "[+] dnsmasq PID: $DNSMASQ_PID"
echo ""
echo "[*] Now run: sudo python3 -I mitm_probe.py --iface $IFACE"
echo "[*] Press Ctrl+C to stop AP"

cleanup() {
    echo "[*] Stopping AP..."
    kill $HOSTAPD_PID $DNSMASQ_PID 2>/dev/null
    wait $HOSTAPD_PID $DNSMASQ_PID 2>/dev/null
    rm -f "$HOSTAPD_CONF" "$DNSMASQ_CONF"
    ip addr flush dev "$IFACE"
    nmcli device set "$IFACE" managed yes 2>/dev/null || true
    echo "[*] AP stopped"
}
trap cleanup EXIT INT TERM

wait
