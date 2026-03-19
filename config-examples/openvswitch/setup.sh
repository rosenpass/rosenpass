#!/bin/bash
# Setup script for Rosenpass + WireGuard + Open vSwitch integration
#
# Creates a WireGuard interface, generates Rosenpass and WireGuard keys,
# creates an OVS bridge, and adds the WireGuard interface as a port.
#
# Usage: sudo ./setup.sh [INTERFACE] [ROLE]
#   INTERFACE  WireGuard interface name (default: wg0)
#   ROLE       "server" or "client" (default: server)
#
# Environment variables:
#   BRIDGE     OVS bridge name (default: br-rp)
#   RP_PORT    Rosenpass listen port, server only (default: 9999)
#   WG_PORT    WireGuard listen port, server only (default: 51820)

set -euo pipefail

INTERFACE="${1:-wg0}"
ROLE="${2:-server}"
BRIDGE="${BRIDGE:-br-rp}"
RP_PORT="${RP_PORT:-9999}"
WG_PORT="${WG_PORT:-51820}"
CONFIG_DIR="/etc/rosenpass/${INTERFACE}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root" >&2
    exit 1
fi

if ! command -v ovs-vsctl >/dev/null 2>&1; then
    echo "Error: ovs-vsctl not found. Install Open vSwitch first." >&2
    exit 1
fi

if ! command -v wg >/dev/null 2>&1; then
    echo "Error: wg not found. Install wireguard-tools first." >&2
    exit 1
fi

if ! command -v rosenpass >/dev/null 2>&1; then
    echo "Error: rosenpass not found. Install Rosenpass first." >&2
    exit 1
fi

echo "==> Setting up Rosenpass + WireGuard + OVS (interface=${INTERFACE}, role=${ROLE}, bridge=${BRIDGE})"

# --- Key generation ---

mkdir -p "${CONFIG_DIR}/peers"
chmod 700 "${CONFIG_DIR}"

echo "==> Generating WireGuard keys..."
wg genkey | tee "${CONFIG_DIR}/wg.key" | wg pubkey > "${CONFIG_DIR}/wg.pub"
chmod 600 "${CONFIG_DIR}/wg.key"
echo "    WireGuard public key: $(cat "${CONFIG_DIR}/wg.pub")"

echo "==> Generating Rosenpass keys..."
rosenpass gen-keys --secret-key "${CONFIG_DIR}/pqsk" --public-key "${CONFIG_DIR}/pqpk"
echo "    Rosenpass public key: ${CONFIG_DIR}/pqpk"

# --- WireGuard interface ---

echo "==> Creating WireGuard interface ${INTERFACE}..."
ip link add dev "${INTERFACE}" type wireguard 2>/dev/null || true

if [ "${ROLE}" = "server" ]; then
    wg set "${INTERFACE}" listen-port "${WG_PORT}" private-key "${CONFIG_DIR}/wg.key"
else
    wg set "${INTERFACE}" private-key "${CONFIG_DIR}/wg.key"
fi

# --- OVS bridge and port ---

echo "==> Configuring Open vSwitch bridge ${BRIDGE}..."
ovs-vsctl --may-exist add-br "${BRIDGE}"
ovs-vsctl --may-exist add-port "${BRIDGE}" "${INTERFACE}"
echo "    Added ${INTERFACE} to bridge ${BRIDGE}"

# --- Rosenpass config ---

echo "==> Writing Rosenpass config to ${CONFIG_DIR}/config.toml..."
if [ "${ROLE}" = "server" ]; then
    cat > "${CONFIG_DIR}/config.toml" << EOF
public_key = "${CONFIG_DIR}/pqpk"
secret_key = "${CONFIG_DIR}/pqsk"
listen = ["0.0.0.0:${RP_PORT}"]
verbosity = "Verbose"

# Add peers below. For each peer:
# [[peers]]
# public_key = "${CONFIG_DIR}/peers/<name>/pqpk"
# device = "${INTERFACE}"
# peer = "<PEER_WG_PUBLIC_KEY>"
EOF
else
    cat > "${CONFIG_DIR}/config.toml" << EOF
public_key = "${CONFIG_DIR}/pqpk"
secret_key = "${CONFIG_DIR}/pqsk"
listen = []
verbosity = "Verbose"

# Add peers below. For each peer:
# [[peers]]
# public_key = "${CONFIG_DIR}/peers/<name>/pqpk"
# endpoint = "<SERVER_IP>:${RP_PORT}"
# device = "${INTERFACE}"
# peer = "<PEER_WG_PUBLIC_KEY>"
EOF
fi
chmod 600 "${CONFIG_DIR}/config.toml"

echo ""
echo "==> Setup complete!"
echo ""
echo "    WireGuard public key : $(cat "${CONFIG_DIR}/wg.pub")"
echo "    Rosenpass public key : ${CONFIG_DIR}/pqpk"
echo "    Rosenpass config     : ${CONFIG_DIR}/config.toml"
echo "    OVS bridge           : ${BRIDGE}"
echo ""
echo "==> Next steps:"
echo "    1. Exchange public keys with peer"
echo "    2. Copy peer's Rosenpass public key to ${CONFIG_DIR}/peers/<name>/pqpk"
echo "    3. Add peer to ${CONFIG_DIR}/config.toml (see comments in file)"
echo "    4. Configure WireGuard peer:"
echo "       wg set ${INTERFACE} peer <PEER_WG_PUB> endpoint <IP>:<PORT> allowed-ips <CIDR>"
echo "    5. Assign IP and bring interface up:"
echo "       ip addr add <IP>/<CIDR> dev ${BRIDGE}"
echo "       ip link set ${INTERFACE} up"
echo "       ip link set ${BRIDGE} up"
echo "    6. Start Rosenpass:"
echo "       rosenpass exchange-config ${CONFIG_DIR}/config.toml"
echo "       # or: systemctl start rosenpass@${INTERFACE}"
