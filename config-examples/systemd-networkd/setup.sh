#!/bin/bash
# Setup script for Rosenpass + WireGuard + systemd-networkd integration
#
# Generates WireGuard and Rosenpass keys, writes systemd-networkd .netdev
# and .network unit files, and produces a ready-to-use Rosenpass config.
#
# Usage: sudo ./setup.sh [INTERFACE] [ROLE]
#   INTERFACE  WireGuard interface name (default: wg0)
#   ROLE       "server" or "client" (default: server)
#
# Environment variables:
#   RP_PORT    Rosenpass listen port, server only (default: 9999)
#   WG_PORT    WireGuard listen port, server only (default: 51820)
#   TUNNEL_IP  IP address for the WireGuard tunnel (required)

set -euo pipefail

INTERFACE="${1:-wg0}"
ROLE="${2:-server}"
RP_PORT="${RP_PORT:-9999}"
WG_PORT="${WG_PORT:-51820}"
TUNNEL_IP="${TUNNEL_IP:-}"
CONFIG_DIR="/etc/rosenpass/${INTERFACE}"
NETWORKD_DIR="/etc/systemd/network"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root" >&2
    exit 1
fi

if [ -z "${TUNNEL_IP}" ]; then
    echo "Error: TUNNEL_IP must be set (e.g. TUNNEL_IP=10.0.0.1/24)" >&2
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

if ! systemctl is-active --quiet systemd-networkd 2>/dev/null; then
    echo "Warning: systemd-networkd is not running. Start it before using this config." >&2
fi

echo "==> Setting up Rosenpass + WireGuard + systemd-networkd (interface=${INTERFACE}, role=${ROLE})"

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

# --- systemd-networkd .netdev file ---

echo "==> Writing systemd-networkd .netdev file..."
mkdir -p "${NETWORKD_DIR}"

if [ "${ROLE}" = "server" ]; then
    cat > "${NETWORKD_DIR}/50-${INTERFACE}.netdev" << EOF
[NetDev]
Name=${INTERFACE}
Kind=wireguard
Description=WireGuard tunnel (Rosenpass post-quantum PSK)

[WireGuard]
ListenPort=${WG_PORT}
PrivateKeyFile=${CONFIG_DIR}/wg.key

# Peers are added below. Do NOT set PresharedKey here --
# Rosenpass manages PSK rotation via wg set.
# [WireGuardPeer]
# PublicKey=PEER_WG_PUBLIC_KEY_HERE
# AllowedIPs=PEER_TUNNEL_CIDR
EOF
else
    cat > "${NETWORKD_DIR}/50-${INTERFACE}.netdev" << EOF
[NetDev]
Name=${INTERFACE}
Kind=wireguard
Description=WireGuard tunnel (Rosenpass post-quantum PSK)

[WireGuard]
PrivateKeyFile=${CONFIG_DIR}/wg.key

# Peers are added below. Do NOT set PresharedKey here --
# Rosenpass manages PSK rotation via wg set.
# [WireGuardPeer]
# PublicKey=PEER_WG_PUBLIC_KEY_HERE
# Endpoint=SERVER_IP:${WG_PORT}
# AllowedIPs=PEER_TUNNEL_CIDR
EOF
fi
chmod 640 "${NETWORKD_DIR}/50-${INTERFACE}.netdev"

# --- systemd-networkd .network file ---

echo "==> Writing systemd-networkd .network file..."
cat > "${NETWORKD_DIR}/50-${INTERFACE}.network" << EOF
[Match]
Name=${INTERFACE}

[Network]
Address=${TUNNEL_IP}
EOF

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
echo "    systemd-networkd     : ${NETWORKD_DIR}/50-${INTERFACE}.netdev"
echo "                           ${NETWORKD_DIR}/50-${INTERFACE}.network"
echo ""
echo "==> Next steps:"
echo "    1. Exchange public keys with peer"
echo "    2. Copy peer's Rosenpass public key to ${CONFIG_DIR}/peers/<name>/pqpk"
echo "    3. Add [WireGuardPeer] section to ${NETWORKD_DIR}/50-${INTERFACE}.netdev"
echo "    4. Add [[peers]] section to ${CONFIG_DIR}/config.toml"
echo "    5. Reload systemd-networkd:"
echo "       networkctl reload"
echo "    6. Start Rosenpass:"
echo "       rosenpass exchange-config ${CONFIG_DIR}/config.toml"
echo "       # or: systemctl start rosenpass@${INTERFACE}"
