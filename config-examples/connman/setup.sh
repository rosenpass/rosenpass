#!/bin/bash
# Setup script for Rosenpass + WireGuard + ConnMan integration
#
# Generates WireGuard and Rosenpass keys, creates a ConnMan VPN
# provisioning file, and produces a ready-to-use Rosenpass config.
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
CONNMAN_VPN_DIR="/var/lib/connman-vpn"

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

if ! command -v connmanctl >/dev/null 2>&1; then
    echo "Warning: connmanctl not found. Install ConnMan first." >&2
fi

if ! systemctl is-active --quiet connman 2>/dev/null; then
    echo "Warning: connman is not running. Start it before using this config." >&2
fi

echo "==> Setting up Rosenpass + WireGuard + ConnMan (interface=${INTERFACE}, role=${ROLE})"

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
# ConnMan's connman-vpnd creates the WireGuard interface from the
# provisioning file. We create it manually here so Rosenpass can
# attach immediately; ConnMan will adopt the existing interface.

echo "==> Creating WireGuard interface ${INTERFACE}..."
if ! ip link show "${INTERFACE}" >/dev/null 2>&1; then
    ip link add dev "${INTERFACE}" type wireguard
fi
wg set "${INTERFACE}" private-key "${CONFIG_DIR}/wg.key"
if [ "${ROLE}" = "server" ]; then
    wg set "${INTERFACE}" listen-port "${WG_PORT}"
fi
ip address add "${TUNNEL_IP}" dev "${INTERFACE}" 2>/dev/null || true
ip link set "${INTERFACE}" up

# --- ConnMan VPN provisioning file ---

echo "==> Writing ConnMan VPN provisioning file..."
mkdir -p "${CONNMAN_VPN_DIR}"

PROVISION_FILE="${CONNMAN_VPN_DIR}/${INTERFACE}.config"
WG_PRIVKEY=$(cat "${CONFIG_DIR}/wg.key")

if [ "${ROLE}" = "server" ]; then
    cat > "${PROVISION_FILE}" << EOF
[provider_${INTERFACE}]
Type = WireGuard
Name = Rosenpass WireGuard (${ROLE})
Host = 0.0.0.0
Domain = vpn.rosenpass.local
WireGuard.Address = ${TUNNEL_IP}
WireGuard.ListenPort = ${WG_PORT}
WireGuard.PrivateKey = ${WG_PRIVKEY}
WireGuard.DNS =
# Do NOT set WireGuard.PresharedKey here.
# Rosenpass manages PSK rotation via wg set at runtime.
# A static PresharedKey would be immediately overwritten.
#
# Add peers below:
# WireGuard.AllowedIPs = PEER_TUNNEL_CIDR
# WireGuard.EndpointPort = PEER_WG_PORT
# WireGuard.PublicKey = PEER_WG_PUBLIC_KEY
EOF
else
    cat > "${PROVISION_FILE}" << EOF
[provider_${INTERFACE}]
Type = WireGuard
Name = Rosenpass WireGuard (${ROLE})
Host = SERVER_IP
Domain = vpn.rosenpass.local
WireGuard.Address = ${TUNNEL_IP}
WireGuard.PrivateKey = ${WG_PRIVKEY}
WireGuard.DNS =
# Do NOT set WireGuard.PresharedKey here.
# Rosenpass manages PSK rotation via wg set at runtime.
# A static PresharedKey would be immediately overwritten.
#
# Add peers below:
# WireGuard.AllowedIPs = PEER_TUNNEL_CIDR
# WireGuard.EndpointPort = PEER_WG_PORT
# WireGuard.PublicKey = PEER_WG_PUBLIC_KEY
EOF
fi
chmod 600 "${PROVISION_FILE}"

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
echo "    ConnMan provisioning : ${PROVISION_FILE}"
echo ""
echo "==> Next steps:"
echo "    1. Exchange public keys with peer"
echo "    2. Copy peer's Rosenpass public key to ${CONFIG_DIR}/peers/<name>/pqpk"
echo "    3. Update ConnMan provisioning file with peer's WireGuard public key"
echo "    4. Add [[peers]] section to ${CONFIG_DIR}/config.toml"
echo "    5. Restart ConnMan VPN daemon:"
echo "       systemctl restart connman-vpn"
echo "    6. Start Rosenpass:"
echo "       rosenpass exchange-config ${CONFIG_DIR}/config.toml"
echo "       # or: systemctl start rosenpass@${INTERFACE}"
