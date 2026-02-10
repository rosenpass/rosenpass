#!/usr/bin/env bash
# setup-rosenpass-networkd.sh
#
# Helper script to set up a Rosenpass + WireGuard tunnel using
# systemd-networkd.
#
# This script generates all necessary configuration files:
#   - /etc/systemd/network/<IFACE>.netdev   (WireGuard device)
#   - /etc/systemd/network/<IFACE>.network  (network addressing)
#   - /etc/rosenpass/<IFACE>.toml           (Rosenpass config)
#   - /etc/rosenpass/<IFACE>/pqsk           (Rosenpass secret key)
#   - /etc/rosenpass/<IFACE>/pqpk           (Rosenpass public key)
#   - /etc/wireguard/<IFACE>.key            (WireGuard private key)
#
# Usage:
#   sudo ./setup-rosenpass-networkd.sh <INTERFACE_NAME>
#
# After running this script you still need to:
#   1. Exchange Rosenpass public keys with the remote peer.
#   2. Fill in peer-specific values (public keys, endpoints).
#   3. Enable and start the services:
#        systemctl daemon-reload
#        systemctl restart systemd-networkd
#        systemctl enable --now rosenpass-networkd@<IFACE>.service
#
# See the accompanying README for detailed instructions.

set -euo pipefail

usage() {
    echo "Usage: $0 <INTERFACE_NAME>"
    echo ""
    echo "Creates Rosenpass + WireGuard configuration for systemd-networkd."
    echo ""
    echo "Example:"
    echo "  sudo $0 rosenpass0"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

IFACE="$1"

# Validate interface name (must be a valid Linux network interface name).
if [[ ! "$IFACE" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]] || [ "${#IFACE}" -gt 15 ]; then
    echo "Error: Invalid interface name '$IFACE'."
    echo "Must start with a letter, contain only alphanumerics/hyphens/underscores,"
    echo "and be at most 15 characters long."
    exit 1
fi

# Check for required tools.
for cmd in wg rosenpass; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' not found in PATH."
        exit 1
    fi
done

# Check for root.
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
fi

NETWORKD_DIR="/etc/systemd/network"
RP_DIR="/etc/rosenpass/${IFACE}"
WG_DIR="/etc/wireguard"

echo "Setting up Rosenpass + WireGuard for interface: $IFACE"
echo ""

# Create directories.
mkdir -p "$NETWORKD_DIR" "$RP_DIR/peers" "$WG_DIR"

# Generate WireGuard keypair if the private key does not exist.
WG_KEY_FILE="${WG_DIR}/${IFACE}.key"
WG_PUB_FILE="${WG_DIR}/${IFACE}.pub"
if [ ! -f "$WG_KEY_FILE" ]; then
    echo "Generating WireGuard keypair..."
    wg genkey | tee "$WG_KEY_FILE" | wg pubkey > "$WG_PUB_FILE"
    chmod 0600 "$WG_KEY_FILE"
    chmod 0644 "$WG_PUB_FILE"
else
    echo "WireGuard private key already exists at $WG_KEY_FILE, skipping."
    if [ ! -f "$WG_PUB_FILE" ]; then
        wg pubkey < "$WG_KEY_FILE" > "$WG_PUB_FILE"
        chmod 0644 "$WG_PUB_FILE"
    fi
fi

WG_PUBKEY=$(cat "$WG_PUB_FILE")

# Generate Rosenpass keypair if the secret key does not exist.
if [ ! -f "${RP_DIR}/pqsk" ]; then
    echo "Generating Rosenpass keypair..."
    rosenpass gen-keys --secret-key "${RP_DIR}/pqsk" --public-key "${RP_DIR}/pqpk"
    chmod 0600 "${RP_DIR}/pqsk"
    chmod 0644 "${RP_DIR}/pqpk"
else
    echo "Rosenpass secret key already exists at ${RP_DIR}/pqsk, skipping."
fi

# Create the .netdev file for systemd-networkd.
NETDEV_FILE="${NETWORKD_DIR}/${IFACE}.netdev"
if [ ! -f "$NETDEV_FILE" ]; then
    echo "Creating $NETDEV_FILE..."
    cat > "$NETDEV_FILE" <<EOF
[NetDev]
Name=${IFACE}
Kind=wireguard
Description=WireGuard tunnel with Rosenpass post-quantum key exchange

[WireGuard]
PrivateKeyFile=${WG_KEY_FILE}
ListenPort=51820

# Add one or more [WireGuardPeer] sections below.
# Do NOT set PresharedKey here; Rosenpass manages it automatically.
#
# [WireGuardPeer]
# PublicKey=<PEER_WG_PUBLIC_KEY>
# Endpoint=<PEER_IP>:51820
# AllowedIPs=10.0.0.2/32
# PersistentKeepalive=25
EOF
    chmod 0640 "$NETDEV_FILE"
else
    echo "$NETDEV_FILE already exists, skipping."
fi

# Create the .network file for systemd-networkd.
NETWORK_FILE="${NETWORKD_DIR}/${IFACE}.network"
if [ ! -f "$NETWORK_FILE" ]; then
    echo "Creating $NETWORK_FILE..."
    cat > "$NETWORK_FILE" <<EOF
[Match]
Name=${IFACE}

[Network]
# Assign an address to this end of the tunnel.
# Address=10.0.0.1/24
EOF
    chmod 0644 "$NETWORK_FILE"
else
    echo "$NETWORK_FILE already exists, skipping."
fi

# Create the Rosenpass configuration file.
RP_CONFIG="/etc/rosenpass/${IFACE}.toml"
if [ ! -f "$RP_CONFIG" ]; then
    echo "Creating $RP_CONFIG..."
    cat > "$RP_CONFIG" <<EOF
# Rosenpass configuration for systemd-networkd interface: ${IFACE}
#
# The WireGuard device is created and managed by systemd-networkd.
# Rosenpass only handles the post-quantum key exchange, supplying
# rotating pre-shared keys to WireGuard via \`wg set\`.

public_key = "${RP_DIR}/pqpk"
secret_key = "${RP_DIR}/pqsk"

# Rosenpass protocol listen address (separate from WireGuard port).
# listen = ["0.0.0.0:9999"]
verbosity = "Quiet"

# Add peers below. For each [WireGuardPeer] in your .netdev file,
# add a corresponding [[peers]] section here.
#
# [[peers]]
# public_key = "${RP_DIR}/peers/peer1-pqpk"
# endpoint = "<PEER_IP>:9999"
# device = "${IFACE}"
# peer = "<PEER_WG_PUBLIC_KEY>"
EOF
    chmod 0644 "$RP_CONFIG"
else
    echo "$RP_CONFIG already exists, skipping."
fi

echo ""
echo "============================================="
echo "Setup complete for interface: $IFACE"
echo "============================================="
echo ""
echo "Your WireGuard public key (share with peers):"
echo "  $WG_PUBKEY"
echo ""
echo "Your Rosenpass public key (share with peers):"
echo "  ${RP_DIR}/pqpk"
echo ""
echo "Next steps:"
echo "  1. Edit $NETDEV_FILE and add [WireGuardPeer] sections"
echo "  2. Edit $NETWORK_FILE and set the tunnel Address"
echo "  3. Edit $RP_CONFIG and add [[peers]] sections"
echo "  4. Copy peer Rosenpass public keys to ${RP_DIR}/peers/"
echo "  5. Reload and start:"
echo "       systemctl daemon-reload"
echo "       systemctl restart systemd-networkd"
echo "       systemctl enable --now rosenpass-networkd@${IFACE}.service"
echo ""
echo "To check status:"
echo "  systemctl status rosenpass-networkd@${IFACE}.service"
echo "  wg show ${IFACE}"
