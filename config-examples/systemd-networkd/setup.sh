#!/bin/bash
# Setup script for Rosenpass + WireGuard + systemd-networkd integration
set -e

INTERFACE="${1:-wg0}"
ROLE="${2:-server}"  # "server" or "client"
CONFIG_DIR="/etc/rosenpass/${INTERFACE}"

echo "==> Setting up Rosenpass + WireGuard for interface ${INTERFACE} (${ROLE})"

# Create directories
mkdir -p "${CONFIG_DIR}/peers"
chmod 700 "${CONFIG_DIR}"

# Generate WireGuard keys
echo "==> Generating WireGuard keys..."
wg genkey | tee "${CONFIG_DIR}/wg-${ROLE}.key" | wg pubkey > "${CONFIG_DIR}/wg-${ROLE}.pub"
chmod 600 "${CONFIG_DIR}/wg-${ROLE}.key"
echo "    WireGuard public key: $(cat ${CONFIG_DIR}/wg-${ROLE}.pub)"

# Generate Rosenpass keys
echo "==> Generating Rosenpass keys..."
rosenpass gen-keys "${CONFIG_DIR}"
echo "    Rosenpass public key stored in: ${CONFIG_DIR}/pqpk"

echo ""
echo "==> Done! Share your public keys with your peer:"
echo "    WireGuard pubkey : $(cat ${CONFIG_DIR}/wg-${ROLE}.pub)"
echo "    Rosenpass pubkey : ${CONFIG_DIR}/pqpk"
echo ""
echo "==> Next steps:"
echo "    1. Copy peer's Rosenpass public key to ${CONFIG_DIR}/peers/<peer>/pqpk"
echo "    2. Update config.toml with peer's WireGuard public key"
echo "    3. Copy .netdev and .network files to /etc/systemd/network/"
echo "    4. Run: systemctl enable --now rosenpass-networkd@${INTERFACE}"