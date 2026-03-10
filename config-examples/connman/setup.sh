#!/bin/bash
# Rosenpass + ConnMan Integration (Minimalist)
set -e

INTERFACE="${1:-wg0}"
ROLE="${2:-server}"
CONFIG_DIR="/etc/rosenpass/${INTERFACE}"

echo "===> Quick Setup: Rosenpass + ConnMan for ${INTERFACE}"

# 1. Standard Key Generation (Consistency)
mkdir -p "${CONFIG_DIR}/peers"
chmod 700 "${CONFIG_DIR}"
rosenpass gen-keys --secret-key "${CONFIG_DIR}/pqsk" --public-key "${CONFIG_DIR}/pqpk"

# 2. ConnMan Configuration (The Lean Way)
CONNMAN_CONF="/var/lib/connman/${INTERFACE}.config"

echo "===> Generating ConnMan provisioning file: ${CONNMAN_CONF}"
cat <<EOM | sudo tee "${CONNMAN_CONF}" > /dev/null
[service_${INTERFACE}]
Type = vpn
Name = Rosenpass_${INTERFACE}
VPN.Type = wireguard
IPv4 = 10.0.0.1/24
EOM

echo "===> Done. Rosenpass keys generated in ${CONFIG_DIR}"
echo "     ConnMan service created. Run 'connmanctl services' to verify."
