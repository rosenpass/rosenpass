#!/bin/bash
# Teardown script for Rosenpass + WireGuard + ConnMan integration
#
# Stops Rosenpass, removes ConnMan VPN provisioning files, and
# optionally deletes keys.
#
# Usage: sudo ./teardown.sh [INTERFACE] [--delete-keys]
#   INTERFACE      WireGuard interface name (default: wg0)
#   --delete-keys  Also remove keys from /etc/rosenpass/<INTERFACE>

set -euo pipefail

INTERFACE="${1:-wg0}"
DELETE_KEYS=false
CONNMAN_VPN_DIR="/var/lib/connman-vpn"

shift || true
for arg in "$@"; do
    case "${arg}" in
        --delete-keys) DELETE_KEYS=true ;;
        *)             echo "Unknown option: ${arg}" >&2; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root" >&2
    exit 1
fi

echo "==> Tearing down Rosenpass + WireGuard + ConnMan (interface=${INTERFACE})"

# Stop Rosenpass if running via systemd
if systemctl is-active --quiet "rosenpass@${INTERFACE}" 2>/dev/null; then
    echo "==> Stopping rosenpass@${INTERFACE}..."
    systemctl stop "rosenpass@${INTERFACE}"
fi

# Disconnect ConnMan VPN if connected
if command -v connmanctl >/dev/null 2>&1; then
    VPN_SERVICE=$(connmanctl services 2>/dev/null | grep -o "vpn_[^ ]*${INTERFACE}[^ ]*" || true)
    if [ -n "${VPN_SERVICE}" ]; then
        echo "==> Disconnecting ConnMan VPN service ${VPN_SERVICE}..."
        connmanctl disconnect "${VPN_SERVICE}" 2>/dev/null || true
    fi
fi

# Remove ConnMan VPN provisioning file
PROVISION_FILE="${CONNMAN_VPN_DIR}/${INTERFACE}.config"
if [ -f "${PROVISION_FILE}" ]; then
    echo "==> Removing ConnMan provisioning file ${PROVISION_FILE}..."
    rm -f "${PROVISION_FILE}"
fi

# Restart connman-vpn to pick up the removal
if systemctl is-active --quiet connman-vpn 2>/dev/null; then
    echo "==> Restarting connman-vpn..."
    systemctl restart connman-vpn
fi

# The interface may linger after ConnMan releases it
if ip link show "${INTERFACE}" >/dev/null 2>&1; then
    echo "==> Deleting WireGuard interface ${INTERFACE}..."
    ip link del dev "${INTERFACE}" 2>/dev/null || true
fi

# Optionally delete keys
if [ "${DELETE_KEYS}" = true ]; then
    CONFIG_DIR="/etc/rosenpass/${INTERFACE}"
    if [ -d "${CONFIG_DIR}" ]; then
        echo "==> Removing keys and config from ${CONFIG_DIR}..."
        rm -rf "${CONFIG_DIR}"
    fi
fi

echo "==> Teardown complete"
