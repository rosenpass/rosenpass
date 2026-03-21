#!/bin/bash
# Teardown script for Rosenpass + WireGuard + systemd-networkd integration
#
# Stops Rosenpass, removes systemd-networkd .netdev and .network files,
# and optionally deletes keys.
#
# Usage: sudo ./teardown.sh [INTERFACE] [--delete-keys]
#   INTERFACE      WireGuard interface name (default: wg0)
#   --delete-keys  Also remove keys from /etc/rosenpass/<INTERFACE>

set -euo pipefail

INTERFACE="${1:-wg0}"
DELETE_KEYS=false
NETWORKD_DIR="/etc/systemd/network"

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

echo "==> Tearing down Rosenpass + WireGuard + systemd-networkd (interface=${INTERFACE})"

# Stop Rosenpass if running via systemd
if systemctl is-active --quiet "rosenpass@${INTERFACE}" 2>/dev/null; then
    echo "==> Stopping rosenpass@${INTERFACE}..."
    systemctl stop "rosenpass@${INTERFACE}"
fi

# Remove systemd-networkd unit files
for f in "${NETWORKD_DIR}/50-${INTERFACE}.netdev" "${NETWORKD_DIR}/50-${INTERFACE}.network"; do
    if [ -f "${f}" ]; then
        echo "==> Removing ${f}..."
        rm -f "${f}"
    fi
done

# Reload networkd so it drops the interface
if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
    echo "==> Reloading systemd-networkd..."
    networkctl reload 2>/dev/null || systemctl restart systemd-networkd
fi

# The interface may linger if networkd doesn't remove it
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
