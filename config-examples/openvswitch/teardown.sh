#!/bin/bash
# Teardown script for Rosenpass + WireGuard + Open vSwitch integration
#
# Removes the WireGuard interface from the OVS bridge and optionally
# deletes the bridge if no other ports remain.
#
# Usage: sudo ./teardown.sh [INTERFACE] [--delete-bridge] [--delete-keys]
#   INTERFACE      WireGuard interface name (default: wg0)
#   --delete-bridge  Also delete the OVS bridge if empty
#   --delete-keys    Also remove keys from /etc/rosenpass/<INTERFACE>
#
# Environment variables:
#   BRIDGE     OVS bridge name (default: br-rp)

set -euo pipefail

INTERFACE="${1:-wg0}"
BRIDGE="${BRIDGE:-br-rp}"
DELETE_BRIDGE=false
DELETE_KEYS=false

shift || true
for arg in "$@"; do
    case "${arg}" in
        --delete-bridge) DELETE_BRIDGE=true ;;
        --delete-keys)   DELETE_KEYS=true ;;
        *)               echo "Unknown option: ${arg}" >&2; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root" >&2
    exit 1
fi

echo "==> Tearing down Rosenpass + WireGuard + OVS (interface=${INTERFACE}, bridge=${BRIDGE})"

# Stop Rosenpass if running via systemd
if systemctl is-active --quiet "rosenpass@${INTERFACE}" 2>/dev/null; then
    echo "==> Stopping rosenpass@${INTERFACE}..."
    systemctl stop "rosenpass@${INTERFACE}"
fi

# Remove WireGuard port from OVS bridge
if ovs-vsctl port-to-br "${INTERFACE}" >/dev/null 2>&1; then
    echo "==> Removing ${INTERFACE} from OVS bridge..."
    ovs-vsctl --if-exists del-port "${BRIDGE}" "${INTERFACE}"
fi

# Delete WireGuard interface
if ip link show "${INTERFACE}" >/dev/null 2>&1; then
    echo "==> Deleting WireGuard interface ${INTERFACE}..."
    ip link del dev "${INTERFACE}"
fi

# Optionally delete the bridge if empty
if [ "${DELETE_BRIDGE}" = true ]; then
    PORT_COUNT=$(ovs-vsctl list-ports "${BRIDGE}" 2>/dev/null | wc -l)
    if [ "${PORT_COUNT}" -eq 0 ]; then
        echo "==> Deleting empty OVS bridge ${BRIDGE}..."
        ovs-vsctl --if-exists del-br "${BRIDGE}"
    else
        echo "==> Bridge ${BRIDGE} still has ${PORT_COUNT} port(s), keeping it"
    fi
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
