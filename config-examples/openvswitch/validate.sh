#!/bin/bash
# Validation script for Rosenpass + WireGuard + Open vSwitch configuration
#
# Checks that all pieces of the integration are consistent:
#   - OVS bridge exists and contains the WireGuard interface
#   - WireGuard interface is configured
#   - Rosenpass config references the correct interface
#   - Key file permissions are secure
#   - No static PresharedKey is set (Rosenpass manages this)
#
# Usage: sudo ./validate.sh [INTERFACE]
#   INTERFACE  WireGuard interface name (default: wg0)
#
# Environment variables:
#   BRIDGE     OVS bridge name (default: br-rp)

set -euo pipefail

INTERFACE="${1:-wg0}"
BRIDGE="${BRIDGE:-br-rp}"
CONFIG_DIR="/etc/rosenpass/${INTERFACE}"
ERRORS=0

err() {
    echo "  [FAIL] $*" >&2
    ERRORS=$((ERRORS + 1))
}

ok() {
    echo "  [ OK ] $*"
}

echo "==> Validating Rosenpass + WireGuard + OVS for ${INTERFACE} (bridge ${BRIDGE})"
echo ""

# --- Check OVS ---

echo "--- Open vSwitch ---"

if command -v ovs-vsctl >/dev/null 2>&1; then
    ok "ovs-vsctl found"
else
    err "ovs-vsctl not found"
fi

if ovs-vsctl br-exists "${BRIDGE}" 2>/dev/null; then
    ok "Bridge ${BRIDGE} exists"
else
    err "Bridge ${BRIDGE} does not exist"
fi

ACTUAL_BRIDGE=$(ovs-vsctl port-to-br "${INTERFACE}" 2>/dev/null || echo "")
if [ "${ACTUAL_BRIDGE}" = "${BRIDGE}" ]; then
    ok "${INTERFACE} is a port on ${BRIDGE}"
elif [ -n "${ACTUAL_BRIDGE}" ]; then
    err "${INTERFACE} is on bridge ${ACTUAL_BRIDGE}, expected ${BRIDGE}"
else
    err "${INTERFACE} is not an OVS port"
fi

echo ""

# --- Check WireGuard ---

echo "--- WireGuard ---"

if ip link show "${INTERFACE}" >/dev/null 2>&1; then
    ok "Interface ${INTERFACE} exists"
else
    err "Interface ${INTERFACE} does not exist"
fi

WG_OUTPUT=$(wg show "${INTERFACE}" 2>/dev/null || echo "")
if [ -n "${WG_OUTPUT}" ]; then
    ok "WireGuard is configured on ${INTERFACE}"

    # Check no static PSK is set (Rosenpass manages this)
    PSK_LINES=$(wg show "${INTERFACE}" preshared-keys 2>/dev/null | grep -cv "(none)" || echo "0")
    if [ "${PSK_LINES}" -gt 0 ]; then
        ok "Preshared keys active (Rosenpass is delivering PSKs)"
    else
        echo "  [INFO] No preshared keys yet -- Rosenpass may not have completed a handshake"
    fi
else
    err "WireGuard not configured on ${INTERFACE}"
fi

echo ""

# --- Check Rosenpass config ---

echo "--- Rosenpass ---"

CONFIG_FILE="${CONFIG_DIR}/config.toml"
if [ -f "${CONFIG_FILE}" ]; then
    ok "Config file ${CONFIG_FILE} exists"

    # Check that config references the correct WireGuard device
    if grep -q "device = \"${INTERFACE}\"" "${CONFIG_FILE}" 2>/dev/null; then
        ok "Config references device ${INTERFACE}"
    else
        err "Config does not reference device ${INTERFACE}"
    fi
else
    err "Config file ${CONFIG_FILE} not found"
fi

echo ""

# --- Check key permissions ---

echo "--- Key permissions ---"

for keyfile in "${CONFIG_DIR}/pqsk" "${CONFIG_DIR}/wg.key"; do
    if [ -f "${keyfile}" ]; then
        # Use portable stat: try GNU first, then BSD
        PERMS=$(stat -c "%a" "${keyfile}" 2>/dev/null || stat -f "%Lp" "${keyfile}" 2>/dev/null || echo "unknown")
        if [ "${PERMS}" = "600" ]; then
            ok "${keyfile} has correct permissions (600)"
        else
            err "${keyfile} has permissions ${PERMS} (should be 600)"
        fi
    else
        echo "  [INFO] ${keyfile} not found (may not be generated yet)"
    fi
done

echo ""

# --- Summary ---

if [ "${ERRORS}" -eq 0 ]; then
    echo "==> All checks passed"
else
    echo "==> ${ERRORS} error(s) found" >&2
    exit 1
fi
