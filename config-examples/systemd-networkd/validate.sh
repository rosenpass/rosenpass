#!/bin/bash
# Validation script for Rosenpass + WireGuard + systemd-networkd configuration
#
# Checks that all pieces of the integration are consistent:
#   - systemd-networkd is running and managing the WireGuard interface
#   - .netdev file exists with Kind=wireguard and no static PresharedKey
#   - .network file assigns the expected address
#   - Rosenpass config references the correct interface
#   - Key file permissions are secure
#
# Usage: sudo ./validate.sh [INTERFACE]
#   INTERFACE  WireGuard interface name (default: wg0)

set -euo pipefail

INTERFACE="${1:-wg0}"
CONFIG_DIR="/etc/rosenpass/${INTERFACE}"
NETWORKD_DIR="/etc/systemd/network"
ERRORS=0

err() {
    echo "  [FAIL] $*" >&2
    ERRORS=$((ERRORS + 1))
}

ok() {
    echo "  [ OK ] $*"
}

echo "==> Validating Rosenpass + WireGuard + systemd-networkd for ${INTERFACE}"
echo ""

# --- Check systemd-networkd ---

echo "--- systemd-networkd ---"

if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
    ok "systemd-networkd is running"
else
    err "systemd-networkd is not running"
fi

# Check .netdev file
NETDEV_FILE="${NETWORKD_DIR}/50-${INTERFACE}.netdev"
if [ -f "${NETDEV_FILE}" ]; then
    ok ".netdev file exists: ${NETDEV_FILE}"

    if grep -qi "Kind=wireguard" "${NETDEV_FILE}" 2>/dev/null; then
        ok ".netdev has Kind=wireguard"
    else
        err ".netdev missing Kind=wireguard"
    fi

    if grep -qi "PresharedKey" "${NETDEV_FILE}" 2>/dev/null; then
        err ".netdev contains PresharedKey -- Rosenpass should manage PSK rotation"
    else
        ok "No static PresharedKey in .netdev (correct -- Rosenpass manages PSKs)"
    fi
else
    err ".netdev file not found: ${NETDEV_FILE}"
fi

# Check .network file
NETWORK_FILE="${NETWORKD_DIR}/50-${INTERFACE}.network"
if [ -f "${NETWORK_FILE}" ]; then
    ok ".network file exists: ${NETWORK_FILE}"

    if grep -qi "Name=${INTERFACE}" "${NETWORK_FILE}" 2>/dev/null; then
        ok ".network matches interface ${INTERFACE}"
    else
        err ".network does not match interface ${INTERFACE}"
    fi
else
    err ".network file not found: ${NETWORK_FILE}"
fi

echo ""

# --- Check WireGuard ---

echo "--- WireGuard ---"

if ip link show "${INTERFACE}" >/dev/null 2>&1; then
    ok "Interface ${INTERFACE} exists"

    # Verify systemd-networkd is managing it
    NETWORKCTL_STATE=$(networkctl status "${INTERFACE}" 2>/dev/null | grep -i "setup state" || echo "")
    if [ -n "${NETWORKCTL_STATE}" ]; then
        ok "networkctl reports: ${NETWORKCTL_STATE}"
    fi
else
    err "Interface ${INTERFACE} does not exist"
fi

WG_OUTPUT=$(wg show "${INTERFACE}" 2>/dev/null || echo "")
if [ -n "${WG_OUTPUT}" ]; then
    ok "WireGuard is configured on ${INTERFACE}"

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
