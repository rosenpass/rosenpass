#!/bin/bash
# Validation script for Rosenpass + WireGuard + ConnMan configuration
#
# Checks that all pieces of the integration are consistent:
#   - ConnMan is running and its VPN daemon is active
#   - ConnMan VPN provisioning file exists with Type=WireGuard
#   - No static PresharedKey in provisioning file
#   - WireGuard interface exists
#   - Rosenpass config references the correct interface
#   - Key file permissions are secure
#
# Usage: sudo ./validate.sh [INTERFACE]
#   INTERFACE  WireGuard interface name (default: wg0)

set -euo pipefail

INTERFACE="${1:-wg0}"
CONFIG_DIR="/etc/rosenpass/${INTERFACE}"
CONNMAN_VPN_DIR="/var/lib/connman-vpn"
ERRORS=0

err() {
    echo "  [FAIL] $*" >&2
    ERRORS=$((ERRORS + 1))
}

ok() {
    echo "  [ OK ] $*"
}

echo "==> Validating Rosenpass + WireGuard + ConnMan for ${INTERFACE}"
echo ""

# --- Check ConnMan ---

echo "--- ConnMan ---"

if systemctl is-active --quiet connman 2>/dev/null; then
    ok "connman is running"
else
    err "connman is not running"
fi

if systemctl is-active --quiet connman-vpn 2>/dev/null; then
    ok "connman-vpn is running"
else
    err "connman-vpn is not running (needed for WireGuard VPN provisioning)"
fi

# Check provisioning file
PROVISION_FILE="${CONNMAN_VPN_DIR}/${INTERFACE}.config"
if [ -f "${PROVISION_FILE}" ]; then
    ok "Provisioning file exists: ${PROVISION_FILE}"

    if grep -qi "Type = WireGuard" "${PROVISION_FILE}" 2>/dev/null || \
       grep -qi "Type=WireGuard" "${PROVISION_FILE}" 2>/dev/null; then
        ok "Provisioning file has Type=WireGuard"
    else
        err "Provisioning file missing Type=WireGuard"
    fi

    if grep -qi "PresharedKey" "${PROVISION_FILE}" 2>/dev/null; then
        err "Provisioning file contains PresharedKey -- Rosenpass should manage PSK rotation"
    else
        ok "No static PresharedKey in provisioning file (correct -- Rosenpass manages PSKs)"
    fi

    PERMS=$(stat -c "%a" "${PROVISION_FILE}" 2>/dev/null || stat -f "%Lp" "${PROVISION_FILE}" 2>/dev/null || echo "unknown")
    if [ "${PERMS}" = "600" ]; then
        ok "Provisioning file has correct permissions (600)"
    else
        err "Provisioning file has permissions ${PERMS} (should be 600, contains private key)"
    fi
else
    err "Provisioning file not found: ${PROVISION_FILE}"
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
