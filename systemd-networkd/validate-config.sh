#!/usr/bin/env bash
# validate-config.sh
#
# Validates the structure of systemd-networkd + Rosenpass configuration files
# for a given interface without requiring root or a running system.
#
# Usage:
#   ./validate-config.sh <INTERFACE_NAME>
#
# This checks:
#   - Required files exist
#   - .netdev file has correct structure
#   - .network file references the right interface
#   - Rosenpass .toml file references the same device name
#   - PresharedKey is NOT set in the .netdev (Rosenpass manages it)

set -euo pipefail

usage() {
    echo "Usage: $0 <INTERFACE_NAME>"
    echo ""
    echo "Validates systemd-networkd + Rosenpass configuration for the given interface."
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

IFACE="$1"
ERRORS=0
WARNINGS=0

info()    { echo "[INFO]    $*"; }
warn()    { echo "[WARNING] $*"; WARNINGS=$((WARNINGS + 1)); }
error()   { echo "[ERROR]   $*"; ERRORS=$((ERRORS + 1)); }
ok()      { echo "[OK]      $*"; }

NETWORKD_DIR="/etc/systemd/network"
RP_DIR="/etc/rosenpass"

# Check .netdev file
NETDEV="${NETWORKD_DIR}/${IFACE}.netdev"
if [ -f "$NETDEV" ]; then
    ok "Found $NETDEV"

    if grep -q "^Kind=wireguard" "$NETDEV"; then
        ok ".netdev Kind is wireguard"
    else
        error ".netdev missing Kind=wireguard"
    fi

    if grep -q "^Name=${IFACE}" "$NETDEV"; then
        ok ".netdev Name matches interface"
    else
        error ".netdev Name does not match interface '$IFACE'"
    fi

    if grep -qi "^PresharedKey=" "$NETDEV"; then
        error "PresharedKey is set in .netdev -- Rosenpass should manage this"
    elif grep -qi "^PresharedKeyFile=" "$NETDEV"; then
        error "PresharedKeyFile is set in .netdev -- Rosenpass should manage this"
    else
        ok "No static PresharedKey in .netdev (correct for Rosenpass)"
    fi

    if grep -q "^PrivateKeyFile=" "$NETDEV"; then
        ok ".netdev has PrivateKeyFile"
        KEYFILE=$(grep "^PrivateKeyFile=" "$NETDEV" | cut -d= -f2)
        if [ -f "$KEYFILE" ]; then
            ok "WireGuard private key file exists: $KEYFILE"
            PERMS=$(stat -c %a "$KEYFILE" 2>/dev/null || stat -f %Lp "$KEYFILE" 2>/dev/null)
            if [ "$PERMS" = "600" ]; then
                ok "WireGuard private key has correct permissions (0600)"
            else
                warn "WireGuard private key permissions are $PERMS (expected 0600)"
            fi
        else
            warn "WireGuard private key file not found: $KEYFILE"
        fi
    else
        error ".netdev missing PrivateKeyFile"
    fi
else
    error "Missing $NETDEV"
fi

# Check .network file
NETWORK="${NETWORKD_DIR}/${IFACE}.network"
if [ -f "$NETWORK" ]; then
    ok "Found $NETWORK"

    if grep -q "^Name=${IFACE}" "$NETWORK"; then
        ok ".network matches interface name"
    else
        warn ".network [Match] Name may not match interface '$IFACE'"
    fi
else
    error "Missing $NETWORK"
fi

# Check Rosenpass config
RP_CONFIG="${RP_DIR}/${IFACE}.toml"
if [ -f "$RP_CONFIG" ]; then
    ok "Found $RP_CONFIG"

    if grep -q "public_key" "$RP_CONFIG" && grep -q "secret_key" "$RP_CONFIG"; then
        ok "Rosenpass config has key paths"
    else
        error "Rosenpass config missing public_key or secret_key"
    fi

    if grep -q "device.*=.*\"${IFACE}\"" "$RP_CONFIG"; then
        ok "Rosenpass config device matches interface"
    else
        warn "No peer with device = \"${IFACE}\" found (may be unconfigured)"
    fi
else
    error "Missing $RP_CONFIG"
fi

# Check Rosenpass keys
if [ -f "${RP_DIR}/${IFACE}/pqsk" ]; then
    ok "Rosenpass secret key exists"
    PERMS=$(stat -c %a "${RP_DIR}/${IFACE}/pqsk" 2>/dev/null || stat -f %Lp "${RP_DIR}/${IFACE}/pqsk" 2>/dev/null)
    if [ "$PERMS" = "600" ]; then
        ok "Rosenpass secret key has correct permissions (0600)"
    else
        warn "Rosenpass secret key permissions are $PERMS (expected 0600)"
    fi
else
    warn "Rosenpass secret key not found at ${RP_DIR}/${IFACE}/pqsk"
fi

if [ -f "${RP_DIR}/${IFACE}/pqpk" ]; then
    ok "Rosenpass public key exists"
else
    warn "Rosenpass public key not found at ${RP_DIR}/${IFACE}/pqpk"
fi

echo ""
echo "============================================="
echo "Validation complete: $ERRORS error(s), $WARNINGS warning(s)"
echo "============================================="

if [ "$ERRORS" -gt 0 ]; then
    exit 1
fi
