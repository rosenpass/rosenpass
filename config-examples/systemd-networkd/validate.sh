#!/bin/bash
# Validation script for Rosenpass + systemd-networkd configuration
set -e

INTERFACE="${1:-wg0}"
CONFIG_DIR="/etc/rosenpass/${INTERFACE}"
NETWORK_DIR="/etc/systemd/network"
ERRORS=0

echo "==> Validating Rosenpass + systemd-networkd config for ${INTERFACE}"

# Check no static PresharedKey in .netdev files
echo "==> Checking for forbidden static PresharedKey..."
for f in "${NETWORK_DIR}"/*.netdev; do
    if grep -qi "PresharedKey" "$f"; then
        echo "  [ERROR] $f contains a static PresharedKey — Rosenpass manages this!"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check interface names match between .netdev and .network
echo "==> Checking interface name consistency..."
NETDEV_NAME=$(grep -i "^Name=" "${NETWORK_DIR}/${INTERFACE}.netdev" 2>/dev/null | cut -d= -f2)
NETWORK_NAME=$(grep -i "^Name=" "${NETWORK_DIR}/${INTERFACE}.network" 2>/dev/null | cut -d= -f2)
if [ "$NETDEV_NAME" != "$NETWORK_NAME" ]; then
    echo "  [ERROR] Interface name mismatch: .netdev=$NETDEV_NAME .network=$NETWORK_NAME"
    ERRORS=$((ERRORS + 1))
fi

# Check key file permissions
echo "==> Checking key file permissions..."
for keyfile in "${CONFIG_DIR}/pqsk" "${CONFIG_DIR}/wg-"*.key; do
    if [ -f "$keyfile" ]; then
        PERMS=$(stat -c "%a" "$keyfile" 2>/dev/null || stat -f "%A" "$keyfile")
        if [ "$PERMS" != "600" ]; then
            echo "  [ERROR] $keyfile has permissions $PERMS (should be 600)"
            ERRORS=$((ERRORS + 1))
        fi
    fi
done

# Summary
if [ $ERRORS -eq 0 ]; then
    echo ""
    echo "  [OK] All checks passed!"
else
    echo ""
    echo "  [FAIL] $ERRORS error(s) found. Please fix before running."
    exit 1
fi