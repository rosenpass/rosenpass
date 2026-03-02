#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  validate-config.sh --instance NAME [options]

Options:
  --instance NAME            Instance/profile identifier
  --rp-config-dir DIR        Rosenpass config directory (default: /etc/rosenpass/connman)
  --connman-config-dir DIR   ConnMan VPN config dir (default: /var/lib/connman-vpn)
  --skip-rosenpass-validate  Skip `rosenpass validate`
  -h, --help                 Show this help
USAGE
}

connman_value() {
    local key="$1"
    local file="$2"
    awk -v key="$key" '
        /^[[:space:]]*#/ { next }
        index($0, "=") {
            split_at = index($0, "=")
            lhs = substr($0, 1, split_at - 1)
            rhs = substr($0, split_at + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
            if (lhs == key) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)
                sub(/[[:space:]]+#.*$/, "", rhs)
                print rhs
                exit
            }
        }
    ' "$file"
}

toml_string_value() {
    local key="$1"
    local file="$2"
    awk -v key="$key" '
        /^[[:space:]]*#/ { next }
        {
            if (match($0, "^[[:space:]]*" key "[[:space:]]*=[[:space:]]*\"([^\"]+)\"", m)) {
                print m[1]
                exit
            }
        }
    ' "$file"
}

require() {
    local msg="$1"
    local value="$2"
    if [[ -z "$value" ]]; then
        echo "Validation failed: ${msg}" >&2
        exit 1
    fi
}

instance=""
rp_config_dir="/etc/rosenpass/connman"
connman_config_dir="/var/lib/connman-vpn"
skip_rosenpass_validate="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --instance)
            instance="$2"
            shift 2
            ;;
        --rp-config-dir)
            rp_config_dir="$2"
            shift 2
            ;;
        --connman-config-dir)
            connman_config_dir="$2"
            shift 2
            ;;
        --skip-rosenpass-validate)
            skip_rosenpass_validate="true"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$instance" ]]; then
    echo "Missing required option: --instance" >&2
    usage
    exit 1
fi

rp_cfg="${rp_config_dir}/${instance}.toml"
connman_cfg="${connman_config_dir}/${instance}.config"

for f in "$rp_cfg" "$connman_cfg"; do
    if [[ ! -f "$f" ]]; then
        echo "Validation failed: missing file ${f}" >&2
        exit 1
    fi
done

if [[ "$skip_rosenpass_validate" != "true" ]]; then
    if ! command -v rosenpass >/dev/null 2>&1; then
        echo "Validation failed: rosenpass binary not found in PATH" >&2
        exit 1
    fi
    rosenpass validate "$rp_cfg" >/dev/null
fi

provider_type="$(connman_value "Type" "$connman_cfg")"
host="$(connman_value "Host" "$connman_cfg")"
wg_address="$(connman_value "WireGuard.Address" "$connman_cfg")"
wg_private_key="$(connman_value "WireGuard.PrivateKey" "$connman_cfg")"
wg_public_key="$(connman_value "WireGuard.PublicKey" "$connman_cfg")"
wg_allowed_ips="$(connman_value "WireGuard.AllowedIPs" "$connman_cfg")"
wg_psk="$(connman_value "WireGuard.PresharedKey" "$connman_cfg")"

require "Type must be set" "$provider_type"
require "Host must be set" "$host"
require "WireGuard.Address must be set" "$wg_address"
require "WireGuard.PrivateKey must be set" "$wg_private_key"
require "WireGuard.PublicKey must be set" "$wg_public_key"
require "WireGuard.AllowedIPs must be set" "$wg_allowed_ips"

if [[ "$provider_type" != "WireGuard" ]]; then
    echo "Validation failed: Type must be WireGuard, got '${provider_type}'" >&2
    exit 1
fi

if [[ -n "$wg_psk" ]]; then
    echo "Validation failed: WireGuard.PresharedKey must be omitted; Rosenpass manages PSK rotation" >&2
    exit 1
fi

rp_peer="$(toml_string_value "peer" "$rp_cfg")"
rp_device="$(toml_string_value "device" "$rp_cfg")"

require "Rosenpass peer key must be set in ${rp_cfg}" "$rp_peer"
require "Rosenpass device must be set in ${rp_cfg}" "$rp_device"

if [[ "$rp_peer" != "$wg_public_key" ]]; then
    echo "Validation failed: Rosenpass peer key does not match ConnMan WireGuard.PublicKey" >&2
    echo "  rosenpass: ${rp_peer}" >&2
    echo "  connman:   ${wg_public_key}" >&2
    exit 1
fi

echo "Validation succeeded for instance '${instance}'."
echo "  ConnMan config:   ${connman_cfg}"
echo "  Rosenpass config: ${rp_cfg}"
