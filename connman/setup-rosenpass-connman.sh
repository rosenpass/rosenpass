#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  setup-rosenpass-connman.sh [options]

Required options:
  --instance NAME               Instance/profile identifier (e.g. peer-a)
  --provider-name NAME          Human-readable ConnMan provider name
  --host HOST                   Remote host/IP used by ConnMan (Host)
  --wg-address CIDR             Local WireGuard tunnel address (e.g. 10.44.0.1/24)
  --allowed-ips LIST            WireGuard.AllowedIPs value (comma-separated)
  --peer-wg-public-key KEY      Remote WireGuard public key (base64)
  --peer-rp-public-key-file P   Path to remote Rosenpass public key file
  --rp-endpoint HOST:PORT       Remote Rosenpass endpoint

Optional:
  --rp-listen ADDR:PORT         Local Rosenpass listen socket (default: none)
  --wg-endpoint-port PORT       Remote WireGuard listen port (default: 51820)
  --wg-listen-port PORT         Local WireGuard listen port (default: unset)
  --persistent-keepalive SEC    WireGuard keepalive in seconds (default: unset)
  --dns LIST                    Comma-separated DNS servers for ConnMan
  --wireguard-device NAME       WireGuard interface used by Rosenpass (default: wg0)
  --rp-config-dir DIR           Rosenpass config directory (default: /etc/rosenpass/connman)
  --connman-config-dir DIR      ConnMan VPN config dir (default: /var/lib/connman-vpn)
  --force                       Overwrite existing files
  -h, --help                    Show this help
USAGE
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

instance=""
provider_name=""
host=""
wg_address=""
allowed_ips=""
peer_wg_public_key=""
peer_rp_public_key_file=""
rp_endpoint=""
rp_listen=""
wg_endpoint_port="51820"
wg_listen_port=""
persistent_keepalive=""
dns=""
wireguard_device="wg0"
rp_config_dir="/etc/rosenpass/connman"
connman_config_dir="/var/lib/connman-vpn"
force="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --instance)
            instance="$2"
            shift 2
            ;;
        --provider-name)
            provider_name="$2"
            shift 2
            ;;
        --host)
            host="$2"
            shift 2
            ;;
        --wg-address)
            wg_address="$2"
            shift 2
            ;;
        --allowed-ips)
            allowed_ips="$2"
            shift 2
            ;;
        --peer-wg-public-key)
            peer_wg_public_key="$2"
            shift 2
            ;;
        --peer-rp-public-key-file)
            peer_rp_public_key_file="$2"
            shift 2
            ;;
        --rp-endpoint)
            rp_endpoint="$2"
            shift 2
            ;;
        --rp-listen)
            rp_listen="$2"
            shift 2
            ;;
        --wg-endpoint-port)
            wg_endpoint_port="$2"
            shift 2
            ;;
        --wg-listen-port)
            wg_listen_port="$2"
            shift 2
            ;;
        --persistent-keepalive)
            persistent_keepalive="$2"
            shift 2
            ;;
        --dns)
            dns="$2"
            shift 2
            ;;
        --wireguard-device)
            wireguard_device="$2"
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
        --force)
            force="true"
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

for v in instance provider_name host wg_address allowed_ips peer_wg_public_key peer_rp_public_key_file rp_endpoint; do
    if [[ -z "${!v}" ]]; then
        echo "Missing required option: --${v//_/-}" >&2
        usage
        exit 1
    fi
done

require_cmd wg
require_cmd rosenpass

profile_dir="${rp_config_dir}/${instance}"
rp_cfg_file="${rp_config_dir}/${instance}.toml"
connman_cfg_file="${connman_config_dir}/${instance}.config"

mkdir -p "$profile_dir" "$rp_config_dir" "$connman_config_dir"

if [[ "$force" != "true" ]]; then
    for p in "$rp_cfg_file" "$connman_cfg_file"; do
        if [[ -e "$p" ]]; then
            echo "Refusing to overwrite existing file without --force: $p" >&2
            exit 1
        fi
    done
fi

wg_private_key_file="${profile_dir}/wg-private.key"
wg_public_key_file="${profile_dir}/wg-public.key"
rp_secret_key_file="${profile_dir}/rp-secret-key"
rp_public_key_file="${profile_dir}/rp-public-key"

umask 077

if [[ "$force" == "true" || ! -s "$wg_private_key_file" || ! -s "$wg_public_key_file" ]]; then
    wg genkey | tee "$wg_private_key_file" | wg pubkey > "$wg_public_key_file"
fi

if [[ "$force" == "true" || ! -s "$rp_secret_key_file" || ! -s "$rp_public_key_file" ]]; then
    gen_keys_args=(
        --public-key "$rp_public_key_file"
        --secret-key "$rp_secret_key_file"
    )
    if [[ "$force" == "true" ]]; then
        gen_keys_args+=(--force)
    fi
    rosenpass gen-keys "${gen_keys_args[@]}"
fi

chmod 600 "$wg_private_key_file" "$wg_public_key_file" "$rp_secret_key_file" "$rp_public_key_file"

local_wg_private_key="$(tr -d '\n' < "$wg_private_key_file")"

{
    echo "[provider_${instance}]"
    echo "Type = WireGuard"
    echo "Name = ${provider_name}"
    echo "Host = ${host}"
    echo "WireGuard.Address = ${wg_address}"
    if [[ -n "$wg_listen_port" ]]; then
        echo "WireGuard.ListenPort = ${wg_listen_port}"
    fi
    if [[ -n "$dns" ]]; then
        echo "WireGuard.DNS = ${dns}"
    fi
    echo "WireGuard.PrivateKey = ${local_wg_private_key}"
    echo "WireGuard.PublicKey = ${peer_wg_public_key}"
    echo "WireGuard.AllowedIPs = ${allowed_ips}"
    echo "WireGuard.EndpointPort = ${wg_endpoint_port}"
    if [[ -n "$persistent_keepalive" ]]; then
        echo "WireGuard.PersistentKeepalive = ${persistent_keepalive}"
    fi
} > "$connman_cfg_file"
chmod 600 "$connman_cfg_file"

{
    echo "public_key = \"${rp_public_key_file}\""
    echo "secret_key = \"${rp_secret_key_file}\""
    if [[ -n "$rp_listen" ]]; then
        echo "listen = [\"${rp_listen}\"]"
    else
        echo "listen = []"
    fi
    echo "verbosity = \"Quiet\""
    echo
    echo "[[peers]]"
    echo "public_key = \"${peer_rp_public_key_file}\""
    echo "endpoint = \"${rp_endpoint}\""
    echo "device = \"${wireguard_device}\""
    echo "peer = \"${peer_wg_public_key}\""
    echo "extra_params = []"
} > "$rp_cfg_file"
chmod 600 "$rp_cfg_file"

cat <<SUMMARY
Created ConnMan + Rosenpass configuration for instance '${instance}'.

ConnMan provider config:
  ${connman_cfg_file}

Rosenpass config:
  ${rp_cfg_file}

Local public keys to copy to the remote peer:
  WireGuard: ${wg_public_key_file}
  Rosenpass: ${rp_public_key_file}
SUMMARY
