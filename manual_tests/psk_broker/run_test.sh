#! /bin/bash

set -e -o pipefail

enquote() {
  while (( "$#" > 1)); do
    printf "%q " "$1"
    shift
  done
  if (("$#" > 0)); then
    printf "%q" "$1"
  fi
}

CLEANUP_HOOKS=()
hook_cleanup() {
  local hook
  set +e +o pipefail
  for hook in "${CLEANUP_HOOKS[@]}"; do
    eval "${hook}"
  done
}

cleanup() {
  CLEANUP_HOOKS=("$(enquote exc_with_ctx cleanup "$@")" "${CLEANUP_HOOKS[@]}")
}

cleanup_eval() {
  cleanup eval "$*"
}

stderr() {
  echo >&2 "$@"
}

log() {
  local level; level="$1"; shift || fatal "USAGE: log LVL MESSAGE.."
  stderr "[${level}]" "$@"
}

info() {
  log "INFO" "$@"
}

debug() {
  log "DEBUG" "$@"
}

fatal() {
  log "FATAL" "$@"
  exit 1
}

assert() {
  local msg; msg="$1"; shift || fatal "USAGE: assert_cmd MESSAGE COMMAND.."
  "$@" || fatal "${msg}"
}

abs_dir() {
  local dir; dir="$1"; shift || fatal "USAGE: abs_dir DIR"
  (
    cd "${dir}"
    pwd -P
  )
}

exc_with_ctx() {
  local ctx; ctx="$1"; shift || fatal "USAGE: exc_with_ctx CONTEXT COMMAND.."
  if [[ -z "${ctx}" ]]; then
    info '$' "$@"
  else
    info "${ctx}\$" "$@"
  fi

  "$@"
}

exc() {
  exc_with_ctx "" "$@"
}

exc_eval() {
  exc eval "$*"
} 

exc_eval_with_ctx() {
  local ctx; ctx="$1"; shift || fatal "USAGE: exc_eval_with_ctx CONTEXT EVAL_COMMAND.."
  exc_with_ctx "eval:${ctx}" "$*"
} 

exc_as_user() {
  exc sudo -u "${SUDO_USER}" "$@"
}

exc_eval_as_user() {
  exc_as_user bash -c "$*"
}

fork_eval_as_user() {
  exc sudo -u "${SUDO_USER}" bash -c "$*" &
  local pid; pid="$!"
  cleanup wait "${pid}"
  cleanup pkill -2 -P "${pid}" # Reverse ordering
}

info_success() {
  stderr
  stderr
  if [[ "${SUCCESS}" = 1 ]]; then
    stderr "  Test was a success!"
  else
    stderr "  !!! TEST WAS A FAILURE!!!"
  fi
  stderr
}

main() {
  assert "Use as root with sudo" [ "$(id -u)" -eq 0 ]
  assert "Use as root with sudo" [ -n "${SUDO_UID}" ]
  assert "SUDO_UID is 0; refusing to build as root" [ "${SUDO_UID}" -ne 0 ]

  cleanup info_success

  trap hook_cleanup EXIT

  SCRIPT="$0"
  CFG_TEMPLATE_DIR="$(abs_dir "$(dirname "${SCRIPT}")")"
  REPO="$(abs_dir "${CFG_TEMPLATE_DIR}/../..")"
  BINS="${REPO}/target/debug"

  # Create temp dir
  TMP_DIR="/tmp/rosenpass-psk-broker-test-$(date +%s)-$(uuidgen)"
  cleanup rm -rf "${TMP_DIR}"
  exc_as_user mkdir -p "${TMP_DIR}"

  # Copy config
  CFG_DIR="${TMP_DIR}/cfg"
  exc_as_user cp -R "${CFG_TEMPLATE_DIR}" "${CFG_DIR}"

  exc umask 077

  exc cd "${REPO}"
  local build_cmd; build_cmd=(cargo build --workspace --color=always --all-features --bins --profile dev)
  if test -e "${BINS}/rosenpass-wireguard-broker-privileged" -a -e "${BINS}/rosenpass"; then
    info "Found the binaries rosenpass-wireguard-broker-privileged and rosenpass." \
      "Run following commands as a regular user to recompile the binaries with the right options" \
      "in case of an error:" '$' "${build_cmd[@]}"
  else
    exc_as_user "${build_cmd[@]}"
  fi
  exc sudo setcap CAP_NET_ADMIN=+eip "${BINS}/rosenpass-wireguard-broker-privileged"

  exc cd "${CFG_DIR}"
  exc_eval_as_user "wg genkey > peer_a.wg.sk"
  exc_eval_as_user "wg pubkey < peer_a.wg.sk > peer_a.wg.pk"
  exc_eval_as_user "wg genkey > peer_b.wg.sk"
  exc_eval_as_user "wg pubkey < peer_b.wg.sk > peer_b.wg.pk"
  exc_eval_as_user "wg genpsk > peer_a_invalid.psk"
  exc_eval_as_user "wg genpsk > peer_b_invalid.psk"
  exc_eval_as_user "echo $(enquote "peer = \"$(cat peer_b.wg.pk)\"") >> peer_a.rp.config"
  exc_eval_as_user "echo $(enquote "peer = \"$(cat peer_a.wg.pk)\"") >> peer_b.rp.config"
  exc_as_user "${BINS}"/rosenpass gen-keys peer_a.rp.config
  exc_as_user "${BINS}"/rosenpass gen-keys peer_b.rp.config

  cleanup ip l del dev rpPskBrkTestA
  cleanup ip l del dev rpPskBrkTestB
  exc ip l add dev rpPskBrkTestA type wireguard
  exc ip l add dev rpPskBrkTestB type wireguard

  exc wg set rpPskBrkTestA \
    listen-port 46125 \
    private-key peer_a.wg.sk \
    peer "$(cat peer_b.wg.pk)" \
      endpoint 'localhost:46126' \
      preshared-key peer_a_invalid.psk \
      allowed-ips fe80::2/64
  exc wg set rpPskBrkTestB \
    listen-port 46126 \
    private-key peer_b.wg.sk \
    peer "$(cat peer_a.wg.pk)" \
      endpoint 'localhost:46125' \
      preshared-key peer_b_invalid.psk \
      allowed-ips fe80::1/64

  exc ip l set rpPskBrkTestA up
  exc ip l set rpPskBrkTestB up

  exc ip a add fe80::1/64 dev rpPskBrkTestA
  exc ip a add fe80::2/64 dev rpPskBrkTestB

  fork_eval_as_user "\
    RUST_LOG='info' \
    PATH=$(enquote "${REPO}/target/debug:${PATH}") \
    $(enquote "${BINS}/rosenpass") --psk-broker-spawn \
      exchange-config peer_a.rp.config"
  fork_eval_as_user "\
    RUST_LOG='info' \
    PATH=$(enquote "${REPO}/target/debug:${PATH}") \
    $(enquote "${BINS}/rosenpass-wireguard-broker-socket-handler") \
      --listen-path broker.sock"
  fork_eval_as_user "\
    RUST_LOG='info' \
    PATH=$(enquote "$PWD/target/debug:${PATH}") \
    $(enquote "${BINS}/rosenpass") --psk-broker-path broker.sock \
      exchange-config peer_b.rp.config"

  exc_as_user ping -c 2 -w 10 fe80::1%rpPskBrkTestA
  exc_as_user ping -c 2 -w 10 fe80::2%rpPskBrkTestB
  exc_as_user ping -c 2 -w 10 fe80::2%rpPskBrkTestA
  exc_as_user ping -c 2 -w 10 fe80::1%rpPskBrkTestB

  SUCCESS=1
}

main "$@"
