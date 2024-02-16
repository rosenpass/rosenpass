#! /bin/bash

set -e # Needed by bail()

log() {
  local lvl; lvl="${1}"; shift || bail "log()" "USAGE: log LEVEL CONTEXT MSG..."
  local ctx; ctx="${1}"; shift || bail "log()" "USAGE: log LEVEL CONTEXT MSG..."
  echo >&2 "[entrypoint.sh/${ctx} ${lvl}]:" "$@"
}

log_debug() {
  if [[ -n "${DEBUG_ENTRYPOINT}" ]]; then
    log "DEBUG" "$@"
  fi
}

log_info() {
  log "INFO" "$@"
}

log_err() {
  log "ERROR" "$@"
}

exc() {
  local ctx; ctx="${1}"; shift || bail "exc()" "USAGE: exc CONTEXT CMD..."
  log_debug '$' "$@"
  "$@"
}

bail() {
  local ctx; ctx="${1}"; shift || bail "bail()" "USAGE: bail CONTEXT MSG..."
  (( "$#" != 0 )) || bail "${ctx}" $'USAGE: bail CONTEXT MSG... # Bail called without parameters! Please use error messages dear developer.'
  log_err "${ctx}" "$@"
  return 1
}

join() {
  local delim; delim="$1"; shift || bail "join()" "USAGE: join DELIM ELMS..."
  local tmp fst
  fst="true"
  for tmp in "$@"; do
    if [[ "${fst}" = "true" ]]; then
      printf "%s" "${tmp}"
      fst=""
    else
      printf "%s%s" "${delim}" "${tmp}"
    fi
  done
}

# Shred files after they where red (recursively)
# USAGE: $ burn_after_reading DIR
burn_after_reading() {
  local dir; dir="$1"; shift || bail "join()" "USAGE: burn_after_reading DIR"

  log_info burn_after_reading "Started for ${dir}"

  # Load the list of configuration files
  local -a files_arr # Array
  readarray -td $'\0' files_arr < <(find "${dir}" -type f -print0)

  # Convert configuration file list to associative array
  local file
  local -A files_todo # Associative array
  for file in "${files_arr[@]}"; do
    files_todo["${file}"]="1"
  done

  # Watch for closed files
  local file
  # The --exclude '/$' excludes directories
  inotifywait --quiet --monitor --event close_nowrite --exclude '/$' --recursive . --no-newline --format "%w%f%0" \
    | while read -d $'\0' -r file; do

        # Check if the file is in the todo list, if yes, erase it
        if [[ "${files_todo["${file}"]+1}" = "1" ]]; then
          log_info burn_after_reading "File loaded from configuration; removing now: ${file}";
          shred "${file}"
          # Clear from the todo list; What in the devils name is this quoting style bash
          unset 'files_todo["${file}"]'
        fi

        # We're done if the todo list is empty
        if (( "${#files_todo[@]}" == 0 )); then
          return
        fi
      done
}


as_user() {
  local -a cmd_prefix
  if [[ "$1" = "--exec" ]]; then
    cmd_prefix=("exec")
    shift
  fi

  local user; user="$1"; shift || bail "as_user()" "USAGE: as_user USER CMD..."
  (( "$#" > 0 )) || bail "as_user()" "USAGE: as_user USER CMD..."

  if [[ -n "${USER_GAINS_CAP_NET_ADMIN}" ]]; then # TODO: Dirty to do this here; use --cap-net-admin or something?
    exc "as_user()" "${cmd_prefix[@]}" \
      capsh --caps="cap_net_admin+eip cap_setuid,cap_setgid+ep" --keep=1 \
        --user="${user}" --addamb=cap_net_admin -- -c 'exec "$@"' -- "$@"
  elif [[ "${user}" = "$(whoami)" ]]; then
    exc "as_user()" "${cmd_prefix[@]}" "$@"
  else
    exc "as_user()" "${cmd_prefix[@]}" runuser -u "${user}" -- "$@"
  fi
}

usage() {
  bail "USAGE: ${SCRIPT} rosenpass|psk_broker"
}

cmd_internal() {
  "$@"
}

cmd_run_command() {
  exc "run_command()" as_user --exec "${SWITCH_USER}" "$@"
}

cmd_psk_broker() {
  exc "psk_broker()" exec \
    fd_passing --listen /socket/psk_broker.sock \
      "$SCRIPT" internal as_user --exec "${SWITCH_USER}" \
        rosenpass-wireguard-broker-socket-handler --listen-fd
}

rosenpass_start_with_socket_fd() {
  local fd; fd="$1"; shift || bail "rosenpass_start_with_socket_fd()" "USAGE: rosenpass_start_with_socket_fd PSK_BROKER_FD"
  exc "rosenpass_start_with_socket_fd()" exec \
    rosenpass --psk-broker-fd "$fd" exchange-config /config/config.toml
}

cmd_rosenpass() {
  test -z "${USER_GAINS_CAP_NET_ADMIN}" || bail "rosenpass()" "USER_GAINS_CAP_NET_ADMIN should be unset. The rosenpass instance doing key exchanges should not have network admin privileges!"
  exc "psk_broker()" exec \
    fd_passing --connect /socket/psk_broker.sock \
      "$SCRIPT" internal as_user --exec "${SWITCH_USER}" \
        "$SCRIPT" internal rosenpass_start_with_socket_fd
}

main() {
  local command; command="$1"; shift || usage
  case "${command}" in 
    internal) cmd_internal "$@" ;;
    run_command) ;;
    psk_broker) ;;
    rosenpass) ;;
    *) usage;;
  esac

  exc "main()" umask u=rw,og=
  exc "main()" cp -R "${CONFIG_MOUNT}" "${CONFIG_TMP}"
  exc "main()" chmod -R u+X "${CONFIG_TMP}"
  exc "main()" chown -R rosenpass:rosenpass "${CONFIG_TMP}"
  # TODO: How can we do this? We should probably use a dedicated config broker.
  #exc "main()" umount "${CONFIG_MOUNT}"
  exc "main()" cd "${CONFIG_TMP}"

  if [[ -n "${BURN_AFTER_READING}" ]]; then
    ( burn_after_reading /dev/shm/rosenpass-config )&
  fi

  local -a path_cpy extra_path_cpy
  mapfile -td ':' path_cpy < <(echo -n "$PATH")
  mapfile -td ':' extra_path_cpy < <(echo -n "$EXTRA_PATH")
  PATH="$(join ":" "${extra_path_cpy[@]}" "${path_cpy[@]}")"
  export PATH

  exc "main()" "cmd_${command}" "$@"
}

SCRIPT="$0"

# Config
CONFIG_MOUNT="${CONFIG_MOUNT:-/config}"
CONFIG_TMP="${CONFIG_TMP:-/dev/shm/rosenpass-config}"
BURN_AFTER_READING="${BURN_AFTER_READING:-true}"
SWITCH_USER="${SWITCH_USER:-rosenpass}"
#USER_GAINS_CAP_NET_ADMIN="${USER_GAINS_CAP_NET_ADMIN}"
EXTRA_PATH="${EXTRA_PATH:-"$(eval echo ~rosenpass)/usr/bin"}"

main "$@"
