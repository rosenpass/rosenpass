#!/usr/bin/env bash

exc() {
  echo >&2 "\$" "$@"
  "$@"
}

run_proverif() {
  local file; file="$1"; shift
  local log; log="$1"; shift # intentionally unused

  exc rosenpass-marzipan run-proverif "${file}" "${@}"
}

clean_warnings() {
    exc rosenpass-marzipan clean-warnings
}

color_red='red'
color_green='green'
color_gray='gray'
color_clear=''

checkmark="✔"
cross="❌"

pretty_output_line() {
  exc rosenpass-marzipan pretty-output-line "${@}"
}

pretty_output() {
  local file; file="$1"; shift
  local expected=() descs=()

  # Lemmas are processed first
  readarray -t -O "${#expected[@]}" expected < <(
    < "$file" grep -Po '@(lemma)(?=\s+"[^\"]*")' \
      | sed 's/@lemma/true/')
  readarray -t -O "${#descs[@]}" descs < <(
    < "$file" grep -Po '@(lemma)\s+"[^\"]*"' \
      | sed 's/@\w\+\s\+//; s/"//g')

  # Then regular queries
  readarray -t -O "${#expected[@]}" expected < <(
    < "$file" grep -Po '@(query|reachable)(?=\s+"[^\"]*")' \
      | sed 's/@query/true/; s/@reachable/false/')
  readarray -t -O "${#descs[@]}" descs < <(
    < "$file" grep -Po '@(query|reachable)\s+"[^\"]*"' \
      | sed 's/@\w\+\s\+//; s/"//g')

  local outp ctr res ta tz; ctr=0; res=0; ta="$(date +%s)"
  while read -r outp; do
    tz="$(date +%s)"
    if [[ "${outp}" = "${expected[$ctr]}" ]]; then
      pretty_output_line "$((tz - ta))s " "${checkmark}" "${color_green}" "${descs[$ctr]}"
    else
      res=1
      pretty_output_line "$((tz - ta))s " "${cross}" "${color_red}" "${descs[$ctr]}"
    fi
    echo

    (( ctr += 1 ))
    ta="${tz}"
  done

  return "$res"
}

metaverif() {
  local file; file="$1"; shift
  local name; name="$(echo "${file}" | grep -Po '[^/]*(?=\.mpv)')"

  local cpp_prep; cpp_prep="${tmpdir}/${name}.i.pv"
  local awk_prep; awk_prep="${tmpdir}/${name}.o.pv"

  exc rosenpass-marzipan cpp ${file} ${cpp_prep}
  exc rosenpass-marzipan awk-prep ${cpp_prep} ${awk_prep}

  local log; log="${tmpdir}/${name}.log"
  {
    run_proverif "${awk_prep}" "$@" \
      | clean_warnings \
      | tee "${log}" \
      | awk '
          /^RESULT/ {
            gsub(/\./, "", $NF);
            print($NF);
            fflush(stdout);
          }' \
      | pretty_output "${cpp_prep}"
  } || {
    if ! grep -q "^Verification summary" "${log}"; then
      echo -ne "\033[0\r"
      cat "${log}"
    fi
  }
}

analyze() {
  mkdir -p "${tmpdir}"

  entries=()
  readarray -t -O "${#entries[@]}" entries < <(
    find analysis -iname '*.entry.mpv' | sort)

  local entry
  local procs; procs=()
  for entry in "${entries[@]}"; do
    echo "call metaverif"
    exc metaverif "${entry}" "$@" >&2 & procs+=("$!")
  done

  for entry in "${procs[@]}"; do
    exc wait -f "${entry}"
  done
}

err_usage() {
    echo >&1 "USAGE: ${0} analyze PATH"
    echo >&1 "The script will cd into PATH and continue there."
    exit 1
}

main() {
  set -e -o pipefail

  local cmd="$1"; shift || err_usage
  local dir="$1"; shift || err_usage

  cd -- "${dir}"
  tmpdir="target/proverif"

  echo "call main"

  case "${cmd}" in
    analyze) analyze ;;
    pretty) pretty_output_line PREFIX MARK green TEXT ;;
    clean_warnings) clean_warnings ;;
    *) err_usage
  esac
}

# Do not execute main if sourced
(return 0 2>/dev/null) || main "$@"
