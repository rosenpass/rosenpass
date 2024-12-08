#! /usr/bin/env bash

set -e -o pipefail

OUTPUT_DIR="target/grcov"

log() {
  echo >&2 "$@"
}

exc() {
  echo '$' "$@"
  "$@"
}

main() {
  exc cd "$(dirname "$0")"

  local open="0"
  if [[ "$1" == "--open" ]]; then
    open="1"
  fi

  exc cargo llvm-cov --all-features --workspace --doctests

  exc rm -rf "${OUTPUT_DIR}"
  exc mkdir -p "${OUTPUT_DIR}"
  exc grcov target/llvm-cov-target/ --llvm  -s . --branch \
    --binary-path ./target/llvm-cov-target/debug/deps \
    --ignore-not-existing --ignore '../*' --ignore "/*" \
    --excl-line '^\s*#\[(derive|repr)\(' \
    -t lcov,html,markdown -o "${OUTPUT_DIR}"

  if (( "${open}" == 1 )); then
    xdg-open "${PWD}/${OUTPUT_DIR}/html/index.html"
  fi

  log ""
  log "Generated reports in \"${PWD}/${OUTPUT_DIR}\"."
  log "Open \"${PWD}/${OUTPUT_DIR}/html/index.html\" to view HTML report."
  log ""
}

main "$@"
