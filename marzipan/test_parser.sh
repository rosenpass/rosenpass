#!/usr/bin/env bash
shopt -s nullglob globstar

proverif_repo=$1

# Prerequisites:
# * built ProVerif
# * ran ./test (and aborted it) such that the preparation scripts have been run

# Test pitype files
for f in $proverif_repo/examples/pitype/**/*.pv; do
  [[ $f == *.m4.pv ]] && continue
  echo "$f"
  nix run .# -- parse "$f"
done


# Test cryptoverif files
for f in $proverif_repo/examples/cryptoverif/**/*.pcv; do
  [[ $f == *.m4.pcv ]] && continue
  echo "$f"
  nix run .# -- parse "$f"
done