# Rewriting analyze.sh in Python

* `../analyze.sh` is the old script
* `src/analyze.sh` is the new script

* call the old script from the Rosenpass repository's root directory with `./analyze.sh`
* call the new script:
  * `nix run .# -- analyze analyze $repo` where `$repo` is the absolute(?) path to the root directory of the Rosenpass repository.
