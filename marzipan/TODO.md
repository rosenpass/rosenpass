# TODO for the project of rewriting Marzipan

## Done

* ~~figure out why ProVerif is started on the non-processed mpv file~~
* ~~rework rebound warnings (`clean_warnings` Bash function)~~
  ```bash
  rosenpass$ rosenpass-marzipan run-proverif target/proverif/03_identity_hiding_responder.entry.o.pv target/proverif/03_identity_hiding_responder.entry.log
  ```
* ~~provide log parameter to `rosenpass-marzipan`-call~~ (no, it was intentionally not used)

## Next Steps

* cpp pre-processing stuff
* awk pre-processing stuff
* `pretty_output` Bash function
