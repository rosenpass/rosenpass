# TODO for the project of rewriting Marzipan

## Done

* ~~figure out why ProVerif is started on the non-processed mpv file~~
* ~~rework rebound warnings (`clean_warnings` Bash function)~~
  ```bash
  rosenpass$ rosenpass-marzipan run-proverif target/proverif/03_identity_hiding_responder.entry.o.pv target/proverif/03_identity_hiding_responder.entry.log
  ```
* ~~provide log parameter to `rosenpass-marzipan`-call~~ (no, it was intentionally not used)
* ~~cpp pre-processing stuff~~
* ~~awk pre-processing stuff~~

## Next Steps

* `pretty_output` Bash function
  * ~~pretty_output_line~~
  * awk RESULT flush in marzipan()
  * click function intervention weirdness
  * why is everything red in the pretty output? (see line 96 in __init__.py)
* move the whole metaverif function to Python
* move the whole analyze function to Python
  * find the files
  * start subprocesses in parallel
  * wait for them to finish
* think about next steps
  * integrate this upstream, into the CI?
  * “make it beautiful” steps? more resiliency to working directory?
  * rewrite our awk usages into Python/…?
    * yes, possibly as extension to the LARK grammar
    * and rewrite the AST within Python
    * reconstruct ProVerif input file for ProVerif
  * rewrite our CPP usages into Python/…?
