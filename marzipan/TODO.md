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
* ~~`pretty_output` Bash function~~
  * ~~pretty_output_line~~
  * ~~click function intervention weirdness~~
  * ~~why is everything red in the pretty output? (see line 96 in __init__.py)~~
  * ~~awk RESULT flush in marzipan()~~
  * ~~move the whole metaverif function to Python~~
* ~move the whole analyze function to Python~
  * ~find the files~
  * ~start subprocesses in parallel~
  * ~wait for them to finish~
* ~~rebase from main~~
* ~~see if we still need the `extra_args is None` check in `_run_proverif`~`
* ~~set colors differently to prevent injection attack~~
  * ~~by calling a function~~
  * ~~by prepared statements~~
* ~~standalone function parse_result_line is no longer necessary~~
* ~~is the clean function still necessary?~~
* ~~implement better main function for click~~
* ~~why does analyze fail when the target/proverif directory is not empty?~~
* ~~return an exit status that is meaningful for CI~~
* ~~exception handling in analyze() and in run_proverif()~~
* ~~refactor filtering in run_proverif (see karo's comment)~~

## Next Steps
* configurable target directory
* do not assume that the repo path has subdir analysis and marzipan
* integrate marzipan.awk into Python, somehow
* rewrite marzipan.awk into Python/LARK
* rewrite cpp into Python/LARK
* integrate the Nix flake into the main Nix flake
  * pull the gawk dependency into the Nix flake
* think about next steps
  * integrate this upstream, into the CI?
  * “make it beautiful” steps? more resiliency to working directory?
  * rewrite our awk usages into Python/…?
    * yes, possibly as extension to the LARK grammar
    * and rewrite the AST within Python
    * reconstruct ProVerif input file for ProVerif
  * rewrite our CPP usages into Python/…?


“it replaces the Bash script and is idiomatic Python code”
