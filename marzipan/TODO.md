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
* ~configurable target directory~
* ~lark parser: multiline comments, how???~
* ~parse errors~
  * ~error when trying with: `nix run .# -- parse ../target/proverif/01_secrecy.entry.i.pv`~
    * ~`in(C, Cinit_conf(Ssskm, Spsk, Sspkt, ic));`~
    * ~                                          ^~
  * ~04_dos… has a syntax error (see below)~
  * ~~rewrite marzipan.awk into Python/LARK~~
  * ~~define a LARK grammar for marzipan.awk rules~~
  * ~~write python code for processing marzipan rules, e.g. alias replacement (step: i.pv->o.pv)~~

## Next Steps

* refactor letfundecl.py into separate modules, shorter functions, …
* write a test framework
  * file in, test succeeds if parsing succeeds
  * file in, test succeeds if parsing and pretty printing succeeds and matches input up to whitespace, and opinionated things like empty square brackets.
* integrate marzipan.awk into Python, somehow
  * review letfundecl.py
    * [X] distill what we learned about grammar style
      * cyclic dependencies are problematic if we wanted to split the grammar into multiple files and import within a lark grammar, because Lark would then complain when one file is not self-containing/completely resolvable
      * rules with multiple sub-rules, if the sub-rules have differently long or different "type signatures", or different constants, except if all sub-rules only have one base type and no different constants
      * rules that have list values in them together with other values: the list value must be moved into a dedicated rule to not be problematic with the AsList class inheritance
      * in the transformer class, each terminal must have a function that handles it
    * [X] learnings w.r.t. pretty_format
      * if an optional attribute is an integer that can be 0, `is not None` must be used explicitly, otherwise 0 will be treated as false; for strings this is fine because we do not want to print empty strings
    * all rules shall have a test file that touches/uses them
  * scale letfundecl.py to the entire grammar
    * rewrite the grammar in the new style
    * generate/write the dataclasses
    * write a test framework that computes test coverage for rules
* options term special cases (c.f. manual page 133, starting with "fun" term)
  * complete with CryptoVerif options
* do not assume that the repo path has subdir marzipan
* do not assume that the repo path has subdir analysis
* rewrite cpp into Python/LARK (step: mpv->i.pv)
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
* low priority: nested comments in ProVerif code

## Idea

* somehow parse Horn clauses output from ProVerif into something more helpful?

## First Target

“it replaces the Bash script and is idiomatic Python code”
