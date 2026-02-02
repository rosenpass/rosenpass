import re
import sys
from pathlib import Path

from lark import Lark, Token, Transformer, exceptions, tree

# taken from Page 17 in the ProVerif manual
# At the moment, we do not reject a ProVerif model that uses reserved words as identifier,
# because this caused problems with the LARK grammar. We plan to check this in a later
# processing step.
reserved_words = [
    "among",
    "axiom",
    "channel",
    "choice",
    "clauses",
    "const",
    "def",
    "diff",
    "do",
    "elimtrue",
    "else",
    "equation",
    "equivalence",  # no rule yet (this is CryptoVerif-specific)
    "event",
    "expand",
    "fail",
    "for",
    "forall",
    "foreach",
    "free",
    "fun",
    "get",
    "if",
    "implementation",  # no rule yet (this is CryptoVerif-specific)
    "in",
    "inj-event",
    "insert",
    "lemma",
    "let",
    "letfun",
    "letproba",
    "new",
    "noninterf",
    "noselect",
    "not",
    "nounif",
    "or",
    "otherwise",
    "out",
    "param",
    "phase",
    "pred",
    "proba",
    "process",
    "proof",
    "public_vars",
    "putbegin",
    "query",
    "reduc",
    "restriction",
    "secret",
    "select",
    "set",
    "suchthat",
    "sync",
    "table",
    "then",
    "type",
    "weaksecret",
    "yield",
]

ident_regex = (
    "/^" + "".join(f"(?!{w}$)" for w in reserved_words) + "[a-zA-Z][a-zA-Z0-9À-ÿ'_]*/"
)

"""
It might be desirable to move the grammar files around such that we only need
to import _main.lark and import all other .larks files in _main.lark.
This does not work at the moment due to cyclic dependencies between the grammar files,
so we are loading all files as strings and simply concatenating for now...
"""
# gawk_file = "./src/grammars/marzipan_awk.lark"
# gproverif = "./src/grammars/proverif.lark"
# gmain = "./src/grammar/main.lark"
# gfile = gmain
# with open(gfile) as f:
#     parser = Lark(
#         f
#         #grammar=grammar,
#         # debug=True,
#         # lexer_callbacks={"COMMENT": comments.append},
#     )
# files = sorted(Path("./src/grammar").glob("*.lark"))
# gfiles = [f for f in files if not f.name.startswith("_")]
# gfiles = ["common.lark", "decl.lark", "process.lark", "query.lark", "term.lark"]
# grammar = "\n".join(parent_dir + f.read_text() for f in gfiles)

parent_dir = "./src/grammar/"

common_rules = Path(parent_dir + "common.lark").read_text()
decl_rules = Path(parent_dir + "decl.lark").read_text()
process_rules = Path(parent_dir + "process.lark").read_text()
query_rules = Path(parent_dir + "query.lark").read_text()
lemma_rules = Path(parent_dir + "lemma.lark").read_text()
term_rules = Path(parent_dir + "term.lark").read_text()
cryptoverif_rules = Path(parent_dir + "cryptoverif.lark").read_text()

# marzipan additives
common_rules = (
    """
QUERY: "@query"
REACHABLE: "@reachable"
LEMMA: "@lemma"
"""
    + common_rules
)


# add @query and @reachable to query_decl, @lemma to lemma_decl
def modify_decl_rule(rules: str, decl_rule: str, new_rule: str) -> str:
    old_decl_renamed = f"{decl_rule}_core"
    rename_target = f"{decl_rule}\s*:"
    # rename *_decl -> *_decl_core
    rules, count = re.subn(rename_target, f"{old_decl_renamed}:", rules, count=1)
    if count == 0:
        raise RuntimeError("*_decl not found!")
    wrapper = f"{decl_rule}: {new_rule} {old_decl_renamed}"
    old_decl_target = f"{old_decl_renamed}\s*:"
    # get index of *_decl_core rule
    match = re.search(old_decl_target, rules, flags=re.MULTILINE)
    if not match:
        raise RuntimeError("*_decl_core: rule not found after rename")
    insert_pos = match.start()
    rules = rules[:insert_pos] + wrapper + "\n" + rules[insert_pos:]
    return rules


query_rules = modify_decl_rule(
    query_rules, "query_decl", "[(REACHABLE|QUERY) ESCAPED_STRING]"
)

lemma_rules = modify_decl_rule(lemma_rules, "lemma_decl", "[LEMMA ESCAPED_STRING]")

grammar = (
    common_rules + decl_rules + process_rules + query_rules + lemma_rules + term_rules + cryptoverif_rules
)

with open(Path(parent_dir + "generated_grammar.lark"), "w") as f:
    f.write(grammar)

parser = Lark(grammar)

# COMMENT:  /\(\*(\*(?!\))|[^*])*\*\)/
# COMMENT:  "(*" /(\*(?!\))|[^*])*/  "*)"
# comment: /\(\*(?:(?!\(\*|\*\)).|(?R))*\*\)/

# TODO Open ProVerif compatibility questions
# TODO * does it allow leading zeros for NAT?
# TODO * tag is not defined? is it ident?
# TODO * are spaces between "event" and ":" allowed?
# TODO * spaces between "nat" and "("? "choice" and "["?


def parsertest(input):
    parsetree = parser.parse(input)
    # tree.pydot__tree_to_png(parsetree, name + ".png")
    return parsetree


def parse_main(file_path):
    with open(file_path, "r") as f:
        content = f.read()
        # print(content)
        parsertest(content)
