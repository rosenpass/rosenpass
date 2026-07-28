import re
from pathlib import Path

from lark import Discard, Lark, Transformer
from lark.reconstruct import Reconstructor


class TreeVisitor(Transformer):
    # def __default_token__(self, token):
    #     if token.type == "PROCESS":
    #         return ""
    #     elif token.type == "IDENT":
    #         return token
    #         # return f"<ident>{token}</ident>"

    # def __default__(self, data, children, meta):
    # #return "\n".join([c for c in children if c])
    # amazing_str = ""
    # for c in children:
    #     if c:
    #         amazing_str += c
    # return f"<{data}> {amazing_str} </{data}>"

    # lemma_decl_core: original_stuff
    # lemma_annotation: [LEMMA ESCAPED_STRING]
    # lemma_decl: lemma_annotation lemma_decl_core
    # lemma_decl: original_stuff
    def lemma_annotation(self, children):
        return Discard

    def query_annotation(self, children):
        return Discard


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

parser = Lark.open("proverif/grammars/marzipan.lark", rel_to=__file__, maybe_placeholders=False)

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


"""
    parse in i.pv file using new awk-marzipan grammar,
    eliminate aliases from i.pv using lark TreeVisitor,
    then return o.pv (awk_prep)
"""


def parse_main(ipv_path, opv_path):
    with open(ipv_path, "r") as f:
        content = f.read()
        # content += "\nprocess main"

        forest = parsertest(content)
        with open("i.pv", "w") as ipvf:
            ipvf.write(forest.pretty())

        tree = TreeVisitor().transform(forest)
        # TODO: tree -> o.pv
        new_json = Reconstructor(parser).reconstruct(tree)

        with open(opv_path, "w") as opvf:
            # opvf.write(tree.pretty())
            opvf.write(new_json)
