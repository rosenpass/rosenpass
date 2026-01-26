import sys
from dataclasses import dataclass
from typing import List, Optional

from lark import Lark, Transformer, ast_utils, v_args
from lark.tree import Meta

this_module = sys.modules[__name__]


@dataclass
class Ident(ast_utils.Ast):
    ident: str


@dataclass
class Pterm(ast_utils.Ast, ast_utils.AsList):
    pterm: Ident | int | List


@dataclass
class LetfunDecl(ast_utils.Ast):
    ident: Ident
    typedecl: Optional[List[Ident]]
    pterm: Pterm


parser = Lark("""
start: letfun_decl
_non_empty_seq{x}: x ("," x)*
_maybe_empty_seq{x}: [ _non_empty_seq{x} ]
IDENT:/[a-zA-Z][a-zA-Z0-9À-ÿ'_]*/
NAT: DIGIT+
typeid: IDENT
typedecl: IDENT ":" typeid
pterm: IDENT | NAT | "(" _maybe_empty_seq{pterm} ")"
letfun_decl: "letfun" IDENT [ "(" [ typedecl ] ")" ] "=" pterm "."
%import common (DIGIT, WS)
%ignore WS
""")


class ToAst(Transformer):
    def NAT(self, n):
        n = int(n)
        assert n > 0, "NAT must be an integer > 0"
        return n

    @v_args(inline=True)
    def start(self, x):
        return x


transformer = ast_utils.create_transformer(this_module, ToAst())


def parse(input: str):
    tree = parser.parse(input)
    print(tree)
    ast = transformer.transform(tree)
    print(ast)
    # ast -> input


if __name__ == "__main__":
    parse("""
    letfun test = foo .
    """)

    # parse("""
    # letfun test ( foo : bar ) = foo .
    # """)
