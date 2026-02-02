import sys
from dataclasses import dataclass
from typing import List, Optional

from lark import Lark, Transformer, Tree, ast_utils, tree, v_args
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
start: decl*
decl: lemma_decl | query_decl
_non_empty_seq{x}: x ("," x)*
_maybe_empty_seq{x}: [ _non_empty_seq{x} ]
IDENT:/[a-zA-Z][a-zA-Z0-9À-ÿ'_]*/
NAT: DIGIT+
typeid: IDENT
typedecl: _non_empty_seq{IDENT} ":" typeid [ "," typedecl ]
pterm: IDENT | NAT | "(" _maybe_empty_seq{pterm} ")"
letfun_decl: "letfun" IDENT [ "(" [ typedecl ] ")" ] "=" pterm "."
QUERY: "@query"
REACHABLE: "@reachable"
LEMMA: "@lemma"

INFIX: "||"
        | "&&"
        | "="
        | "<>"
        | "<="
        | ">="
        | "<"
        | ">"
gterm: ident_gterm
        | fun_gterm
        | choice_gterm
        | infix_gterm
        | arith_gterm
        | arith2_gterm
        | event_gterm
        | injevent_gterm
        | implies_gterm
        | paren_gterm
        | sample_gterm
        | let_gterm
ident_gterm: IDENT
fun_gterm: IDENT "(" _maybe_empty_seq{gterm} ")" ["phase" NAT] ["@" IDENT]
choice_gterm: "choice" "[" gterm "," gterm "]"
infix_gterm: gterm INFIX gterm
arith_gterm: gterm ( "+" | "-" ) NAT
arith2_gterm: NAT "+" gterm
event_gterm: "event" "(" _maybe_empty_seq{gterm} ")" ["@" IDENT]
injevent_gterm: "inj-event" "(" _maybe_empty_seq{gterm} ")" ["@" IDENT]
implies_gterm: gterm "==>" gterm
paren_gterm: "(" _maybe_empty_seq{gterm} ")"
sample_gterm: "new" IDENT [ "[" [ gbinding ] "]" ]
let_gterm: "let" IDENT "=" gterm "in" gterm

gbinding: "!" NAT "=" gterm [";" gbinding]
        | IDENT "=" gterm [";" gbinding]

lemma: gterm [";" lemma]
         | gterm "for" "{" "public_vars" _non_empty_seq{IDENT} "}" [";" lemma]
         | gterm "for" "{" "secret" IDENT [ "public_vars" _non_empty_seq{IDENT}] "[real_or_random]" "}" [";" lemma]
lemma_annotation: LEMMA ESCAPED_STRING
lemma_decl: [lemma_annotation] lemma_decl_core
lemma_decl_core: "lemma" [ typedecl ";"] lemma "."
query_annotation: (REACHABLE|QUERY) ESCAPED_STRING
query_decl: [query_annotation] query_decl_core
query_decl_core: "query" [ typedecl ";"] query "."
query: gterm ["public_vars" _non_empty_seq{IDENT}] [";" query]
        | "secret" IDENT ["public_vars" _non_empty_seq{IDENT}] [";" query]
        | "putbegin" "event" ":" _non_empty_seq{IDENT} [";" query] // Opportunistically left a space between "event" and ":", ProVerif might not accept it with spaces.
        | "putbegin" "inj-event" ":" _non_empty_seq{IDENT} [";" query]

%import common (DIGIT, WS, ESCAPED_STRING)
%ignore WS
""")


class ToAst(Transformer):
    def NAT(self, n):
        n = int(n)
        assert n > 0, "NAT must be an integer > 0"
        return n

    # @v_args(inline=True)
    def start(self, x):
        return x


transformer = ast_utils.create_transformer(this_module, ToAst())


def gen_tree(asttree: list, column=0, indent=2):
    for node in asttree:
        cur_list = []
        if isinstance(node, Tree):
            cur_list = node.children
        else:
            cur_list = node
        if isinstance(cur_list, list):
            gen_tree(cur_list, column=column + indent)
        else:
            print(f"{' ' * column}{cur_list}")
        # for n in path:
        #     parent = parent.setdefault(n, {})
    # pprint.pprint(root, width=1)


def parse(input: str):
    parsetree = parser.parse(input)
    print(parsetree.pretty())
    ast = transformer.transform(parsetree)
    print("=" * 100)
    # print(ast)
    gen_tree(ast)
    # ast -> input


if __name__ == "__main__":
    parse("""

    @lemma "secrecy: Adv can not learn shared secret key"
    lemma kp:key_prec, skp:kem_sk_prec;
        attacker(trusted_key(kp)).

    @reachable "non-secrecy: The attacker can learn the value of a shared key"
    query k:key;
        attacker(prepare_key(k)) && attacker(k).

    @query "non-interruptability: Adv cannot start a responder session with the same key twice"
    query ic1:InitConf_t, ic2:InitConf_t, ck:key, t1:time, t2:time;
        event(ResponderSession(ic1, ck))@t1 && event(ResponderSession(ic2, ck))@t2
        ==> t1 = t2.
    """)

    # parse("""
    # letfun test ( foo : bar ) = foo .
    # """)
