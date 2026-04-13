from __future__ import annotations

import cProfile
import dataclasses
import io
import pprint
import pstats
import sys
from copy import deepcopy
from dataclasses import asdict, dataclass, fields, is_dataclass
from pstats import SortKey
from typing import List, Optional, Tuple

from lark import Lark, Token, Transformer, Tree, ast_utils, tree, v_args
from lark.tree import Meta
from typing_extensions import Type

from util import T

this_module = sys.modules[__name__]

pp = pprint.PrettyPrinter(indent=4, width=50)


@dataclass
class Ident(ast_utils.Ast):
    ident: str


@dataclass
class Typeid(ast_utils.Ast):
    ident: str


@dataclass
class Infix(ast_utils.Ast):
    infix: str


@dataclass
class Pterm(ast_utils.Ast, ast_utils.AsList):
    pterm: Ident | int | List


@dataclass
class Gbinding(ast_utils.Ast):
    value: int | Ident


@dataclass
class IdentGterm(ast_utils.Ast):
    ident_gterm: Ident


@dataclass
class GtermList(ast_utils.Ast, ast_utils.AsList):
    gterms: List[Gterm]


@dataclass
class FunGterm(ast_utils.Ast):
    # def __init__(self, arg1, arg2=None, arg3=None, arg4=None, arg5=None):
    #    breakpoint()

    fun_gterm: Ident
    gterm_list: GtermList
    phase: Optional[int] = None
    at: Optional[Ident] = None


@dataclass
class InfixGterm(ast_utils.Ast):
    first_infix_gterm: Gterm
    infix: Infix
    second_infix_gterm: Gterm


@dataclass
class ChoiceGterm(ast_utils.Ast):
    choice_gterm: Optional[Tuple[Gterm, Gterm]] = None


@dataclass
class ArithGterm(ast_utils.Ast):
    arith_gterm: Gterm
    operand: str
    value: int | Gterm


@dataclass
class Arith2Gterm(ast_utils.Ast):
    value: int | Gterm
    arith_gterm: Gterm


@dataclass
class InjEventGterm(ast_utils.Ast):
    event_gterms: GtermList
    at: Optional[Ident] = None

    def pretty_print(self, indent=0):
        return ""


@dataclass
class ImpliesGterm(ast_utils.Ast):
    left: Gterm
    right: Gterm

    def pretty_print(self, column=0, indent=2):
        return f"{self.left.pretty_print(column, indent)} ==> {self.right.pretty_print(column, indent)}"


@dataclass
class EventGterm(ast_utils.Ast):
    event_gterms: GtermList
    at: Optional[Ident] = None


@dataclass
class ParenGterm(ast_utils.Ast):
    paren_gterms: Optional[GtermList] = None


@dataclass
class LetGterm(ast_utils.Ast):
    ident: Ident
    first_gterm: Gterm
    second_gterm: Gterm


@dataclass
class SampleGterm(ast_utils.Ast):
    ident: Ident
    gbintion: Optional[Gbinding] = None


@dataclass
class Gterm(ast_utils.Ast):
    gterm: (
        IdentGterm
        | FunGterm
        | InfixGterm
        | ChoiceGterm
        | ArithGterm
        | Arith2Gterm
        | InjEventGterm
        | ImpliesGterm
        | EventGterm
        | ParenGterm
        | SampleGterm
        | LetGterm
    )

    def pretty_print(self, column=0, indent=2):
        return f"{' ' * indent}{self}"


@dataclass
class Typedecl(ast_utils.Ast):
    type_list: List[Ident]
    typeid: Typeid
    optional_typedecl: Optional[Type] = None


@dataclass
class LetfunDecl(ast_utils.Ast):
    ident: Ident
    typedecl: Optional[List[Ident]]
    pterm: Pterm


@dataclass
class LemmaGterm(ast_utils.Ast):
    gterm: Gterm
    lemma: Optional[Lemma] = None


@dataclass
class LemmaPublicVars(ast_utils.Ast):
    gterm: Gterm
    public_vars: Optional[List] = None
    lemma: Optional[Lemma] = None


@dataclass
class LemmaPublicVarsSecret(ast_utils.Ast):
    gterm: Gterm
    secret: Ident
    public_vars: Optional[List] = None
    lemma: Optional[Lemma] = None


@dataclass
class Lemma(ast_utils.Ast):
    lemma: LemmaGterm | LemmaPublicVars | LemmaPublicVarsSecret

    # def __post_init__(self):
    #    print(f"[constructor] Lemma: lemma={self.lemma}")

    # def __init__(self, lemma=None, arg2=None, arg3=None):
    #    print(f"[constructor] Lemma: {lemma}, {arg2}, {arg3}")
    #    self.lemma = lemma
    # def pretty_print(self, column=0, indent=2):
    #     print(f"{self}: not implemented")


@dataclass
class LemmaDeclCore(ast_utils.Ast):
    typedecl: Optional[Typedecl]
    lemma: Lemma

    def pretty_print(self, column=0, indent=2):
        print(f"{self}: not implemented")


@dataclass
class LemmaAnnotation(ast_utils.Ast):
    annotation: str


@dataclass
class LemmaDecl(ast_utils.Ast):
    lemma_decl_annotation: Optional[LemmaAnnotation]
    lemma_decl_core: LemmaDeclCore

    pptemplate = "{% if lemma_decl_annotation %}@lemma {{lemma_decl_annotation}}{% endif %}{{lemma_decl_core}}"

    # def pretty_print(self, column=0, indent=2):
    #    return f"{'@lemma' + a if a is not None else ''}{l}"

    def pretty_print(self, column=0, indent=2):
        a = self.lemma_decl_annotation
        l = self.lemma_decl_core
        return f"{'@lemma' + a.pretty_print(column, indent) if a is not None else ''}{l.pretty_print(column, indent)}"


@dataclass
class Query(ast_utils.Ast):
    query: QueryGterm | QuerySecret | QueryPutBegin


@dataclass
class QueryAnnotation(ast_utils.Ast):
    annotation: str


@dataclass
class ReachableAnnotation(ast_utils.Ast):
    annotation: str


@dataclass
class QueryDeclCore(ast_utils.Ast):
    typedecl: Optional[Typedecl]
    query: Query


@dataclass
class QueryDecl(ast_utils.Ast):
    query_decl_annotation: Optional[QueryAnnotation | ReachableAnnotation]
    query_decl_core: QueryDeclCore

    def pretty_print(self, column=0, indent=2):
        return "QueryDecl not implemented"


@dataclass
class QueryGterm(ast_utils.Ast):
    gterm: Gterm
    public_vars: Optional[List[Ident]] = None
    query: Optional[Query] = None


@dataclass
class QuerySecret(ast_utils.Ast):
    ident: Ident
    public_vars: Optional[List[Ident]] = None
    query: Optional[Query] = None


@dataclass
class QueryPutBegin(ast_utils.Ast):
    event_list: List[Ident]
    query: Optional[Query] = None


@dataclass
class Decl(ast_utils.Ast):
    decl: LemmaDecl | QueryDecl

    def pretty_print(self, column=0, indent=2):
        return self.decl.pretty_print(column, indent)


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
_QUERY: "@query"
_REACHABLE: "@reachable"
_LEMMA: "@lemma"

INFIX: "||"
        | "&&"
        | "="
        | "<>"
        | "<="
        | ">="
        | "<"
        | ">"
gterm: ident_gterm
        | event_gterm
        | fun_gterm
        | choice_gterm
        | infix_gterm
        | arith_gterm
        | arith2_gterm
        | injevent_gterm
        | implies_gterm
        | paren_gterm
        | sample_gterm
        | let_gterm
gterm_list: _maybe_empty_seq{gterm}
ident_gterm: IDENT
fun_gterm: IDENT "(" gterm_list ")" ["phase" NAT] ["@" IDENT]
choice_gterm: "choice" "[" gterm "," gterm "]"
infix_gterm: gterm INFIX gterm
arith_gterm: gterm ( "+" | "-" ) NAT
arith2_gterm: NAT "+" gterm
event_gterm: "event" "(" gterm_list ")" ["@" IDENT]
injevent_gterm: "inj-event" "(" gterm_list ")" ["@" IDENT]
implies_gterm: gterm "==>" gterm
paren_gterm: "(" gterm_list ")"
sample_gterm: "new" IDENT [ "[" [ gbinding ] "]" ]
let_gterm: "let" IDENT "=" gterm "in" gterm

gbinding: "!" NAT "=" gterm [";" gbinding]
        | IDENT "=" gterm [";" gbinding]

lemma_gterm: gterm [";" lemma]
lemma_public_vars: gterm "for" "{" "public_vars" _non_empty_seq{IDENT} "}" [";" lemma]
lemma_public_vars_secret: gterm "for" "{" "secret" IDENT [ "public_vars" _non_empty_seq{IDENT}] "[real_or_random]" "}" [";" lemma]
lemma: lemma_gterm
         | lemma_public_vars
         | lemma_public_vars_secret
lemma_annotation: _LEMMA ESCAPED_STRING
lemma_decl: [lemma_annotation] lemma_decl_core
lemma_decl_core: "lemma" [ typedecl ";"] lemma "."

query_gterm: gterm ["public_vars" _non_empty_seq{IDENT}] [";" query]
query_secret: "secret" IDENT ["public_vars" _non_empty_seq{IDENT}] [";" query]
query_putbegin: "putbegin" "event" ":" _non_empty_seq{IDENT} [";" query] // Opportunistically left a space between "event" and ":", ProVerif might not accept it with spaces.
| "putbegin" "inj-event" ":" _non_empty_seq{IDENT} [";" query]
query: query_gterm
        | query_secret
        | query_putbegin
query_annotation: _QUERY ESCAPED_STRING
reachable_annotation: _REACHABLE ESCAPED_STRING
query_decl: [ query_annotation | reachable_annotation] query_decl_core
query_decl_core: "query" [ typedecl ";"] query "."

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


def ast_deepcopy_except(node):
    if is_dataclass(node):
        if (
            isinstance(node, QueryAnnotation)
            or isinstance(node, ReachableAnnotation)
            or isinstance(node, LemmaAnnotation)
        ):
            return None

        dataclass_type = type(node)
        kwargs = {}

        for field in fields(node):
            if isinstance(node, QueryDecl) and field.name == "query_decl_annotation":
                kwargs[field.name] = None
            elif isinstance(node, LemmaDecl) and field.name == "lemma_decl_annotation":
                kwargs[field.name] = None
            else:
                child_node = getattr(node, field.name)
                child_node_deepcopy = ast_deepcopy_except(child_node)
                kwargs[field.name] = child_node_deepcopy

        return dataclass_type(**kwargs)

    elif isinstance(node, list):
        return [ast_deepcopy_except(item) for item in node]
    else:
        return deepcopy(node)


def parsetree_deepcopy_except(nodes: list, data_exclusion_list: list):
    elements = []
    for node in nodes:
        if isinstance(node, Tree):
            if node.data not in data_exclusion_list:
                children = parsetree_deepcopy_except(node.children, data_exclusion_list)
                elements.append(Tree(node.data, children))
        else:
            elements.append(deepcopy(node))
    return elements


# INPUT: dict_tree = {"A": {"b": {"c": {"d": {}, "e": {"f": {}}}}}}
# OUTPUT:
# A
# |-b
#     |-c
#         |-d
#         |-e
#             |-f
def print_tree_level(dct, column=0, indent=2):
    for key, value in dct.items():
        print(f"{' ' * (column - 1)}{key} {'|-' if column else ''}")
        print_tree_level(value, column + 1)


def print_tree(asttree: list, column=0, indent=2):

    def handle_dict(d):
        for key, value in d.items():
            print(f"{' ' * (column)}{key} [handle_dict]")
            print_tree(value, column + 1)

    def handle_dataclass(d):
        # if hasattr(d, "pretty_print") and callable(getattr(d, "pretty_print")):
        #    pp = f"[{d.pretty_print()}]"
        # else:
        #    pp = ""

        # print(f"{' ' * (column)}{type(d).__name__} [handle_dataclass: class name] {pp}")
        print(f"{' ' * (column)}{type(d).__name__} [handle_dataclass: class name]")
        for f in fields(d):
            next_d = getattr(d, f.name)
            if next_d is not None:
                print(f"{' ' * (column + 1)}{f.name} [handle_dataclass: attr]")
                print_tree(next_d, column + 2)

    def inner(node):
        cur_list = []
        if is_dataclass(node):
            # pp.pprint(asdict(node))
            # dct = asdict(node)
            handle_dataclass(node)
        elif isinstance(node, dict):
            handle_dict(node)
        else:
            if isinstance(node, Tree):
                print(f"{' ' * column}{node.data} [Tree]")
                cur_list = node.children
            else:
                cur_list = node

            if isinstance(cur_list, list):
                print_tree(cur_list, column=column + indent)
            else:
                if cur_list is not None:
                    print(f"{' ' * column}{cur_list} [else]")

    if isinstance(asttree, list):
        for node in asttree:
            inner(node)
    else:
        inner(asttree)


def pretty_print(asttree: list, column=0, indent=2):

    def handle_dataclass(d):
        if hasattr(d, "pretty_print") and callable(getattr(d, "pretty_print")):
            pp = f"{d.pretty_print(column, indent)}"
        else:
            pp = "not implemented"

        print(pp)

    def inner(node):
        if is_dataclass(node):
            handle_dataclass(node)
        else:
            assert False

    if isinstance(asttree, list):
        for node in asttree:
            inner(node)
    else:
        inner(asttree)


# def print_class_tree(classtree: list, column=0, indent=2):
#     for o in classtree:
#         if isinstance(o, Tree):
#             print(f"{' ' * column}{o}")


def parse(input: str):
    parsetree = parser.parse(input)
    # print("=" * 100)
    # print("print parsetree")
    # print(parsetree.pretty())
    ast = transformer.transform(parsetree)
    # print("=" * 100)
    # print("print_tree ast")
    # print_tree(ast)
    # print("=" * 100)
    # print(ast)
    # # clean_ast = parsetree_deepcopy_except(
    # #     ast, ["lemma_annotation", "query_annotation", "reachable_annotation"]
    # # )
    pr = cProfile.Profile()
    pr.enable()
    clean_ast = ast_deepcopy_except(ast)
    pr.disable()
    s = io.StringIO()
    sortby = SortKey.CUMULATIVE
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats()
    print(s.getvalue())
    # print("=" * 100)
    print("print clean_ast")
    print(clean_ast)
    print("=" * 100)
    print("print_tree clean_ast")
    print_tree(clean_ast)

    print("=" * 100)
    pretty_print(clean_ast)

    # print("=" * 100)
    # print("=" * 100)
    # print(ast)


if __name__ == "__main__":
    parse("""
        @lemma "secrecy: Adv can not learn shared secret key"
        lemma kp:key_prec, skp:kem_sk_prec;
            attacker(trusted_key(kp)).

        @query "non-interruptability: Adv cannot start a responder session with the same key twice"
        query ic1:InitConf_t, ic2:InitConf_t, ck:key, t1:time, t2:time;
            event(ResponderSession(ic1, ck))@t1 && event(ResponderSession(ic2, ck))@t2
            ==> t1 = t2.

        @reachable "non-secrecy: The attacker can learn the value of a shared key"
        query k:key;
            attacker(prepare_key(k)) && attacker(k).

        @lemma "secrecy: The adversary can learn a trusted kem pk only by using the reveal oracle"
        lemma skp:kem_sk_prec;
            attacker(kem_pub(trusted_kem_sk(skp)))
              ==> event(RevealPk(kem_pub(trusted_kem_sk(skp)))).

        @lemma "secrecy: Attacker knowledge of a kem sk implies the key is not trusted"
          lemma k:kem_sk, kp:kem_sk_prec;
            attacker(prepare_kem_sk(k)) && attacker(k) ==> k <> trusted_kem_sk(kp).

        @lemma "asymmetric secrecy: Secure SSKI is sufficient for ck secrecy after trusted InitHello transmission from responder perspective"
        lemma ck_ini:key, ck:key, any_psk:key, any_sskr:kem_sk, PSsski:kem_sk_prec, any_epki:kem_pk, any_epti:key, PSspti:seed_prec;
            let secure_spki = kem_pub(trusted_kem_sk(PSsski)) in
            let secure_spti = rng_key(trusted_seed(PSspti)) in
            attacker(ck)
            && event(OskOinit_hello(ck_ini, ck, any_psk, any_sskr, secure_spki, any_epki, any_epti, secure_spti)).
    """)
