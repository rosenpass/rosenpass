from __future__ import annotations

import cProfile
import dataclasses
import io
import pprint
import pstats
import sys
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass, fields, is_dataclass
from pstats import SortKey
from string import Formatter
from typing import Any, List, Optional, Tuple

from lark import Lark, Token, Transformer, Tree, ast_utils, tree, v_args
from lark.tree import Meta
from typing_extensions import Type

from util import T

this_module = sys.modules[__name__]

pp = pprint.PrettyPrinter(indent=4, width=50)


CONFIG = {
    "space": " ",
    "pterm": {
        "list_separator": ", ",
        "left_bracket": "(",
        "right_bracket": ")",
        "empty_brackets": True,
    },
    "gterm": {
        "list_separator": ", ",
        "left_bracket": "",
        "right_bracket": "",
        "empty_brackets": False,
    },
    "infix_separator": " ",
    "line_break": "\n",
}


class AttrMap:
    """
    Small wrapper so that dict values can be accessed as {ctx.foo}
    instead of only {ctx[foo]}.
    """

    def __init__(self, mapping: Mapping[str, Any]):
        self._mapping = mapping

    def __getattr__(self, name: str) -> Any:
        try:
            return self._mapping[name]
        except KeyError:
            raise AttributeError(name) from None

    def __getitem__(self, name: str) -> Any:
        return self._mapping[name]

    def __contains__(self, name: str) -> bool:
        return name in self._mapping

    def __str__(self) -> str:
        return str(self._mapping)


def get_list_config(format_spec: str, ctx: Mapping[str, Any] | None = None):
    if ctx:
        if format_spec in ctx:
            list_config = ctx[format_spec]
            return (
                list_config["left_bracket"],
                list_config["right_bracket"],
                list_config["list_separator"],
                list_config["empty_brackets"],
            )
    return None


def pretty(
    value: Any, column: int, format_spec: str, ctx: Mapping[str, Any] | None = None
) -> str:
    if isinstance(value, List):
        left_bracket, right_bracket, list_separator, empty_brackets = get_list_config(
            format_spec, ctx
        )
        if len(value) > 1:
            return (
                left_bracket
                + list_separator.join(
                    pretty(item, column=column, format_spec=format_spec, ctx=ctx)
                    for item in value
                )
                + right_bracket
            )
        elif len(value) == 1:
            return pretty(value[0], column=column, format_spec=format_spec, ctx=ctx)
        else:
            return left_bracket + right_bracket if empty_brackets else ""

    pretty_print = getattr(value, "pretty_print", None)

    if callable(pretty_print):
        return pretty_print(column=column)

    return str(value)


class PrettyFormatter(Formatter):
    def __init__(
        self,
        root: Any,
        *,
        column: int,
        ctx: Mapping[str, Any] | None = None,
    ):
        super().__init__()
        self.root = root
        self.column = column
        self.ctx = AttrMap(ctx or {})

    def get_value(
        self,
        key: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        if key == "self":
            return self.root

        if key == "ctx":
            return self.ctx

        if isinstance(key, str):
            return getattr(self.root, key)

        return super().get_value(key, args, kwargs)

    def format_field(self, value: Any, format_spec: str) -> str:
        child_column = self.column

        return pretty(value, column=child_column, format_spec=format_spec, ctx=self.ctx)


def pretty_format(obj: Any, template: str, *, column: int = 0) -> str:
    return PrettyFormatter(obj, column=column, ctx=CONFIG).format(template)


# type Ident = str
# @dataclass
# class Ident(ast_utils.Ast):
#     ident: str

#     def pretty_print(self, column : int = 0):
#         if isinstance(self.ident, Token):
#             return f"{self.ident.value}"
#         else:
#             return "whaaaaat"


@dataclass
class TypeDecl(ast_utils.Ast):
    ident: Token

    def pretty_print(self, column: int = 0):
        template = "type {ident}."
        return pretty_format(self, template, column=column)


@dataclass
class Typeid(ast_utils.Ast):
    ident: Token

    def pretty_print(self, column: int = 0):
        template = "{ident}"
        return pretty_format(self, template, column=column)


# @dataclass
# class Infix(ast_utils.Ast):
#     infix: Token

#     def pretty_print(self, column : int = 0):
#         return self.infix.value


@dataclass
class Pterm(ast_utils.Ast, ast_utils.AsList):
    pterm: Ident | int | List

    def pretty_print(self, column: int = 0):
        template = "{pterm:pterm}"
        return pretty_format(self, template, column=column)


@dataclass
class Gbinding(ast_utils.Ast):
    value: int | Ident
    gterm: Gterm
    gbinding: Optional[Gbinding] = None

    def pretty_print(self, column: int = 0):
        result = ""
        if type(self.value) is int:
            result = pretty_format(self, "!{value}={gterm}", column=column)
        else:
            result = pretty_format(self, "{value}={gterm}", column=column)

        if self.gbinding is not None:
            result += pretty_format(self, ";{gbinding}", column=column)

        return result


@dataclass
class IdentGterm(ast_utils.Ast):
    ident_gterm: Ident

    def pretty_print(self, column: int = 0):
        return pretty_format(self, "{ident_gterm}", column=column)


@dataclass
class GtermList(ast_utils.Ast, ast_utils.AsList):
    gterms: Optional[List[Gterm]] = None

    def pretty_print(self, column: int = 0):
        # TODO: move the None case into the Formatter? none_repr config entry, and if clause in the beginning of pretty function
        if self.gterms is None:
            return ""
        return pretty_format(self, "{gterms:gterm}", column=column)


@dataclass
class FunGterm(ast_utils.Ast):
    # def __init__(self, arg1, arg2=None, arg3=None, arg4=None, arg5=None):
    #    breakpoint()

    fun_gterm: Ident
    gterm_list: GtermList
    phase: Optional[int] = None
    at: Optional[Ident] = None

    def pretty_print(self, column: int = 0):
        str = ""
        str += self.fun_gterm.value
        str += "("
        str += self.gterm_list.pretty_print()
        str += ")"
        if self.phase is not None:
            str += f"phase {self.phase}"
        if self.at is not None:
            str += f"@ {self.at}"
        return str


@dataclass
class InfixGterm(ast_utils.Ast):
    first_infix_gterm: Gterm
    infix: Infix
    second_infix_gterm: Gterm

    def pretty_print(self, column: int = 0):
        return f"{self.first_infix_gterm.pretty_print()} {self.infix} {self.second_infix_gterm.pretty_print()}"


@dataclass
class ChoiceGterm(ast_utils.Ast):
    choice_gterm: Tuple[Gterm, Gterm]

    def pretty_print(self, column: int = 0):
        left, right = self.choice_gterm
        return f"choice [ {left.pretty_print()}, {right.pretty_print()} ]"


@dataclass
class ArithGterm(ast_utils.Ast):
    arith_gterm: Gterm
    operand: str
    value: int

    def pretty_print(self, column: int = 0):
        return f"{self.arith_gterm.pretty_print()} {self.operand} {self.value}"


@dataclass
class Arith2Gterm(ast_utils.Ast):
    value: int
    arith_gterm: Gterm

    def pretty_print(self, column: int = 0):
        return f"{self.value} + {self.arith_gterm.pretty_print()}"


@dataclass
class InjeventGterm(ast_utils.Ast):
    event_gterms: GtermList
    at: Optional[Ident] = None

    def pretty_print(self, column: int = 0):
        result = f"inj-event ( {self.event_gterms.pretty_print()} )"
        if self.at is not None:
            result += f"@ {self.at}"
        return result


@dataclass
class ImpliesGterm(ast_utils.Ast):
    left: Gterm
    right: Gterm

    def pretty_print(self, column: int = 0):
        return f"{self.left.pretty_print()} ==> {self.right.pretty_print()}"


@dataclass
class EventGterm(ast_utils.Ast):
    event_gterms: GtermList
    at: Optional[Ident] = None

    def pretty_print(self, column: int = 0):
        str = "event ("
        str += self.event_gterms.pretty_print()
        str += ")"
        if self.at is not None:
            str += "@" + self.at.value
        return str


@dataclass
class ParenGterm(ast_utils.Ast):
    paren_gterms: GtermList

    def pretty_print(self, column: int = 0):
        return "(" + self.paren_gterms.pretty_print() + ")"


@dataclass
class LetGterm(ast_utils.Ast):
    ident: Ident
    first_gterm: Gterm
    second_gterm: Gterm

    def pretty_print(self, column: int = 0):
        return f"let {self.ident.value} = {self.first_gterm.pretty_print()} in\n {self.second_gterm.pretty_print()}"


@dataclass
class SampleGterm(ast_utils.Ast):
    ident: Ident
    gbinding: Optional[Gbinding] = None

    def pretty_print(self, column: int = 0):
        str = f"new {self.ident.value}"
        if self.gbinding is not None:
            str += "["
            str += self.gbinding.pretty_print()
            str += "]"
        return str


@dataclass
class Gterm(ast_utils.Ast):
    gterm: (
        IdentGterm
        | FunGterm
        | InfixGterm
        | ChoiceGterm
        | ArithGterm
        | Arith2Gterm
        | InjeventGterm
        | ImpliesGterm
        | EventGterm
        | ParenGterm
        | SampleGterm
        | LetGterm
    )

    def pretty_print(self, column: int = 0):
        if isinstance(
            self.gterm,
            (
                IdentGterm,
                FunGterm,
                InfixGterm,
                ChoiceGterm,
                ArithGterm,
                Arith2Gterm,
                InjeventGterm,
                ImpliesGterm,
                EventGterm,
                ParenGterm,
                SampleGterm,
                LetGterm,
            ),
        ):
            return self.gterm.pretty_print()
        return "not implemented"
        # return f"{' ' * indent}{self}"


@dataclass
class Typedecl(ast_utils.Ast):
    type_list: List[Ident]
    typeid: Typeid
    optional_typedecl: Optional[Typedecl] = None

    # _non_empty_seq{IDENT} ":" typeid [ "," typedecl ]
    def pretty_print(self, column: int = 0):
        str = ""
        # str += ", ".join([t.pretty_print() for t in self.type_list])
        if isinstance(self.type_list, List):
            str += ", ".join([t for t in self.type_list])
        elif isinstance(self.type_list, Token):
            str += self.type_list.value
        str += ": "
        str += self.typeid.pretty_print()
        if self.optional_typedecl is not None:
            str += ", "
            str += self.optional_typedecl.pretty_print()
        return str


@dataclass
class LetfunDecl(ast_utils.Ast):
    ident: Ident
    typedecl: Optional[Typedecl]
    pterm: Pterm

    def pretty_print(self, column: int = 0):
        str = f"letfun {self.ident.value}"
        if self.typedecl is not None:
            str += "("
            str += self.typedecl.pretty_print()
            # str += ", ".join(
            #     [
            #         t.pretty_print() if hasattr(t, "pretty_print") else str(t)
            #         for t in self.typedecl
            #     ]
            # )
            str += ")"
        str += " = "
        str += self.pterm.pretty_print()
        str += "."
        return str


@dataclass
class LemmaGterm(ast_utils.Ast):
    gterm: Gterm
    lemma: Optional[Lemma] = None

    def pretty_print(self, column: int = 0):
        str = self.gterm.pretty_print()
        if self.lemma is not None:
            str += ";" + self.lemma.pretty_print()
        return str


@dataclass
class LemmaPublicVars(ast_utils.Ast):
    gterm: Gterm
    public_vars: List
    lemma: Optional[Lemma] = None

    def pretty_print(self, column: int = 0):
        str = self.gterm.pretty_print()
        str += "for { public_vars"
        str += ",".join(
            [
                v.pretty_print() if hasattr(v, "pretty_print") else str(v)
                for v in self.public_vars
            ]
        )
        str += "}"
        if self.lemma is not None:
            str += ";" + self.lemma.pretty_print()
        return str


@dataclass
class LemmaPublicVarsSecret(ast_utils.Ast):
    gterm: Gterm
    secret: Ident
    public_vars: List
    lemma: Optional[Lemma] = None

    def pretty_print(self, column: int = 0):
        str = self.gterm.pretty_print()
        str += "for { secret"
        str += self.secret.value
        str += ",".join(
            [
                v.pretty_print() if hasattr(v, "pretty_print") else str(v)
                for v in self.public_vars
            ]
        )
        str += "[real_or_random] }"
        if self.lemma is not None:
            str += ";" + self.lemma.pretty_print()
        return str


@dataclass
class Lemma(ast_utils.Ast):
    lemma: LemmaGterm | LemmaPublicVars | LemmaPublicVarsSecret

    def pretty_print(self, column: int = 0):
        return self.lemma.pretty_print()

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

    # lemma_decl_core: "lemma" [ typedecl ";"] lemma "."
    def pretty_print(self, column: int = 0):
        str = ""
        str += "lemma "
        if self.typedecl is not None:
            str += self.typedecl.pretty_print()
            str += ";\n "
        str += self.lemma.pretty_print()
        str += "."
        return str


@dataclass
class LemmaAnnotation(ast_utils.Ast):
    annotation: str

    def pretty_print(self, column: int = 0):
        str = ""
        str += self.annotation
        return str


@dataclass
class LemmaDecl(ast_utils.Ast):
    lemma_decl_annotation: Optional[LemmaAnnotation]
    lemma_decl_core: LemmaDeclCore

    def pretty_print(self, column: int = 0):
        str = ""
        if self.lemma_decl_annotation is not None:
            str += f"@lemma {self.lemma_decl_annotation}\n"
        str += f"{self.lemma_decl_core.pretty_print()}"
        return str

    # "{% if lemma_decl_annotation %}@lemma {{lemma_decl_annotation}}{% endif %}{{lemma_decl_core}}"

    # def pretty_print(self, column=0, indent=2):
    #    return f"{'@lemma' + a if a is not None else ''}{l}"

    # def pretty_print(self, column=0, indent=2):
    #    a = self.lemma_decl_annotation
    #    l = self.lemma_decl_core
    #    return f"{'@lemma' + a.pretty_print(column, indent) if a is not None else ''}{l.pretty_print(column, indent)}"


@dataclass
class Query(ast_utils.Ast):
    query: QueryGterm | QuerySecret | QueryPutBegin

    def pretty_print(self, column: int = 0):
        return self.query.pretty_print()


@dataclass
class QueryAnnotation(ast_utils.Ast):
    annotation: str

    def pretty_print(self, column: int = 0):
        return self.annotation


@dataclass
class ReachableAnnotation(ast_utils.Ast):
    annotation: str

    def pretty_print(self, column: int = 0):
        return self.annotation


@dataclass
class QueryDeclCore(ast_utils.Ast):
    typedecl: Optional[Typedecl]
    query: Query

    def pretty_print(self, column: int = 0):
        str = "query "
        if self.typedecl is not None:
            str += self.typedecl.pretty_print()
            str += ";\n "
        str += self.query.pretty_print()
        str += "."
        return str


@dataclass
class QueryDecl(ast_utils.Ast):
    query_decl_annotation: Optional[QueryAnnotation | ReachableAnnotation]
    query_decl_core: QueryDeclCore

    def pretty_print(self, column: int = 0):
        str = ""
        if self.query_decl_annotation is not None:
            if isinstance(self.query_decl_annotation, QueryAnnotation):
                str += f"@query {self.query_decl_annotation.pretty_print()}\n"
            elif isinstance(self.query_decl_annotation, ReachableAnnotation):
                str += f"@reachable {self.query_decl_annotation.pretty_print()}\n"
        str += self.query_decl_core.pretty_print()
        return str


@dataclass
class QueryGterm(ast_utils.Ast):
    gterm: Gterm
    public_vars: Optional[List[Ident]] = None
    query: Optional[Query] = None

    def pretty_print(self, column: int = 0):
        str = self.gterm.pretty_print()
        if self.public_vars is not None:
            str += "public_vars "
            str += ", ".join(
                [
                    v.pretty_print() if hasattr(v, "pretty_print") else str(v)
                    for v in self.public_vars
                ]
            )
        if self.query is not None:
            str += ";" + self.query.pretty_print()
        return str


@dataclass
class QuerySecret(ast_utils.Ast):
    ident: Ident
    public_vars: Optional[List[Ident]] = None
    query: Optional[Query] = None

    def pretty_print(self, column: int = 0):
        str = "secret"
        str += self.ident.pretty_print()
        if self.public_vars is not None:
            str += "public_vars "
            str += ", ".join(
                [
                    v.pretty_print() if hasattr(v, "pretty_print") else str(v)
                    for v in self.public_vars
                ]
            )
        if self.query is not None:
            str += ";" + self.query.pretty_print()
        return str


@dataclass
class QueryPutBegin(ast_utils.Ast):
    event_list: List[Ident]
    query: Optional[Query] = None

    def pretty_print(self, column: int = 0):
        str = "putbegin event :"
        str += ", ".join(
            [
                e.pretty_print() if hasattr(e, "pretty_print") else str(e)
                for e in self.event_list
            ]
        )
        if self.query is not None:
            str += ";" + self.query.pretty_print()
        return str


@dataclass
class Decl(ast_utils.Ast):
    decl: LemmaDecl | QueryDecl | TypeDecl | LetfunDecl

    def pretty_print(self, column: int = 0):
        return self.decl.pretty_print()


parser = Lark("""
start: decl*
decl: lemma_decl | query_decl | type_decl | letfun_decl
_non_empty_seq{x}: x ("," x)*
_maybe_empty_seq{x}: [ _non_empty_seq{x} ]
IDENT: /[a-zA-Z][a-zA-Z0-9À-ÿ'_]*/
NAT: DIGIT+
typeid: IDENT

type_decl: "type" IDENT "."

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
    def IDENT(self, str):
        return str

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


def pretty_print(asttree: list):

    result_str = ""

    def handle_dataclass(d):
        if hasattr(d, "pretty_print") and callable(getattr(d, "pretty_print")):
            pp = d.pretty_print() + "\n"
        else:
            pp = "not implemented"

        return pp

    def inner(node):
        if is_dataclass(node):
            return handle_dataclass(node)
        else:
            assert False

    if isinstance(asttree, list):
        for node in asttree:
            result_str += inner(node)
    else:
        result_str += inner(asttree)

    print(result_str)
    return result_str


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
    return pretty_print(clean_ast)

    # print("=" * 100)
    # print("=" * 100)
    # print(ast)


if __name__ == "__main__":
    with open("sample.pv", "r", encoding="utf-8") as f:
        input = f.read()

    output = parse(input)

    with open("sample-output.pv", "w", encoding="utf-8") as f:
        f.write(output)
