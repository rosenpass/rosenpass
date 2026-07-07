from __future__ import annotations

import cProfile
import dataclasses
import io
import pprint
import pstats
import sys
from abc import ABC, abstractmethod
from collections import UserString
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass, fields, is_dataclass
from pstats import SortKey
from string import Formatter
from typing import Any, Iterator, List, Optional, Sequence, Tuple

from lark import Lark, Token, Transformer, Tree, ast_utils, tree, v_args
from lark.tree import Meta
from typing_extensions import Type

from proverif.ast.attributemap import AttrMap
from util import T

this_module = sys.modules[__name__]

pp = pprint.PrettyPrinter(indent=4, width=50)

DEBUG = False

PTERM_LIST_CONFIG = {
    "list_separator": ", ",
    "left_bracket": "(",
    "right_bracket": ")",
    "empty_brackets": True,
    "none_representation": "",
}

CONFIG = {
    "space": " ",
    "list.pterm": PTERM_LIST_CONFIG,
    "list.default": PTERM_LIST_CONFIG,
    "list.gterm": {
        "list_separator": ", ",
        "left_bracket": "",
        "right_bracket": "",
        "empty_brackets": False,
        "none_representation": "",
    },
    "infix_separator": " ",
    "line_break": "\n",
    "indentation_style": " " * 4,  # 4 spaces
    "empty_lines_after_decl": "\n" * 1,
    "break_after_n_list_elements": 4,
}


def get_list_config(format_spec: str, ctx: Mapping[str, Any] | None = None):
    if ctx:
        if format_spec not in ctx:
            format_spec = "list.default"

        list_config = ctx[format_spec]
        return (
            list_config["left_bracket"],
            list_config["right_bracket"],
            list_config["list_separator"],
            list_config["empty_brackets"],
            list_config["none_representation"],
        )
    else:
        raise KeyError(
            f"Cannot find pretty printer configuration for list type {format_spec}."
        )


format_spec_parser = Lark("""
start: list_config | linebreaks

LIST_PREFIX: "list"
LIST_TYPES: "pterm" | "gterm" | "default"
list_config: LIST_PREFIX "." LIST_TYPES

linebreaks: "indentline" | "newline"
""")


def check_format_spec(format_spec: str):
    if not format_spec == "":
        # This raises an error in case the format spec string
        # does not match the grammar
        format_spec_parser.parse(format_spec)
    return True


def pretty(
    value: Any, column: int, format_spec: str, ctx: Mapping[str, Any] | None = None
) -> str:

    return_str = ""

    if DEBUG:
        return_str += f"[c:{column}, f:{format_spec}, t:{type(value)}]"

    # new line that is indented one column more
    if format_spec == "indentline":
        return_str += ctx.indentation_style * (column + 1)
        column += 1
    # new line with the same indentation
    elif format_spec == "newline":
        return_str += ctx.indentation_style * (column)

    if value is None and format_spec.startswith("list."):
        (_, _, _, _, none_representation) = get_list_config(format_spec, ctx)
        return_str += none_representation

    elif isinstance(value, List):
        (
            left_bracket,
            right_bracket,
            list_separator,
            empty_brackets,
            _,
        ) = get_list_config(format_spec, ctx)

        if len(value) > 1:
            break_after_n = 5
            if len(value) < break_after_n:
                return_str += (
                    left_bracket
                    + list_separator.join(
                        pretty(item, column=column, format_spec=format_spec, ctx=ctx)
                        for item in value
                    )
                    + right_bracket
                )
            else:
                # TODO: make it work generally
                # it might actually work with a recursive call, alternatively construct
                # the list of sublists of length 5 (or whatever).
                # Maybe then we need a separator for format_spec to be able to do
                # "newline,gterm"
                return_str += (
                    left_bracket
                    + list_separator.join(
                        pretty(item, column=column, format_spec=format_spec, ctx=ctx)
                        for item in value[:break_after_n]
                    )
                    + list_separator
                    + "\n"
                    + ctx.indentation_style * (column + 1)
                    + pretty(
                        value[break_after_n:],
                        column=column,
                        format_spec=format_spec,
                        ctx=ctx,
                    )
                    + right_bracket
                )
        elif len(value) == 1:
            return_str += pretty(
                value[0], column=column, format_spec=format_spec, ctx=ctx
            )
        else:
            return_str += left_bracket + right_bracket if empty_brackets else ""

    elif isinstance(value, MarzipanAST):
        return_str += value.pretty_print(column=column)
    else:
        return_str += str(value)

    return return_str


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
        args: Sequence[Any],
        kwargs: Mapping[str, Any],
    ) -> Any:
        """Retrieve a given field value. Uses the prefix `self.` to
        refer to fields within the dataclass that is formatted, and uses
        the prefix `ctx.` to refer to pretty printer configuration variables.
        If no prefix is used, defaults to `self.`.
        """

        # As documented in https://docs.python.org/3/library/string.html#string.Formatter.get_value,
        # for compound field names, get_value is only called for the first component.
        if key == "self":
            return self.root

        if key == "ctx":
            return self.ctx

        # For a key that is not prefixed with `self` or `ctx`, assume `self`.
        if isinstance(key, str):
            return getattr(self.root, key)

        raise KeyError(f"Unsupported non-string key: {key}")

    def format_field(self, value: Any, format_spec: str) -> str:
        """This function override injects the column and configuration context"""
        if not check_format_spec(format_spec):
            raise ValueError(f"invalid format spec {format_spec}")
        return pretty(value, column=self.column, format_spec=format_spec, ctx=self.ctx)


def pretty_format(obj: Any, template: str, *, column: int = 0) -> str:
    return PrettyFormatter(obj, column=column, ctx=CONFIG).format(template)


type Ident = str
type Infix = str


class MarzipanAST(ast_utils.Ast, ABC):
    @abstractmethod
    def pretty_print(self, column: int = 0) -> str:
        raise NotImplementedError()


@dataclass
class TypeDecl(MarzipanAST):
    ident: Ident

    def pretty_print(self, column: int = 0) -> str:
        template = "type {ident}."
        return pretty_format(self, template, column=column)


@dataclass
class Typeid(MarzipanAST):
    ident: Ident

    def pretty_print(self, column: int = 0) -> str:
        template = "{ident}"
        return pretty_format(self, template, column=column)


@dataclass
class Pterm(MarzipanAST, ast_utils.AsList):
    pterm: Ident | int | List

    def pretty_print(self, column: int = 0) -> str:
        template = "{pterm:list.pterm}"
        return pretty_format(self, template, column=column)


@dataclass
class GbindingNat(MarzipanAST):
    value: int
    gterm: Gterm
    gbinding: Optional[Gbinding] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "!{value}={gterm}" + (";{gbinding}" if self.gbinding else ""),
            column=column,
        )


@dataclass
class GbindingIdent(MarzipanAST):
    value: Ident
    gterm: Gterm
    gbinding: Optional[Gbinding] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{value}={gterm}" + (";{gbinding}" if self.gbinding else ""),
            column=column,
        )


@dataclass
class Gbinding(MarzipanAST):
    gbinding: GbindingNat | GbindingIdent

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{gbinding}", column=column)


@dataclass
class IdentGterm(MarzipanAST):
    ident_gterm: Ident

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{ident_gterm}", column=column)


@dataclass
class GtermList(MarzipanAST, ast_utils.AsList):
    gterms: Optional[List[Gterm]] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{gterms:list.gterm}", column=column)


@dataclass
class FunGterm(MarzipanAST):
    fun_gterm: Ident
    gterm_list: GtermList
    phase: Optional[int] = None
    at: Optional[Ident] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{fun_gterm}({gterm_list})"
            # phase is an int, so we need to check for None explicitly,
            # because the int might be 0, and 0 would be interpreted as false.
            + (" phase {phase}" if self.phase is not None else "")
            + (" @ {at}" if self.at else ""),
            column=column,
        )


@dataclass
class InfixGterm(MarzipanAST):
    first_infix_gterm: Gterm
    infix: Infix
    second_infix_gterm: Gterm

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self, "{first_infix_gterm} {infix} {second_infix_gterm}", column=column
        )


@dataclass
class ChoiceGterm(MarzipanAST):
    left: Gterm
    right: Gterm

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "choice [{left}, {right}]", column=column)


@dataclass
class ArithGterm(MarzipanAST):
    arith_gterm: Gterm
    operand: str
    value: int

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{arith_gterm} {operand} {value}", column=column)


@dataclass
class Arith2Gterm(MarzipanAST):
    value: int
    arith_gterm: Gterm

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{value} + {arith_gterm}", column=column)


@dataclass
class InjeventGterm(MarzipanAST):
    event_gterms: GtermList
    at: Optional[Ident] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "inj-event ( {event_gterms} )" + ("@ {at}" if self.at else ""),
            column=column,
        )


@dataclass
class ImpliesGterm(MarzipanAST):
    left: Gterm
    right: Gterm

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{left} ==> {right}", column=column)


@dataclass
class EventGterm(MarzipanAST):
    event_gterms: GtermList
    at: Optional[Ident] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "event ({event_gterms:list.gterm})" + ("@{at}" if self.at else ""),
            column=column,
        )


@dataclass
class ParenGterm(MarzipanAST):
    paren_gterms: GtermList

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "({paren_gterms:list.gterm})",
            column=column,
        )


@dataclass
class LetGterm(MarzipanAST):
    ident: Ident
    first_gterm: Gterm
    second_gterm: Gterm

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "let {ident} = {first_gterm} in\n{second_gterm:newline}",  # {'\t' * column}
            column=column,
        )


@dataclass
class SampleGterm(MarzipanAST):
    ident: Ident
    # The implementation here does not allow to reproduce empty square brackets.
    # Empty square brackets in the input will result in no square brackets in the output.
    gbinding: Optional[Gbinding] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "new {ident}" + ("[{gbinding}]" if self.gbinding else ""),
            column=column,
        )


@dataclass
class Gterm(MarzipanAST):
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

    def pretty_print(self, column: int = 0) -> str:
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
            return pretty_format(
                self,
                "{gterm}",
                column=column,
            )
        return "not implemented"


@dataclass
class Typedecl(MarzipanAST):
    type_list: IdentList
    typeid: Typeid
    optional_typedecl: Optional[Typedecl] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{type_list:list.gterm}: {typeid}"
            + (", {optional_typedecl}" if self.optional_typedecl else ""),
            column=column,
        )


@dataclass
class LetfunDecl(MarzipanAST):
    ident: Ident
    typedecl: Optional[Typedecl]
    pterm: Pterm

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "letfun {ident}"
            + ("({typedecl})" if self.typedecl else "")
            + " =\n{pterm:indentline}."
            + "{ctx.empty_lines_after_decl}",
            column=column,
        )


@dataclass
class LemmaGterm(MarzipanAST):
    gterm: Gterm
    lemma: Optional[Lemma] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{gterm}" + ("; {lemma}" if self.lemma else ""),
            column=column,
        )


@dataclass
class IdentList(MarzipanAST, ast_utils.AsList):
    idents: List[Ident]

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{idents:list.gterm}", column=column)


@dataclass
class LemmaPublicVars(MarzipanAST):
    gterm: Gterm
    public_vars: IdentList
    lemma: Optional[Lemma] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{gterm} for {{ public_vars {public_vars} }}"
            + ("; {lemma}" if self.lemma else ""),
            column=column,
        )


@dataclass
class LemmaPublicVarsSecret(MarzipanAST):
    gterm: Gterm
    secret: Ident
    public_vars: Optional[IdentList]
    lemma: Optional[Lemma] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{gterm} for {{ secret {secret}"
            + ("public_vars {public_vars}" if self.public_vars else "")
            + "[real_or_random] }}"
            + ("; {lemma}" if self.lemma else ""),
            column=column,
        )


@dataclass
class Lemma(MarzipanAST):
    lemma: LemmaGterm | LemmaPublicVars | LemmaPublicVarsSecret

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{lemma}",
            column=column,
        )

    # def __post_init__(self):
    #    print(f"[constructor] Lemma: lemma={self.lemma}")

    # def __init__(self, lemma=None, arg2=None, arg3=None):
    #    print(f"[constructor] Lemma: {lemma}, {arg2}, {arg3}")
    #    self.lemma = lemma
    # def pretty_print(self, column=0, indent=2):
    #     print(f"{self}: not implemented")


@dataclass
class LemmaDeclCore(MarzipanAST):
    typedecl: Optional[Typedecl]
    lemma: Lemma

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "lemma "
            + ("{typedecl};" if self.typedecl else "")
            + "\n"
            + "{lemma:indentline}."
            + "{ctx.empty_lines_after_decl}",
            column=column,
        )


@dataclass
class LemmaAnnotation(MarzipanAST):
    annotation: str

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{annotation}", column=column)


@dataclass
class LemmaDecl(MarzipanAST):
    lemma_decl_annotation: Optional[LemmaAnnotation]
    lemma_decl_core: LemmaDeclCore

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            ("@lemma {lemma_decl_annotation}" if self.lemma_decl_annotation else "")
            + "{lemma_decl_core}",
            column=column,
        )

    # "{% if lemma_decl_annotation %}@lemma {{lemma_decl_annotation}}{% endif %}{{lemma_decl_core}}"

    # def pretty_print(self, column=0, indent=2):
    #    return f"{'@lemma' + a if a else ''}{l}"

    # def pretty_print(self, column=0, indent=2):
    #    a = self.lemma_decl_annotation
    #    l = self.lemma_decl_core
    #    return f"{'@lemma' + a.pretty_print(column, indent) if a else ''}{l.pretty_print(column, indent)}"


@dataclass
class Query(MarzipanAST):
    query: QueryGterm | QuerySecret | QueryPutBegin

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{query}", column=column)


@dataclass
class QueryAnnotation(MarzipanAST):
    annotation: str

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{annotation}", column=column)


@dataclass
class ReachableAnnotation(MarzipanAST):
    annotation: str

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{annotation}", column=column)


@dataclass
class QueryDeclCore(MarzipanAST):
    typedecl: Optional[Typedecl]
    query: Query

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "query "
            + ("{typedecl};" if self.typedecl else "")
            + "\n"
            + "{query:indentline}."
            + "{ctx.empty_lines_after_decl}",
            column=column,
        )


@dataclass
class QueryDecl(MarzipanAST):
    annotation: Optional[QueryAnnotation]
    query_decl_core: QueryDeclCore

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            ("@query {annotation}" if self.annotation else "") + "{query_decl_core}",
            column=column,
        )


@dataclass
class ReachableDecl(MarzipanAST):
    annotation: Optional[ReachableAnnotation]
    query_decl_core: QueryDeclCore

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            ("@reachable {annotation}" if self.annotation else "")
            + "{query_decl_core}",
            column=column,
        )


@dataclass
class QueryGterm(MarzipanAST):
    gterm: Gterm
    public_vars: Optional[IdentList] = None
    query: Optional[Query] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{gterm}"
            + ("public_vars {public_vars:list.gterm}" if self.public_vars else "")
            + ("; {query}" if self.query else ""),
            column=column,
        )


@dataclass
class QuerySecret(MarzipanAST):
    ident: Ident
    public_vars: Optional[IdentList] = None
    query: Optional[Query] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "secret {ident}"
            + ("public_vars {public_vars:list.gterm}" if self.public_vars else "")
            + ("; {query}" if self.query else ""),
            column=column,
        )


@dataclass
class QueryPutBegin(MarzipanAST):
    event_list: IdentList
    query: Optional[Query] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "putbegin event :"
            + ("{event_list:list.gterm}" if self.event_list else "")
            + ("; {query}" if self.query else ""),
            column=column,
        )


@dataclass
class QueryPutBeginInj(MarzipanAST):
    event_list: IdentList
    query: Optional[Query] = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "putbegin inj-event :"
            + ("{event_list:list.gterm}" if self.event_list else "")
            + ("; {query}" if self.query else ""),
            column=column,
        )


@dataclass
class Decl(MarzipanAST):
    decl: LemmaDecl | QueryDecl | ReachableDecl | TypeDecl | LetfunDecl

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{decl}",
            column=column,
        )


parser = Lark("""
start: decl*
decl: lemma_decl | query_decl | reachable_decl | type_decl | letfun_decl
_non_empty_seq{x}: x ("," x)*
_maybe_empty_seq{x}: [ _non_empty_seq{x} ]
IDENT: /[a-zA-Z][a-zA-Z0-9À-ÿ'_]*/
NAT: DIGIT+ // ProVerif Manual 4.1.3: 0 is considered as natural number
typeid: IDENT

type_decl: "type" IDENT "."

typedecl: ident_list ":" typeid [ "," typedecl ]
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

gbinding_nat: "!" NAT "=" gterm [";" gbinding]
gbinding_ident: IDENT "=" gterm [";" gbinding]

gbinding: gbinding_nat
        | gbinding_ident

ident_list: _non_empty_seq{IDENT}
lemma_gterm: gterm [";" lemma]
lemma_public_vars: gterm "for" "{" "public_vars" ident_list "}" [";" lemma]
lemma_public_vars_secret: gterm "for" "{" "secret" IDENT [ "public_vars" ident_list] "[real_or_random]" "}" [";" lemma]
lemma: lemma_gterm
         | lemma_public_vars
         | lemma_public_vars_secret
lemma_annotation: _LEMMA ESCAPED_STRING
lemma_decl: [lemma_annotation] lemma_decl_core
lemma_decl_core: "lemma" [ typedecl ";"] lemma "."

query_gterm: gterm ["public_vars" ident_list] [";" query]
query_secret: "secret" IDENT ["public_vars" ident_list] [";" query]
query_putbegin: "putbegin" "event" ":" ident_list [";" query] // Opportunistically left a space between "event" and ":", ProVerif might not accept it with spaces.
query_putbegin_inj: "putbegin" "inj-event" ":" ident_list [";" query]
query: query_gterm
        | query_secret
        | query_putbegin
        | query_putbegin_inj

query_annotation: _QUERY ESCAPED_STRING
reachable_annotation: _REACHABLE ESCAPED_STRING

query_decl: [query_annotation] query_decl_core
reachable_decl: [reachable_annotation] query_decl_core
query_decl_core: "query" [ typedecl ";"] query "."

%import common (DIGIT, WS, ESCAPED_STRING)
%ignore WS
""")


class ToAst(Transformer):
    def IDENT(self, token: Token) -> str:
        return str(token.value)

    def INFIX(self, token: Token) -> str:
        return str(token.value)

    def NAT(self, token: Token) -> int:
        n = int(token.value)
        assert n >= 0, "NAT must be an integer >= 0"
        return n

    # This captures all tokens that are not explicitly handled by other methods,
    # like ESCAPED_STRING, etc, that we import in our grammar.
    def __default_token__(self, token: Token) -> Any:
        return token.value

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
    global DEBUG
    parsetree = parser.parse(input)
    # print("=" * 100)
    # print("print parsetree")
    # print(parsetree.pretty())
    # print(parsetree)
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
    if DEBUG:
        DEBUG = False
        pretty_print(clean_ast)
        DEBUG = True
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
