from __future__ import annotations

from dataclasses import dataclass

from lark import ast_utils

from proverif.ast.formatting_helpers import MarzipanAST, pretty_format

type Ident = str
type Infix = str


@dataclass
class TypeDecl(MarzipanAST):
    ident: Ident

    def pretty_print(self, column: int = 0) -> str:
        template = "type {ident}."+ "{ctx.empty_lines_after_decl}"
        return pretty_format(self, template, column=column)


@dataclass
class Typeid(MarzipanAST):
    ident: Ident

    def pretty_print(self, column: int = 0) -> str:
        template = "{ident}"
        return pretty_format(self, template, column=column)


@dataclass
class Pterm(MarzipanAST, ast_utils.AsList):
    pterm: Ident | int | list

    def pretty_print(self, column: int = 0) -> str:
        template = "{pterm:list.pterm}"
        return pretty_format(self, template, column=column)


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
class GbindingNat(MarzipanAST):
    value: int
    gterm: Gterm
    gbinding: Gbinding | None = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "!{value}={gterm}" + (";{gbinding}" if self.gbinding else ""),
            column=column,
        )


@dataclass
class Gbinding(MarzipanAST):
    gbinding: GbindingNat | GbindingIdent

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{gbinding}", column=column)


@dataclass
class GbindingIdent(MarzipanAST):
    value: Ident
    gterm: Gterm
    gbinding: Gbinding | None = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{value}={gterm}" + (";{gbinding}" if self.gbinding else ""),
            column=column,
        )


@dataclass
class IdentGterm(MarzipanAST):
    ident_gterm: Ident

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{ident_gterm}", column=column)


@dataclass
class GtermList(MarzipanAST, ast_utils.AsList):
    gterms: list[Gterm] | None = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{gterms:list.gterm}", column=column)


@dataclass
class FunGterm(MarzipanAST):
    fun_gterm: Ident
    gterm_list: GtermList
    phase: int | None = None
    at: Ident | None = None

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
    at: Ident | None = None

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
    at: Ident | None = None

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
    gbinding: Gbinding | None = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "new {ident}" + ("[{gbinding}]" if self.gbinding else ""),
            column=column,
        )


@dataclass
class Typedecl(MarzipanAST):
    type_list: IdentList
    typeid: Typeid
    optional_typedecl: Typedecl | None = None

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
    typedecl: Typedecl | None
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
    lemma: Lemma | None = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{gterm}" + ("; {lemma}" if self.lemma else ""),
            column=column,
        )


@dataclass
class IdentList(MarzipanAST, ast_utils.AsList):
    idents: list[Ident]

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{idents:list.gterm}", column=column)


@dataclass
class LemmaPublicVars(MarzipanAST):
    gterm: Gterm
    public_vars: IdentList
    lemma: Lemma | None = None

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
    public_vars: IdentList | None
    lemma: Lemma | None = None

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


@dataclass
class LemmaDecl(MarzipanAST):
    typedecl: Typedecl | None
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
class AnnotatedLemmaDecl(MarzipanAST):
    lemma_annotation: LemmaAnnotation
    typedecl: Typedecl | None
    lemma: Lemma

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "@lemma {lemma_annotation}\nlemma "
            + ("{typedecl};" if self.typedecl else "")
            + "\n"
            + "{lemma:indentline}."
            + "{ctx.empty_lines_after_decl}",
            column=column,
        )


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
class QueryDecl(MarzipanAST):
    typedecl: Typedecl | None
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
class AnnotatedQueryDecl(MarzipanAST):
    query_annotation: QueryAnnotation
    typedecl: Typedecl | None
    query: Query

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "@query {query_annotation}\n"
            + "query "
            + ("{typedecl};" if self.typedecl else "")
            + "\n"
            + "{query:indentline}."
            + "{ctx.empty_lines_after_decl}",
            column=column,
        )


@dataclass
class ReachableQueryDecl(MarzipanAST):
    reachable_annotation: ReachableAnnotation
    typedecl: Typedecl | None
    query: Query

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "@reachable {reachable_annotation}\n"
            + "query "
            + ("{typedecl};" if self.typedecl else "")
            + "\n"
            + "{query:indentline}."
            + "{ctx.empty_lines_after_decl}",
            column=column,
        )


@dataclass
class QueryGterm(MarzipanAST):
    gterm: Gterm
    public_vars: IdentList | None = None
    query: Query | None = None

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
    public_vars: IdentList | None = None
    query: Query | None = None

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
    query: Query | None = None

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
    query: Query | None = None

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "putbegin inj-event :"
            + ("{event_list:list.gterm}" if self.event_list else "")
            + ("; {query}" if self.query else ""),
            column=column,
        )


@dataclass
class Query(MarzipanAST):
    query: QueryGterm | QuerySecret | QueryPutBegin

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(self, "{query}", column=column)


@dataclass
class Decl(MarzipanAST):
    decl: LemmaDecl | QueryDecl | TypeDecl | LetfunDecl

    def pretty_print(self, column: int = 0) -> str:
        return pretty_format(
            self,
            "{decl}",
            column=column,
        )
