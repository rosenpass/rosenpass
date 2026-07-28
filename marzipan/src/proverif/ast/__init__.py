from __future__ import annotations

from copy import deepcopy
from dataclasses import fields, is_dataclass
from typing import Any

from lark import Token, Transformer, Tree, ast_utils

from . import ast_dataclasses
from .ast_dataclasses import (
    AnnotatedLemmaDecl,
    AnnotatedQueryDecl,
    LemmaAnnotation,
    LemmaDecl,
    QueryAnnotation,
    QueryDecl,
    ReachableAnnotation,
    ReachableQueryDecl,
)


def ast_deepcopy_except(node):
    if is_dataclass(node):
        if (
            isinstance(node, (QueryAnnotation, ReachableAnnotation, LemmaAnnotation))
        ):
            return None

        dataclass_type = type(node)

        # The following classes need to be transformed to classes
        # with fewer attributes.
        if isinstance(node, (AnnotatedQueryDecl, ReachableQueryDecl)):
            dataclass_type = QueryDecl
        elif isinstance(node, AnnotatedLemmaDecl):
            dataclass_type = LemmaDecl

        kwargs = {}

        for field in fields(node):
            # For a few classes, we skip the annotation attribute
            if (isinstance(node, ReachableQueryDecl) and field.name == "reachable_annotation") or (isinstance(node, AnnotatedQueryDecl) and field.name == "query_annotation") or (isinstance(node, AnnotatedLemmaDecl) and field.name == "lemma_annotation"):
                continue
            else:
                child_node = getattr(node, field.name)
                child_node_deepcopy = ast_deepcopy_except(child_node)
                kwargs[field.name] = child_node_deepcopy

        return dataclass_type(**kwargs)

    elif isinstance(node, list):
        return [ast_deepcopy_except(item) for item in node]
    else:
        return deepcopy(node)


def print_tree(asttree, column=0, indent=2):

    def handle_dict(d):
        for key, value in d.items():
            print(f"{' ' * (column)}{key} [handle_dict]")
            print_tree(value, column + 1)

    def handle_dataclass(d):
        print(f"{' ' * (column)}{type(d).__name__} [handle_dataclass: class name]")
        for f in fields(d):
            next_d = getattr(d, f.name)
            if next_d is not None:
                print(f"{' ' * (column + 1)}{f.name} [handle_dataclass: attr]")
                print_tree(next_d, column + 2)

    def inner(node):
        cur_list = []
        if is_dataclass(node):
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


def pretty_print(asttree):

    result_str = ""

    def handle_dataclass(d):
        if hasattr(d, "pretty_print") and callable(d.pretty_print):
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

    return result_str


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


def create_transformer():
    return ast_utils.create_transformer(ast_dataclasses, ToAst())
