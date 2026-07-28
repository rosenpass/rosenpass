from abc import ABC, abstractmethod
from collections.abc import Mapping
from string import Formatter
from typing import Any, Iterator, Sequence

from lark import Lark, ast_utils

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


class MarzipanAST(ast_utils.Ast, ABC):
    @abstractmethod
    def pretty_print(self, column: int = 0) -> str:
        raise NotImplementedError()


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


class AttrMap(Mapping):
    """
    Small wrapper so that dict values can be accessed as {ctx.foo}
    instead of only {ctx["foo"]} inside our custom format strings.
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

    def __contains__(self, key: object) -> bool:
        return key in self._mapping

    def __str__(self) -> str:
        return str(self._mapping)

    def __iter__(self) -> Iterator[Any]:
        return self._mapping.__iter__()

    def __len__(self) -> int:
        return len(self._mapping)


def check_format_spec(format_spec: str):
    if format_spec != "":
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

    elif isinstance(value, list):
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
        ctx: Mapping[str, Any] | None = None
    ):
        super().__init__()
        self.root = root
        self.column = column
        self.ctx = AttrMap(ctx or CONFIG)


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


def pretty_format(obj: Any, template: str, column: int = 0) -> str:
    return PrettyFormatter(obj, column=column).format(template)
