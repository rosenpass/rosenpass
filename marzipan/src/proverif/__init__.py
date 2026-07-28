from pathlib import Path

from lark import Lark

from .ast import ast_deepcopy_except, create_transformer, pretty_print


_GRAMMAR = Path(__file__).parent / "grammars" / "marzipan_minimal.lark"


def parse_marzipan_to_proverif(input) -> str | None:
    parser = Lark.open(_GRAMMAR)
    parsetree = parser.parse(input)
    transformer = create_transformer()
    ast = transformer.transform(parsetree)
    clean_ast = ast_deepcopy_except(ast)
    if clean_ast:
        return pretty_print(clean_ast)
    else:
        return None
