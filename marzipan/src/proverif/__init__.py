from lark import Lark

from proverif.ast import ast_deepcopy_except, create_transformer, pretty_print


def parse_marzipan_to_proverif(input) -> str | None:
    parser = Lark.open('proverif/grammars/marzipan_minimal.lark')
    parsetree = parser.parse(input)
    transformer = create_transformer()
    ast = transformer.transform(parsetree)
    clean_ast = ast_deepcopy_except(ast)
    if clean_ast:
        return pretty_print(clean_ast)
    else:
        return None
