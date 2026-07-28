from __future__ import annotations


from .proverif import parse_marzipan_to_proverif

# def parse(input: str):
#     #global DEBUG
#     # print(parser.source_grammar)

#     parsetree = parser.parse(input)
#     # print("=" * 100)
#     # print("print parsetree")
#     # print(parsetree.pretty())
#     # print(parsetree)
#     ast = transformer.transform(parsetree)
#     # print("=" * 100)
#     # print("print_tree ast")
#     # print_tree(ast)
#     # print("=" * 100)
#     # print(ast)
#     # # clean_ast = parsetree_deepcopy_except(
#     # #     ast, ["lemma_annotation", "query_annotation", "reachable_annotation"]
#     # # )
#     pr = cProfile.Profile()
#     pr.enable()
#     clean_ast = ast_deepcopy_except(ast)
#     #clean_ast = ast
#     pr.disable()
#     s = io.StringIO()
#     sortby = SortKey.CUMULATIVE
#     ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
#     ps.print_stats()
#     print(s.getvalue())
#     # print("=" * 100)
#     print("print clean_ast")
#     print(clean_ast)
#     print("=" * 100)
#     print("print_tree clean_ast")
#     print_tree(clean_ast)

#     print("=" * 100)
#     #if DEBUG:
#     #    DEBUG = False
#     #    pretty_print(clean_ast)
#     #    DEBUG = True
#     str = pretty_print(clean_ast)
#     print(str)
#     return(str)

#     # print("=" * 100)
#     # print("=" * 100)
#     # print(ast)


if __name__ == "__main__":
    with open("sample.pv", "r", encoding="utf-8") as f:
        input = f.read()

    output = parse_marzipan_to_proverif(input)

    if output:
        with open("sample-output.pv", "w", encoding="utf-8") as f:
            f.write(output)
    else:
        print("Parsing returned None")
