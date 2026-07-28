from copy import deepcopy

from lark import Tree


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
