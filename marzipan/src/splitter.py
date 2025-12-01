import os
from pathlib import Path

"""
ChatGPT generated code for initial proverif grammar split
"""

# ---------- CONFIG ----------
OUT = Path("grammar")
OUT.mkdir(exist_ok=True)

# Raw grammar text (paste full grammar here)
GRAMMAR = read("grammars/proverif.lark")

# Rules grouped by prefix – expandable later if needed
GROUPS = {
    "common.lark": [
        "PROCESS",
        "YIELD",
        "CHANNEL",
        "IDENT",
        "ZERO",
        "INFIX",
        "typeid",
        "_non_empty_seq",
        "_maybe_empty_seq",
        "OPTIONS_",  # all options-related rules
        "BOOL",
        "NONE",
        "FULL",
        "ALL",
        "FUNC",
        "ignoretype_options",
        "boolean_settings_names",
        "INT",
        "COMMENT",
    ],
    "process.lark": [
        "start",
        "process",
        "bracketed_process",
        "piped_process",
        "replicated_process",
        "replicated_process_bounds",
        "sample_process",
        "let_process",
        "if_process",
        "in_process",
        "out_process",
        "insert_process",
        "event_process",
        "term",
        "phase",
        "sync",
    ],
    "term.lark": [
        "gterm",
        "ident_gterm",
        "fun_gterm",
        "choice_gterm",
        "infix_gterm",
        "arith_gterm",
        "arith2_gterm",
        "event_gterm",
        "injevent_gterm",
        "implies_gterm",
        "paren_gterm",
        "sample_gterm",
        "let_gterm",
        "gbinding",
        "pterm",
        "choice_pterm",
        "if_pterm",
        "not_pterm",
        "let_pterm",
        "sample_pterm",
        "insert_pterm",
        "event_pterm",
        "get_pterm",
        "pattern",
        "mayfailterm",
        "mayfailterm_seq",
        "typedecl",
        "failtypedecl",
    ],
    "decl.lark": [
        "decl",
        "type_decl",
        "channel_decl",
        "free_decl",
        "const_decl",
        "fun_decl",
        "letfun_decl",
        "reduc_decl",
        "fun_reduc_decl",
        "equation_decl",
        "pred_decl",
        "table_decl",
        "let_decl",
        "set_settings_decl",
        "event_decl",
        "select_decl",
        "noselect_decl",
        "nounif_decl",
        "elimtrue_decl",
        "clauses_decl",
        "module_decl",
        "nidecl",
        "equality",
        "mayfailequality",
        "eqlist",
        "clause",
        "clauses",
        "mayfailreduc",
    ],
    "query.lark": [
        "query",
        "lemma",
        "nounifdecl",
        "gformat",
        "fbinding",
        "nounifoption",
        "TAG",
    ],
}

# ---------- SPLITTING LOGIC ----------
rules = GRAMMAR.strip().splitlines()
buckets = {k: [] for k in GROUPS}


def match(rule, prefixes):
    return any(rule.startswith(p) for p in prefixes)


current_target = None

for line in rules:
    striped = line.strip()
    if ":" in striped and not striped.startswith("%"):
        rule_name = striped.split(":")[0].strip()
        for module, prefixes in GROUPS.items():
            if match(rule_name, prefixes):
                current_target = module
                break
    if current_target:
        buckets[current_target].append(line)

# main.lark will import everything else
main_lark = """start: decl* PROCESS process
%import .common.*
%import .process.*
%import .term.*
%import .decl.*
%import .query.*
%ignore WS
%ignore COMMENT
"""

# ---------- OUTPUT ----------
for filename, lines in buckets.items():
    path = OUT / filename
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

(OUT / "main.lark").write_text(main_lark)

print("Grammar split completed into:", OUT)
