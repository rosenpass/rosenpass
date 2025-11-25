import sys

from lark import Lark, Token, Transformer, exceptions, tree

# taken from Page 17 in the ProVerif manual
# At the moment, we do not reject a ProVerif model that uses reserved words as identifier,
# because this caused problems with the LARK grammar. We plan to check this in a later
# processing step.
reserved_words = [
    "among",
    "axiom",
    "channel",
    "choice",
    "clauses",
    "const",
    "def",
    "diff",
    "do",
    "elimtrue",
    "else",
    "equation",
    "equivalence",  # no rule yet (this is CryptoVerif-specific)
    "event",
    "expand",
    "fail",
    "for",
    "forall",
    "foreach",
    "free",
    "fun",
    "get",
    "if",
    "implementation",  # no rule yet (this is CryptoVerif-specific)
    "in",
    "inj-event",
    "insert",
    "lemma",
    "let",
    "letfun",
    "letproba",
    "new",
    "noninterf",
    "noselect",
    "not",
    "nounif",
    "or",
    "otherwise",
    "out",
    "param",
    "phase",
    "pred",
    "proba",
    "process",
    "proof",
    "public_vars",
    "putbegin",
    "query",
    "reduc",
    "restriction",
    "secret",
    "select",
    "set",
    "suchthat",
    "sync",
    "table",
    "then",
    "type",
    "weaksecret",
    "yield",
]

ident_regex = (
    "/^" + "".join(f"(?!{w}$)" for w in reserved_words) + "[a-zA-Z][a-zA-Z0-9À-ÿ'_]*/"
)

proverif_grammar = Lark(
    grammar="""
    PROCESS: "process"
    start: decl* PROCESS process
    YIELD: "yield"
    channel: CHANNEL
    CHANNEL: "channel"
    """
    + "IDENT: /[a-zA-Z][a-zA-Z0-9À-ÿ'_]*/"
    + """
    ZERO: "0"
    INFIX: "||"
         | "&&"
         | "="
         | "<>"
         | "<="
         | ">="
         | "<"
         | ">"
    typeid: channel
          | IDENT
    _non_empty_seq{x}: x ("," x)*
    _maybe_empty_seq{x}: [ _non_empty_seq{x} ]

    OPTIONS_FUN_CONST: "data" | "private" | "typeConverter"
    OPTIONS_FUN: OPTIONS_FUN_CONST
    OPTIONS_CONST: OPTIONS_FUN_CONST
    OPTIONS_FREE_REDUC: "private"
    OPTIONS_PRED: "memberOptim" | "block"
    OPTIONS_PROCESS: "precise"
    OPTIONS_QUERY_LEMMA_AXIOM: "noneSat" | "discardSat" | "instantiateSat" | "fullSat" | "noneVerif" | "discardVerif" | "instantiateVerif" | "fullVerif"
    OPTIONS_AXIOM: OPTIONS_QUERY_LEMMA_AXIOM
    OPTIONS_QUERY_LEMMA: OPTIONS_QUERY_LEMMA_AXIOM | "induction" | "noInduction"
    OPTIONS_LEMMA: OPTIONS_QUERY_LEMMA_AXIOM | "maxSubset"
    OPTIONS_QUERY: OPTIONS_QUERY_LEMMA_AXIOM | "proveAll"
    OPTIONS_QUERY_SECRET: "reachability" | "pv_reachability" | "real_or_random" | "pv_real_or_random" | "/cv_[a-zA-Z0-9À-ÿ'_]*/"
    OPTIONS_RESTRICTION: "removeEvents" | "keepEvents" | "keep" # transl_option_lemma_query in pitsyntax.ml
    OPTIONS_EQUATION: "convergent" | "linear" # check_equations in pitsyntax.ml
    OPTIONS_TYPE: "fixed" | "bounded" # TODO(blipp): complete this. These are only for compatibility with CryptoVerif and are ignored
    options{idents}: [ "[" _non_empty_seq{idents} "]" ]
    process: ZERO
           | YIELD
           | IDENT [ "(" _maybe_empty_seq{pterm} ")" ]
           | bracketed_process
           | piped_process
           | replicated_process
           | replicated_process_bounds
           | sample_process
           | if_process
           | in_process
           | out_process
           | let_process
           | insert_process
           | get_process
           | event_process
           | phase
           | sync
    bracketed_process: "(" process ")"
    piped_process: process "|" process
    replicated_process: "!" process
    replicated_process_bounds: "!" IDENT "<=" IDENT process
                             | "foreach" IDENT "<=" IDENT "do" process
    sample_process: "new" IDENT [ "[" _maybe_empty_seq{IDENT} "]" ] ":" typeid [";" process]
                  | IDENT "<-R" typeid [";" process]
    let_process: "let" pattern "=" pterm ["in" process [ "else" process ]]
               | IDENT [":" typeid] "<-" pterm [";" process]
               | "let" typedecl "suchthat" pterm options{OPTIONS_PROCESS} [ "in" process [ "else" process ] ]
    if_process: "if" pterm "then" process [ "else" process ]
    in_process: "in" "(" pterm "," pattern ")" options{OPTIONS_PROCESS} [ ";" process ]
    get_process: IDENT "(" _maybe_empty_seq{pattern} ")" [ "suchthat" pterm ] options{OPTIONS_PROCESS} [ "in" process [ "else" process ] ]
    out_process: "out" "(" pterm "," pterm ")" [ ";" process ]
    insert_process: "insert" IDENT "(" _maybe_empty_seq{pterm} ")" [ ";" process ]
    event_process: "event" IDENT [ "(" _maybe_empty_seq{pterm} ")" ] [ ";" process ]
    term: IDENT
          | NAT
          | "(" _maybe_empty_seq{term} ")"
          | IDENT "(" _maybe_empty_seq{term} ")"
          | term ( "+" | "-" ) NAT
          | NAT "+" term
          | term INFIX term
          | "not" "(" term ")"

    query: gterm ["public_vars" _non_empty_seq{IDENT}] [";" query]
         | "secret" IDENT ["public_vars" _non_empty_seq{IDENT}] options{OPTIONS_QUERY_SECRET} [";" query]
         | "putbegin" "event" ":" _non_empty_seq{IDENT} [";" query] // Opportunistically left a space between "event" and ":", ProVerif might not accept it with spaces.
         | "putbegin" "inj-event" ":" _non_empty_seq{IDENT} [";" query]
    lemma: gterm [";" lemma]
         | gterm "for" "{" "public_vars" _non_empty_seq{IDENT} "}" [";" lemma]
         | gterm "for" "{" "secret" IDENT [ "public_vars" _non_empty_seq{IDENT}] "[real_or_random]" "}" [";" lemma]
    gterm: ident_gterm
         | fun_gterm
         | choice_gterm
         | infix_gterm
         | arith_gterm
         | arith2_gterm
         | event_gterm
         | injevent_gterm
         | implies_gterm
         | paren_gterm
         | sample_gterm
         | let_gterm
    ident_gterm: IDENT
    fun_gterm: IDENT "(" _maybe_empty_seq{gterm} ")" ["phase" NAT] ["@" IDENT]
    choice_gterm: "choice" "[" gterm "," gterm "]"
    infix_gterm: gterm INFIX gterm
    arith_gterm: gterm ( "+" | "-" ) NAT
    arith2_gterm: NAT "+" gterm
    event_gterm: "event" "(" _maybe_empty_seq{gterm} ")" ["@" IDENT]
    injevent_gterm: "inj-event" "(" _maybe_empty_seq{gterm} ")" ["@" IDENT]
    implies_gterm: gterm "==>" gterm
    paren_gterm: "(" _maybe_empty_seq{gterm} ")"
    sample_gterm: "new" IDENT [ "[" [ gbinding ] "]" ]
    let_gterm: "let" IDENT "=" gterm "in" gterm

    gbinding: "!" NAT "=" gterm [";" gbinding]
            | IDENT "=" gterm [";" gbinding]

    nounifdecl: "let" IDENT "=" gformat "in" nounifdecl
              | IDENT ["(" _maybe_empty_seq{gformat} ")" ["phase" NAT]]
    gformat: IDENT
           | "*" IDENT
           | IDENT "(" _maybe_empty_seq{gformat} ")"
           | "choice" "[" gformat "," gformat "]"
           | "not" "(" _maybe_empty_seq{gformat} ")"
           | "new" IDENT [ "[" [ fbinding ] "]" ]
           | "let" IDENT "=" gformat "in" gformat
    fbinding: "!" NAT "=" gformat [";" fbinding]
            | IDENT "=" gformat [";" fbinding]
    nounifoption: "hypothesis"
                | "conclusion"
                | "ignoreAFewTimes"
                | "inductionOn" "=" IDENT
                | "inductionOn" "=" "{" _non_empty_seq{IDENT} "}"

    pterm: IDENT
          | NAT
          | "(" _maybe_empty_seq{pterm} ")"
          | IDENT "(" _maybe_empty_seq{pterm} ")"
          | choice_pterm
          | pterm ("+" | "-") NAT
          | NAT "+" pterm
          | pterm INFIX pterm
          | not_pterm
          | sample_pterm
          | if_pterm
          | let_pterm
          | insert_pterm
          | get_pterm
          | event_pterm
    choice_pterm: "choice[" pterm "," pterm "]"
    if_pterm: "if" pterm "then" pterm [ "else" pterm ]
    not_pterm: "not" "(" pterm ")"
    let_pterm: "let" pattern "=" pterm "in" pterm [ "else" pterm ]
             | IDENT [":" typeid] "<-" pterm ";" pterm
             | "let" typedecl "suchthat" pterm "in" pterm [ "else" pterm ]
    sample_pterm: "new" IDENT [ "[" _maybe_empty_seq{IDENT} "]" ] ":" typeid [";" pterm]
                | IDENT "<-R" typeid [";" pterm]
    insert_pterm: "insert" IDENT "(" _maybe_empty_seq{pterm} ")" ";" pterm
    event_pterm: "event" IDENT [ "(" _maybe_empty_seq{pterm} ")" ] ";" pterm
    get_pterm: IDENT "(" _maybe_empty_seq{pattern} ")" [ "suchthat" pterm ] options{OPTIONS_PROCESS} [ "in" pterm [ "else" pterm ] ]
    pattern: IDENT [":" typeid]
           | "_" [ ":" typeid ]
           | NAT
           | pattern "+" NAT
           | NAT "+" pattern
           | "(" _maybe_empty_seq{pattern} ")"
           | IDENT "(" _maybe_empty_seq{pattern} ")"
           | "=" pterm
    mayfailterm: term
               | "fail"
    mayfailterm_seq: "(" _non_empty_seq{mayfailterm} ")"
    typedecl: _non_empty_seq{IDENT} ":" typeid [ "," typedecl ]
    failtypedecl: _non_empty_seq{IDENT} ":" typeid [ "or fail" ] [ "," failtypedecl ]

    decl: type_decl
        | channel_decl
        | free_decl
        | const_decl
        | fun_decl
        | letfun_decl
        | reduc_decl
        | fun_reduc_decl
        | equation_decl
        | pred_decl
        | table_decl
        | let_decl
        | set_settings_decl
        | event_decl
        | query_decl
        | axiom_decl
        | restriction_decl
        | lemma_decl
        | noninterf_decl
        | weaksecret_decl
        | not_decl
        | select_decl
        | noselect_decl
        | nounif_decl
        | elimtrue_decl
        | clauses_decl
        | module_decl
        #| param_decl
        #| proba_decl
        #| letproba_decl
        #| proof_decl
        #| def_decl
        #| expand_decl

    type_decl: "type" IDENT options{OPTIONS_TYPE} "."
    channel_decl: "channel" _non_empty_seq{IDENT} "."
    free_decl: "free" _non_empty_seq{IDENT} ":" typeid options{OPTIONS_FREE_REDUC} "."
    const_decl: "const" _non_empty_seq{IDENT} ":" typeid options{OPTIONS_FUN_CONST} "."
    fun_decl: "fun" IDENT "(" _maybe_empty_seq{typeid} ")" ":" typeid options{OPTIONS_FUN_CONST} "."
    letfun_decl: "letfun" IDENT [ "(" [ typedecl ] ")" ] "=" pterm "."
    reduc_decl: "reduc" eqlist options{OPTIONS_FREE_REDUC} "."
    fun_reduc_decl: "fun" IDENT "(" _maybe_empty_seq{typeid} ")" ":" typeid "reduc" mayfailreduc options{OPTIONS_FUN_CONST} "."
    equation_decl: "equation" eqlist options{OPTIONS_EQUATION} "."
    pred_decl: "pred" IDENT [ "(" [ _maybe_empty_seq{typeid} ] ")" ] options{OPTIONS_PRED} "."
    table_decl: IDENT "(" _maybe_empty_seq{typeid} ")" "."
    let_decl: "let" IDENT [ "(" [ typedecl ] ")" ] "=" process "."

    BOOL : "true" | "false"
    NONE: "none"
    FULL: "full"
    ALL: "all"
    FUNC: IDENT
    ignoretype_options: BOOL | ALL | NONE | "attacker"
    boolean_settings_names: "privateCommOnPublicTerms"
                            | "rejectChoiceTrueFalse"
                            | "rejectNoSimplif"
                            | "allowDiffPatterns"
                            | "inductionQueries"
                            | "inductionLemmas"
                            | "movenew"
                            | "movelet"
                            | "stopTerm"
                            | "removeEventsForLemma"
                            | "simpEqAll"
                            | "eqInNames"
                            | "preciseLetExpand"
                            | "expandSimplifyIfCst"
                            | "featureFuns"
                            | "featureNames"
                            | "featurePredicates"
                            | "featureEvents"
                            | "featureTables"
                            | "featureDepth"
                            | "featureWidth"
                            | "simplifyDerivation"
                            | "abbreviateDerivation"
                            | "explainDerivation"
                            | "unifyDerivation"
                            | "reconstructDerivation"
                            | "displayDerivation"
                            | "traceBacktracking"
                            | "interactiveSwapping"
                            | "color"
                            | "verboseLemmas"
                            | "abbreviateClauses"
                            | "removeUselessClausesBeforeDisplay"
                            | "verboseEq"
                            | "verboseDestructors"
                            | "verboseTerm"
                            | "verboseStatistics"
                            | "verboseRules"
                            | "verboseBase"
                            | "verboseRedundant"
                            | "verboseCompleted"
                            | "verboseGoalReachable"

    _decl_pair{name, value}: "set" name "=" value "."

    set_settings_boolean_decl: _decl_pair{boolean_settings_names, BOOL}

    ignore_types_values: BOOL | "all" | "none" | "attacker"
    simplify_process_values: BOOL | "interactive"
    precise_actions_values: BOOL | "trueWithoutArgsInNames"
    redundant_hyp_elim_values: BOOL | "beginOnly"
    reconstruct_trace_values: BOOL | "n"
    attacker_values: "active" | "passive"
    key_compromise_values: "none" | "approx" | "strict"
    predicates_implementable: "check" | "nocheck"
    application_values: "instantiate" | "full" | "none" | "discard"
    max_values: "none" | "n"
    sel_fun_values: "TermMaxsize" | "Term"| "NounifsetMaxsize" | "Nounifset"
    redundancy_elim_values: "best" | "simple" | "no"
    nounif_ignore_a_few_times_values: "none" | "auto" | "all"
    nounif_ignore_ntimes_values: "n"
    trace_display_values: "short" | "long" | "none"
    verbose_clauses_values: "none" | "explained" | "short"
    set_settings_decl: set_settings_boolean_decl
                | _decl_pair{"ignoreTypes", ignore_types_values}
                | _decl_pair{"simplifyProcess", simplify_process_values}
                | _decl_pair{"preciseActions", precise_actions_values}
                | _decl_pair{"redundantHypElim", redundant_hyp_elim_values}
                | _decl_pair{"reconstructTrace", reconstruct_trace_values}
                | _decl_pair{"attacker", attacker_values}
                | _decl_pair{"keyCompromise", key_compromise_values}
                | _decl_pair{"predicatesImplementable", predicates_implementable}
                | _decl_pair{"saturationApplication", application_values}
                | _decl_pair{"verificationApplication", application_values}
                | _decl_pair{"maxDepth", max_values}
                | _decl_pair{"maxHyp", max_values}
                | _decl_pair{"selFun", sel_fun_values}
                | _decl_pair{"redundancyElim", redundancy_elim_values}
                | _decl_pair{"nounifIgnoreAFewTimes", nounif_ignore_a_few_times_values}
                | _decl_pair{"nounifIgnoreNtimes", nounif_ignore_ntimes_values}
                | _decl_pair{"traceDisplay", trace_display_values}
                | _decl_pair{"verboseClauses", verbose_clauses_values}
                | set_strategy
                | set_symb_order

    _swap_strategy_seq{x}: x ("->" x)*
    set_strategy: "set" "swapping" "=" _swap_strategy_seq{TAG} "."
    _symb_ord_seq{x}: x (">" x)*
    set_symb_order: "set" "symbOrder" "=" _symb_ord_seq{FUNC} "."

    event_decl: "event" IDENT ["(" _maybe_empty_seq{typeid} ")"] "."
    query_decl: "query" [ typedecl ";"] query options{OPTIONS_QUERY} "."

    axiom_decl:       "axiom"       [ typedecl ";"] lemma options{OPTIONS_AXIOM} "."
    restriction_decl: "restriction" [ typedecl ";"] lemma options{OPTIONS_RESTRICTION} "."
    lemma_decl:       "lemma"       [ typedecl ";"] lemma options{OPTIONS_LEMMA} "."

    noninterf_decl: [ typedecl ";"] _maybe_empty_seq{nidecl} "."
    weaksecret_decl: "weaksecret" IDENT "."
    not_decl: "not" [ typedecl ";"] gterm "."

    INT: NAT | "-" NAT
    select_decl:    "select"    [ typedecl ";"] nounifdecl [ "/" INT ] [ "[" _non_empty_seq{nounifoption} "]" ] "."
    noselect_decl:  "noselect"  [ typedecl ";"] nounifdecl [ "/" INT ] [ "[" _non_empty_seq{nounifoption} "]" ] "."
    nounif_decl:    "nounif"    [ typedecl ";"] nounifdecl [ "/" INT ] [ "["_non_empty_seq{nounifoption} "]" ] "."

    elimtrue_decl: "elimtrue" [ failtypedecl ";" ] term "."
    clauses_decl: "clauses" clauses "."

    module_decl: "@module" " " IDENT

    # TODO: finish defining these (comes from Cryptoverif)
    #param_decl: "param" _non_empty_seq{IDENT} options "."
    #proba_decl: "proba" IDENT ["(...)"] options "."
    #letproba_decl: "letproba" IDENT ["(...)"] "= ..." "."
    #proof_decl: "proof" "{" proof "}"
    #def_decl: "def" IDENT "(" _maybe_empty_seq{typeid} ")" "{" decl* "}"
    #expand_decl: "expand" IDENT "(" _maybe_empty_seq{typeid} ")" "."

    nidecl: IDENT [ "among" "(" _non_empty_seq{term} ")" ]
    equality: term "=" term
            | "let" IDENT "=" term "in" equality
    mayfailequality: IDENT mayfailterm_seq "=" mayfailterm
    eqlist: [ "forall" typedecl ";" ] equality [ ";" eqlist ]
    clause: term
           | term "->" term
           | term "<->" term
           | term "<=>" term
    clauses: [ "forall" failtypedecl ";" ] clause [ ";" clauses ]
    mayfailreduc: [ "forall" failtypedecl ";" ] mayfailequality [ "otherwise" mayfailreduc ]
    NAT: DIGIT+
    phase: "phase" NAT [";" process]
    TAG: IDENT
    sync: "sync" NAT ["[" TAG "]"] [";" process]
    COMMENT:  /\(\*(\*(?!\))|[^*])*\*\)/
    %import common (WORD, DIGIT, NUMBER, WS) // imports from terminal library
    %ignore WS // Disregard spaces in text
    %ignore COMMENT
""",
    debug=True,
    # lexer_callbacks={"COMMENT": comments.append},
)

# COMMENT:  /\(\*(\*(?!\))|[^*])*\*\)/
# COMMENT:  "(*" /(\*(?!\))|[^*])*/  "*)"
# comment: /\(\*(?:(?!\(\*|\*\)).|(?R))*\*\)/

# TODO Open ProVerif compatibility questions
# TODO * does it allow leading zeros for NAT?
# TODO * tag is not defined? is it ident?
# TODO * are spaces between "event" and ":" allowed?
# TODO * spaces between "nat" and "("? "choice" and "["?


def parsertest(input):
    parsetree = proverif_grammar.parse(input)
    # tree.pydot__tree_to_png(parsetree, name + ".png")
    return parsetree


def parse_main(file_path):
    with open(file_path, "r") as f:
        content = f.read()
        # print(content)
        parsertest(content)
