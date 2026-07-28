.PHONY: all

all: proverif.lark marzipan_minimal.lark marzipan.lark

proverif.lark: common.lark decl.lark process.lark query.lark lemma.lark term.lark cryptoverif.lark
	cat $^ > $@

marzipan_minimal.lark: proverif_minimal.lark marzipan_additions.lark
	cat $^ > $@

marzipan.lark: proverif.lark marzipan_additions.lark
	cat $^ > $@

