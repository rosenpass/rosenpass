if exists("b:current_syntax")
  finish
endif

runtime syntax/c.vim
unlet b:current_syntax
runtime syntax/proverif.vim
let b:current_syntax = "marzipan"
