import re
from pygments.lexer import RegexLexer, bygroups, words
from pygments.token import *

class CryptoVerifLexer(RegexLexer):
	"""
	Lexer for the CryptoVerif
	"""
	flags = re.MULTILINE | re.DOTALL
	
	name = 'CrptoVerif'
	aliases = ['cryptoverif']
	filenames = ['*.ocvl']

	tokens = {
		'root': [
			(r'\(\*', Comment.Multiline, 'comment'), 
			(r'\s+', Text),
            (r'(%|&)[^;]*;', Name.Entity),
            ('<!--', Comment, 'comment'),
            (r'[(|)*,?+]', Operator),
            (r'"[^"]*"', String.Double),
            (r'\'[^\']*\'', String.Single),
			(r'[{}]', Name.Builtin),
			 (words((
                'type', 'let', 'letfun', 'in', 'out', 'if', 'then', 'else', 'equation', 'forall', 'foreach', 'table', 'find', 'implementation', 'const', 'fun', 'bottom', 'serial', 'equal', 'inverse', 'fixed', 'large', 'bounded', 'unique', 'data', 'event', 'inj-event', 'query', 'get', 'proba', 'process', 'proof', 'param', 'def', 'expand', 'run', 'use_entropy', 'do', 'random', 'set', 'yield', 'insert', 'return', 'suchthat'), suffix=r'\b'),
             Keyword),
			(r'[\w_]+', Text),
			(r'\d', Number),
			(r'\s', Text),
		 	(r'[]{}:(),;\.[]', Punctuation),
			(r'=', Operator),
       ],
       'comment':[
            (r'[^*]+', Comment.Multiline),
            (r'\(\*', Comment.Multiline, '#push'),
            (r'\*\)', Comment.Multiline, '#pop'),
            (r'[*\)]', Comment.Multiline)
       ],
       'format': [
            (r'\.\n', String.Interpol, '#pop'),
            (r'[^\n]*\n', String.Interpol),
        ],
	}
