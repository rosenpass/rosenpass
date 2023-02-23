import re
from pygments.lexers.rust import RustLexer
from pygments.token import Error, _TokenType

class PseudoRustLexer(RustLexer):
	"""
	Lexer for Rust like Pseudo Code
	"""
	
	name = 'PseudoRust'
	aliases = ['pseudorust']
	
	"""
	Modify unprocessed tokens for string replacement without having to register a separate filter
	"""
	def get_tokens_unprocessed(self, text, stack=('root',)):
		"""
		Split ``text`` into (tokentype, text) pairs.

		``stack`` is the initial stack (default: ``['root']``)
		"""
		replace_symbols = {
			'->'     : '\U00002190',
			'<-'     : '\U00002190',
			'->'     : '\U00002192',
			'=>'     : '\U000021d2',
			'|->'    : '\U000021a6',
			'<<'     : '\U0000226a',
			'>>'     : '\U0000226b',
			'<='     : '\U00002264',
			'>='     : '\U00002265'
	    }
		pattern = re.compile(r'(?<!\w)(' + '|'.join(re.escape(key) for key in replace_symbols.keys()) + r')(?!\w)')
		text = pattern.sub(lambda x: replace_symbols[x.group()], text)
		pos = 0
		tokendefs = self._tokens
		statestack = list(stack)
		statetokens = tokendefs[statestack[-1]]
		while 1:
			for rexmatch, action, new_state in statetokens:
				m = rexmatch(text, pos)
				if m:
					if action is not None:
						if type(action) is _TokenType:
							yield pos, action, m.group()
						else:
							yield from action(self, m)
					pos = m.end()
					if new_state is not None:
						# state transition
						if isinstance(new_state, tuple):
							for state in new_state:
								if state == '#pop':
									if len(statestack) > 1:
										statestack.pop()
								elif state == '#push':
									statestack.append(statestack[-1])
								else:
									statestack.append(state)
						elif isinstance(new_state, int):
							# pop, but keep at least one state on the stack
							# (random code leading to unexpected pops should
							# not allow exceptions)
							if abs(new_state) >= len(statestack):
								del statestack[1:]
							else:
								del statestack[new_state:]
						elif new_state == '#push':
							statestack.append(statestack[-1])
						else:
							assert False, "wrong state def: %r" % new_state
						statetokens = tokendefs[statestack[-1]]
					break
			else:
				# We are here only if all state tokens have been considered
				# and there was not a match on any of them.
				try:
					if text[pos] == '\n':
						# at EOL, reset state to "root"
						statestack = ['root']
						statetokens = tokendefs['root']
						yield pos, Whitespace, '\n'
						pos += 1
						continue
					yield pos, Error, text[pos]
					pos += 1
				except IndexError:
					break
	


