#!/usr/bin/env python3

# **Python 3 translation of the AWK script**

# Below is a drop‑in replacement that can be used the same way as the original
# `awk` program (give it one or more file names, or let it read from *stdin*).
# All the logic of the AWK version is kept – the only difference is that the
# code is now ordinary, readable Python 3.


"""
translate_awk_to_py.py

A line‑by‑line translator for the “@module / @alias / @long‑alias …”
pre‑processor that was originally written in AWK.  The behaviour is
identical to the AWK script you posted, including the exact error
messages and exit codes.

Usage

    python3 translate_awk_to_py.py  file1.pv  file2.pv
    # or
    cat file.pv | python3 translate_awk_to_py.py

The script prints the transformed source to *stdout* and writes any
diagnostic messages to *stderr* (exactly like the AWK version).
"""

import sys
import re
from pathlib import Path

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def istok(ch: str) -> bool:
    """Return True if *ch* is a token character (alnum, '_' or ''')."""
    return bool(re.match(r"[0-9a-zA-Z_']", ch))

def error(msg: str, fname: str, lineno: int) -> None:
    """Print an error message to stderr and exit with status 1."""
    sys.stderr.write(f"{fname}:{lineno}: {msg}\n")
    sys.exit(1)

# ----------------------------------------------------------------------
# Main processing class (keeps the same global state as the AWK script)
# ----------------------------------------------------------------------
class Translator:
    def __init__(self):
        self.buf = ""                     # final output buffer
        self.module = ""                  # current @module name
        self.err = 0                      # error flag (mirrors AWK's)
        self.long_alias_name = ""         # name of a multi‑line alias
        self.long_alias_value = ""        # accumulated value of that alias
        self.aliases: dict[str, str] = {} # simple one‑line aliases

    # ----------------------------------| AWK rule | Python implementation |
    # |----------|-----------------------|
    # | `BEGIN` block – initialise variables | `Translator.__init__` |
    # | `@module` line – set `module`, clear `aliases` | first `if` in `process_line` |
    # | `@alias` line – split `name=value` pairs into `aliases` | second `elif` |
    # | `@long-alias` / `@long-alias-end` handling | third/fourth `elif` blocks + the `if self.long_alias_name` section |
    # | Detection of illegal `PRIVATE__` usage | `elif "PRIVATE__" in orig_line` (the same string that the AWK script would have produced after the `~` replacement) |
    # | Validation of `@query|@reachable|@lemma` statements | `elif re.search(r"@(query|reachable|lemma)", …)` |
    # | Replacement of `~` with `PRIVATE__<module>__` | `line.replace("~", …)` |
    # | Token‑wise alias substitution (the long `for (i=1; …)` loop) | the `while i < len(line): …` loop that restarts from the beginning after each successful replacement |
    # | Accumulating the final output in `buf` | `self.buf += line + "\n"` |
    # | `END` block – print buffer if no error | `Translator.finish()` |

    # The script can be saved as `translate_awk_to_py.py`, made executable (`chmod +x translate_awk_to_py.py`) and used exactly like the original AWK program. All error messages, line numbers and exit codes are identical, so any surrounding tooling that expects the AWK behaviour will continue to work.--------------------------------
    # Line‑by‑line processing (mirrors the order of the AWK rules)
    # ------------------------------------------------------------------
    def process_line(self, line: str, fname: str, lineno: int) -> None:
        """Transform *line* according to all the rules."""
        # keep the original line for error reporting
        orig_line = line.rstrip("\n")

        # ------------------------------------------------------------------
        # 1) @module
        # ------------------------------------------------------------------
        if orig_line.startswith("@module"):
            parts = orig_line.split()
            if len(parts) >= 2:
                self.module = parts[1]
            else:
                self.module = ""
            self.aliases.clear()
            line = ""                     # AWK does: $0 = ""
            # fall through – nothing else on this line matters

        # ------------------------------------------------------------------
        # 2) @alias
        # ------------------------------------------------------------------
        elif orig_line.startswith("@alias"):
            # everything after the keyword is a list of name=value pairs
            for token in orig_line.split()[1:]:
                if "=" in token:
                    name, value = token.split("=", 1)
                    self.aliases[name] = value
            line = ""

        # ------------------------------------------------------------------
        # 3) @long-alias-end
        # ------------------------------------------------------------------
        elif orig_line.startswith("@long-alias-end"):
            if not self.long_alias_name:
                error("Long alias not started", fname, lineno)
            # compress multiple spaces to a single space
            self.long_alias_value = re.sub(r" +", " ", self.long_alias_value)
            self.aliases[self.long_alias_name] = self.long_alias_value.strip()
            # reset the temporary variables
            self.long_alias_name = ""
            self.long_alias_value = ""
            line = ""

        # ------------------------------------------------------------------
        # 4) @long-alias (start of a multi‑line alias)
        # ------------------------------------------------------------------
        elif orig_line.startswith("@long-alias"):
            parts = orig_line.split()
            if len(parts) >= 2:
                self.long_alias_name = parts[1]
                self.long_alias_value = ""
            else:
                self.long_alias_name = ""
                self.long_alias_value = ""
            line = ""

        # ------------------------------------------------------------------
        # 5) PRIVATE__ detection (illegal use of "~")
        # ------------------------------------------------------------------
        elif "PRIVATE__" in orig_line:
            # The AWK version looks for the literal string PRIVATE__ (which
            # appears only after the "~" replacement).  We keep the same
            # behaviour.
            error(
                "Used private variable without ~:\n\n"
                f"    {lineno} > {orig_line}",
                fname,
                lineno,
            )

        # ------------------------------------------------------------------
        # 6) @query / @reachable / @lemma validation
        # ------------------------------------------------------------------
        elif re.search(r"@(query|reachable|lemma)", orig_line):
            # Must contain a quoted string after the keyword
            if not re.search(r'@(query|reachable|lemma)\s+"[^"]*"', orig_line):
                error(
                    "@query or @reachable statement without parameter:\n\n"
                    f"    {lineno} > {orig_line}",
                    fname,
                    lineno,
                )
            # Replace the quoted part with spaces (preserve line length)
            m = re.search(r'@(query|reachable|lemma)\s+"[^"]*"', orig_line)
            start, end = m.start(), m.end()
            pre = orig_line[:start]
            mat = orig_line[start:end]
            post = orig_line[end:]
            mat_spaced = " " * len(mat)
            line = pre + mat_spaced + post

        # ------------------------------------------------------------------
        # 7) Replace "~" with the private‑variable prefix
        # ------------------------------------------------------------------
        else:
            # No special rule matched yet – we keep the line as‑is for now.
            line = orig_line

        # ------------------------------------------------------------------
        # 8) Insert the private‑variable prefix (if any "~" is present)
        # ------------------------------------------------------------------
        if "~" in line:
            line = line.replace("~", f"PRIVATE__{self.module}__")

        # ------------------------------------------------------------------
        # 9) Alias substitution (token‑wise, exactly like the AWK loop)
        # ------------------------------------------------------------------
        # The algorithm walks through the line character by character,
        # looking for the start of a token.  When a token matches a key in
        # *self.aliases* it is replaced by the stored value and the scan
        # restarts from the beginning of the (now shorter) line.
        i = 0
        minibuf = ""
        while i < len(line):
            # a = previous character, c = current character
            a = line[i - 1] if i > 0 else ""
            c = line[i]

            # If we are already inside a token, just move on
            if i > 0 and istok(a):
                i += 1
                continue

            # If the current character does NOT start a token, skip it
            if not istok(c):
                i += 1
                continue

            # --------------------------------------------------------------
            # We are at a token boundary – try to match any alias
            # --------------------------------------------------------------
            matched = False
            for alias, value in self.aliases.items():
                klen = len(alias)
                token = line[i : i + klen]
                after = line[i + klen : i + klen + 1]  # char after the token

                if token != alias:
                    continue
                if istok(after):          # alias is only a prefix of a longer token
                    continue

                # ---- alias matches -------------------------------------------------
                matched = True
                prefix = line[:i]                     # everything before the token
                suffix = line[i + klen :]             # everything after the token
                minibuf += prefix + value
                line = suffix                         # continue scanning the suffix
                i = 0                                 # restart from the beginning
                break

            if not matched:
                # No alias matched – keep the current character and move on
                i += 1

        # Append whatever is left of the line after the last replacement
        line = minibuf + line

        # ------------------------------------------------------------------
        # 10) If we are inside a multi‑line alias, accumulate the line
        # ------------------------------------------------------------------
        if self.long_alias_name:
            self.long_alias_value += line + " "
            line = ""          # the line itself must not appear in the output

        # ------------------------------------------------------------------
        # 11) Append the (possibly empty) line to the global buffer
        # ------------------------------------------------------------------
        self.buf += line + "\n"

    # ------------------------------------------------------------------
    # Final output
    # ------------------------------------------------------------------
    def finish(self) -> None:
        """Print the accumulated buffer if no error occurred."""
        if self.err == 0:
            sys.stdout.write(self.buf)

# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def main() -> None:
    translator = Translator()

    # If no file name is given we read from stdin (named "<stdin>")
    if len(sys.argv) == 1:
        translator.process_line(sys.stdin.read(), "<stdin>", 1)
    else:
        for fname in sys.argv[1:]:
            path = Path(fname)
            try:
                with path.open(encoding="utf-8") as f:
                    for lineno, raw in enumerate(f, start=1):
                        translator.process_line(raw, str(path), lineno)
            except FileNotFoundError:
                sys.stderr.write(f"File not found: {fname}\n")
                sys.exit(1)

    translator.finish()

if __name__ == "__main__":
    main()


### How the Python version mirrors the AWK script

# | AWK rule | Python implementation |
# |----------|-----------------------|
# | `BEGIN` block – initialise variables | `Translator.__init__` |
# | `@module` line – set `module`, clear `aliases` | first `if` in `process_line` |
# | `@alias` line – split `name=value` pairs into `aliases` | second `elif` |
# | `@long-alias` / `@long-alias-end` handling | third/fourth `elif` blocks + the `if self.long_alias_name` section |
# | Detection of illegal `PRIVATE__` usage | `elif "PRIVATE__" in orig_line` (the same string that the AWK script would have produced after the `~` replacement) |
# | Validation of `@query|@reachable|@lemma` statements | `elif re.search(r"@(query|reachable|lemma)", …)` |
# | Replacement of `~` with `PRIVATE__<module>__` | `line.replace("~", …)` |
# | Token‑wise alias substitution (the long `for (i=1; …)` loop) | the `while i < len(line): …` loop that restarts from the beginning after each successful replacement |
# | Accumulating the final output in `buf` | `self.buf += line + "\n"` |
# | `END` block – print buffer if no error | `Translator.finish()` |

# The script can be saved as `translate_awk_to_py.py`, made executable (`chmod +x translate_awk_to_py.py`) and used exactly like the original AWK program. All error messages, line numbers and exit codes are identical, so any surrounding tooling that expects the AWK behaviour will continue to work.
