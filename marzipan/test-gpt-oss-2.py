#!/usr/bin/env python3

# Below is a **more “Pythonic”** rewrite of the original AWK‑to‑Python translator.
# The logic is exactly the same – the same error messages, line numbers and exit
# codes – but the code is organized into small, reusable functions, uses
# `dataclasses`, type hints, `Path.read_text()`, `re.sub()` and other idiomatic
# constructs.  It is also easier to read and to extend.


"""
py_awk_translator.py

A line‑by‑line pre‑processor that implements the same behaviour as the
original AWK script you posted (handling @module, @alias, @long‑alias,
private‑variable expansion, @query/@reachable/@lemma checks and token‑wise
alias substitution).

Usage

    python3 py_awk_translator.py  file1.pv  file2.pv
    # or
    cat file.pv | python3 py_awk_translator.py
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable

# ----------------------------------------------------------------------
# Helper utilities
# ----------------------------------------------------------------------
TOKEN_RE = re.compile(r"[0-9A-Za-z_']")

def is_token_char(ch: str) -> bool:
    """Return True if *ch* can be part of an identifier token."""
    return bool(TOKEN_RE.fullmatch(ch))

def die(msg: str, fname: str, lineno: int) -> None:
    """Print an error to stderr and exit with status 1 (exactly like AWK)."""
    sys.stderr.write(f"{fname}:{lineno}: {msg}\n")
    sys.exit(1)

# ----------------------------------------------------------------------
# Core translator – holds the mutable state that the AWK script kept in
# global variables.
# ----------------------------------------------------------------------
@dataclass
class Translator:
    """Collects state while processing a file line‑by‑line."""

    # final output buffer
    out: list[str] = field(default_factory=list)

    # current @module name (used when expanding "~")
    module: str = ""

    # simple one‑line aliases: name → replacement text
    aliases: Dict[str, str] = field(default_factory=dict)

    # multi‑line alias handling
    long_name: str = ""
    long_value: str = ""

    # error flag – mirrors the AWK variable `err`
    err: int = 0

    # ------------------------------------------------------------------
    # Public entry point for a single line
    # ------------------------------------------------------------------
    def process(self, raw: str, fname: str, lineno: int) -> None:
        """Apply all transformation rules to *raw* and store the result."""
        line = raw.rstrip("\n")          # keep a copy for error messages
        original = line                  # keep the untouched line for later

        # --------------------------------------------------------------
        # 1️⃣  @module
        # --------------------------------------------------------------
        if line.startswith("@module"):
            parts = line.split(maxsplit=1)
            self.module = parts[1] if len(parts) > 1 else ""
            self.aliases.clear()
            line = ""

        # --------------------------------------------------------------
        # 2️⃣  @alias
        # --------------------------------------------------------------
        elif line.startswith("@alias"):
            for token in line.split()[1:]:
                if "=" in token:
                    name, value = token.split("=", 1)
                    self.aliases[name] = value
            line = ""

        # --------------------------------------------------------------
        # 3️⃣  @long-alias‑end
        # --------------------------------------------------------------
        elif line.startswith("@long-alias-end"):
            if not self.long_name:
                die("Long alias not started", fname, lineno)
            # collapse multiple spaces → single space, strip trailing space
            self.long_value = re.sub(r" +", " ", self.long_value).strip()
            self.aliases[self.long_name] = self.long_value
            self.long_name = self.long_value = ""
            line = ""

        # --------------------------------------------------------------
        # 4️⃣  @long-alias (start)
        # --------------------------------------------------------------
        elif line.startswith("@long-alias"):
            parts = line.split(maxsplit=1)
            self.long_name = parts[1] if len(parts) > 1 else ""
            self.long_value = ""
            line = ""

        # --------------------------------------------------------------
        # 5️⃣  PRIVATE__ detection (illegal use of "~")
        # --------------------------------------------------------------
        elif "PRIVATE__" in line:
            die(
                "Used private variable without ~:\n\n"
                f"    {lineno} > {original}",
                fname,
                lineno,
            )

        # --------------------------------------------------------------
        # 6️⃣  @query / @reachable / @lemma validation
        # --------------------------------------------------------------
        elif re.search(r"@(query|reachable|lemma)", line):
            if not re.search(r'@(query|reachable|lemma)\s+"[^"]*"', line):
                die(
                    "@query or @reachable statement without parameter:\n\n"
                    f"    {lineno} > {original}",
                    fname,
                    lineno,
                )
            # replace the quoted part with blanks (preserve line length)
            m = re.search(r'@(query|reachable|lemma)\s+"[^"]*"', line)
            start, end = m.span()
            line = line[:start] + " " * (end - start) + line[end:]

        # --------------------------------------------------------------
        # 7️⃣  Expand "~" to the private‑variable prefix
        # --------------------------------------------------------------
        if "~" in line:
            line = line.replace("~", f"PRIVATE__{self.module}__")

        # --------------------------------------------------------------
        # 8️⃣  Token‑wise alias substitution (the long AWK loop)
        # --------------------------------------------------------------
        line = self._expand_aliases(line)

        # --------------------------------------------------------------
        # 9️⃣  Accumulate a multi‑line alias, if we are inside one
        # --------------------------------------------------------------
        if self.long_name:
            self.long_value += line + " "
            line = ""                     # the line itself must not appear in output

        # --------------------------------------------------------------
        # 🔟  Store the (possibly empty) line for final output
        # --------------------------------------------------------------
        self.out.append(line + "\n")

    # ------------------------------------------------------------------
    # Helper that implements the token‑wise alias replacement
    # ------------------------------------------------------------------
    def _expand_aliases(self, text: str) -> str:
        """Replace every whole‑token alias in *text* with its value."""
        i = 0
        result = ""

        while i < len(text):
            # a = previous char, c = current char
            a = text[i - 1] if i > 0 else ""
            c = text[i]

            # If we are already inside a token, just move forward
            if i > 0 and is_token_char(a):
                i += 1
                continue

            # If the current char does not start a token, skip it
            if not is_token_char(c):
                i += 1
                continue

            # ----------------------------------------------------------
            # At a token boundary – try to match any alias
            # ----------------------------------------------------------
            matched = False
            for name, value in self.aliases.items():
                if text.startswith(name, i):
                    after = text[i + len(name) : i + len(name) + 1]
                    if is_token_char(after):          # name is only a prefix
                        continue
                    # Alias matches – replace it
                    result += text[:i] + value
                    text = text[i + len(name) :]       # continue scanning the suffix
                    i = 0
                    matched = True
                    break

            if not matched:
                i += 1

        return result + text

    # ------------------------------------------------------------------
    # Finalisation
    # ------------------------------------------------------------------
    def finish(self) -> None:
        """Write the accumulated output to stdout (unless an error occurred)."""
        if self.err == 0:
            sys.stdout.write("".join(self.out))

# ----------------------------------------------------------------------
# Command‑line driver
# ----------------------------------------------------------------------
def _process_path(path: Path, translator: Translator) -> None:
    """Read *path* line‑by‑line and feed it to *translator*."""
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(True), start=1):
        translator.process(raw, str(path), lineno)

def main() -> None:
    translator = Translator()

    # No file arguments → read from stdin (named "<stdin>")
    if len(sys.argv) == 1:
        # stdin may contain multiple lines; we treat it as a single “virtual”
        # file so that line numbers are still correct.
        for lineno, raw in enumerate(sys.stdin, start=1):
            translator.process(raw, "<stdin>", lineno)
    else:
        for name in sys.argv[1:]:
            p = Path(name)
            if not p.is_file():
                sys.stderr.write(f"File not found: {name}\n")
                sys.exit(1)
            _process_path(p, translator)

    translator.finish()

if __name__ == "__main__":
    main()


## What makes this version more Pythonic?

# | Aspect | Original style | Refactored style |
# |--------|----------------|------------------|
# | **State handling** | Global variables (`buf`, `module`, …) | `@dataclass Translator` encapsulates all mutable state |
# | **Regular‑expression reuse** | Re‑compiled on every call (`match`, `gsub`) | Compiled once (`TOKEN_RE`) and reused |
# | **String manipulation** | Manual `substr`, concatenation in loops | Slicing, `str.replace`, `re.sub` for clarity |
# | **Loop logic** | `for (i=1; i<length($0); i+=1)` with many manual index tricks | A single `while` loop with early‑continue guards; the inner alias‑search is a clean `for name, value in self.aliases.items()` |
# | **Error handling** | `print(... > "/dev/stderr")` and `exit(1)` | Dedicated `die()` helper that writes to `stderr` and exits |
# | **File I/O** | Manual `while (getline ...)` in AWK → `for` over `sys.stdin` / `Path.read_text()` | Uses `Path.read_text()` and `enumerate` for line numbers |
# | **Readability** | Mixed AWK‑style comments, one‑liner `if` statements | Docstrings, section comments, type hints, and small helper methods |
# | **Extensibility** | Adding a new rule required editing a monolithic block | New rules can be added as separate `elif` blocks or new methods without touching the core loop |

# The script can be saved as `py_awk_translator.py`, made executable (`chmod +x py_awk_translator.py`), and used exactly like the original AWK program while being easier to maintain and understand.
