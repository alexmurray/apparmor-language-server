"""
AppArmor LSP – shared line/text helpers.

Tiny module so that the server, parser and diagnostics layers share one
implementation of "where does a comment start on this line?" rather than
each carrying its own copy.
"""

from __future__ import annotations

import re

# Lines starting with a directive (#include, #abi) use '#' as a directive
# marker, not a comment introducer.
_RE_DIRECTIVE_LINE = re.compile(r"^\s*#(include|abi)\b")


def code_end(line: str) -> int:
    """Return the column at which a trailing comment begins on *line*.

    Returns ``len(line)`` if the line has no trailing comment, or if the
    line is itself a directive (``#include``/``#abi``) where '#' is the
    directive marker rather than a comment introducer.
    """
    if _RE_DIRECTIVE_LINE.match(line):
        return len(line)
    idx = line.find("#")
    return idx if idx >= 0 else len(line)
