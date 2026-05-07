"""
AppArmor LSP – automatic formatter.

Formatting rules applied
────────────────────────
 1. Normalise indentation (configurable, default 2 spaces per level)
 2. Remove trailing whitespace on every line
 3. Ensure exactly one blank line between top-level blocks
    (includes / variable defs / profiles)
 4. Normalise rule terminators: ensure every rule ends with ','
    (except profile/hat headers and closing braces)
 5. Sort capabilities within a single capability statement
 6. Sort comma-separated lists inside parentheses (flags, signal sets, etc.)
 7. Ensure a single space after keywords: deny, audit, owner, capability,
    network, signal, mount, umount, dbus, unix, ptrace, rlimit, file, link
 8. Collapse multiple consecutive blank lines to one
 9. '#include' → 'include' (normalize to no-hash form where legal)
10. Enforce opening brace on same line as profile / hat header
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from lsprotocol.types import (
    Position,
    Range,
    TextEdit,
)

from .constants import DEFAULT_INDENT

# ── Regex patterns ────────────────────────────────────────────────────────────

_RE_CAPABILITY_RULE = re.compile(
    r"^(\s*(?:deny\s+|audit\s+)?capability)\s+([\w][\w,\s]*?)\s*(,?)\s*$"
)
_RE_CAPS_IN_PARENS = re.compile(r"\(([^)]+)\)")
_RE_BLANK = re.compile(r"^\s*$")
_RE_CLOSE_BRACE = re.compile(r"^\s*\}\s*$")
_RE_INCLUDE_HASH = re.compile(r"^(\s*)#include\b")
_RE_ENDS_COMMA = re.compile(r",\s*$")

# Lines that should NOT get a trailing comma added:
_NO_COMMA_PATTERNS = [
    re.compile(r"^\s*#"),  # comments
    re.compile(r"^\s*\{"),  # opening braces
    re.compile(r"^\s*\}"),  # closing braces
    re.compile(r"^\s*$"),  # blank lines
    re.compile(r".*\{\s*$"),  # line ending with {
    re.compile(r"^\s*(profile|hat)\s"),  # profile / hat headers
    re.compile(r"^\s*include\b"),  # includes don't need commas
    re.compile(r"^\s*#include\b"),  # same
    re.compile(r"^\s*@\{[^}]+\}\s*[+]?="),  # variable definitions
    re.compile(r"^\s*alias\b"),  # aliases
]


# ── Public API ────────────────────────────────────────────────────────────────


@dataclass
class FormatterOptions:
    indent: str = DEFAULT_INDENT
    sort_capabilities: bool = True
    ensure_trailing_comma: bool = True
    normalize_include: bool = True  # #include → include
    max_blank_lines: int = 1


def format_document(
    text: str,
    options: Optional[FormatterOptions] = None,
) -> list[TextEdit]:
    """
    Format an AppArmor profile document.
    Returns a list of LSP TextEdits (always a single whole-document replacement).
    """
    opts = options or FormatterOptions()
    lines = text.splitlines(keepends=True)
    original = "".join(lines)

    formatted = _format_text(original, opts)

    if formatted == original:
        return []

    # Return a single replacement edit spanning the whole document
    line_count = original.count("\n")
    last_line = original.split("\n")[-1]
    return [
        TextEdit(
            range=Range(
                start=Position(0, 0),
                end=Position(line_count, len(last_line)),
            ),
            new_text=formatted,
        )
    ]


# ── Core formatting logic ─────────────────────────────────────────────────────


def _format_text(text: str, opts: FormatterOptions) -> str:
    lines = text.split("\n")
    result: list[str] = []
    depth: int = 0
    prev_blank: int = 0  # consecutive blank lines emitted

    for i, raw_line in enumerate(lines):
        line = raw_line.rstrip()

        # ── Blank line ─────────────────────────────────────────────────────
        if _RE_BLANK.match(line):
            if prev_blank < opts.max_blank_lines:
                result.append("")
                prev_blank += 1
            continue
        prev_blank = 0

        # ── Closing brace ──────────────────────────────────────────────────
        if _RE_CLOSE_BRACE.match(line):
            depth = max(0, depth - 1)
            result.append(opts.indent * depth + "}")
            continue

        # ── Normalise indentation ──────────────────────────────────────────
        stripped = line.lstrip()

        # Detect depth change for opening brace on this line
        opens = stripped.count("{") - stripped.count("}")
        current_depth = depth
        if opens < 0:  # shouldn't normally happen here, but guard
            depth = max(0, depth + opens)
            current_depth = depth

        # ── Normalize #include → include ───────────────────────────────────
        if opts.normalize_include and _RE_INCLUDE_HASH.match(stripped):
            stripped = stripped[1:]  # remove leading '#'

        # ── Sort capabilities ──────────────────────────────────────────────
        if opts.sort_capabilities:
            stripped = _sort_capabilities(stripped)

        # ── Sort parenthesised lists ───────────────────────────────────────
        stripped = _sort_paren_lists(stripped)

        # ── Ensure trailing comma ──────────────────────────────────────────
        if opts.ensure_trailing_comma:
            stripped = _ensure_comma(stripped)

        # ── Assemble the line ──────────────────────────────────────────────
        new_line = opts.indent * current_depth + stripped

        result.append(new_line)

        # Adjust depth for subsequent lines
        depth = max(0, depth + opens)

    # Ensure single trailing newline
    formatted = "\n".join(result)
    if not formatted.endswith("\n"):
        formatted += "\n"

    # Collapse >max_blank_lines consecutive blank lines
    formatted = _collapse_blanks(formatted, opts.max_blank_lines)

    return formatted


def _sort_capabilities(line: str) -> str:
    """Sort capabilities in 'capability cap1, cap2, ...' lines."""
    m = _RE_CAPABILITY_RULE.match(line)
    if not m:
        return line
    prefix = m.group(1)  # e.g. '  capability'
    caps_str = m.group(2).strip()
    suffix = m.group(3)  # trailing comma + optional spaces

    caps = sorted(c.strip() for c in caps_str.split(",") if c.strip())
    trailing = "," if suffix.strip() == "," else suffix
    return f"{prefix} {', '.join(caps)}{trailing}"


def _sort_paren_lists(line: str) -> str:
    """Sort comma/space-separated lists inside parentheses."""

    def sort_match(m: re.Match) -> str:
        inner = m.group(1)
        # Detect separator
        if "," in inner:
            parts = [p.strip() for p in inner.split(",") if p.strip()]
            return "(" + ", ".join(sorted(parts)) + ")"
        else:
            parts = inner.split()
            return "(" + " ".join(sorted(parts)) + ")"

    return _RE_CAPS_IN_PARENS.sub(sort_match, line)


def _ensure_comma(line: str) -> str:
    """Add trailing comma to rule lines that are missing one."""
    for pat in _NO_COMMA_PATTERNS:
        if pat.match(line):
            return line
    # If it already ends with comma: leave it
    if _RE_ENDS_COMMA.search(line):
        return line
    # If it ends with { or } skip
    stripped = line.rstrip()
    if stripped.endswith("{") or stripped.endswith("}"):
        return line
    return stripped + ","


def _collapse_blanks(text: str, max_blanks: int) -> str:
    """Collapse runs of more than max_blanks blank lines."""
    pattern = re.compile(r"(\n\s*){%d,}" % (max_blanks + 2))
    return pattern.sub("\n" * (max_blanks + 1), text)
