"""
AppArmor LSP – hover provider.

Provides rich Markdown documentation for:
 • Rule keywords (capability, network, signal, …)
 • Capabilities
 • Network families / types
 • File permission characters
 • AppArmor variables (@{HOME}, @{PROC}, …)
 • Profile flags
"""

from __future__ import annotations

import re
from typing import Optional

from lsprotocol.types import (
    Hover,
    MarkupContent,
    MarkupKind,
    Position,
    Range,
)

from .constants import (
    CAPABILITIES,
    CAPABILITY_DEFS,
    EXECUTE_PERMISSIONS,
    FILE_PERMISSIONS,
    FLAG_DEFS,
    KEYWORD_DEFS,
    NETWORK_DOMAINS,
    NETWORK_TYPES,
    PROFILE_FLAGS,
    PTRACE_DEFS,
    PTRACE_PERMISSIONS,
    QUALIFIER_DEFS,
    RE_FILE_PERMISSIONS,
    SIGNAL_NAMES,
)
from .parser import DocumentNode

# ── Word extraction ───────────────────────────────────────────────────────────

_RE_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RE_VAR = re.compile(r"@\{([A-Za-z_][A-Za-z0-9_]*)\}")


def get_hover(
    doc: DocumentNode,
    line_text: str,
    position: Position,
) -> Optional[Hover]:
    """Return hover documentation for the word at the cursor."""
    ch = position.character

    # ── Variable hover ────────────────────────────────────────────────────
    for m in _RE_VAR.finditer(line_text):
        if m.start() <= ch <= m.end():
            var_name = "@{" + m.group(1) + "}"
            for uri, vars in doc.all_variables.items():
                if var_name in vars:
                    var = vars[var_name]
                    return _make_hover(
                        f"**`{var_name}`**\n\n{' '.join([comment.text for comment in var.comments])}\n\n{var_name} = {' '.join(var.values)}\n\nDefined at {uri} line {var.range.start.line}",
                        line_text,
                        m.start(),
                        m.end(),
                    )

    # ── Word under cursor ─────────────────────────────────────────────────
    word, word_start, word_end = _word_at(line_text, ch)
    # include if exists should be treated as a single keyword, so check for that first
    if word in ["include", "if", "exists"]:
        for kw in ["include if exists"]:
            kw_start = line_text.find(kw)
            if kw_start != -1 and kw_start <= ch <= kw_start + len(kw):
                word = "include if exists"
                word_start = kw_start
                word_end = kw_start + len(kw)
                break
    if not word:
        return None

    # Check capability
    if word in CAPABILITIES:
        return _make_hover(
            f"**Linux capability `{word}`** (`CAP_{word.upper()}`)\n\n"
            + _cap_doc(word),
            line_text,
            word_start,
            word_end,
        )

    # Check network family
    if word in NETWORK_DOMAINS:
        return _make_hover(
            f"**Network family `{word}`**\n\n"
            "Restricts network access to this address family.",
            line_text,
            word_start,
            word_end,
        )

    # Check network type
    if word in NETWORK_TYPES:
        return _make_hover(
            f"**Network socket type `{word}`**\n\n"
            "Restricts network access to this socket type.",
            line_text,
            word_start,
            word_end,
        )

    # Check qualifiers
    qual_def = QUALIFIER_DEFS.get(word)
    if qual_def:
        return _make_hover(qual_def.doc, line_text, word_start, word_end)

    # Check keyword docs
    kw_def = KEYWORD_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, line_text, word_start, word_end)

    # Check profile flags
    if word in PROFILE_FLAGS:
        return _make_hover(
            f"**Profile flag `{word}`**\n\n" + _flag_doc(word),
            line_text,
            word_start,
            word_end,
        )

    # Check signal names
    if word in SIGNAL_NAMES:
        return _make_hover(
            f"**Signal `{word.upper()}`**\n\nPOSIX signal name used in `signal` rules.",
            line_text,
            word_start,
            word_end,
        )

    # Check ptrace perms
    if word in PTRACE_PERMISSIONS:
        return _make_hover(
            f"**ptrace permission `{word}`**\n\n" + _ptrace_doc(word),
            line_text,
            word_start,
            word_end,
        )

    # ── Permission character hover ─────────────────────────────────────────
    # Look for a permission string adjacent to the cursor
    for pm in RE_FILE_PERMISSIONS.finditer(line_text):
        if pm.start() <= ch <= pm.end():
            import logging

            logger = logging.getLogger(__name__)
            logger.debug(
                f"Using regex {RE_FILE_PERMISSIONS.pattern} to find permission string at {ch}"
            )
            logger.debug(
                f"Found permission string `{pm.group(1)}` at {pm.start()}-{pm.end()}"
            )
            perm_str = pm.group(1)
            # split perm_str into individual permission groups based on
            # PERMISSIONS keys - e.g. "r", "pix", "ix" etc
            perms = []
            i = 0
            while i < len(perm_str):
                for p in sorted(
                    FILE_PERMISSIONS.keys() | EXECUTE_PERMISSIONS.keys(),
                    key=len,
                    reverse=True,
                ):
                    p = str(p)
                    if perm_str.startswith(p, i):
                        perms.append(p)
                        i += len(p)
                        break
                else:
                    # no match - skip this character
                    i += 1
            lines_out = [f"**File permissions `{perm_str}`**\n"]
            for perm in perms:
                desc = FILE_PERMISSIONS.get(perm) or EXECUTE_PERMISSIONS.get(perm)
                if desc:
                    lines_out.append(f"- `{perm}` — {desc}")
            return _make_hover(
                "\n".join(lines_out),
                line_text,
                pm.start(),
                pm.end(),
            )

    return None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _word_at(line: str, ch: int) -> tuple[str, int, int]:
    for m in _RE_WORD.finditer(line):
        if m.start() <= ch <= m.end():
            return m.group(), m.start(), m.end()
    return "", ch, ch


def _make_hover(md: str, line: str, start: int, end: int) -> Hover:
    return Hover(
        contents=MarkupContent(kind=MarkupKind.Markdown, value=md),
        range=Range(
            start=Position(0, start),  # line offset is handled by caller
            end=Position(0, end),
        ),
    )


def _flag_doc(flag: str) -> str:
    try:
        return FLAG_DEFS[flag].doc
    except KeyError:
        return "AppArmor profile flag."


def _cap_doc(cap: str) -> str:
    try:
        return CAPABILITY_DEFS[cap].doc
    except KeyError:
        return "Linux capability — see `man 7 capabilities` for details."


def _ptrace_doc(perm: str) -> str:
    try:
        return PTRACE_DEFS[perm].doc
    except KeyError:
        return "ptrace permission."
