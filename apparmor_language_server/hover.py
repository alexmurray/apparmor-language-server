"""
AppArmor LSP – hover provider.

Walks the parsed DocumentNode AST to find the node under the cursor, then
dispatches to a per-node-type handler.  This lets each handler produce
context-aware documentation (e.g. "r" means a signal permission inside a
SignalRuleNode, not a file permission).

Variable references (@{VAR}) are resolved before node dispatch because they
can appear inside any rule type.
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
    CAPABILITY_DEFS,
    DBUS_BUS_DEFS,
    DBUS_PERMISSION_DEFS,
    EXECUTE_PERMISSIONS,
    FILE_PERMISSIONS,
    FLAG_DEFS,
    IO_URING_PERMISSION_DEFS,
    KEYWORD_DEFS,
    MOUNT_OPTION_DEFS,
    MQUEUE_PERMISSION_DEFS,
    NETWORK_DOMAINS,
    NETWORK_PERMISSIONS,
    NETWORK_TYPES,
    PTRACE_DEFS,
    QUALIFIER_DEFS,
    RE_FILE_PERMISSIONS,
    RLIMIT_DEFS,
    SIGNAL_NAMES,
    SIGNAL_PERMISSIONS,
    UNIX_TYPES,
)
from .parser import (
    ABINode,
    CapabilityNode,
    ChangeHatRuleNode,
    ChangeProfileRuleNode,
    CommentNode,
    DbusRuleNode,
    DocumentNode,
    FileRuleNode,
    IncludeNode,
    IoUringRuleNode,
    MountRuleNode,
    MqueueRuleNode,
    NetworkNode,
    Node,
    PivotRootRuleNode,
    ProfileNode,
    PtraceRuleNode,
    RlimitRuleNode,
    SignalRuleNode,
    UmountRuleNode,
    UnixRuleNode,
    UnknownRuleNode,
    UsernsRuleNode,
)

_RE_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RE_VAR = re.compile(r"@\{([A-Za-z_][A-Za-z0-9_]*)\}")


# ── Public entry point ────────────────────────────────────────────────────────


def get_hover(
    doc: DocumentNode,
    line_text: str,
    position: Position,
) -> Optional[Hover]:
    """Return hover documentation for the token at *position*."""
    ch = position.character

    # Variable references can appear inside any rule — resolve them first.
    for m in _RE_VAR.finditer(line_text):
        if m.start() <= ch <= m.end():
            var_name = "@{" + m.group(1) + "}"
            for uri, vars in doc.all_variables.items():
                if var_name in vars:
                    var = vars[var_name]
                    comment_text = " ".join(c.text for c in var.comments)
                    body = f"**`{var_name}`**\n\n"
                    if comment_text:
                        body += comment_text + "\n\n"
                    body += f"`{var_name}` = {' '.join(var.values)}\n\nDefined at {uri} line {var.range.start.line}"
                    return _make_hover(body, m.start(), m.end())

    node = _node_at_position(doc, position.line)
    if node is None:
        return None
    return _hover_for_node(node, line_text, ch)


# ── AST navigation ────────────────────────────────────────────────────────────


def _node_at_position(doc: DocumentNode, line: int) -> Optional[Node]:
    """Return the innermost AST node whose range contains *line*."""

    def search(children: list[Node]) -> Optional[Node]:
        for child in children:
            if child.range.start.line <= line <= child.range.end.line:
                if isinstance(child, ProfileNode):
                    inner = search(child.children)
                    if inner is not None:
                        return inner
                return child
        return None

    return search(doc.children)


# ── Per-node hover dispatch ───────────────────────────────────────────────────


def _hover_for_node(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    if isinstance(node, CommentNode):
        return None
    if isinstance(node, CapabilityNode):
        return _hover_capability(line_text, ch)
    if isinstance(node, NetworkNode):
        return _hover_network(line_text, ch)
    if isinstance(node, SignalRuleNode):
        return _hover_signal(line_text, ch)
    if isinstance(node, FileRuleNode):
        return _hover_file_rule(line_text, ch)
    if isinstance(node, ProfileNode):
        return _hover_profile(line_text, ch)
    if isinstance(node, IncludeNode):
        return _hover_include(node, line_text, ch)
    if isinstance(node, ABINode):
        return _hover_abi(line_text, ch)
    if isinstance(node, PtraceRuleNode):
        return _hover_ptrace(line_text, ch)
    if isinstance(node, DbusRuleNode):
        return _hover_dbus(line_text, ch)
    if isinstance(node, UnixRuleNode):
        return _hover_unix(line_text, ch)
    if isinstance(node, (MountRuleNode, UmountRuleNode)):
        return _hover_mount(line_text, ch)
    if isinstance(node, RlimitRuleNode):
        return _hover_rlimit(line_text, ch)
    if isinstance(node, IoUringRuleNode):
        return _hover_io_uring(line_text, ch)
    if isinstance(node, MqueueRuleNode):
        return _hover_mqueue(line_text, ch)
    if isinstance(
        node,
        (UsernsRuleNode, PivotRootRuleNode, ChangeProfileRuleNode, ChangeHatRuleNode),
    ):
        return _hover_keyword_rule(line_text, ch)
    if isinstance(node, UnknownRuleNode):
        return _hover_unknown(line_text, ch)
    # VariableDefNode: the @{name} token is already handled by _RE_VAR above.
    return None


def _hover_capability(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "capability":
        return _make_hover(KEYWORD_DEFS["capability"].doc, ws, we)
    cap_def = CAPABILITY_DEFS.get(word)
    if cap_def:
        return _make_hover(cap_def.doc, ws, we)
    return None


def _hover_network(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "network":
        return _make_hover(KEYWORD_DEFS["network"].doc, ws, we)
    if word in NETWORK_DOMAINS:
        return _make_hover(
            f"**Network family `{word}`**\n\nRestricts network access to this address family.",
            ws,
            we,
        )
    if word in NETWORK_TYPES:
        return _make_hover(
            f"**Network socket type `{word}`**\n\nRestricts network access to this socket type.",
            ws,
            we,
        )
    if word in NETWORK_PERMISSIONS:
        return _make_hover(
            f"**Network permission `{word}`**\n\nAllows `{word}` operations on network sockets.",
            ws,
            we,
        )
    return None


def _hover_signal(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "signal":
        return _make_hover(KEYWORD_DEFS["signal"].doc, ws, we)
    if word in SIGNAL_PERMISSIONS:
        return _make_hover(
            f"**Signal permission `{word}`**\n\nPermission for `signal` rules.",
            ws,
            we,
        )
    if word in SIGNAL_NAMES:
        return _make_hover(
            f"**Signal `{word.upper()}`**\n\nPOSIX signal name used in `signal` rules.",
            ws,
            we,
        )
    return None


def _hover_file_rule(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "owner":
        return _make_hover(
            "**Qualifier `owner`**\n\nRestrict the rule to files owned by the running process's UID.",
            ws,
            we,
        )
    if word == "file":
        return _make_hover(KEYWORD_DEFS["file"].doc, ws, we)
    for pm in RE_FILE_PERMISSIONS.finditer(line_text):
        if pm.start() <= ch <= pm.end():
            return _file_perm_hover(pm.group(1), pm.start(), pm.end())
    return None


def _hover_profile(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in ("profile", "hat"):
        kw_def = KEYWORD_DEFS.get(word)
        if kw_def:
            return _make_hover(kw_def.doc, ws, we)
    flag_def = FLAG_DEFS.get(word)
    if flag_def:
        return _make_hover(flag_def.doc, ws, we)
    return None


def _hover_include(node: IncludeNode, line_text: str, ch: int) -> Optional[Hover]:
    if node.conditional:
        kw = "include if exists"
        kw_start = line_text.find(kw)
        if kw_start != -1 and kw_start <= ch <= kw_start + len(kw):
            kw_def = KEYWORD_DEFS.get("include if exists")
            if kw_def:
                return _make_hover(kw_def.doc, kw_start, kw_start + len(kw))
    word, ws, we = _word_at(line_text, ch)
    if word == "include":
        kw_def = KEYWORD_DEFS.get("include")
        if kw_def:
            return _make_hover(kw_def.doc, ws, we)
    return None


def _hover_abi(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if word == "abi":
        kw_def = KEYWORD_DEFS.get("abi")
        if kw_def:
            return _make_hover(kw_def.doc, ws, we)
    return None


def _hover_ptrace(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "ptrace":
        return _make_hover(KEYWORD_DEFS["ptrace"].doc, ws, we)
    return _hover_ptrace_token(word, ws, we)


def _hover_dbus(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "dbus":
        return _make_hover(KEYWORD_DEFS["dbus"].doc, ws, we)
    return _hover_dbus_token(word, ws, we)


def _hover_unix(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "unix":
        return _make_hover(KEYWORD_DEFS["unix"].doc, ws, we)
    return _hover_unix_token(word, ws, we)


def _hover_mount(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word in ("mount", "umount", "remount"):
        kw_def = KEYWORD_DEFS.get(word)
        if kw_def:
            return _make_hover(kw_def.doc, ws, we)
    return _hover_mount_token(word, ws, we)


def _hover_rlimit(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    return _hover_rlimit_token(word, ws, we)


def _hover_io_uring(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "io_uring":
        return _make_hover(KEYWORD_DEFS["io_uring"].doc, ws, we)
    return _hover_io_uring_token(word, ws, we)


def _hover_mqueue(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "mqueue":
        return _make_hover(KEYWORD_DEFS["mqueue"].doc, ws, we)
    return _hover_mqueue_token(word, ws, we)


def _hover_keyword_rule(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    kw_def = KEYWORD_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    return None


def _hover_unknown(line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    kw_def = KEYWORD_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    return None


# ── Per-keyword token handlers ────────────────────────────────────────────────


def _hover_ptrace_token(word: str, ws: int, we: int) -> Optional[Hover]:
    perm_def = PTRACE_DEFS.get(word)
    if perm_def:
        return _make_hover(perm_def.doc, ws, we)
    return None


def _hover_dbus_token(word: str, ws: int, we: int) -> Optional[Hover]:
    kw_def = DBUS_PERMISSION_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    kw_def = DBUS_BUS_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    return None


def _hover_unix_token(word: str, ws: int, we: int) -> Optional[Hover]:
    if word in NETWORK_PERMISSIONS:
        return _make_hover(
            f"**Unix socket permission `{word}`**\n\nAllows `{word}` operations on Unix domain sockets.",
            ws,
            we,
        )
    if word in UNIX_TYPES:
        return _make_hover(
            f"**Unix socket type `{word}`**\n\nRestricts the rule to `{word}` Unix domain sockets.",
            ws,
            we,
        )
    return None


def _hover_mount_token(word: str, ws: int, we: int) -> Optional[Hover]:
    kw_def = MOUNT_OPTION_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    return None


def _hover_rlimit_token(word: str, ws: int, we: int) -> Optional[Hover]:
    # "set" and "rlimit" are both part of the two-word keyword.
    if word in ("set", "rlimit"):
        kw_def = KEYWORD_DEFS.get("set rlimit")
        if kw_def:
            return _make_hover(kw_def.doc, ws, we)
    kw_def = RLIMIT_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    return None


def _hover_io_uring_token(word: str, ws: int, we: int) -> Optional[Hover]:
    kw_def = IO_URING_PERMISSION_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    return None


def _hover_mqueue_token(word: str, ws: int, we: int) -> Optional[Hover]:
    kw_def = MQUEUE_PERMISSION_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    if word in ("posix", "sysv"):
        return _make_hover(
            f"**mqueue type `{word}`**\n\nMessage queue implementation: `{word}`.",
            ws,
            we,
        )
    return None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _word_at(line: str, ch: int) -> tuple[str, int, int]:
    for m in _RE_WORD.finditer(line):
        if m.start() <= ch <= m.end():
            return m.group(), m.start(), m.end()
    return "", ch, ch


def _make_hover(md: str, start: int, end: int) -> Hover:
    return Hover(
        contents=MarkupContent(kind=MarkupKind.Markdown, value=md),
        range=Range(
            start=Position(
                0, start
            ),  # line number is adjusted by the caller in server.py
            end=Position(0, end),
        ),
    )


def _file_perm_hover(perm_str: str, start: int, end: int) -> Hover:
    perms: list[str] = []
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
            i += 1
    lines_out = [f"**File permissions `{perm_str}`**\n"]
    for perm in perms:
        desc = FILE_PERMISSIONS.get(perm) or EXECUTE_PERMISSIONS.get(perm)
        if desc:
            lines_out.append(f"- `{perm}` — {desc}")
    return _make_hover("\n".join(lines_out), start, end)
