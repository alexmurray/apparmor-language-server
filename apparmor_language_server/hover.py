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

import logging
import re
from typing import Callable, Optional

from lsprotocol.types import (
    Hover,
    MarkupContent,
    MarkupKind,
    Position,
    Range,
)

from .constants import (
    CAPABILITIES,
    DBUS_BUS_DEFS,
    DBUS_PERMISSION_DEFS,
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
from .docs import capability_doc, file_permissions_doc, variable_doc
from .parser import (
    ABINode,
    AllRuleNode,
    CapabilityNode,
    ChangeHatRuleNode,
    ChangeProfileRuleNode,
    DbusRuleNode,
    DocumentNode,
    FileRuleNode,
    IncludeNode,
    IoUringRuleNode,
    LinkRuleNode,
    MountRuleNode,
    MqueueRuleNode,
    NetworkNode,
    Node,
    PivotRootRuleNode,
    ProfileNode,
    PtraceRuleNode,
    RemountRuleNode,
    RlimitRuleNode,
    SignalRuleNode,
    UmountRuleNode,
    UnixRuleNode,
    UnknownRuleNode,
    UsernsRuleNode,
)

logger = logging.getLogger(__name__)

_RE_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
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
                    return _make_hover(
                        variable_doc(var_name, vars[var_name], uri),
                        m.start(),
                        m.end(),
                    )

    node = _node_at_position(doc, position.line)
    logger.debug(
        "Hover node at line %d: %s",
        position.line,
        type(node).__name__ if node is not None else None,
    )
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


_HoverHandler = Callable[[Node, str, int], Optional[Hover]]


def _hover_for_node(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    handler = _HOVER_DISPATCH.get(type(node))
    if handler is None:
        return None
    return handler(node, line_text, ch)


def _hover_capability(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "capability":
        return _make_hover(KEYWORD_DEFS["capability"].doc, ws, we)
    if word in CAPABILITIES:
        return _make_hover(capability_doc(word), ws, we)
    return None


def _hover_network(node: Node, line_text: str, ch: int) -> Optional[Hover]:
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


def _hover_signal(node: Node, line_text: str, ch: int) -> Optional[Hover]:
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


def _hover_file_rule(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    assert isinstance(node, FileRuleNode)
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
    if node.exec_target and word == node.exec_target:
        return _make_hover(
            # exec_target is the designator of a profile name / attachment etc
            f"**File rule exec target `{word}`**\n\nDesignator for the profile or path attachment to which this `file` rule applies.",
            ws,
            we,
        )
    # Check path before permissions: RE_FILE_PERMISSIONS matches substrings of
    # paths (e.g. 'r' in '/var/run/', 'ar' in '/var/') producing false positives.
    if node.path:
        idx = line_text.find(node.path)
        if idx != -1 and idx <= ch <= idx + len(node.path):
            return _make_hover(
                f"**File rule path** `{node.path}`\n\n"
                "Path pattern for the target of this file rule.\n\n"
                "AppArmor glob patterns: `*` matches any character except `/`; "
                "`**` matches any character including `/`; "
                "`?` matches any single character except `/`.",
                idx,
                idx + len(node.path),
            )
    for pm in RE_FILE_PERMISSIONS.finditer(line_text):
        if pm.start() <= ch <= pm.end():
            return _file_perm_hover(pm.group(1), pm.start(), pm.end())
    return None


def _hover_profile(node: Node, line_text: str, ch: int) -> Optional[Hover]:
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


def _hover_include(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    assert isinstance(node, IncludeNode)
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


def _hover_abi(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if word == "abi":
        kw_def = KEYWORD_DEFS.get("abi")
        if kw_def:
            return _make_hover(kw_def.doc, ws, we)
    return None


def _hover_ptrace(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "ptrace":
        return _make_hover(KEYWORD_DEFS["ptrace"].doc, ws, we)
    return _hover_ptrace_token(word, ws, we)


def _hover_dbus(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "dbus":
        return _make_hover(KEYWORD_DEFS["dbus"].doc, ws, we)
    return _hover_dbus_token(word, ws, we)


def _hover_unix(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "unix":
        return _make_hover(KEYWORD_DEFS["unix"].doc, ws, we)
    return _hover_unix_token(word, ws, we)


def _hover_mount(node: Node, line_text: str, ch: int) -> Optional[Hover]:
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


def _hover_rlimit(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    return _hover_rlimit_token(word, ws, we)


def _hover_io_uring(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "io_uring":
        return _make_hover(KEYWORD_DEFS["io_uring"].doc, ws, we)
    return _hover_io_uring_token(word, ws, we)


def _hover_mqueue(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word == "mqueue":
        return _make_hover(KEYWORD_DEFS["mqueue"].doc, ws, we)
    return _hover_mqueue_token(word, ws, we)


def _hover_keyword_rule(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    kw_def = KEYWORD_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    return None


def _hover_link(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    if word in ("link", "subset"):
        kw_def = KEYWORD_DEFS.get("link")
        if kw_def:
            return _make_hover(kw_def.doc, ws, we)
    if word == "owner":
        return _make_hover(
            "**Qualifier `owner`**\n\nRestrict the rule to files owned by the running process's UID.",
            ws,
            we,
        )
    return None


def _hover_unknown(node: Node, line_text: str, ch: int) -> Optional[Hover]:
    word, ws, we = _word_at(line_text, ch)
    if not word:
        return None
    if word in QUALIFIER_DEFS:
        return _make_hover(QUALIFIER_DEFS[word].doc, ws, we)
    kw_def = KEYWORD_DEFS.get(word)
    if kw_def:
        return _make_hover(kw_def.doc, ws, we)
    return None


# ── Dispatch table ────────────────────────────────────────────────────────────
# Map each AST node type to its hover handler. Node types not present here
# (CommentNode, VariableDefNode) have no hover; the variable @{name} tokens
# inside any node are resolved earlier via _RE_VAR in get_hover.

_HOVER_DISPATCH: dict[type[Node], _HoverHandler] = {
    CapabilityNode: _hover_capability,
    NetworkNode: _hover_network,
    SignalRuleNode: _hover_signal,
    FileRuleNode: _hover_file_rule,
    ProfileNode: _hover_profile,
    IncludeNode: _hover_include,
    ABINode: _hover_abi,
    PtraceRuleNode: _hover_ptrace,
    DbusRuleNode: _hover_dbus,
    UnixRuleNode: _hover_unix,
    MountRuleNode: _hover_mount,
    UmountRuleNode: _hover_mount,
    RemountRuleNode: _hover_mount,
    RlimitRuleNode: _hover_rlimit,
    IoUringRuleNode: _hover_io_uring,
    MqueueRuleNode: _hover_mqueue,
    UsernsRuleNode: _hover_keyword_rule,
    PivotRootRuleNode: _hover_keyword_rule,
    ChangeProfileRuleNode: _hover_keyword_rule,
    ChangeHatRuleNode: _hover_keyword_rule,
    AllRuleNode: _hover_keyword_rule,
    LinkRuleNode: _hover_link,
    UnknownRuleNode: _hover_unknown,
}


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
    return _make_hover(file_permissions_doc(perm_str), start, end)
