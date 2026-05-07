"""
AppArmor LSP – completion provider.

Completion contexts
───────────────────
 1. Top-level / after '{':        rule keywords
 2. After 'capability':           capability names
 3. After 'network':              network families, then types
 4. After 'signal':               permissions, then signal names
 5. After 'ptrace':               ptrace permissions
 6. After 'mount'/'umount':       mount options
 7. After 'dbus':                 dbus permissions, bus names
 8. After 'deny'/'audit'/'owner': rule keywords
 9. After '#include' / 'include': angle-bracket or quoted paths
10. After '@{':                   variable names
11. On a path token:              filesystem path completion
12. After a path:                 file permissions
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Optional

from lsprotocol.types import (
    CompletionItem,
    CompletionItemKind,
    CompletionList,
    InsertTextFormat,
    MarkupContent,
    MarkupKind,
    Position,
)

from .constants import (
    CAPABILITIES,
    DBUS_BUSES,
    DBUS_PERMISSIONS,
    DEFAULT_INCLUDE_SEARCH_DIRS,
    KEYWORD_DEFS,
    MOUNT_OPTIONS,
    NETWORK_DOMAINS,
    NETWORK_PERMISSIONS,
    NETWORK_TYPES,
    PERMISSION_COMBINATIONS,
    PROFILE_FLAGS,
    PTRACE_PERMISSIONS,
    QUALIFIERS,
    RE_FILE_PERMISSIONS,
    SIGNAL_NAMES,
    SIGNAL_PERMISSIONS,
)
from .docs import capability_doc, file_permissions_doc, variable_doc
from .parser import DocumentNode

# ── Regex helpers ─────────────────────────────────────────────────────────────

_RE_ABI_START = re.compile(r"""^\s*#?abi\s+(<|")""")
_RE_ABI_PATH = re.compile(r"""^\s*#?abi\s+[<"]([^>"]*)?,$""")
_RE_INCLUDE_START = re.compile(r"""^\s*#?include\s+(<|")""")
_RE_INCLUDE_PATH = re.compile(r"""^\s*#?include\s+[<"]([^>"]*)?$""")
_RE_QUALIFIERS = re.compile(r"^\s*((" + r"|".join(QUALIFIERS) + r")\s+)")
_RE_CAPABILITY = re.compile(_RE_QUALIFIERS.pattern + r"*capability\s+")
_RE_NETWORK = re.compile(_RE_QUALIFIERS.pattern + r"*network\s+")
_RE_SIGNAL = re.compile(_RE_QUALIFIERS.pattern + r"*signal\s+")
_RE_PTRACE = re.compile(_RE_QUALIFIERS.pattern + r"*ptrace\s+")
_RE_MOUNT = re.compile(_RE_QUALIFIERS.pattern + r"*(mount|umount)\s+")
_RE_DBUS = re.compile(_RE_QUALIFIERS.pattern + r"*dbus\s+")
_RE_UNIX = re.compile(_RE_QUALIFIERS.pattern + r"*unix\s+")
_RE_FILE_QUALIFIERS = re.compile(
    r"^\s*((" + r"|".join(QUALIFIERS + ["owner"]) + r")\s+)"
)
_RE_PATH_START = re.compile(_RE_FILE_QUALIFIERS.pattern + r"*(file\s+)?([/@][^\s]*)$")
_RE_AFTER_PATH = re.compile(
    _RE_FILE_QUALIFIERS.pattern
    + r"*(file\s+)?([/@][^\s]+)\s+"
    + RE_FILE_PERMISSIONS.pattern
    + "?$"
)
_RE_VAR_START = re.compile(r"@(\{([A-Za-z][A-Za-z0-9_]*)?)?$")
_RE_PROFILE_FLAGS = re.compile(r"flags\s*=\s*\(([^)]*)$")


logger = logging.getLogger(__name__)

# ── Public entry point ────────────────────────────────────────────────────────


def get_completions(
    doc: DocumentNode,
    line_text: str,
    position: Position,
    document_uri: str,
    search_dirs: Optional[list[Path]] = None,
) -> CompletionList:
    """
    Return completion items for the given cursor position.
    """
    # Text up to the cursor on this line
    prefix = line_text[: position.character]

    items: list[CompletionItem] = []

    # ── Variable reference completion ──────────────────────────────────────
    vm = _RE_VAR_START.search(prefix)
    if vm:
        partial = vm.group(0)
        logger.debug(f"Variable completion triggered with partial: '{partial}'")
        items = _complete_variables(partial, doc)
        return CompletionList(is_incomplete=False, items=items)

    # ── ABI completion ────────────────────────────────────────────
    if _RE_ABI_START.match(prefix):
        im = _RE_ABI_PATH.match(prefix)
        partial = im.group(1) if im else ""
        logger.debug(f"ABI completion triggered with partial: '{partial}'")
        items = _complete_abi_paths(partial, document_uri, search_dirs)
        return CompletionList(is_incomplete=False, items=items)

    # ── Include path completion ────────────────────────────────────────────
    if _RE_INCLUDE_START.match(prefix):
        im = _RE_INCLUDE_PATH.match(prefix)
        partial = im.group(1) if im else ""
        logger.debug(f"Include path completion triggered with partial: '{partial}'")
        items = _complete_include_paths(partial, document_uri, search_dirs)
        return CompletionList(is_incomplete=False, items=items)

    # ── Profile flags completion ───────────────────────────────────────────
    fm = _RE_PROFILE_FLAGS.search(prefix)
    if fm:
        partial = fm.group(1).split(",")[-1].strip()
        logger.debug(f"Profile flags completion triggered with partial: '{partial}'")
        items = _complete_profile_flags(partial)
        return CompletionList(is_incomplete=False, items=items)

    # ── Capability ────────────────────────────────────────────────────────
    if _RE_CAPABILITY.match(prefix):
        partial = prefix.split()[-1] if prefix.split() else ""
        # Don't re-complete 'capability' itself
        if partial in ("capability",):
            partial = ""
        logger.debug(f"Capability completion triggered with partial: '{partial}'")
        items = _complete_capabilities(partial)
        return CompletionList(is_incomplete=False, items=items)

    # ── Network ───────────────────────────────────────────────────────────
    if _RE_NETWORK.match(prefix):
        tokens = prefix.split()
        # After 'network': families; after a family: types
        net_tokens = [t for t in tokens if t not in ("network", "deny", "audit")]
        if len(net_tokens) == 0:
            items = _complete_list(
                NETWORK_DOMAINS, CompletionItemKind.Value, "Network domain"
            )
        elif len(net_tokens) == 1:
            items = _complete_list(
                NETWORK_TYPES, CompletionItemKind.Value, "Network socket type"
            )
        return CompletionList(is_incomplete=False, items=items)

    # ── Signal ────────────────────────────────────────────────────────────
    if _RE_SIGNAL.match(prefix):
        tokens = [t for t in prefix.split() if t not in ("signal", "deny", "audit")]
        if len(tokens) == 0:
            items = _complete_list(
                SIGNAL_PERMISSIONS, CompletionItemKind.Value, "Signal permission"
            )
        else:
            items = _complete_list(
                SIGNAL_NAMES, CompletionItemKind.Value, "Signal name"
            )
        return CompletionList(is_incomplete=False, items=items)

    # ── Ptrace ────────────────────────────────────────────────────────────
    if _RE_PTRACE.match(prefix):
        items = _complete_list(
            PTRACE_PERMISSIONS, CompletionItemKind.Value, "ptrace permission"
        )
        return CompletionList(is_incomplete=False, items=items)

    # ── Mount ─────────────────────────────────────────────────────────────
    if _RE_MOUNT.match(prefix):
        items = _complete_list(MOUNT_OPTIONS, CompletionItemKind.Value, "Mount option")
        return CompletionList(is_incomplete=False, items=items)

    # ── DBus ──────────────────────────────────────────────────────────────
    if _RE_DBUS.match(prefix):
        tokens = [t for t in prefix.split() if t not in ("dbus", "deny", "audit")]
        if len(tokens) == 0:
            items = _complete_list(
                DBUS_PERMISSIONS, CompletionItemKind.Value, "DBus permission"
            )
        elif len(tokens) == 1 and tokens[0] == "bus":
            items = _complete_list(
                DBUS_BUSES, CompletionItemKind.Value, "DBus bus name"
            )
        else:
            items = _complete_dbus_keys()
        return CompletionList(is_incomplete=False, items=items)

    # ── Unix ──────────────────────────────────────────────────────────────
    if _RE_UNIX.match(prefix):
        tokens = [t for t in prefix.split() if t not in ("unix", "deny", "audit")]
        if len(tokens) == 0:
            items = _complete_list(
                NETWORK_PERMISSIONS, CompletionItemKind.Value, "Unix socket permission"
            )
        return CompletionList(is_incomplete=False, items=items)

    # ── File permissions (after a path) ───────────────────────────────────
    am = _RE_AFTER_PATH.match(prefix)
    if am:
        partial_perm = am.group(5) or ""
        logger.debug(
            f"File permission completion triggered with partial: '{partial_perm}'"
        )
        items = _complete_file_permissions(partial_perm)
        return CompletionList(is_incomplete=False, items=items)

    # ── Filesystem path ───────────────────────────────────────────────────
    logger.debug(
        f"Checking for filesystem path completion with prefix: '{prefix}' against regex: '{_RE_PATH_START.pattern}'"
    )
    pm = _RE_PATH_START.search(prefix)
    if pm:
        partial_path = pm.group(4)
        logger.debug(
            f"Filesystem path completion triggered with partial: '{partial_path}'"
        )
        items, truncated = _complete_filesystem_path(partial_path, doc)
        return CompletionList(is_incomplete=truncated, items=items)

    # ── Qualifier shorthand ────────────────────────────────────────────────
    if _RE_QUALIFIERS.match(prefix):
        items = _complete_keywords("")
        return CompletionList(is_incomplete=False, items=items)

    # ── Default: rule keywords ────────────────────────────────────────────
    stripped = prefix.strip()
    items = _complete_keywords(stripped)
    return CompletionList(is_incomplete=False, items=items)


# ── Keyword completions ───────────────────────────────────────────────────────


# Line-starter snippets that don't have a KEYWORD_DEFS entry: rule qualifiers
# and the bare "rlimit" form (KEYWORD_DEFS uses the multi-word "set rlimit" key).
_EXTRA_KEYWORD_SNIPPETS: dict[str, tuple[str, str]] = {
    "deny": (
        "deny ${1:/path/**} ${2:rw},",
        "**Qualifier `deny`**\n\nExplicitly deny access to a resource.",
    ),
    "audit": (
        "audit ${1:/path/**} ${2:r},",
        "**Qualifier `audit`**\n\nAllow but audit access.",
    ),
    "owner": (
        "owner ${1:/path/**} ${2:rw},",
        "**Qualifier `owner`**\n\nAllow only when the process owns the file.",
    ),
    "rlimit": (
        "rlimit ${1:nofile} <= ${2:1024},",
        "Set a resource limit for the confined process.",
    ),
}


def _keyword_item(label: str, snippet: str, doc: str) -> CompletionItem:
    return CompletionItem(
        label=label,
        kind=CompletionItemKind.Keyword,
        insert_text=snippet,
        insert_text_format=InsertTextFormat.Snippet,
        documentation=MarkupContent(kind=MarkupKind.Markdown, value=doc),
    )


def _complete_keywords(partial: str) -> list[CompletionItem]:
    """Snippet completions for all AppArmor rule keywords."""
    items: list[CompletionItem] = []
    seen: set[str] = set()

    # Single-word rule keywords from KEYWORD_DEFS (the canonical source of truth).
    # Multi-word keys (e.g. "set rlimit", "include if exists") are skipped; their
    # short forms appear via _EXTRA_KEYWORD_SNIPPETS or KEYWORD_DEFS itself.
    for kw, kw_def in KEYWORD_DEFS.items():
        if " " in kw or kw_def.snippet is None:
            continue
        if not partial or kw.startswith(partial):
            items.append(_keyword_item(kw, kw_def.snippet, kw_def.doc))
        seen.add(kw)

    for kw, (snippet, doc) in _EXTRA_KEYWORD_SNIPPETS.items():
        if kw in seen:
            continue
        if not partial or kw.startswith(partial):
            items.append(_keyword_item(kw, snippet, doc))

    return items


# ── Capability completions ────────────────────────────────────────────────────


def _complete_capabilities(partial: str) -> list[CompletionItem]:
    items: list[CompletionItem] = []
    for cap in CAPABILITIES:
        if not partial or cap.startswith(partial):
            items.append(
                CompletionItem(
                    label=cap,
                    kind=CompletionItemKind.EnumMember,
                    documentation=MarkupContent(
                        kind=MarkupKind.Markdown,
                        value=capability_doc(cap),
                    ),
                )
            )
    return items


# ── File permission completions ───────────────────────────────────────────────


def _complete_file_permissions(partial: str) -> list[CompletionItem]:
    """Complete file permission strings."""
    items: list[CompletionItem] = []
    for perm, desc in PERMISSION_COMBINATIONS.items():
        if not partial or perm.startswith(partial):
            items.append(
                CompletionItem(
                    label=perm,
                    kind=CompletionItemKind.EnumMember,
                    detail=desc,
                    documentation=MarkupContent(
                        kind=MarkupKind.Markdown,
                        value=file_permissions_doc(perm),
                    ),
                )
            )
    return items


# ── Include path completions ──────────────────────────────────────────────────

# Walking /etc/apparmor.d takes ~tens of ms and runs on every keystroke that
# triggers include-path completion. Cache the listing per (base, glob) for a
# short TTL so most completion requests just hit memory. The directory itself
# is also inotify-watched by WorkspaceIndexer for the workspace case, but the
# system search dirs here may not be — a TTL is the simpler bound.
_RGLOB_TTL_SECONDS = 30.0
_rglob_cache: dict[tuple[Path, str], tuple[float, list[str]]] = {}


def _cached_rglob_files(base: Path, pattern: str) -> list[str]:
    """Return file paths under *base* matching *pattern*, relative to *base*."""
    key = (base, pattern)
    now = time.monotonic()
    cached = _rglob_cache.get(key)
    if cached is not None and now - cached[0] < _RGLOB_TTL_SECONDS:
        return cached[1]
    rels: list[str] = []
    try:
        for entry in base.rglob(pattern):
            if entry.is_file():
                rels.append(str(entry.relative_to(base)))
    except (OSError, PermissionError):
        pass
    _rglob_cache[key] = (now, rels)
    return rels


def _complete_abi_paths(
    partial: str,
    doc_uri: str,
    search_dirs: Optional[list[Path]] = None,
) -> list[CompletionItem]:
    """
    Complete ABI paths.
    Shows known ABIs, then files found in abi dirs.
    """
    items: list[CompletionItem] = []
    seen: set[str] = set()

    for base in search_dirs if search_dirs is not None else DEFAULT_INCLUDE_SEARCH_DIRS:
        if not base.is_dir():
            continue
        for rel in _cached_rglob_files(base, "abi/*"):
            if rel not in seen and (not partial or rel.startswith(partial)):
                items.append(
                    CompletionItem(
                        label=rel,
                        kind=CompletionItemKind.File,
                        detail=str(base),
                        insert_text=rel,
                    )
                )
                seen.add(rel)

    return items


def _complete_include_paths(
    partial: str,
    doc_uri: str,
    search_dirs: Optional[list[Path]] = None,
) -> list[CompletionItem]:
    """
    Complete include paths.
    Shows known abstractions, then files found in search dirs, then local files.
    """
    items: list[CompletionItem] = []
    seen: set[str] = set()

    # 1. Files on disk under search dirs
    for base in search_dirs if search_dirs is not None else DEFAULT_INCLUDE_SEARCH_DIRS:
        if not base.is_dir():
            continue
        for rel in _cached_rglob_files(base, "*"):
            if rel not in seen and (not partial or rel.startswith(partial)):
                items.append(
                    CompletionItem(
                        label=rel,
                        kind=CompletionItemKind.File,
                        detail=str(base),
                        insert_text=rel,
                    )
                )
                seen.add(rel)

    # 2. Relative to document dir
    doc_path = Path(doc_uri.removeprefix("file://"))
    doc_dir = doc_path.parent
    partial_path = Path(partial) if partial else Path(".")
    search_in = doc_dir / partial_path.parent
    try:
        if search_in.is_dir():
            for entry in search_in.iterdir():
                rel = str(entry.relative_to(doc_dir))
                if rel not in seen:
                    items.append(
                        CompletionItem(
                            label=rel,
                            kind=CompletionItemKind.File
                            if entry.is_file()
                            else CompletionItemKind.Folder,
                            insert_text=rel,
                        )
                    )
    except (PermissionError, ValueError):
        pass

    return items


# ── Filesystem path completion ────────────────────────────────────────────────


_FS_PATH_LIMIT = 80


def _complete_filesystem_path(
    partial: str, doc: DocumentNode
) -> tuple[list[CompletionItem], bool]:
    """
    Complete filesystem paths for file rules.
    Completes against the real filesystem plus known AppArmor path globs.

    Returns (items, truncated) so the caller can set ``is_incomplete=True``
    and let the client request more results as the user types.
    """
    items: list[CompletionItem] = []

    # Variable-prefixed paths – just offer var names
    if partial.startswith("@"):
        return (
            _complete_variables(partial[2:] if partial.startswith("@{") else "", doc),
            False,
        )

    truncated = False
    try:
        parent = Path(partial).parent
        if not parent.is_absolute():
            parent = Path("/") / parent
        if parent.is_dir():
            entries = sorted(parent.iterdir())
            if len(entries) > _FS_PATH_LIMIT:
                truncated = True
                entries = entries[:_FS_PATH_LIMIT]
            for entry in entries:
                label = str(entry)
                if label.startswith(partial):
                    kind = (
                        CompletionItemKind.Folder
                        if entry.is_dir()
                        else CompletionItemKind.File
                    )
                    insert = label + ("/" if entry.is_dir() else "")
                    items.append(
                        CompletionItem(
                            label=label,
                            kind=kind,
                            insert_text=insert,
                        )
                    )
    except (PermissionError, OSError):
        pass

    return items, truncated


# ── Variable completions ──────────────────────────────────────────────────────


def _complete_variables(partial: str, doc: DocumentNode) -> list[CompletionItem]:
    items: list[CompletionItem] = []
    for uri, vars in doc.all_variables.items():
        for name, var in vars.items():
            if not partial or name.startswith(partial):
                items.append(
                    CompletionItem(
                        label=name,
                        kind=CompletionItemKind.Variable,
                        documentation=MarkupContent(
                            kind=MarkupKind.Markdown,
                            value=variable_doc(name, var, uri),
                        ),
                    )
                )
    return items


# ── Profile flags completions ─────────────────────────────────────────────────


def _complete_profile_flags(partial: str) -> list[CompletionItem]:
    items: list[CompletionItem] = []
    for flag in PROFILE_FLAGS:
        if not partial or flag.startswith(partial):
            items.append(
                CompletionItem(
                    label=flag,
                    kind=CompletionItemKind.EnumMember,
                )
            )
    return items


# ── DBus key completions ──────────────────────────────────────────────────────


def _complete_dbus_keys() -> list[CompletionItem]:
    keys = [
        ("bus", "bus=" + "|".join(DBUS_BUSES)),
        ("path", "path=/org/example/Path"),
        ("interface", "interface=org.example.Interface"),
        ("member", "member=MethodName"),
        ("peer", "peer=(label=@{profile_name})"),
        ("name", 'name="org.example.Service"'),
        ("label", "label=@{profile_name}"),
    ]
    return [
        CompletionItem(
            label=k,
            kind=CompletionItemKind.Property,
            detail=detail,
            insert_text=f"{k}=${{1:{k}_value}}",
            insert_text_format=InsertTextFormat.Snippet,
        )
        for k, detail in keys
    ]


# ── Generic list helper ───────────────────────────────────────────────────────


def _complete_list(
    values: list[str],
    kind: CompletionItemKind,
    detail: str = "",
) -> list[CompletionItem]:
    return [CompletionItem(label=v, kind=kind, detail=detail) for v in values]
