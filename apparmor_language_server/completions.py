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
from pathlib import Path

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
        items = _complete_abi_paths(partial, document_uri)
        return CompletionList(is_incomplete=False, items=items)

    # ── Include path completion ────────────────────────────────────────────
    if _RE_INCLUDE_START.match(prefix):
        im = _RE_INCLUDE_PATH.match(prefix)
        partial = im.group(1) if im else ""
        logger.debug(f"Include path completion triggered with partial: '{partial}'")
        items = _complete_include_paths(partial, document_uri)
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
        items = _complete_filesystem_path(partial_path, doc)
        return CompletionList(is_incomplete=True, items=items)

    # ── Qualifier shorthand ────────────────────────────────────────────────
    if _RE_QUALIFIERS.match(prefix):
        items = _complete_keywords("")
        return CompletionList(is_incomplete=False, items=items)

    # ── Default: rule keywords ────────────────────────────────────────────
    stripped = prefix.strip()
    items = _complete_keywords(stripped)
    return CompletionList(is_incomplete=False, items=items)


# ── Keyword completions ───────────────────────────────────────────────────────


def _complete_keywords(partial: str) -> list[CompletionItem]:
    """Snippet completions for all AppArmor rule keywords."""
    snippets: dict[str, tuple[str, str]] = {
        "capability": (
            "capability ${1:cap_name},",
            "Grant a Linux capability to the confined process.",
        ),
        "network": (
            "network ${1:inet} ${2:stream},",
            "Allow network access for the given family/type.",
        ),
        "signal": (
            "signal (${1:send receive}) set=(${2:term}) peer=${3:@{profile_name}},",
            "Allow sending/receiving signals.",
        ),
        "ptrace": (
            "ptrace (${1:read trace}) peer=${2:@{profile_name}},",
            "Allow ptrace of another process.",
        ),
        "mount": (
            "mount options=(${1:ro}) ${2:/path/} -> ${3:/mnt/},",
            "Allow a mount operation.",
        ),
        "umount": (
            "umount ${1:/mnt/},",
            "Allow unmounting a filesystem.",
        ),
        "dbus": (
            "dbus (${1:send}) bus=${2:session} path=${3:/org/example} interface=${4:org.example.Interface},",
            "Allow DBus interaction.",
        ),
        "unix": (
            "unix (${1:connect}) type=${2:stream} addr=${3:@path},",
            "Allow Unix domain socket operation.",
        ),
        "deny": (
            "deny ${1:/path/**} ${2:rw},",
            "Explicitly deny access to a resource.",
        ),
        "audit": (
            "audit ${1:/path/**} ${2:r},",
            "Allow but audit access.",
        ),
        "owner": (
            "owner ${1:/path/**} ${2:rw},",
            "Allow only when the process owns the file.",
        ),
        "change_profile": (
            "change_profile -> ${1:profile_name},",
            "Allow switching to another AppArmor profile.",
        ),
        "rlimit": (
            "rlimit ${1:nofile} <= ${2:1024},",
            "Set a resource limit for the confined process.",
        ),
        "abi": (
            "abi <${1:abi/5.0}>,",
            "The AppArmor ABI to target for this profile.",
        ),
        "include": (
            "include <${1:abstractions/base}>",
            "Include an AppArmor abstraction or sub-policy file.",
        ),
        "profile": (
            "profile ${1:name} {\n  include <abstractions/base>\n  $0\n}",
            "Define a new AppArmor profile.",
        ),
        "hat": (
            "hat ${1:name} {\n  $0\n}",
            "Define a hat (change_hat target) sub-profile.",
        ),
        "userns": (
            "userns,",
            "Allow user namespace creation.",
        ),
        "io_uring": (
            "io_uring (${1:sqpoll override_creds}),",
            "Allow io_uring operations.",
        ),
        "mqueue": (
            "mqueue (${1:create open delete read write}) type=${2:posix} name=${3:/name},",
            "Allow POSIX/SysV message queue operations.",
        ),
    }

    items: list[CompletionItem] = []
    for kw, (snippet, doc) in snippets.items():
        if not partial or kw.startswith(partial):
            items.append(
                CompletionItem(
                    label=kw,
                    kind=CompletionItemKind.Keyword,
                    insert_text=snippet,
                    insert_text_format=InsertTextFormat.Snippet,
                    documentation=MarkupContent(kind=MarkupKind.Markdown, value=doc),
                )
            )
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

_APPARMOR_SEARCH_DIRS = [
    Path("/etc/apparmor.d"),
    Path("/usr/share/apparmor"),
    Path("/usr/share/apparmor.d"),
]


def _complete_abi_paths(partial: str, doc_uri: str) -> list[CompletionItem]:
    """
    Complete ABI paths.
    Shows known ABIs, then files found in abi dirs.
    """
    items: list[CompletionItem] = []
    seen: set[str] = set()

    for base in _APPARMOR_SEARCH_DIRS:
        if not base.is_dir():
            continue
        try:
            for entry in base.rglob("abi/*"):
                if entry.is_file():
                    rel = str(entry.relative_to(base))
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
        except PermissionError:
            pass

    return items


def _complete_include_paths(partial: str, doc_uri: str) -> list[CompletionItem]:
    """
    Complete include paths.
    Shows known abstractions, then files found in search dirs, then local files.
    """
    items: list[CompletionItem] = []
    seen: set[str] = set()

    # 1. Files on disk under search dirs
    for base in _APPARMOR_SEARCH_DIRS:
        if not base.is_dir():
            continue
        try:
            for entry in base.rglob("*"):
                if entry.is_file():
                    rel = str(entry.relative_to(base))
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
        except PermissionError:
            pass

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


def _complete_filesystem_path(partial: str, doc: DocumentNode) -> list[CompletionItem]:
    """
    Complete filesystem paths for file rules.
    Completes against the real filesystem plus known AppArmor path globs.
    """
    items: list[CompletionItem] = []

    # Variable-prefixed paths – just offer var names
    if partial.startswith("@"):
        return _complete_variables(partial[2:] if partial.startswith("@{") else "", doc)

    # Real filesystem
    try:
        parent = Path(partial).parent
        if not parent.is_absolute():
            parent = Path("/") / parent
        if parent.is_dir():
            for entry in sorted(parent.iterdir())[:80]:  # cap to avoid flooding
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

    return items


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
