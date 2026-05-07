"""
AppArmor LSP – profile parser.

Produces a lightweight AST suitable for:
  • goto-definition (resolves #include targets)
  • diagnostics (syntax / semantic checks)
  • formatting (re-serialises the AST)
  • hover / completion context
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

from lsprotocol.types import Position, Range

from ._text import code_end as _code_end
from .constants import (
    DEFAULT_INCLUDE_SEARCH_DIRS,
    KEYWORD_DEFS,
    QUALIFIERS,
    RE_FILE_PERMISSIONS,
    SIGNAL_PERMISSIONS,
)

# ── Regex patterns ────────────────────────────────────────────────────────────

RE_BLANK = re.compile(r"^\s*$")
RE_COMMENT = re.compile(r"^\s*#.*$")
RE_ABI_GLOB = re.compile(r"""^\s*#?abi\s+[<"]([^>"]+)[>"],""")
RE_INCLUDE_GLOB = re.compile(r"""^\s*#?include\s+[<"]([^>"]+)[>"]?""")
RE_INCLUDE_IF = re.compile(r"""^\s*include\s+if\s+exists\s+[<"]([^>"]+)[>"]?""")
RE_VARIABLE_DEF = re.compile(
    r"^\s*(@\{[A-Za-z_][A-Za-z0-9_]*\})\s*(?:\+=|\?=|:=|=)\s*(.*)$"
)

# Matches all profile/sub-profile opening lines, e.g.:
#   profile myapp /usr/bin/myapp {
#   profile myapp flags=(complain) {
#   /usr/bin/myapp {
# Named groups: n (full "name [attachment]" token), flags
_PROFILE_OPEN_PAT = (
    r"^\s*(?:profile\s+)?"  # optional 'profile' keyword
    r"(?P<n>[^\s{(=][^\s{(]*)?"  # name (first token)
    r"(?:\s+(?P<att>[^\s{(=][^\s{(]*))?"  # optional attachment path (second token)
    r"(?:\s*flags\s*=\s*\((?P<flags>[^)]*)\))?"  # optional flags=(...)
    r"\s*\{"  # opening brace
)
RE_PROFILE_OPEN = re.compile(_PROFILE_OPEN_PAT)
RE_HAT_OPEN = re.compile(r"^\s*hat\s+(?P<n>\S+)\s*\{")
RE_PROFILE_CLOSE = re.compile(r"^\s*\}\s*,?\s*$")

_RE_QUALIFIERS = re.compile(r"^\s*(?P<quals>((" + r"|".join(QUALIFIERS) + r")\s+)*)")
RE_CAPABILITY = re.compile(
    _RE_QUALIFIERS.pattern + r"?capability\b\s*(?P<caps>[^{}\n]*?)\s*,?\s*$"
)
RE_NETWORK = re.compile(
    _RE_QUALIFIERS.pattern + r"?network\b\s*(?P<rest>[^{}\n,]*?)\s*,?\s*$"
)
RE_SIGNAL = re.compile(
    _RE_QUALIFIERS.pattern + r"signal\b\s*(?P<rest>[^{}\n]*?)\s*,?\s*$"
)

_RE_SIGNAL_PAREN_PERMS = re.compile(r"^\s*\(([^)]*)\)")
_SIGNAL_PERM_ALT: str = "|".join(sorted(SIGNAL_PERMISSIONS, key=lambda s: -len(s)))
_RE_SIGNAL_BARE_PERM = re.compile(r"^\s*(" + _SIGNAL_PERM_ALT + r")(?=\s|$)")
_RE_SIGNAL_SET = re.compile(r"\bset=(?:\(([^)]*)\)|\"([^\"]*)\"|(\S+))")
_RE_SIGNAL_PEER = re.compile(r"\bpeer=(\S+)")
_RE_FILE_QUALIFIERS = re.compile(
    r"^\s*(?P<quals>((" + r"|".join(QUALIFIERS + ["owner"]) + r")\s+)*)?"
)
_RE_FILE_PATH = r'"[^"]*"|[@/{]\S+'
RE_FILE_PREFIX = re.compile(
    _RE_FILE_QUALIFIERS.pattern
    + (
        r"(?:file\s+)?"
        r"(?P<perms>" + RE_FILE_PERMISSIONS.pattern + r")\s+"
        r"(?P<path>" + _RE_FILE_PATH + r")"
        r"(?:\s*->\s*(?P<exec_target>\S+))?"
        r"\s*,\s*$"
    )
)
RE_FILE_SUFFIX = re.compile(
    _RE_FILE_QUALIFIERS.pattern
    + (
        r"(?:file\s+)?"
        r"(?P<path>" + _RE_FILE_PATH + r")\s+"
        r"(?P<perms>" + RE_FILE_PERMISSIONS.pattern + r")"
        r"(?:\s*->\s*(?P<exec_target>\S+))?"
        r"\s*,\s*$"
    )
)
RE_ALIAS = re.compile(r"^\s*alias\s+(\S+)\s+->\s+(\S+)\s*,?\s*$")

# ── Generic content extractors ────────────────────────────────────────────────
# Used when parsing a rule's post-keyword content into structured fields.

_RE_LEADING_PARENS = re.compile(r"^\s*\(([^)]*)\)\s*")


def _extract_paren_perms(content: str) -> tuple[list[str], str]:
    """Extract a leading ``(a b c)`` permission group, if any.

    Returns ``(permissions, remainder)`` where *remainder* is *content* with
    the leading group removed; if the content does not begin with a paren
    group, ``permissions`` is empty and *remainder* equals *content*.
    """
    m = _RE_LEADING_PARENS.match(content)
    if not m:
        return [], content
    perms = [p for p in m.group(1).replace(",", " ").split() if p]
    return perms, content[m.end() :]


def _extract_kv(content: str, key: str) -> Optional[str]:
    """Extract ``key=value`` from *content*.

    Value may be parenthesised ``(…)``, double-quoted ``"…"``, or a bare
    token (terminated by whitespace, comma, or paren). Returns the unquoted
    value, or ``None`` if the key is absent.
    """
    pat = re.compile(rf"\b{re.escape(key)}=(?:\(([^)]*)\)|\"([^\"]*)\"|([^\s,()]+))")
    m = pat.search(content)
    if m is None:
        return None
    return m.group(1) or m.group(2) or m.group(3)


def _split_arrow(content: str) -> tuple[str, Optional[str]]:
    """Split ``lhs -> rhs`` if present, returning trimmed parts.

    If there is no ``->`` separator, the right-hand side is ``None``.
    Trailing commas and whitespace are stripped from both sides.
    """
    parts = content.split("->", 1)
    lhs = parts[0].strip().rstrip(",").strip()
    rhs = parts[1].strip().rstrip(",").strip() if len(parts) > 1 else None
    return lhs, rhs


def _rule_ends_line(line: str) -> bool:
    """Return True if *line* terminates an AppArmor rule.

    A rule ends when its rightmost comma sits outside all parentheses and
    quoted strings (paren depth 0).  Lines that end with something other than
    a comma never terminate a rule and must be joined with the next line.
    """
    stripped = line.rstrip()
    if not stripped.endswith(","):
        return False
    depth = 0
    in_string = False
    quote_char: Optional[str] = None
    escaped = False
    for ch in stripped:
        if escaped:
            escaped = False
            continue
        if in_string:
            if ch == "\\":
                escaped = True
            elif ch == quote_char:
                in_string = False
        elif ch in "\"'":
            in_string = True
            quote_char = ch
        elif ch in "({":
            depth += 1
        elif ch in ")}":
            depth -= 1
    return depth == 0 and not in_string


# ── Logging ───────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)


def _parse_signal_rest(
    rest: str,
) -> tuple[list[str], list[str], Optional[str]]:
    """Extract (permissions, signal_set, peer) from the body of a signal rule."""
    permissions: list[str] = []
    signal_set: list[str] = []
    peer: Optional[str] = None

    m = _RE_SIGNAL_PAREN_PERMS.match(rest)
    if m:
        permissions = m.group(1).split()
        rest = rest[m.end() :]
    else:
        m = _RE_SIGNAL_BARE_PERM.match(rest)
        if m:
            permissions = [m.group(1)]
            rest = rest[m.end() :]

    sm = _RE_SIGNAL_SET.search(rest)
    if sm:
        raw_set = sm.group(1) or sm.group(2) or sm.group(3) or ""
        signal_set = [s.strip('"') for s in raw_set.split() if s.strip('"')]

    pm = _RE_SIGNAL_PEER.search(rest)
    if pm:
        peer = pm.group(1).rstrip(",")

    return permissions, signal_set, peer


def _line_opens_profile(line: str) -> bool:
    """Return True if this line starts a profile or sub-profile block."""
    if not line.rstrip().endswith("{"):
        # Check for single-line: profile x { ... }
        # A profile-body '{' is always preceded by whitespace. '{' inside a
        # variable reference (@{VAR}) or brace alternation (/path/{a,b}) is
        # preceded by '@' or a path character, never by a space or tab.
        if not any(
            ch == "{" and i > 0 and line[i - 1] in " \t" for i, ch in enumerate(line)
        ):
            return False
    s = line.lstrip()
    # Hat is handled separately
    if s.startswith("hat "):
        return False
    # A path-leading brace alternation ({/,}bin/foo) is a file rule, not a
    # profile. RE_PROFILE_OPEN excludes '{' from the name group, so any such
    # line would match with an empty name — which is not a valid profile.
    if s.startswith("{"):
        return False
    # Must have 'profile' keyword OR start with a path / name
    if s.startswith("profile") or s.startswith("/") or s.startswith("@"):
        return bool(RE_PROFILE_OPEN.match(line))
    # Also allow bare names (e.g. abstractions can have sub-profiles)
    if RE_PROFILE_OPEN.match(line):
        # Make sure it's not a rule keyword masquerading as a profile
        first_tok = s.split()[0].rstrip("{")
        return first_tok not in KEYWORD_DEFS.keys()
    return False


# ── AST nodes ─────────────────────────────────────────────────────────────────


@dataclass
class Node:
    range: Range
    raw: str


@dataclass
class CommentNode(Node):
    text: str = ""


@dataclass
class ABINode(Node):
    path: str = ""
    angle_bracket: bool = True


@dataclass
class IncludeNode(Node):
    path: str = ""
    angle_bracket: bool = True
    conditional: bool = False
    # When we parse an include, we also parse the included document(s) and attach them here for easy access.
    # Since includes can be a directory, this is a list of documents, not just one.
    # Will be empty if the include file/dir was not found or could not be read.
    documents: list[DocumentNode] = field(default_factory=list)


@dataclass
class VariableDefNode(Node):
    name: str = ""
    values: list[str] = field(default_factory=list)
    augmented: bool = False
    comments: list[CommentNode] = field(default_factory=list)


@dataclass
class RuleNode(Node):
    qualifiers: list[str] = field(default_factory=list)

    def value_strings(self) -> Iterator[str]:
        """Yield every string in this rule that may contain a variable
        reference (paths, peers, addresses, queue names, …).

        Used by the diagnostics layer to detect undefined ``@{var}``
        references without re-parsing ``node.raw``. Subclasses override
        this to expose their structured fields.
        """
        return iter(())


@dataclass
class FileRuleNode(RuleNode):
    path: str = ""
    perms: str = ""
    exec_target: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        if self.path:
            yield self.path
        if self.exec_target:
            yield self.exec_target


@dataclass
class CapabilityNode(RuleNode):
    capabilities: list[str] = field(default_factory=list)

    # Capabilities are a closed enum — no variable references possible.
    # Default value_strings (empty) suffices.


@dataclass
class NetworkNode(RuleNode):
    rest: str = ""

    def value_strings(self) -> Iterator[str]:
        if self.rest:
            yield self.rest


@dataclass
class SignalRuleNode(RuleNode):
    permissions: list[str] = field(default_factory=list)
    signal_set: list[str] = field(default_factory=list)
    peer: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        if self.peer:
            yield self.peer


@dataclass
class PtraceRuleNode(RuleNode):
    content: str = ""
    permissions: list[str] = field(default_factory=list)
    peer: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        if self.peer:
            yield self.peer


@dataclass
class DbusRuleNode(RuleNode):
    content: str = ""
    permissions: list[str] = field(default_factory=list)
    bus: Optional[str] = None
    path: Optional[str] = None
    interface: Optional[str] = None
    member: Optional[str] = None
    peer: Optional[str] = None
    name: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        for v in (
            self.bus,
            self.path,
            self.interface,
            self.member,
            self.peer,
            self.name,
        ):
            if v:
                yield v


@dataclass
class UnixRuleNode(RuleNode):
    content: str = ""
    permissions: list[str] = field(default_factory=list)
    type: Optional[str] = None
    addr: Optional[str] = None
    peer: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        for v in (self.type, self.addr, self.peer):
            if v:
                yield v


@dataclass
class MountRuleNode(RuleNode):
    content: str = ""
    options: list[str] = field(default_factory=list)
    fstype: Optional[str] = None
    source: Optional[str] = None
    target: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        for v in (self.source, self.target, self.fstype):
            if v:
                yield v
        yield from self.options


@dataclass
class UmountRuleNode(RuleNode):
    content: str = ""
    options: list[str] = field(default_factory=list)
    target: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        if self.target:
            yield self.target
        yield from self.options


@dataclass
class UsernsRuleNode(RuleNode):
    content: str = ""

    # ``userns,`` carries no value-bearing fields. Default empty suffices.


@dataclass
class IoUringRuleNode(RuleNode):
    content: str = ""
    permissions: list[str] = field(default_factory=list)
    label: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        if self.label:
            yield self.label


@dataclass
class MqueueRuleNode(RuleNode):
    content: str = ""
    permissions: list[str] = field(default_factory=list)
    type: Optional[str] = None
    name: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        for v in (self.type, self.name):
            if v:
                yield v


@dataclass
class RlimitRuleNode(RuleNode):
    content: str = ""
    resource: str = ""
    value: str = ""

    def value_strings(self) -> Iterator[str]:
        if self.value:
            yield self.value


@dataclass
class PivotRootRuleNode(RuleNode):
    content: str = ""
    oldroot: Optional[str] = None
    newroot: Optional[str] = None
    target_profile: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        for v in (self.oldroot, self.newroot, self.target_profile):
            if v:
                yield v


@dataclass
class ChangeProfileRuleNode(RuleNode):
    content: str = ""
    exec_path: Optional[str] = None
    target_profile: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        for v in (self.exec_path, self.target_profile):
            if v:
                yield v


@dataclass
class ChangeHatRuleNode(RuleNode):
    content: str = ""
    hats: list[str] = field(default_factory=list)

    def value_strings(self) -> Iterator[str]:
        yield from self.hats


@dataclass
class LinkRuleNode(RuleNode):
    subset: bool = False
    link: str = ""
    target: str = ""

    def value_strings(self) -> Iterator[str]:
        if self.link:
            yield self.link
        if self.target:
            yield self.target


@dataclass
class AllRuleNode(RuleNode):
    pass  # ``all,`` carries no fields.


@dataclass
class RemountRuleNode(RuleNode):
    content: str = ""
    options: list[str] = field(default_factory=list)
    target: Optional[str] = None

    def value_strings(self) -> Iterator[str]:
        if self.target:
            yield self.target
        yield from self.options


@dataclass
class UnknownRuleNode(RuleNode):
    keyword: str = ""
    content: str = ""

    def value_strings(self) -> Iterator[str]:
        # Fall back to the post-keyword text: we don't know which tokens are
        # path-like for a rule whose grammar we haven't recognised.
        if self.content:
            yield self.content


_KEYWORD_TO_NODE_CLASS: dict[str, Any] = {
    "ptrace": PtraceRuleNode,
    "dbus": DbusRuleNode,
    "unix": UnixRuleNode,
    "mount": MountRuleNode,
    "umount": UmountRuleNode,
    "userns": UsernsRuleNode,
    "io_uring": IoUringRuleNode,
    "mqueue": MqueueRuleNode,
    "pivot_root": PivotRootRuleNode,
    "change_profile": ChangeProfileRuleNode,
    "change_hat": ChangeHatRuleNode,
    "link": LinkRuleNode,
    "all": AllRuleNode,
    "remount": RemountRuleNode,
}


# ── Per-type rule builders ────────────────────────────────────────────────────
# Each builder takes the post-keyword *content* string and the common Node
# kwargs (range, raw, qualifiers) and returns a fully-populated rule node
# with its structured fields parsed out. ``content`` is preserved on the
# resulting node both as a debugging aid and so existing consumers that read
# the raw body keep working.


def _build_ptrace(content: str, **base: Any) -> PtraceRuleNode:
    perms, rest = _extract_paren_perms(content)
    if not perms:
        # Bare permission form: ``ptrace read peer=…`` (no parens).
        head = rest.split("peer=", 1)[0]
        perms = [p for p in head.replace(",", " ").split() if p]
    peer = _extract_kv(content, "peer")
    return PtraceRuleNode(content=content, permissions=perms, peer=peer, **base)


def _build_dbus(content: str, **base: Any) -> DbusRuleNode:
    perms, _ = _extract_paren_perms(content)
    return DbusRuleNode(
        content=content,
        permissions=perms,
        bus=_extract_kv(content, "bus"),
        path=_extract_kv(content, "path"),
        interface=_extract_kv(content, "interface"),
        member=_extract_kv(content, "member"),
        peer=_extract_kv(content, "peer"),
        name=_extract_kv(content, "name"),
        **base,
    )


def _build_unix(content: str, **base: Any) -> UnixRuleNode:
    perms, _ = _extract_paren_perms(content)
    return UnixRuleNode(
        content=content,
        permissions=perms,
        type=_extract_kv(content, "type"),
        addr=_extract_kv(content, "addr"),
        peer=_extract_kv(content, "peer"),
        **base,
    )


def _build_mountlike(node_cls: type, content: str, **base: Any) -> RuleNode:
    """Builder shared by mount/umount/remount.

    Parses ``options=(…)``, ``fstype=…`` and the optional
    ``source -> target`` path pair (umount has no source).
    """
    options_str = _extract_kv(content, "options")
    options = (
        [o for o in options_str.replace(",", " ").split() if o] if options_str else []
    )
    fstype = _extract_kv(content, "fstype")
    # Strip recognised key=value pairs so what remains is the path component.
    path_part = re.sub(
        r"\b(?:options|fstype)=(?:\([^)]*\)|\"[^\"]*\"|\S+)", "", content
    )
    lhs, rhs = _split_arrow(path_part)
    if node_cls is UmountRuleNode:
        target = (lhs or rhs or "").strip() or None
        return UmountRuleNode(content=content, options=options, target=target, **base)
    if node_cls is RemountRuleNode:
        target = (lhs or rhs or "").strip() or None
        return RemountRuleNode(content=content, options=options, target=target, **base)
    # plain mount: lhs is source, rhs is target
    source = lhs.strip() or None
    target = rhs.strip() if rhs else None
    return MountRuleNode(
        content=content,
        options=options,
        fstype=fstype,
        source=source,
        target=target,
        **base,
    )


def _build_mount(content: str, **base: Any) -> MountRuleNode:
    return _build_mountlike(MountRuleNode, content, **base)  # type: ignore[return-value]


def _build_umount(content: str, **base: Any) -> UmountRuleNode:
    return _build_mountlike(UmountRuleNode, content, **base)  # type: ignore[return-value]


def _build_remount(content: str, **base: Any) -> RemountRuleNode:
    return _build_mountlike(RemountRuleNode, content, **base)  # type: ignore[return-value]


def _build_userns(content: str, **base: Any) -> UsernsRuleNode:
    return UsernsRuleNode(content=content, **base)


def _build_io_uring(content: str, **base: Any) -> IoUringRuleNode:
    perms, _ = _extract_paren_perms(content)
    return IoUringRuleNode(
        content=content,
        permissions=perms,
        label=_extract_kv(content, "label"),
        **base,
    )


def _build_mqueue(content: str, **base: Any) -> MqueueRuleNode:
    perms, rest = _extract_paren_perms(content)
    type_ = _extract_kv(content, "type")
    explicit_name = _extract_kv(content, "name")
    if explicit_name is not None:
        name = explicit_name
    else:
        # Bare path/name appears after `type=…` if present, else after the perms.
        leftover = re.sub(r"\btype=(?:\"[^\"]*\"|\S+)", "", rest).strip().rstrip(",")
        name = leftover or None
    return MqueueRuleNode(
        content=content,
        permissions=perms,
        type=type_,
        name=name,
        **base,
    )


def _build_pivot_root(content: str, **base: Any) -> PivotRootRuleNode:
    oldroot = _extract_kv(content, "oldroot")
    # Strip oldroot=…, leaving "newroot -> profile" or just "newroot".
    rest = re.sub(r"\boldroot=(?:\"[^\"]*\"|\S+)", "", content).strip()
    lhs, rhs = _split_arrow(rest)
    newroot = lhs or None
    target_profile = rhs or None
    return PivotRootRuleNode(
        content=content,
        oldroot=oldroot,
        newroot=newroot,
        target_profile=target_profile,
        **base,
    )


def _build_change_profile(content: str, **base: Any) -> ChangeProfileRuleNode:
    lhs, rhs = _split_arrow(content)
    if rhs is None:
        # ``change_profile target,`` — no exec_path component.
        return ChangeProfileRuleNode(
            content=content,
            exec_path=None,
            target_profile=lhs or None,
            **base,
        )
    return ChangeProfileRuleNode(
        content=content,
        exec_path=lhs or None,
        target_profile=rhs or None,
        **base,
    )


def _build_change_hat(content: str, **base: Any) -> ChangeHatRuleNode:
    hats = [h for h in content.replace(",", " ").split() if h]
    return ChangeHatRuleNode(content=content, hats=hats, **base)


def _build_link(content: str, **base: Any) -> LinkRuleNode:
    subset = content.startswith("subset")
    rest = content[len("subset") :].strip() if subset else content
    parts = rest.split("->", 1)
    link_path = parts[0].strip()
    target_path = parts[1].strip().rstrip(",") if len(parts) > 1 else ""
    return LinkRuleNode(subset=subset, link=link_path, target=target_path, **base)


def _build_all(content: str, **base: Any) -> AllRuleNode:
    # ``all,`` has no body. Drop the content kwarg.
    return AllRuleNode(**base)


def _build_rlimit(content: str, **base: Any) -> RlimitRuleNode:
    # content is e.g. "rlimit nofile <= 1024"
    body = content.removeprefix("rlimit").strip()
    resource, _, value = body.partition("<=")
    return RlimitRuleNode(
        content=content,
        resource=resource.strip(),
        value=value.strip().rstrip(",").strip(),
        **base,
    )


_BUILDERS: dict[type, Any] = {
    PtraceRuleNode: _build_ptrace,
    DbusRuleNode: _build_dbus,
    UnixRuleNode: _build_unix,
    MountRuleNode: _build_mount,
    UmountRuleNode: _build_umount,
    RemountRuleNode: _build_remount,
    UsernsRuleNode: _build_userns,
    IoUringRuleNode: _build_io_uring,
    MqueueRuleNode: _build_mqueue,
    PivotRootRuleNode: _build_pivot_root,
    ChangeProfileRuleNode: _build_change_profile,
    ChangeHatRuleNode: _build_change_hat,
    LinkRuleNode: _build_link,
    AllRuleNode: _build_all,
}


@dataclass
class AliasNode(Node):
    original: str = ""
    replacement: str = ""
    comments: list[CommentNode] = field(default_factory=list)


@dataclass
class ProfileNode(Node):
    name: str = ""
    attachment: Optional[str] = None
    flags: list[str] = field(default_factory=list)
    is_hat: bool = False
    children: list[Node] = field(default_factory=list)
    comments: list[CommentNode] = field(default_factory=list)

    # variables defined within this profile itself
    @property
    def variables(self) -> dict[str, VariableDefNode]:
        vars = {}
        for child in self.children:
            if isinstance(child, VariableDefNode):
                vars[child.name] = child
        return vars


@dataclass
class DocumentNode:
    uri: str
    children: list[Node] = field(default_factory=list)
    abi: Optional[ABINode] = None
    includes: list[IncludeNode] = field(default_factory=list)
    # variables defined in the global scope of this document (i.e. outside of any profile)
    variables: dict[str, VariableDefNode] = field(default_factory=dict)
    # all variables defined in this document and any in included documents -
    # indexed by uri
    all_variables: dict[str, dict[str, VariableDefNode]] = field(default_factory=dict)
    profiles: list[ProfileNode] = field(default_factory=list)
    comments: list[CommentNode] = field(default_factory=list)


# ── Parser ────────────────────────────────────────────────────────────────────


class ParseError(Exception):
    def __init__(self, message: str, uri: str, line: int, character: int = 0):
        super().__init__(message)
        self.uri = uri
        self.line = line
        self.character = character


class Parser:
    """
    Line-oriented, resilient AppArmor profile parser.

    Handles:
      • Multi-line profiles/hats
      • Single-line profiles:  profile x { capability kill, }
      • Variable definitions, aliases, all rule types
      • Nested sub-profiles / hats
    """

    def __init__(
        self,
        uri: str,
        text: str,
        search_dirs: Optional[list[Path]] = None,
        _visited: Optional[set[Path]] = None,
    ):
        self._uri = uri
        self._lines = text.splitlines()
        self._pos = 0
        self._comments = list[CommentNode]()
        self.errors: list[ParseError] = []
        self.included_docs: dict[str, tuple[DocumentNode, list[ParseError]]] = {}
        self._search_dirs = search_dirs
        # Set of resolved absolute paths already being parsed in this include
        # chain. Shared with sub-parsers to break #include cycles.
        self._visited: set[Path] = _visited if _visited is not None else set()

    # ── Entry point ───────────────────────────────────────────────────────────

    def parse(self) -> DocumentNode:
        logger.debug("Parsing %s (%d lines)", self._uri, len(self._lines))
        doc = DocumentNode(uri=self._uri)
        while self._pos < len(self._lines):
            node = self._parse_node()
            if node is None:
                self._advance()  # skip stray '}'
                continue
            doc.children.append(node)
            if isinstance(node, ABINode):
                doc.abi = node
            elif isinstance(node, IncludeNode):
                doc.includes.append(node)
                # parse out the included document(s) immediately so we can
                # report errors with correct line numbers, and also so we can
                # resolve includes for goto-definition and hovers later without
                # reparsing
                self._parse_include_node(node)
            elif isinstance(node, VariableDefNode):
                doc.variables[node.name] = node
            elif isinstance(node, ProfileNode):
                doc.profiles.append(node)
                # Implicit @{exec_path} variable expanded from the profile
                # attachment. With multiple profiles in one file we accumulate
                # the alternatives (variables in AppArmor are value sets) so
                # the last attachment doesn't clobber the first.
                if node.attachment:
                    exec_path_var = "@{exec_path}"
                    existing = doc.variables.get(exec_path_var)
                    if existing is None:
                        doc.variables[exec_path_var] = VariableDefNode(
                            range=node.range,
                            raw=node.attachment,
                            name=exec_path_var,
                            values=[node.attachment],
                        )
                    elif node.attachment not in existing.values:
                        existing.values.append(node.attachment)
                self._collect_includes(node, doc)

        all_vars: dict[str, dict[str, VariableDefNode]] = {doc.uri: doc.variables}

        def collect_vars(d: DocumentNode):
            for inc in d.includes:
                for inc_doc in inc.documents:
                    all_vars[inc_doc.uri] = inc_doc.variables
                    collect_vars(inc_doc)

        collect_vars(doc)
        doc.all_variables = all_vars

        return doc

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _advance(self) -> None:
        self._pos += 1

    def _current(self) -> Optional[str]:
        return self._lines[self._pos] if self._pos < len(self._lines) else None

    def _make_range(self, start_line: int, end_line: int) -> Range:
        end_line = min(end_line, len(self._lines) - 1)
        sl = self._lines[start_line] if start_line < len(self._lines) else ""
        el = self._lines[end_line] if end_line < len(self._lines) else ""
        sc = len(sl) - len(sl.lstrip())
        ec = len(el)
        return Range(Position(start_line, sc), Position(end_line, ec))

    def _parse_include_path(self, path: Path) -> list[DocumentNode]:
        # assume path is a directory
        docs = []
        try:
            for entry in path.iterdir():
                docs.extend(self._parse_include_path(entry))
        except NotADirectoryError:
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in self._visited:
                logger.debug("Skipping cyclic include: %s", resolved)
                return docs
            self._visited.add(resolved)
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            uri = path.as_uri()
            sub_parser = Parser(
                uri=uri,
                text=text,
                search_dirs=self._search_dirs,
                _visited=self._visited,
            )
            doc = sub_parser.parse()
            docs.append(doc)
            self.included_docs[uri] = (doc, sub_parser.errors)
            self.included_docs.update(sub_parser.included_docs)
        return docs

    def _parse_include_node(self, include: IncludeNode):
        path = resolve_include_path(include.path, self._uri, self._search_dirs)
        if path is not None:
            try:
                include.documents = self._parse_include_path(path)
            except Exception as e:
                self.errors.append(
                    ParseError(
                        f"Error reading included file '{include.path}': {e}",
                        self._uri,
                        include.range.start.line,
                        include.range.start.character,
                    )
                )
        else:
            # is only an error when this is not a conditional include
            if not include.conditional:
                self.errors.append(
                    ParseError(
                        f"Included file '{include.path}' not found",
                        self._uri,
                        include.range.start.line,
                        include.range.start.character,
                    )
                )

    def _collect_includes(self, profile: ProfileNode, doc: DocumentNode) -> None:
        for child in profile.children:
            if isinstance(child, IncludeNode):
                doc.includes.append(child)
                self._parse_include_node(child)

            elif isinstance(child, ProfileNode):
                self._collect_includes(child, doc)

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def _parse_node(self) -> Optional[Node]:
        """
        Parse one logical node at self._pos.
        Returns None when we hit a closing '}' (caller consumes it).
        """
        while self._pos < len(self._lines):
            line = self._lines[self._pos]

            if RE_BLANK.match(line):
                self._comments.clear()  # blank line resets comments
                self._advance()
                continue

            # Comment (unless it IS an include directive)
            if RE_COMMENT.match(line) and not RE_INCLUDE_GLOB.match(line):
                comment = self._parse_comment()
                self._comments.append(comment)
                return comment

            if RE_ABI_GLOB.match(line):
                return self._parse_abi()

            if RE_INCLUDE_GLOB.match(line) or RE_INCLUDE_IF.match(line):
                return self._parse_include()

            if RE_VARIABLE_DEF.match(line):
                return self._parse_variable()

            if RE_ALIAS.match(line):
                return self._parse_alias()

            # Hat block
            if RE_HAT_OPEN.match(line):
                return self._parse_profile(is_hat=True)

            # Profile / sub-profile block
            if _line_opens_profile(line):
                return self._parse_profile(is_hat=False)

            # Closing brace — signal caller
            stripped = line.strip().rstrip(",")
            if stripped == "}":
                return None

            return self._parse_rule()

        return None

    # ── Concrete node parsers ─────────────────────────────────────────────────

    def _parse_comment(self) -> CommentNode:
        ln, raw = self._pos, self._lines[self._pos]
        self._advance()
        return CommentNode(
            range=self._make_range(ln, ln),
            raw=raw,
            text=raw.strip().lstrip("#").strip(),
        )

    def _parse_abi(self) -> ABINode:
        ln, raw = self._pos, self._lines[self._pos]
        m = RE_ABI_GLOB.match(raw)
        path = m.group(1) if m else ""
        angle = "<" in raw and ">" in raw
        self._advance()
        logger.debug("ABINode: path=%s (line %d)", path, ln)
        return ABINode(
            range=self._make_range(ln, ln),
            raw=raw,
            path=path,
            angle_bracket=angle,
        )

    def _parse_include(self) -> IncludeNode:
        ln, raw = self._pos, self._lines[self._pos]
        m = RE_INCLUDE_GLOB.match(raw) or RE_INCLUDE_IF.match(raw)
        path = m.group(1) if m else ""
        cond = m.re == RE_INCLUDE_IF if m else False
        angle = "<" in raw and ">" in raw
        self._advance()
        logger.debug("IncludeNode: path=%s conditional=%s (line %d)", path, cond, ln)
        return IncludeNode(
            range=self._make_range(ln, ln),
            raw=raw,
            path=path,
            angle_bracket=angle,
            conditional=cond,
        )

    def _parse_variable(self) -> VariableDefNode:
        ln, raw = self._pos, self._lines[self._pos]
        m = RE_VARIABLE_DEF.match(raw)
        self._advance()
        name = m.group(1) if m else ""
        values = [v for v in (m.group(2) if m else "").split() if v]
        augmented = "+=" in raw
        comments = self._comments
        self._comments = list[CommentNode]()  # clear comments after consuming
        logger.debug("VariableDefNode: name=%s (line %d)", name, ln)
        return VariableDefNode(
            range=self._make_range(ln, ln),
            raw=raw,
            name=name,
            values=values,
            augmented=augmented,
            comments=comments,
        )

    def _parse_alias(self) -> AliasNode:
        ln, raw = self._pos, self._lines[self._pos]
        m = RE_ALIAS.match(raw)
        self._advance()
        comments = self._comments
        self._comments = list[CommentNode]()  # clear comments after consuming
        logger.debug(
            "AliasNode: %s -> %s (line %d)",
            m.group(1) if m else "",
            m.group(2) if m else "",
            ln,
        )
        return AliasNode(
            range=self._make_range(ln, ln),
            raw=raw,
            original=m.group(1) if m else "",
            replacement=m.group(2) if m else "",
            comments=comments,
        )

    def _parse_profile(self, is_hat: bool = False) -> ProfileNode:
        start_line = self._pos
        raw_start = self._lines[self._pos]

        comments = self._comments
        self._comments = list[CommentNode]()  # clear comments after consuming
        # --- Extract name and flags ---
        if is_hat:
            m = RE_HAT_OPEN.match(raw_start)
            name = m.group("n") if m else ""
            attachment = None
            flags: list[str] = []
        else:
            m = RE_PROFILE_OPEN.match(raw_start)
            if m:
                # 'n' is the profile name; 'att' is the optional binary attachment path
                name = (m.group("n") or "").strip()
                attachment = (m.group("att") or "").strip()
                # Remove 'profile' keyword if it bled into name
                if name == "profile":
                    name = (m.group("att") or "").strip()
                flags_str = m.group("flags") or ""
                flags = [f.strip() for f in flags_str.split(",") if f.strip()]
            else:
                name = ""
                attachment = None
                flags = []

        # --- Single-line profile? e.g.  profile x { cap kill, } ---
        brace_open = raw_start.find("{")
        brace_close = raw_start.rfind("}")
        if brace_open != -1 and brace_close > brace_open:
            inner_text = raw_start[brace_open + 1 : brace_close].strip()
            children = self._parse_inline_rules(inner_text, start_line)
            self._advance()
            logger.debug("ProfileNode: %s (line %d)", name or "(anonymous)", start_line)
            return ProfileNode(
                range=self._make_range(start_line, start_line),
                raw=raw_start,
                name=name,
                attachment=attachment,
                flags=flags,
                is_hat=is_hat,
                children=children,
                comments=comments,
            )

        # --- Multi-line profile ---
        self._advance()  # consume opening line

        children = []
        while self._pos < len(self._lines):
            line = self._lines[self._pos]
            stripped = line.strip().rstrip(",")

            if stripped == "}":
                end_line = self._pos
                self._advance()
                logger.debug(
                    "ProfileNode: %s (line %d)", name or "(anonymous)", start_line
                )
                return ProfileNode(
                    range=self._make_range(start_line, end_line),
                    raw=raw_start,
                    name=name,
                    attachment=attachment,
                    flags=flags,
                    is_hat=is_hat,
                    children=children,
                    comments=comments,
                )

            child = self._parse_node()
            if child is None:
                # _parse_node saw '}' — consume it
                end_line = self._pos
                self._advance()
                logger.debug(
                    "ProfileNode: %s (line %d)", name or "(anonymous)", start_line
                )
                return ProfileNode(
                    range=self._make_range(start_line, end_line),
                    raw=raw_start,
                    name=name,
                    attachment=attachment,
                    flags=flags,
                    is_hat=is_hat,
                    children=children,
                    comments=comments,
                )
            children.append(child)

        # EOF without closing brace
        self.errors.append(
            ParseError(f"Profile '{name}' not closed before EOF", self._uri, start_line)
        )
        logger.debug("ProfileNode: %s (line %d)", name or "(anonymous)", start_line)
        return ProfileNode(
            range=self._make_range(start_line, self._pos - 1),
            raw=raw_start,
            name=name,
            attachment=attachment,
            flags=flags,
            is_hat=is_hat,
            children=children,
            comments=comments,
        )

    def _parse_inline_rules(self, text: str, line_no: int) -> list[Node]:
        """Parse comma-separated rules from within a single-line profile body."""
        children: list[Node] = []
        # Each "part" is one rule (roughly)
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            sub = Parser(self._uri, part + ",")
            node = sub._parse_node()
            if node is not None:
                node.range = Range(
                    Position(line_no, 0),
                    Position(line_no, len(text)),
                )
                children.append(node)
        return children

    def _parse_rule(self) -> Node:
        start_line = self._pos
        raw_lines: list[str] = []

        # Accumulate lines until the rule is terminated (trailing comma at
        # paren-depth 0) or until we hit a structural boundary.
        while self._pos < len(self._lines):
            line = self._lines[self._pos]
            if RE_BLANK.match(line):
                break
            if RE_COMMENT.match(line) and not RE_INCLUDE_GLOB.match(line):
                break
            if RE_PROFILE_CLOSE.match(line):
                break
            raw_lines.append(line)
            self._advance()
            if _rule_ends_line(line):
                break

        if not raw_lines:
            logger.debug("UnknownRuleNode: (empty) (line %d)", start_line)
            return UnknownRuleNode(
                range=self._make_range(start_line, start_line),
                raw="",
                keyword="",
                content="",
            )

        end_line = self._pos - 1
        raw = "\n".join(raw_lines)
        # Normalise for regex matching: strip each line and join with a space
        # so that multi-line rules look like a single logical line. Inline
        # comments (``rule, # explanation``) are dropped here so that they
        # don't leak into structured fields like dbus path= or unknown-rule
        # content; the original raw_lines are retained on ``raw`` unchanged.
        joined = " ".join(
            stripped[: _code_end(stripped)].rstrip()
            for stripped in (line.strip() for line in raw_lines)
        )

        # -- Capability --
        mc = RE_CAPABILITY.match(joined)
        if mc:
            caps_raw = mc.group("caps").strip()
            if "," in caps_raw:
                caps = [c.strip() for c in caps_raw.split(",") if c.strip()]
            else:
                caps = caps_raw.split()
            logger.debug("CapabilityNode: %s (line %d)", caps, start_line)
            return CapabilityNode(
                range=self._make_range(start_line, end_line),
                raw=raw,
                qualifiers=self._leading_qualifiers(joined),
                capabilities=caps,
            )

        # -- Network --
        mn = RE_NETWORK.match(joined)
        if mn:
            logger.debug(
                "NetworkNode: %s (line %d)", mn.group("rest").strip(), start_line
            )
            return NetworkNode(
                range=self._make_range(start_line, end_line),
                raw=raw,
                qualifiers=self._leading_qualifiers(joined),
                rest=mn.group("rest").strip(),
            )

        # -- Signal --
        ms = RE_SIGNAL.match(joined)
        if ms:
            perms, sig_set, peer = _parse_signal_rest(ms.group("rest"))
            logger.debug(
                "SignalRuleNode: perms=%s signals=%s (line %d)",
                perms,
                sig_set,
                start_line,
            )
            return SignalRuleNode(
                range=self._make_range(start_line, end_line),
                raw=raw,
                qualifiers=self._leading_qualifiers(joined),
                permissions=perms,
                signal_set=sig_set,
                peer=peer,
            )

        # -- File rule - permissions as prefix or suffix variants --
        mf = None
        for regexp in (RE_FILE_PREFIX, RE_FILE_SUFFIX):
            mf = regexp.match(joined)
            if mf:
                break
        if mf:
            quals_str = str(mf.group("quals") or "")
            quals = quals_str.split()
            path_raw = mf.group("path")
            path = path_raw[1:-1] if path_raw.startswith('"') else path_raw
            logger.debug(
                "FileRuleNode: path=%s perms=%s (line %d)",
                path,
                mf.group("perms"),
                start_line,
            )
            return FileRuleNode(
                range=self._make_range(start_line, end_line),
                raw=raw,
                qualifiers=quals,
                path=path,
                perms=mf.group("perms"),
                exec_target=mf.group("exec_target"),
            )

        # -- Specific keyword rules --
        # Strip leading qualifiers to find the actual rule keyword.
        quals = self._leading_qualifiers(joined)
        kw_start = joined
        for q in quals:
            kw_start = kw_start.lstrip().removeprefix(q).lstrip()
        # Remove trailing rule-terminating comma (at paren depth 0) so that
        # single-token rules like "pivot_root," don't get the comma included
        # in the keyword.
        kw_start = kw_start.rstrip(", ")
        tokens = kw_start.split()
        keyword = tokens[0] if tokens else ""
        content = kw_start[len(keyword) :].strip() if tokens else ""
        rng = self._make_range(start_line, end_line)

        # "set rlimit" is a two-word keyword; detect by first two tokens.
        if keyword == "set" and content.startswith("rlimit"):
            logger.debug("RlimitRuleNode: %s (line %d)", content, start_line)
            return _build_rlimit(content, range=rng, raw=raw, qualifiers=quals)

        builder = _BUILDERS.get(_KEYWORD_TO_NODE_CLASS.get(keyword))
        if builder is not None:
            logger.debug("%s: %s (line %d)", builder.__name__, keyword, start_line)
            return builder(content, range=rng, raw=raw, qualifiers=quals)

        logger.debug("UnknownRuleNode: keyword=%s (line %d)", keyword, start_line)
        return UnknownRuleNode(
            range=rng, raw=raw, qualifiers=quals, keyword=keyword, content=content
        )

    @staticmethod
    def _leading_qualifiers(
        stripped: str, qualifiers: list[str] = QUALIFIERS
    ) -> list[str]:
        quals = []
        for kw in qualifiers:
            if stripped.startswith(kw + " "):
                quals.append(kw)
                stripped = stripped[len(kw) :].lstrip()
        return quals


# ── Convenience helpers ───────────────────────────────────────────────────────


def parse_document(uri: str, text: str) -> tuple[DocumentNode, list[ParseError]]:
    """Parse an AppArmor profile document; return (AST, errors)."""
    p = Parser(uri, text)
    return p.parse(), p.errors


def resolve_include_path(
    include_path: str,
    document_uri: str,
    search_dirs: Optional[list[Path]] = None,
) -> Optional[Path]:
    """Resolve an include path to an absolute filesystem path."""
    if search_dirs is None:
        search_dirs = DEFAULT_INCLUDE_SEARCH_DIRS

    candidate = Path(include_path)

    for base in search_dirs:
        resolved = base / candidate
        if resolved.exists():
            return resolved

    try:
        doc_path = Path(document_uri.removeprefix("file://"))
        resolved = doc_path.parent / candidate
        if resolved.exists():
            return resolved
    except Exception:
        pass

    return None
