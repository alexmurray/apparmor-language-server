"""
AppArmor LSP – profile parser.

Produces a lightweight AST suitable for:
  • goto-definition (resolves #include targets)
  • diagnostics (syntax / semantic checks)
  • formatting (re-serialises the AST)
  • hover / completion context
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# ── Regex patterns ────────────────────────────────────────────────────────────

RE_BLANK = re.compile(r"^\s*$")
RE_COMMENT = re.compile(r"^\s*#.*$")
RE_ABI_GLOB = re.compile(r"""^\s*#?abi\s+[<"]([^>"]+)[>"],""")
RE_INCLUDE_GLOB = re.compile(r"""^\s*#?include\s+[<"]([^>"]+)[>"]?""")
RE_INCLUDE_IF = re.compile(r"""^\s*include\s+if\s+exists\s+[<"]([^>"]+)[>"]?""")
RE_VARIABLE_DEF = re.compile(r"^\s*(@\{[A-Za-z_][A-Za-z0-9_]*\})\s*[+]?=\s*(.*)$")

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

RE_CAPABILITY = re.compile(
    r"^\s*(?:deny\s+|audit\s+)?capability\b\s*(?P<caps>[^{}\n]*?)\s*,?\s*$"
)
RE_NETWORK = re.compile(
    r"^\s*(?:deny\s+|audit\s+)?network\b\s*(?P<rest>[^{}\n,]*?)\s*,?\s*$"
)
RE_FILE = re.compile(
    r"^\s*(?P<mods>(?:(?:deny|audit|owner)\s+)*)"
    r"(?P<path>[@{}/~][^\s]+)\s+"
    r"(?P<perms>[rwaxmlkdDuUipPcCbBI]+)"
    r"(?:\s*->\s*(?P<link_target>\S+))?"
    r"\s*,?\s*$"
)
RE_ALIAS = re.compile(r"^\s*alias\s+(\S+)\s+->\s+(\S+)\s*,?\s*$")


def _line_opens_profile(line: str) -> bool:
    """Return True if this line starts a profile or sub-profile block."""
    if not line.rstrip().endswith("{"):
        # Check for single-line: profile x { ... }
        if "{" not in line:
            return False
    s = line.lstrip()
    # Hat is handled separately
    if s.startswith("hat "):
        return False
    # Must have 'profile' keyword OR start with a path / name
    if s.startswith("profile") or s.startswith("/") or s.startswith("@"):
        return bool(RE_PROFILE_OPEN.match(line))
    # Also allow bare names (e.g. abstractions can have sub-profiles)
    if RE_PROFILE_OPEN.match(line):
        # Make sure it's not a rule keyword masquerading as a profile
        first_tok = s.split()[0].rstrip("{")
        rule_kws = {
            "abi",
            "capability",
            "network",
            "signal",
            "ptrace",
            "mount",
            "umount",
            "dbus",
            "unix",
            "deny",
            "audit",
            "owner",
            "rlimit",
            "include",
            "change_profile",
            "change_hat",
            "alias",
            "pivot_root",
            "userns",
            "io_uring",
            "mqueue",
        }
        return first_tok not in rule_kws
    return False


# ── AST nodes ─────────────────────────────────────────────────────────────────


@dataclass
class Position:
    line: int
    character: int


@dataclass
class Range:
    start: Position
    end: Position


@dataclass
class Node:
    uri: str
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


@dataclass
class VariableDefNode(Node):
    name: str = ""
    values: list[str] = field(default_factory=list)
    augmented: bool = False


@dataclass
class FileRuleNode(Node):
    modifiers: list[str] = field(default_factory=list)
    path: str = ""
    perms: str = ""
    link_target: Optional[str] = None


@dataclass
class CapabilityNode(Node):
    modifiers: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)


@dataclass
class NetworkNode(Node):
    modifiers: list[str] = field(default_factory=list)
    rest: str = ""


@dataclass
class GenericRuleNode(Node):
    keyword: str = ""
    content: str = ""


@dataclass
class AliasNode(Node):
    original: str = ""
    replacement: str = ""


@dataclass
class ProfileNode(Node):
    name: str = ""
    flags: list[str] = field(default_factory=list)
    is_hat: bool = False
    children: list[Node] = field(default_factory=list)


@dataclass
class DocumentNode:
    uri: str
    children: list[Node] = field(default_factory=list)
    abi: Optional[ABINode] = None
    includes: list[IncludeNode] = field(default_factory=list)
    variables: dict[str, VariableDefNode] = field(default_factory=dict)
    profiles: list[ProfileNode] = field(default_factory=list)


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

    def __init__(self, uri: str, text: str):
        self._uri = uri
        self._lines = text.splitlines()
        self._pos = 0
        self.errors: list[ParseError] = []

    # ── Entry point ───────────────────────────────────────────────────────────

    def parse(self) -> DocumentNode:
        doc = DocumentNode(uri=self._uri)
        while self._pos < len(self._lines):
            node = self._parse_node()
            if node is None:
                self._advance()  # skip stray '}'
                continue
            doc.children.append(node)
            if isinstance(node, ABINode):
                doc.abi = node
            if isinstance(node, IncludeNode):
                doc.includes.append(node)
                inc_doc = self._parse_include_node(node)
                for inc in inc_doc:
                    self._inherit_document_info(doc, inc)
            elif isinstance(node, VariableDefNode):
                doc.variables[node.name] = node
            elif isinstance(node, ProfileNode):
                doc.profiles.append(node)
                self._collect_includes(node, doc)
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

    def _parse_include_path(self, path: Path) -> List[DocumentNode]:
        # assume path is a directory
        docs = []
        try:
            for entry in path.iterdir():
                with open(entry, "r") as f:
                    text = f.read()
                sub_parser = Parser(uri=str(entry), text=text)
                docs.append(sub_parser.parse())
        except NotADirectoryError:
            with open(path, "r") as f:
                text = f.read()
            sub_parser = Parser(uri=str(path), text=text)
            docs.append(sub_parser.parse())
        return docs

    def _parse_include_node(self, include_node: IncludeNode) -> List[DocumentNode]:
        docs = []
        path = resolve_include_path(include_node.path, self._uri)
        if path is None:
            # is only an error when this is not a conditional include
            if not include_node.conditional:
                self.errors.append(
                    ParseError(
                        f"Included file '{include_node.path}' not found",
                        include_node.path,
                        include_node.range.start.line,
                        include_node.range.start.character,
                    )
                )
        else:
            try:
                docs = self._parse_include_path(path)
            except Exception as e:
                self.errors.append(
                    ParseError(
                        f"Error reading included file '{include_node.path}': {e}",
                        include_node.path,
                        include_node.range.start.line,
                        include_node.range.start.character,
                    )
                )
        return docs

    def _inherit_document_info(self, doc: DocumentNode, included: DocumentNode) -> None:
        for inc in included.includes:
            if inc not in doc.includes:
                doc.includes.append(inc)
                for inc_doc in (
                    self._parse_include_node(inc) for inc in included.includes
                ):
                    for inc in inc_doc:
                        self._inherit_document_info(doc, inc)
        for var in included.variables.values():
            if var.name not in doc.variables:
                doc.variables[var.name] = var

    def _collect_includes(self, profile: ProfileNode, doc: DocumentNode) -> None:
        for child in profile.children:
            if isinstance(child, IncludeNode):
                doc.includes.append(child)
                inc_doc = self._parse_include_node(child)
                for inc in inc_doc:
                    self._inherit_document_info(doc, inc)

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
                self._advance()
                continue

            # Comment (unless it IS an include directive)
            if RE_COMMENT.match(line) and not RE_INCLUDE_GLOB.match(line):
                return self._parse_comment()

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
            uri=self._uri,
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
        return ABINode(
            uri=self._uri,
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
        return IncludeNode(
            uri=self._uri,
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
        return VariableDefNode(
            uri=self._uri,
            range=self._make_range(ln, ln),
            raw=raw,
            name=name,
            values=values,
            augmented=augmented,
        )

    def _parse_alias(self) -> AliasNode:
        ln, raw = self._pos, self._lines[self._pos]
        m = RE_ALIAS.match(raw)
        self._advance()
        return AliasNode(
            uri=self._uri,
            range=self._make_range(ln, ln),
            raw=raw,
            original=m.group(1) if m else "",
            replacement=m.group(2) if m else "",
        )

    def _parse_profile(self, is_hat: bool = False) -> ProfileNode:
        start_line = self._pos
        raw_start = self._lines[self._pos]

        # --- Extract name and flags ---
        if is_hat:
            m = RE_HAT_OPEN.match(raw_start)
            name = m.group("n") if m else ""
            flags: list[str] = []
        else:
            m = RE_PROFILE_OPEN.match(raw_start)
            if m:
                # 'n' is the profile name; 'att' is the optional binary attachment path
                name = (m.group("n") or "").strip()
                # Remove 'profile' keyword if it bled into name
                if name == "profile":
                    name = (m.group("att") or "").strip()
                flags_str = m.group("flags") or ""
                flags = [f.strip() for f in flags_str.split(",") if f.strip()]
            else:
                name = ""
                flags = []

        # --- Single-line profile? e.g.  profile x { cap kill, } ---
        brace_open = raw_start.find("{")
        brace_close = raw_start.rfind("}")
        if brace_open != -1 and brace_close > brace_open:
            inner_text = raw_start[brace_open + 1 : brace_close].strip()
            children = self._parse_inline_rules(inner_text, start_line)
            self._advance()
            return ProfileNode(
                uri=self._uri,
                range=self._make_range(start_line, start_line),
                raw=raw_start,
                name=name,
                flags=flags,
                is_hat=is_hat,
                children=children,
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
                return ProfileNode(
                    uri=self._uri,
                    range=self._make_range(start_line, end_line),
                    raw=raw_start,
                    name=name,
                    flags=flags,
                    is_hat=is_hat,
                    children=children,
                )

            child = self._parse_node()
            if child is None:
                # _parse_node saw '}' — consume it
                end_line = self._pos
                self._advance()
                return ProfileNode(
                    uri=self._uri,
                    range=self._make_range(start_line, end_line),
                    raw=raw_start,
                    name=name,
                    flags=flags,
                    is_hat=is_hat,
                    children=children,
                )
            children.append(child)

        # EOF without closing brace
        self.errors.append(
            ParseError(f"Profile '{name}' not closed before EOF", self._uri, start_line)
        )
        return ProfileNode(
            uri=self._uri,
            range=self._make_range(start_line, self._pos - 1),
            raw=raw_start,
            name=name,
            flags=flags,
            is_hat=is_hat,
            children=children,
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
        ln, raw = self._pos, self._lines[self._pos]
        self._advance()
        stripped = raw.strip()

        # -- Capability --
        mc = RE_CAPABILITY.match(raw)
        if mc:
            caps_raw = mc.group("caps").strip()
            if "," in caps_raw:
                caps = [c.strip() for c in caps_raw.split(",") if c.strip()]
            else:
                caps = caps_raw.split()
            mods = self._leading_mods(stripped)
            return CapabilityNode(
                uri=self._uri,
                range=self._make_range(ln, ln),
                raw=raw,
                modifiers=mods,
                capabilities=caps,
            )

        # -- Network --
        mn = RE_NETWORK.match(raw)
        if mn:
            return NetworkNode(
                uri=self._uri,
                range=self._make_range(ln, ln),
                raw=raw,
                modifiers=self._leading_mods(stripped),
                rest=mn.group("rest").strip(),
            )

        # -- File rule --
        mf = RE_FILE.match(raw)
        if mf:
            mods_str = mf.group("mods") or ""
            mods = mods_str.split()
            return FileRuleNode(
                uri=self._uri,
                range=self._make_range(ln, ln),
                raw=raw,
                modifiers=mods,
                path=mf.group("path"),
                perms=mf.group("perms"),
                link_target=mf.group("link_target"),
            )

        # -- Generic --
        tokens = stripped.split()
        keyword = tokens[0] if tokens else ""
        content = stripped[len(keyword) :].strip() if tokens else ""
        return GenericRuleNode(
            uri=self._uri,
            range=self._make_range(ln, ln),
            raw=raw,
            keyword=keyword,
            content=content,
        )

    @staticmethod
    def _leading_mods(stripped: str) -> list[str]:
        mods = []
        for kw in ("deny", "audit", "owner"):
            if stripped.startswith(kw + " "):
                mods.append(kw)
                stripped = stripped[len(kw) :].lstrip()
        return mods


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
        search_dirs = [
            Path("/etc/apparmor.d"),
            Path("/usr/share/apparmor"),
        ]

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
