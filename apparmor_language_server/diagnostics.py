"""
AppArmor LSP – diagnostics (linting).

Checks performed
────────────────
 • Unknown capabilities
 • Unknown network families / types
 • Unknown signal permissions / names
 • Dangerous exec permissions (ux/Ux) with a warning
 • Unclosed profiles detected by parser
 • Duplicate capability declarations
 • Conflicting allow + deny for the same capability
 • Empty profile bodies
 • Invalid profile flags
 • Variable used but never defined
 • Include / ABI path that does not exist on disk
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from lsprotocol.types import (
    Diagnostic,
    DiagnosticSeverity,
    Position,
    Range,
)

from .constants import (
    CAPABILITIES,
    KEYWORD_DEFS,
    NETWORK_DOMAINS,
    NETWORK_PERMISSIONS,
    NETWORK_PROTOCOLS,
    NETWORK_TYPES,
    PROFILE_FLAGS,
    PTRACE_PERMISSIONS,
    SIGNAL_NAMES,
    SIGNAL_PERMISSIONS,
)
from .parser import (
    ABINode,
    AllRuleNode,
    CapabilityNode,
    ChangeHatRuleNode,
    ChangeProfileRuleNode,
    CommentNode,
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
    ParseError,
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
    VariableDefNode,
    resolve_include_path,
)

# ── helpers ───────────────────────────────────────────────────────────────────

# Dangerous unconfined exec permissions
_DANGEROUS_PERMS = {"ux", "Ux", "pux", "PUx", "cux", "CUx"}

_RE_PAREN_GROUP = re.compile(r"\([^)]*\)")
_RE_RTMIN = re.compile(r"^rtmin\+\d+$")


def _lsp_range(node: Node) -> Range:
    return Range(
        start=Position(node.range.start.line, node.range.start.character),
        end=Position(node.range.end.line, node.range.end.character),
    )


def _diag(
    node: Node,
    message: str,
    severity: DiagnosticSeverity = DiagnosticSeverity.Error,
    code: Optional[str] = None,
) -> Diagnostic:
    return Diagnostic(
        range=_lsp_range(node),
        message=message,
        severity=severity,
        source="apparmor-language-server",
        code=code,
    )


# ── Public entry point ────────────────────────────────────────────────────────


def get_diagnostics(
    doc: DocumentNode,
    parse_errors: list[ParseError],
    search_dirs: Optional[list[Path]] = None,
) -> dict[str, list[Diagnostic]]:
    diags: dict[str, list[Diagnostic]] = {}

    # Convert parser errors first
    for err in parse_errors:
        diags.setdefault(err.uri, []).append(
            Diagnostic(
                range=Range(
                    start=Position(err.line, err.character),
                    end=Position(err.line, 999),
                ),
                message=str(err),
                severity=DiagnosticSeverity.Error,
                source="apparmor-language-server",
                code="parse-error",
            )
        )

    # Collect defined variable names from all_variables in document
    defined_vars: set[str] = set()
    for _, vars in doc.all_variables.items():
        defined_vars.update(set(vars.keys()))

    for node in doc.children:
        _check_node(node, diags, defined_vars, doc.uri, search_dirs)

    return diags


def _check_node(
    node: Node,
    diags: dict[str, list[Diagnostic]],
    defined_vars: set[str],
    uri: str,
    search_dirs: Optional[list[Path]] = None,
) -> None:
    if isinstance(node, ProfileNode):
        _check_profile(node, diags, uri, defined_vars, search_dirs)
    elif isinstance(node, CapabilityNode):
        _check_capability(node, diags, uri)
    elif isinstance(node, NetworkNode):
        _check_network(node, diags, uri)
    elif isinstance(node, SignalRuleNode):
        _check_signal(node, diags, uri)
    elif isinstance(node, PtraceRuleNode):
        _check_ptrace(node, diags, uri)
        _check_var_refs(node, diags, uri, defined_vars)
    elif isinstance(node, FileRuleNode):
        _check_file_rule(node, diags, uri, defined_vars)
    elif isinstance(node, ABINode):
        _check_abi(node, diags, uri, search_dirs)
    elif isinstance(node, IncludeNode):
        _check_include(node, diags, uri, search_dirs)
    elif isinstance(
        node,
        (
            DbusRuleNode,
            UnixRuleNode,
            MountRuleNode,
            UmountRuleNode,
            UsernsRuleNode,
            IoUringRuleNode,
            MqueueRuleNode,
            RlimitRuleNode,
            PivotRootRuleNode,
            ChangeProfileRuleNode,
            ChangeHatRuleNode,
            LinkRuleNode,
            AllRuleNode,
            RemountRuleNode,
        ),
    ):
        _check_var_refs(node, diags, uri, defined_vars)
    elif isinstance(node, UnknownRuleNode):
        _check_unknown_rule(node, diags, uri, defined_vars)


# ── Profile checks ────────────────────────────────────────────────────────────


def _check_profile(
    node: ProfileNode,
    diags: dict[str, list[Diagnostic]],
    uri: str,
    defined_vars: set[str],
    search_dirs: Optional[list[Path]] = None,
) -> None:
    # Invalid flags
    for flag in node.flags:
        flag_name = flag.split("=")[0].strip()
        if flag_name and flag_name not in PROFILE_FLAGS:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unknown profile flag '{flag_name}'.",
                    DiagnosticSeverity.Error,
                    "unknown-flag",
                )
            )

    # Empty body warning
    non_comment_children = [c for c in node.children if not isinstance(c, CommentNode)]
    if not non_comment_children:
        diags.setdefault(uri, []).append(
            _diag(
                node,
                f"Profile '{node.name}' has an empty body.",
                DiagnosticSeverity.Warning,
                "empty-profile",
            )
        )

    # Duplicate capability declarations within same profile
    seen_caps: dict[str, CapabilityNode] = {}
    deny_caps: set[str] = set()

    for child in node.children:
        if isinstance(child, CapabilityNode):
            for cap in child.capabilities:
                if "deny" in child.qualifiers:
                    deny_caps.add(cap)
                else:
                    if cap in seen_caps:
                        diags.setdefault(uri, []).append(
                            _diag(
                                child,
                                f"Capability '{cap}' is declared more than once.",
                                DiagnosticSeverity.Warning,
                                "duplicate-capability",
                            )
                        )
                    else:
                        seen_caps[cap] = child

    # deny + allow same cap
    conflict = set(seen_caps.keys()) & deny_caps
    for cap in conflict:
        diags.setdefault(uri, []).append(
            _diag(
                seen_caps[cap],
                f"Capability '{cap}' is both allowed and denied in this profile.",
                DiagnosticSeverity.Warning,
                "conflicting-capability",
            )
        )

    # Recurse
    local_vars = set(defined_vars)
    for child in node.children:
        if isinstance(child, VariableDefNode):
            local_vars.add(child.name)
        _check_node(child, diags, local_vars, uri, search_dirs)


# ── Capability checks ─────────────────────────────────────────────────────────


def _check_capability(
    node: CapabilityNode, diags: dict[str, list[Diagnostic]], uri: str
) -> None:
    for cap in node.capabilities:
        c = cap.strip().lower()
        if c and c not in CAPABILITIES:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unknown capability '{cap}'. "
                    "Check the list of Linux capabilities.",
                    DiagnosticSeverity.Error,
                    "unknown-capability",
                )
            )


# ── Network checks ────────────────────────────────────────────────────────────


def _check_network(
    node: NetworkNode, diags: dict[str, list[Diagnostic]], uri: str
) -> None:
    rest = node.rest
    # Remove parenthesized groups (access lists, peer conditionals)
    rest = _RE_PAREN_GROUP.sub("", rest)
    parts = rest.split()
    _VALID_NETWORK_TOKENS = (
        set(NETWORK_DOMAINS)
        | set(NETWORK_TYPES)
        | set(NETWORK_PERMISSIONS)
        | set(NETWORK_PROTOCOLS)
        | {"peer"}
    )
    for part in parts:
        p = part.strip().rstrip(",").lower()
        if not p or "=" in p:
            continue
        if p not in _VALID_NETWORK_TOKENS:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unknown network qualifier '{part}'. Expected a family "
                    "(e.g. inet, inet6), type (e.g. stream, dgram), or access permission.",
                    DiagnosticSeverity.Warning,
                    "unknown-network-qualifier",
                )
            )


# ── Signal checks ─────────────────────────────────────────────────────────────


def _check_signal(
    node: SignalRuleNode, diags: dict[str, list[Diagnostic]], uri: str
) -> None:
    for perm in node.permissions:
        if perm.lower() not in SIGNAL_PERMISSIONS:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unknown signal permission '{perm}'. Expected one of: {', '.join(SIGNAL_PERMISSIONS)}.",
                    DiagnosticSeverity.Warning,
                    "unknown-signal-permission",
                )
            )
    for name in node.signal_set:
        if name.lower() not in SIGNAL_NAMES and not _RE_RTMIN.match(name.lower()):
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unknown signal name '{name}'. Expected a signal name such as term, kill, hup.",
                    DiagnosticSeverity.Warning,
                    "unknown-signal-name",
                )
            )


# ── Ptrace checks ────────────────────────────────────────────────────────────


def _check_ptrace(
    node: PtraceRuleNode, diags: dict[str, list[Diagnostic]], uri: str
) -> None:
    content = node.content.strip()
    if content.startswith("("):
        perm_str = (
            content[1 : content.find(")")].strip() if ")" in content else content[1:]
        )
    else:
        # bare permission before "peer="
        perm_str = content.split("peer=")[0].strip()
    perms = perm_str.replace(",", " ").split()
    for perm in perms:
        p = perm.strip().lower()
        if p and p not in PTRACE_PERMISSIONS:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unknown ptrace permission '{perm}'. Expected one of: {', '.join(PTRACE_PERMISSIONS)}.",
                    DiagnosticSeverity.Warning,
                    "unknown-ptrace-permission",
                )
            )


# ── File-rule checks ──────────────────────────────────────────────────────────

_VAR_REF = re.compile(r"@\{[A-Za-z_][A-Za-z0-9_]*\}")


def _check_file_rule(
    node: FileRuleNode,
    diags: dict[str, list[Diagnostic]],
    uri: str,
    defined_vars: set[str],
) -> None:
    perm_str = node.perms

    # Warn about dangerous unconfined exec
    for dp in _DANGEROUS_PERMS:
        if dp in perm_str:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Permission '{dp}' allows unconfined execution — "
                    "consider using 'px' or 'cx' with a named profile instead.",
                    DiagnosticSeverity.Warning,
                    "dangerous-exec",
                )
            )
            break

    # Warn about 'w' that should probably be 'a' (append)
    if "w" in perm_str and node.path.endswith((".log", ".out", ".txt")):
        diags.setdefault(uri, []).append(
            _diag(
                node,
                f"'{node.path}' looks like a log/output file. "
                "Consider using 'a' (append) instead of 'w' (write).",
                DiagnosticSeverity.Information,
                "prefer-append",
            )
        )

    # Undefined variable references in path
    for var_ref in _VAR_REF.findall(node.path):
        if var_ref not in defined_vars:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Variable '{var_ref}' is used but never defined.",
                    DiagnosticSeverity.Warning,
                    "undefined-variable",
                )
            )


# ── Abi checks ────────────────────────────────────────────────────────────


def _check_abi(
    node: ABINode,
    diags: dict[str, list[Diagnostic]],
    uri: str,
    search_dirs: Optional[list[Path]] = None,
) -> None:
    resolved = resolve_include_path(node.path, uri, search_dirs)
    if resolved is None:
        diags.setdefault(uri, []).append(
            _diag(
                node,
                f"ABI target '{node.path}' could not be found on disk.",
                DiagnosticSeverity.Warning,
                "missing-abi",
            )
        )


# ── Include checks ────────────────────────────────────────────────────────────


def _check_include(
    node: IncludeNode,
    diags: dict[str, list[Diagnostic]],
    uri: str,
    search_dirs: Optional[list[Path]] = None,
) -> None:
    resolved = resolve_include_path(node.path, uri, search_dirs)
    if resolved is None:
        # only an error if the include is not conditional
        if not node.conditional:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Include target '{node.path}' could not be found on disk.",
                    DiagnosticSeverity.Warning,
                    "missing-include",
                )
            )


# ── Known and unknown rule checks ────────────────────────────────────────────


def _check_var_refs(
    node: Node,
    diags: dict[str, list[Diagnostic]],
    uri: str,
    defined_vars: set[str],
) -> None:
    for var_ref in _VAR_REF.findall(node.raw):
        if var_ref not in defined_vars:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Variable '{var_ref}' is used but never defined.",
                    DiagnosticSeverity.Warning,
                    "undefined-variable",
                )
            )


def _check_unknown_rule(
    node: UnknownRuleNode,
    diags: dict[str, list[Diagnostic]],
    uri: str,
    defined_vars: set[str],
) -> None:
    kw = node.keyword.lower()
    if not kw:
        return

    if kw not in KEYWORD_DEFS:
        if not kw.startswith("/") and not kw.startswith("@"):
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unrecognised rule keyword '{node.keyword}'.",
                    DiagnosticSeverity.Warning,
                    "unknown-keyword",
                )
            )

    _check_var_refs(node, diags, uri, defined_vars)
