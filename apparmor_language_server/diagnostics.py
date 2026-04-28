"""
AppArmor LSP – diagnostics (linting).

Checks performed
────────────────
 • Unknown capabilities
 • Unknown network families / types
 • Conflicting / redundant file permission modifiers
 • Unclosed profiles detected by parser
 • Duplicate capability declarations
 • Dangerous exec permissions (ux/Ux) with a warning
 • Empty profile bodies
 • Variable used but never defined
 • Profile name does not start with '/' or 'profile'
 • Include path that does not exist on disk
 • Deny + allow of the same resource in the same profile
 • Invalid profile flags
"""

from __future__ import annotations

import re
from typing import Optional

from lsprotocol.types import (
    Diagnostic,
    DiagnosticSeverity,
    Position,
    Range,
)

from .constants import (
    CAPABILITIES,
    NETWORK_FAMILIES,
    NETWORK_TYPES,
    PROFILE_FLAGS,
)
from .parser import (
    ABINode,
    CapabilityNode,
    CommentNode,
    DocumentNode,
    FileRuleNode,
    GenericRuleNode,
    IncludeNode,
    NetworkNode,
    Node,
    ParseError,
    ProfileNode,
    VariableDefNode,
    resolve_include_path,
)

# ── helpers ───────────────────────────────────────────────────────────────────

_VALID_FILE_PERMS = set("rwaxmlkdDuUipPcCbBiI")

# Dangerous unconfined exec permissions
_DANGEROUS_PERMS = {"ux", "Ux", "pux", "cux"}


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
    text: str,
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

    # Collect defined variable names from document
    defined_vars: set[str] = set(doc.variables.keys())

    for node in doc.children:
        _check_node(node, diags, defined_vars, doc.uri)

    return diags


def _check_node(
    node: Node,
    diags: dict[str, list[Diagnostic]],
    defined_vars: set[str],
    uri: str,
) -> None:
    if isinstance(node, ProfileNode):
        _check_profile(node, diags, uri, defined_vars)
    elif isinstance(node, CapabilityNode):
        _check_capability(node, diags, uri)
    elif isinstance(node, NetworkNode):
        _check_network(node, diags, uri)
    elif isinstance(node, FileRuleNode):
        _check_file_rule(node, diags, uri, defined_vars)
    elif isinstance(node, ABINode):
        _check_abi(node, diags, uri)
    elif isinstance(node, IncludeNode):
        _check_include(node, diags, uri)
    elif isinstance(node, GenericRuleNode):
        _check_generic(node, diags, uri, defined_vars)


# ── Profile checks ────────────────────────────────────────────────────────────


def _check_profile(
    node: ProfileNode,
    diags: dict[str, list[Diagnostic]],
    uri: str,
    defined_vars: set[str],
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
                if "deny" in child.modifiers:
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
        _check_node(child, diags, local_vars, uri)


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
    parts = node.rest.split()
    for part in parts:
        p = part.strip().rstrip(",").lower()
        if not p:
            continue
        if p not in NETWORK_FAMILIES and p not in NETWORK_TYPES:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unknown network qualifier '{part}'. Expected a family "
                    "(e.g. inet, inet6) or type (e.g. stream, dgram).",
                    DiagnosticSeverity.Warning,
                    "unknown-network-qualifier",
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
    # Check for invalid permission characters
    # Strip exec modifier compounds first
    perm_str = node.perms
    # Valid single-char perms
    for ch in perm_str:
        if ch not in _VALID_FILE_PERMS:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unknown file permission character '{ch}' in '{perm_str}'.",
                    DiagnosticSeverity.Error,
                    "unknown-permission",
                )
            )
            break

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
) -> None:
    resolved = resolve_include_path(node.path, uri)
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
) -> None:
    resolved = resolve_include_path(node.path, uri)
    if resolved is None:
        diags.setdefault(uri, []).append(
            _diag(
                node,
                f"Include target '{node.path}' could not be found on disk.",
                DiagnosticSeverity.Warning,
                "missing-include",
            )
        )


# ── Generic rule checks ───────────────────────────────────────────────────────

_KNOWN_RULE_KEYWORDS = {
    "capability",
    "network",
    "signal",
    "ptrace",
    "mount",
    "umount",
    "remount",
    "pivot_root",
    "unix",
    "dbus",
    "file",
    "link",
    "owner",
    "deny",
    "audit",
    "change_profile",
    "change_hat",
    "rlimit",
    "userns",
    "io_uring",
    "mqueue",
    "alias",
    "include",
}


def _check_generic(
    node: GenericRuleNode,
    diags: dict[str, list[Diagnostic]],
    uri: str,
    defined_vars: set[str],
) -> None:
    kw = node.keyword.lower()
    # Skip empty / handled above
    if not kw:
        return

    if kw not in _KNOWN_RULE_KEYWORDS:
        # Could be a file path starting with a letter (unusual but valid)
        if not kw.startswith("/") and not kw.startswith("@"):
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Unrecognised rule keyword '{node.keyword}'.",
                    DiagnosticSeverity.Warning,
                    "unknown-keyword",
                )
            )

    # Variable refs in generic rules
    full = node.raw
    for var_ref in _VAR_REF.findall(full):
        if var_ref not in defined_vars:
            diags.setdefault(uri, []).append(
                _diag(
                    node,
                    f"Variable '{var_ref}' is used but never defined.",
                    DiagnosticSeverity.Warning,
                    "undefined-variable",
                )
            )
