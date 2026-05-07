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
 • File rule: 'w' and 'a' are mutually exclusive
 • File rule: multiple exec transition modes in one rule
 • File rule: exec target ('-> profile') without exec transition mode
 • File rule: exec transition mode with 'deny' qualifier
 • File rule: bare 'x' without 'deny' qualifier
 • External: errors reported by apparmor_parser -Q -K (when available)
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Optional

from lsprotocol.types import (
    Diagnostic,
    DiagnosticSeverity,
    Position,
    Range,
)

from ._text import code_end
from .constants import (
    CAPABILITIES,
    EXECUTE_PERMISSIONS,
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

logger = logging.getLogger(__name__)

# ── helpers ───────────────────────────────────────────────────────────────────

# Dangerous unconfined exec permissions
_DANGEROUS_PERMS = {"ux", "Ux", "pux", "PUx", "cux", "CUx"}

_RE_PAREN_GROUP = re.compile(r"\([^)]*\)")
_RE_RTMIN = re.compile(r"^rtmin\+\d+$")

# Regex matching any exec transition mode (longest match first so e.g. "pix"
# beats "ix" and "px" beats "x").
_RE_EXEC_MODES = re.compile(
    "|".join(sorted(EXECUTE_PERMISSIONS.keys(), key=len, reverse=True))
)

# apparmor_parser stderr format:
#   AppArmor parser error for <profile-file> in profile <source-file> at line <N>: <msg>
_RE_PARSER_ERROR = re.compile(
    r"AppArmor parser error for \S+ in profile (\S+) at line (\d+):\s*(.*)"
)


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


def _add(
    diags: dict[str, list[Diagnostic]],
    uri: str,
    node: Node,
    message: str,
    severity: DiagnosticSeverity = DiagnosticSeverity.Error,
    code: Optional[str] = None,
) -> None:
    """Convenience: build a Diagnostic for *node* and route it under *uri*."""
    diags.setdefault(uri, []).append(_diag(node, message, severity, code))


# ── apparmor_parser integration ───────────────────────────────────────────────


def _find_apparmor_parser(configured_path: str) -> Optional[str]:
    """Return the executable path for apparmor_parser, or None if unavailable."""
    if configured_path:
        if shutil.which(configured_path) or (Path(configured_path).is_file()):
            return configured_path
        logger.warning(
            "Configured apparmor_parser path '%s' not found", configured_path
        )
        return None
    return shutil.which("apparmor_parser")


def _check_apparmor_parser(
    document_path: Path,
    uri: str,
    apparmor_parser_path: Optional[str],
) -> dict[str, list[Diagnostic]]:
    """Run apparmor_parser -Q -K against document_path; return diagnostics by URI.

    Errors in included files are attached to those files' URIs so editors
    navigate directly to the offending line.
    """
    parser_bin = _find_apparmor_parser(apparmor_parser_path or "")
    if parser_bin is None:
        logger.debug("apparmor_parser not found; skipping external parse check")
        return {}

    logger.debug("Running %s -Q -K %s", parser_bin, document_path)
    try:
        result = subprocess.run(
            [parser_bin, "-Q", "-K", str(document_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        logger.warning("apparmor_parser binary not found: %s", parser_bin)
        return {}
    except subprocess.TimeoutExpired:
        logger.warning("apparmor_parser timed out parsing %s", document_path)
        return {}
    except OSError as exc:
        logger.warning("apparmor_parser invocation failed: %s", exc)
        return {}

    if result.returncode == 0:
        return {}

    diags: dict[str, list[Diagnostic]] = {}
    for raw_line in result.stderr.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        m = _RE_PARSER_ERROR.match(line)
        if m:
            source_file_str, lineno_str, message = m.group(1), m.group(2), m.group(3)
            lineno = max(0, int(lineno_str) - 1)  # apparmor_parser is 1-based
            source_path = Path(source_file_str)
            if source_path.is_absolute() and source_path.exists():
                diag_uri = source_path.as_uri()
            else:
                # Can't resolve the source file; attach to the top-level document
                diag_uri = uri
                lineno = 0
            diags.setdefault(diag_uri, []).append(
                Diagnostic(
                    range=Range(
                        start=Position(lineno, 0),
                        end=Position(lineno, 999),
                    ),
                    message=message,
                    severity=DiagnosticSeverity.Error,
                    source="apparmor_parser",
                    code="apparmor-parser-error",
                )
            )
        else:
            logger.debug("Unrecognised apparmor_parser output: %r", raw_line)

    return diags


# ── Public entry point ────────────────────────────────────────────────────────


def get_diagnostics(
    doc: DocumentNode,
    parse_errors: list[ParseError],
    search_dirs: Optional[list[Path]] = None,
    document_path: Optional[Path] = None,
    apparmor_parser_path: Optional[str] = None,
) -> dict[str, list[Diagnostic]]:
    diags: dict[str, list[Diagnostic]] = {}
    logger.debug("Running diagnostics for %s", doc.uri)

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

    ctx = DiagContext(
        diags=diags,
        uri=doc.uri,
        defined_vars=defined_vars,
        search_dirs=search_dirs,
    )
    for node in doc.children:
        _check_node(node, ctx)

    # External apparmor_parser check — only when we have a real saved file
    if document_path is not None and document_path.exists():
        for k, v in _check_apparmor_parser(
            document_path, doc.uri, apparmor_parser_path
        ).items():
            diags.setdefault(k, []).extend(v)

    total = sum(len(v) for v in diags.values())
    logger.debug(
        "Diagnostics complete for %s: %d issue(s) across %d file(s)",
        doc.uri,
        total,
        len(diags),
    )
    return diags


@dataclass
class DiagContext:
    """Shared state threaded through the per-node check functions."""

    diags: dict[str, list[Diagnostic]]
    uri: str
    defined_vars: set[str]
    search_dirs: Optional[list[Path]] = None


_DiagCheck = Callable[[Node, "DiagContext"], None]


def _check_node(node: Node, ctx: DiagContext) -> None:
    for check in _CHECKS.get(type(node), ()):
        check(node, ctx)


# ── Profile checks ────────────────────────────────────────────────────────────


def _check_profile(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, ProfileNode)
    diags, uri = ctx.diags, ctx.uri
    # Invalid flags
    for flag in node.flags:
        flag_name = flag.split("=")[0].strip()
        if flag_name and flag_name not in PROFILE_FLAGS:
            _add(
                diags,
                uri,
                node,
                f"Unknown profile flag '{flag_name}'.",
                DiagnosticSeverity.Error,
                "unknown-flag",
            )

    # Empty body warning
    non_comment_children = [c for c in node.children if not isinstance(c, CommentNode)]
    if not non_comment_children:
        _add(
            diags,
            uri,
            node,
            f"Profile '{node.name}' has an empty body.",
            DiagnosticSeverity.Warning,
            "empty-profile",
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
                        _add(
                            diags,
                            uri,
                            child,
                            f"Capability '{cap}' is declared more than once.",
                            DiagnosticSeverity.Warning,
                            "duplicate-capability",
                        )
                    else:
                        seen_caps[cap] = child

    # deny + allow same cap
    conflict = set(seen_caps.keys()) & deny_caps
    for cap in conflict:
        _add(
            diags,
            uri,
            seen_caps[cap],
            f"Capability '{cap}' is both allowed and denied in this profile.",
            DiagnosticSeverity.Warning,
            "conflicting-capability",
        )

    # Recurse with profile-local variables added to scope
    local_vars = set(ctx.defined_vars)
    for child in node.children:
        if isinstance(child, VariableDefNode):
            local_vars.add(child.name)
        _check_node(child, replace(ctx, defined_vars=local_vars))


# ── Capability checks ─────────────────────────────────────────────────────────


def _check_capability(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, CapabilityNode)
    diags, uri = ctx.diags, ctx.uri
    for cap in node.capabilities:
        c = cap.strip().lower()
        if c and c not in CAPABILITIES:
            _add(
                diags,
                uri,
                node,
                f"Unknown capability '{cap}'. Check the list of Linux capabilities.",
                DiagnosticSeverity.Error,
                "unknown-capability",
            )


# ── Network checks ────────────────────────────────────────────────────────────


def _check_network(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, NetworkNode)
    diags, uri = ctx.diags, ctx.uri
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
            _add(
                diags,
                uri,
                node,
                f"Unknown network qualifier '{part}'. Expected a family "
                "(e.g. inet, inet6), type (e.g. stream, dgram), or access permission.",
                DiagnosticSeverity.Warning,
                "unknown-network-qualifier",
            )


# ── Signal checks ─────────────────────────────────────────────────────────────


def _check_signal(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, SignalRuleNode)
    diags, uri = ctx.diags, ctx.uri
    for perm in node.permissions:
        if perm.lower() not in SIGNAL_PERMISSIONS:
            _add(
                diags,
                uri,
                node,
                f"Unknown signal permission '{perm}'. Expected one of: {', '.join(SIGNAL_PERMISSIONS)}.",
                DiagnosticSeverity.Warning,
                "unknown-signal-permission",
            )
    for name in node.signal_set:
        if name.lower() not in SIGNAL_NAMES and not _RE_RTMIN.match(name.lower()):
            _add(
                diags,
                uri,
                node,
                f"Unknown signal name '{name}'. Expected a signal name such as term, kill, hup.",
                DiagnosticSeverity.Warning,
                "unknown-signal-name",
            )


# ── Ptrace checks ────────────────────────────────────────────────────────────


def _check_ptrace(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, PtraceRuleNode)
    diags, uri = ctx.diags, ctx.uri
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
            _add(
                diags,
                uri,
                node,
                f"Unknown ptrace permission '{perm}'. Expected one of: {', '.join(PTRACE_PERMISSIONS)}.",
                DiagnosticSeverity.Warning,
                "unknown-ptrace-permission",
            )


# ── File-rule checks ──────────────────────────────────────────────────────────

_VAR_REF = re.compile(r"@\{[A-Za-z_][A-Za-z0-9_]*\}")


def _check_file_rule(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, FileRuleNode)
    diags, uri = ctx.diags, ctx.uri
    perm_str = node.perms
    exec_modes = _RE_EXEC_MODES.findall(perm_str)

    # Warn about dangerous unconfined exec — match the actual exec mode rather
    # than checking for substring containment, otherwise something like "rux"
    # (not a valid mode) would still trigger via the "ux" substring.
    dangerous = next((m for m in exec_modes if m in _DANGEROUS_PERMS), None)
    if dangerous is not None:
        _add(
            diags,
            uri,
            node,
            f"Permission '{dangerous}' allows unconfined execution — "
            "consider using 'px' or 'cx' with a named profile instead.",
            DiagnosticSeverity.Warning,
            "dangerous-exec",
        )

    # 'w' (write) and 'a' (append) are mutually exclusive
    if "w" in perm_str and "a" in perm_str:
        _add(
            diags,
            uri,
            node,
            "File permissions 'w' (write) and 'a' (append) are mutually exclusive.",
            DiagnosticSeverity.Error,
            "perm-conflict-write-append",
        )

    # Only one exec transition mode is allowed per rule
    if len(exec_modes) > 1:
        _add(
            diags,
            uri,
            node,
            f"Multiple exec transition modes ({', '.join(exec_modes)}) are mutually exclusive — only one is allowed per rule.",
            DiagnosticSeverity.Error,
            "multiple-exec-modes",
        )

    # An exec target ('-> profile') requires an exec transition mode
    if node.exec_target is not None and not exec_modes:
        _add(
            diags,
            uri,
            node,
            f"Exec target '-> {node.exec_target}' requires an exec transition permission (e.g. px, cx, ix).",
            DiagnosticSeverity.Error,
            "exec-target-without-transition",
        )

    # Exec transition modes are incompatible with the deny qualifier
    if "deny" in node.qualifiers and exec_modes:
        _add(
            diags,
            uri,
            node,
            f"Exec transition mode '{exec_modes[0]}' is incompatible with the 'deny' qualifier. "
            "Use 'deny x' to deny execute permission.",
            DiagnosticSeverity.Error,
            "deny-with-exec-transition",
        )

    # Bare 'x' is only valid with the deny qualifier
    bare_perms = _RE_EXEC_MODES.sub("", perm_str)
    if "x" in bare_perms and "deny" not in node.qualifiers:
        _add(
            diags,
            uri,
            node,
            "Bare 'x' (execute) is only valid with the 'deny' qualifier. "
            "Use an exec transition mode such as 'ix', 'px', or 'cx' instead.",
            DiagnosticSeverity.Error,
            "bare-x-without-deny",
        )

    # Warn about 'w' that should probably be 'a' (append)
    if "w" in perm_str and node.path.endswith((".log", ".out", ".txt")):
        _add(
            diags,
            uri,
            node,
            f"'{node.path}' looks like a log/output file. "
            "Consider using 'a' (append) instead of 'w' (write).",
            DiagnosticSeverity.Information,
            "prefer-append",
        )

    # Undefined variable references — handled uniformly by _check_var_refs,
    # which also covers exec_target and any qualifier prefix.


# ── Abi checks ────────────────────────────────────────────────────────────


def _check_abi(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, ABINode)
    resolved = resolve_include_path(node.path, ctx.uri, ctx.search_dirs)
    if resolved is None:
        _add(
            ctx.diags,
            ctx.uri,
            node,
            f"ABI target '{node.path}' could not be found on disk.",
            DiagnosticSeverity.Warning,
            "missing-abi",
        )


# ── Include checks ────────────────────────────────────────────────────────────


def _check_include(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, IncludeNode)
    resolved = resolve_include_path(node.path, ctx.uri, ctx.search_dirs)
    # Conditional includes are not an error if missing
    if resolved is None and not node.conditional:
        _add(
            ctx.diags,
            ctx.uri,
            node,
            f"Include target '{node.path}' could not be found on disk.",
            DiagnosticSeverity.Warning,
            "missing-include",
        )


# ── Known and unknown rule checks ────────────────────────────────────────────


def _check_var_refs(node: Node, ctx: DiagContext) -> None:
    """Flag any @{…} reference in *node* that isn't defined in scope.

    Scans every line of node.raw with trailing comments stripped via
    code_end, so a comment like "# use @{HOME}" no longer false-positives,
    while real references in any structured field (path, exec_target,
    peer=, addr=, …) are caught uniformly across rule types.

    TODO(structured-fields): This is the raw-text scanning implementation.
    The cleaner long-term answer is to iterate the rule's structured fields
    directly — but most rule types currently store their post-keyword body
    as a single ``content: str`` (see the matching TODO above the freeform
    RuleNode declarations in parser.py). Once those types grow real fields,
    this function should iterate ``getattr(node, name)`` for each declared
    value-bearing field and stop relying on raw-text scanning at all. The
    ``code_end`` heuristic and the ``seen`` set below would then go away.
    """
    seen: set[str] = set()
    for line in node.raw.splitlines():
        for var_ref in _VAR_REF.findall(line[: code_end(line)]):
            if var_ref in seen or var_ref in ctx.defined_vars:
                continue
            seen.add(var_ref)
            _add(
                ctx.diags,
                ctx.uri,
                node,
                f"Variable '{var_ref}' is used but never defined.",
                DiagnosticSeverity.Warning,
                "undefined-variable",
            )


def _check_unknown_rule(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, UnknownRuleNode)
    kw = node.keyword.lower()
    if not kw:
        return

    if kw not in KEYWORD_DEFS:
        if not kw.startswith("/") and not kw.startswith("@"):
            _add(
                ctx.diags,
                ctx.uri,
                node,
                f"Unrecognised rule keyword '{node.keyword}'.",
                DiagnosticSeverity.Warning,
                "unknown-keyword",
            )

    _check_var_refs(node, ctx)


# ── Dispatch table ────────────────────────────────────────────────────────────
# Map each AST node type to the ordered list of checks to run against it.
# Adding a new check is a one-line edit here plus its implementation above;
# the previous long isinstance chain in _check_node is now driven by data.

_VAR_REF_RULE_TYPES: tuple[type[Node], ...] = (
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
)

_CHECKS: dict[type[Node], tuple[_DiagCheck, ...]] = {
    ProfileNode: (_check_profile,),
    CapabilityNode: (_check_capability, _check_var_refs),
    NetworkNode: (_check_network, _check_var_refs),
    SignalRuleNode: (_check_signal, _check_var_refs),
    PtraceRuleNode: (_check_ptrace, _check_var_refs),
    FileRuleNode: (_check_file_rule, _check_var_refs),
    ABINode: (_check_abi,),
    IncludeNode: (_check_include,),
    UnknownRuleNode: (_check_unknown_rule,),
    **{cls: (_check_var_refs,) for cls in _VAR_REF_RULE_TYPES},
}
