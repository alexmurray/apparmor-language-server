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
import os
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

from .constants import (
    CAPABILITIES,
    DBUS_PERMISSIONS,
    EXECUTE_PERMISSIONS,
    IO_URING_PERMISSIONS,
    KEYWORD_DEFS,
    MOUNT_OPTIONS,
    MQUEUE_PERMISSIONS,
    MQUEUE_TYPES,
    NETWORK_DOMAINS,
    NETWORK_PERMISSIONS,
    NETWORK_PROTOCOLS,
    NETWORK_TYPES,
    PROFILE_FLAGS,
    PROFILE_MODES,
    PTRACE_PERMISSIONS,
    RE_ERRNO_NAME,
    RLIMIT_TYPES,
    SIGNAL_NAMES,
    SIGNAL_PERMISSIONS,
    SNAP_HOSTFS,
    UNIX_PERMISSIONS,
    UNIX_TYPES,
    USERNS_PERMISSIONS,
)
from .parser import (
    ABINode,
    AliasNode,
    AllRuleNode,
    CapabilityNode,
    ChangeHatRuleNode,
    ChangeProfileRuleNode,
    CommentNode,
    DbusRuleNode,
    DocumentNode,
    FileRuleNode,
    IfBlockNode,
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
    QualifierBlockNode,
    RemountRuleNode,
    RuleNode,
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


def _snap_parser_extra_args() -> list[str]:
    """Return extra apparmor_parser args needed under snap confinement, else []."""
    if not os.environ.get("SNAP"):
        return []
    return [
        "--base",
        str(SNAP_HOSTFS / "etc/apparmor.d"),
        "--config-file",
        str(SNAP_HOSTFS / "etc/apparmor/parser.conf"),
    ]


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
    document_path: Optional[Path],
    uri: str,
    apparmor_parser_path: Optional[str],
    text: Optional[str] = None,
) -> dict[str, list[Diagnostic]]:
    """Run apparmor_parser -Q -K against document_path or stdin; return diagnostics by URI.

    When *text* is provided the profile content is passed via stdin (using
    ``/dev/stdin`` as the path argument) so the file does not need to exist on
    disk.  When neither *text* nor *document_path* is given, return ``{}``.

    Errors in included files are attached to those files' URIs so editors
    navigate directly to the offending line.
    """
    if text is None and document_path is None:
        return {}

    parser_bin = _find_apparmor_parser(apparmor_parser_path or "")
    if parser_bin is None:
        logger.debug("apparmor_parser not found; skipping external parse check")
        return {}

    extra_args = _snap_parser_extra_args()
    if text is not None:
        path_arg = "/dev/stdin"
    else:
        path_arg = str(document_path)
    logger.debug(
        "Running %s -Q -K %s%s",
        parser_bin,
        path_arg,
        f" (snap args: {extra_args})" if extra_args else "",
    )
    try:
        run_kwargs: dict = dict(
            capture_output=True,
            text=True,
            timeout=10,
        )
        if text is not None:
            run_kwargs["input"] = text
        result = subprocess.run(
            [parser_bin, "-Q", "-K", *extra_args, path_arg],
            **run_kwargs,
        )
    except FileNotFoundError:
        logger.warning("apparmor_parser binary not found: %s", parser_bin)
        return {}
    except subprocess.TimeoutExpired:
        logger.warning("apparmor_parser timed out parsing %s", path_arg)
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
            if source_file_str == "/dev/stdin":
                # stdin mode: map the virtual path back to the document URI and
                # keep the line number as reported (already converted to 0-based).
                diag_uri = uri
            else:
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

    # Collect defined variable names from all_variables in document.
    # Seed with AppArmor built-in magic variables that are always available.
    defined_vars: set[str] = {"@{profile_name}"}
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
    # Invalid flags + per-flag value validation
    modes_set: list[str] = []
    for flag in node.flags:
        name, _, value = flag.partition("=")
        flag_name = name.strip()
        if flag_name and flag_name not in PROFILE_FLAGS:
            _add(
                diags,
                uri,
                node,
                f"Unknown profile flag '{flag_name}'.",
                DiagnosticSeverity.Error,
                "unknown-flag",
            )
            continue
        if flag_name in PROFILE_MODES:
            modes_set.append(flag_name)
        if flag_name == "error":
            errno = value.strip().upper()
            if errno and not RE_ERRNO_NAME.match(errno):
                _add(
                    diags,
                    uri,
                    node,
                    f"Profile flag 'error={value}': value must be an errno "
                    "name beginning with 'E' (see errno(3)).",
                    DiagnosticSeverity.Warning,
                    "invalid-error-flag-value",
                )

    # Mode flags are mutually exclusive
    if len(modes_set) > 1:
        _add(
            diags,
            uri,
            node,
            "Profile mode flags are mutually exclusive: "
            f"{', '.join(modes_set)}. Pick one.",
            DiagnosticSeverity.Error,
            "conflicting-profile-modes",
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


# ── Generic qualifier conflict ────────────────────────────────────────────────


def _check_qualifier_conflict(node: Node, ctx: DiagContext) -> None:
    """Flag rules that use both ``allow`` and ``deny`` qualifiers."""
    if not isinstance(node, RuleNode):
        return
    if "allow" in node.qualifiers and "deny" in node.qualifiers:
        _add(
            ctx.diags,
            ctx.uri,
            node,
            "Qualifiers 'allow' and 'deny' are mutually exclusive on the same rule.",
            DiagnosticSeverity.Error,
            "allow-deny-conflict",
        )


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

    Iterates the rule's structured value-bearing fields via
    ``RuleNode.value_strings`` rather than scanning the raw source text, so
    a reference inside a trailing comment (``# use @{HOME}``) is naturally
    ignored and there's no risk of mis-attributing tokens to the wrong
    field. Each undefined variable is reported at most once per node.
    """
    if not isinstance(node, RuleNode):
        return
    seen: set[str] = set()
    for value in node.value_strings():
        for var_ref in _VAR_REF.findall(value):
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


# ── Network: additional semantic checks ──────────────────────────────────────


def _check_network_semantics(node: Node, ctx: DiagContext) -> None:
    """Cross-cutting checks not covered by the simple token validation.

    * ``netlink`` family rules may only specify type ``dgram`` or ``raw``
      (man apparmor.d §"Network Rules").
    """
    assert isinstance(node, NetworkNode)
    if node.domain == "netlink" and node.type and node.type not in {"dgram", "raw"}:
        _add(
            ctx.diags,
            ctx.uri,
            node,
            f"Network rule: netlink may only specify type 'dgram' or 'raw' "
            f"(got '{node.type}').",
            DiagnosticSeverity.Error,
            "netlink-type-restricted",
        )


# ── Mount checks ─────────────────────────────────────────────────────────────

_MOUNT_OPTIONS_SET = frozenset(MOUNT_OPTIONS)


def _check_mount_options(node: Node, ctx: DiagContext) -> None:
    """Validate ``options=…`` tokens against the documented mount-flag list.

    Tokens that look like AARE patterns (contain glob metacharacters) are
    skipped — the man page allows pattern matching against options.
    """
    assert isinstance(node, (MountRuleNode, RemountRuleNode, UmountRuleNode))
    for opt in node.options:
        cleaned = opt.lower().rstrip(",")
        if not cleaned:
            continue
        if any(ch in cleaned for ch in "*?[]{}@"):
            continue
        if cleaned not in _MOUNT_OPTIONS_SET:
            _add(
                ctx.diags,
                ctx.uri,
                node,
                f"Unknown mount option '{opt}'.",
                DiagnosticSeverity.Warning,
                "unknown-mount-option",
            )


# ── Rlimit checks ────────────────────────────────────────────────────────────

_RLIMIT_TYPES_SET = frozenset(RLIMIT_TYPES)
_RLIMIT_SIZE_RES = frozenset(
    {"fsize", "data", "stack", "core", "rss", "as", "memlock", "msgqueue"}
)
_RLIMIT_NUMBER_RES = frozenset(
    {"ofile", "nofile", "locks", "sigpending", "nproc", "rtprio"}
)
_RLIMIT_TIME_RES = frozenset({"cpu", "rttime"})
_RLIMIT_NICE_RES = frozenset({"nice"})

_RE_RLIMIT_SIZE = re.compile(r"^\d+(?:[KMG])?$", re.IGNORECASE)
_RE_RLIMIT_NUMBER = re.compile(r"^\d+$")
_RE_RLIMIT_TIME = re.compile(
    r"^\d+\s*(?:us|microsecond|microseconds|ms|millisecond|milliseconds|"
    r"s|sec|second|seconds|min|minute|minutes|h|hour|hours|d|day|days|"
    r"week|weeks)?$",
    re.IGNORECASE,
)
_RE_RLIMIT_CPU_UNIT = re.compile(
    r"^\d+\s*(?:s|sec|second|seconds|min|minute|minutes|h|hour|hours|"
    r"d|day|days|week|weeks)?$",
    re.IGNORECASE,
)


def _check_rlimit(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, RlimitRuleNode)
    res = node.resource.strip().lower()
    val = node.value.strip()
    if res and res not in _RLIMIT_TYPES_SET:
        _add(
            ctx.diags,
            ctx.uri,
            node,
            f"Unknown rlimit resource '{node.resource}'.",
            DiagnosticSeverity.Error,
            "unknown-rlimit-resource",
        )
        return
    if not val:
        return
    if val.lower() == "infinity":
        return
    ok = True
    msg = ""
    if res in _RLIMIT_SIZE_RES:
        ok = bool(_RE_RLIMIT_SIZE.match(val))
        msg = "expected NUMBER[K|M|G]"
    elif res in _RLIMIT_NUMBER_RES:
        ok = bool(_RE_RLIMIT_NUMBER.match(val))
        msg = "expected a non-negative integer"
    elif res == "cpu":
        ok = bool(_RE_RLIMIT_CPU_UNIT.match(val))
        msg = "rlimit 'cpu' only allows units of seconds or larger"
    elif res in _RLIMIT_TIME_RES:
        ok = bool(_RE_RLIMIT_TIME.match(val))
        msg = "expected NUMBER followed by a time unit (us, ms, s, min, h, d, week)"
    elif res in _RLIMIT_NICE_RES:
        try:
            n = int(val)
            ok = -20 <= n <= 19
        except ValueError:
            ok = False
        msg = "rlimit 'nice' must be an integer in the range -20..19"
    if not ok:
        _add(
            ctx.diags,
            ctx.uri,
            node,
            f"Invalid rlimit value '{val}' for '{res}': {msg}.",
            DiagnosticSeverity.Warning,
            "invalid-rlimit-value",
        )


# ── DBus checks ──────────────────────────────────────────────────────────────

_DBUS_PERM_SET = frozenset(DBUS_PERMISSIONS)
_DBUS_MESSAGE_PERMS = frozenset({"send", "receive", "r", "w", "rw", "read", "write"})
_DBUS_SERVICE_PERMS = frozenset({"bind", "r", "w", "rw", "read", "write"})


def _check_dbus(node: Node, ctx: DiagContext) -> None:
    """Validate dbus permissions and rule-shape incompatibilities."""
    assert isinstance(node, DbusRuleNode)
    diags, uri = ctx.diags, ctx.uri
    perms = [p.lower() for p in node.permissions]
    for perm in perms:
        if perm and perm not in _DBUS_PERM_SET:
            _add(
                diags,
                uri,
                node,
                f"Unknown D-Bus permission '{perm}'. Expected one of: "
                f"{', '.join(DBUS_PERMISSIONS)}.",
                DiagnosticSeverity.Warning,
                "unknown-dbus-permission",
            )

    # Rule-shape incompatibilities (man apparmor.d §"DBus rules").
    has_message_fields = any(
        v is not None for v in (node.path, node.interface, node.member, node.peer)
    )
    has_service_fields = node.name is not None
    if "bind" in perms and has_message_fields:
        _add(
            diags,
            uri,
            node,
            "D-Bus permission 'bind' cannot be used in a message rule "
            "(rules with path=/interface=/member=/peer=).",
            DiagnosticSeverity.Error,
            "dbus-bind-in-message-rule",
        )
    if has_service_fields and (
        {"send", "receive", "r", "w", "rw", "read", "write"} & set(perms)
    ):
        _add(
            diags,
            uri,
            node,
            "D-Bus permissions 'send' and 'receive' cannot be used in a "
            "service rule (rules with name=).",
            DiagnosticSeverity.Error,
            "dbus-send-recv-in-service-rule",
        )
    if "eavesdrop" in perms and (has_message_fields or has_service_fields):
        _add(
            diags,
            uri,
            node,
            "D-Bus permission 'eavesdrop' is incompatible with conditionals "
            "other than 'bus='.",
            DiagnosticSeverity.Error,
            "dbus-eavesdrop-with-conds",
        )


# ── Unix checks ──────────────────────────────────────────────────────────────

_UNIX_PERM_SET = frozenset(UNIX_PERMISSIONS)
_UNIX_TYPE_SET = frozenset(UNIX_TYPES)


def _check_unix(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, UnixRuleNode)
    for perm in node.permissions:
        p = perm.strip().lower()
        if p and p not in _UNIX_PERM_SET:
            _add(
                ctx.diags,
                ctx.uri,
                node,
                f"Unknown unix socket permission '{perm}'.",
                DiagnosticSeverity.Warning,
                "unknown-unix-permission",
            )
    if node.type and node.type.lower() not in _UNIX_TYPE_SET:
        _add(
            ctx.diags,
            ctx.uri,
            node,
            f"Unknown unix socket type '{node.type}'. Expected one of: "
            f"{', '.join(UNIX_TYPES)}.",
            DiagnosticSeverity.Warning,
            "unknown-unix-type",
        )


# ── Mqueue checks ────────────────────────────────────────────────────────────

_MQUEUE_PERM_SET = frozenset(MQUEUE_PERMISSIONS)
_MQUEUE_TYPE_SET = frozenset(MQUEUE_TYPES)


def _check_mqueue(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, MqueueRuleNode)
    for perm in node.permissions:
        p = perm.strip().lower()
        if p and p not in _MQUEUE_PERM_SET:
            _add(
                ctx.diags,
                ctx.uri,
                node,
                f"Unknown mqueue permission '{perm}'.",
                DiagnosticSeverity.Warning,
                "unknown-mqueue-permission",
            )
    type_ = node.type.lower() if node.type else None
    if type_ and type_ not in _MQUEUE_TYPE_SET:
        _add(
            ctx.diags,
            ctx.uri,
            node,
            f"Unknown mqueue type '{node.type}'. Expected 'posix' or 'sysv'.",
            DiagnosticSeverity.Warning,
            "unknown-mqueue-type",
        )

    # Name shape must agree with the type (man apparmor.d §"Message Queue rules").
    name = (node.name or "").strip()
    if name:
        looks_posix = name.startswith("/")
        looks_sysv = name.isdigit()
        if type_ == "posix" and not looks_posix:
            _add(
                ctx.diags,
                ctx.uri,
                node,
                f"POSIX mqueue name '{name}' must start with '/'.",
                DiagnosticSeverity.Error,
                "mqueue-posix-name-shape",
            )
        elif type_ == "sysv" and not looks_sysv:
            _add(
                ctx.diags,
                ctx.uri,
                node,
                f"SysV mqueue name '{name}' must be a positive integer.",
                DiagnosticSeverity.Error,
                "mqueue-sysv-name-shape",
            )


# ── io_uring checks ──────────────────────────────────────────────────────────

_IO_URING_PERM_SET = frozenset(IO_URING_PERMISSIONS)


def _check_io_uring(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, IoUringRuleNode)
    for perm in node.permissions:
        p = perm.strip().lower()
        if p and p not in _IO_URING_PERM_SET:
            _add(
                ctx.diags,
                ctx.uri,
                node,
                f"Unknown io_uring permission '{perm}'. Expected one of: "
                f"{', '.join(IO_URING_PERMISSIONS)}.",
                DiagnosticSeverity.Warning,
                "unknown-io-uring-permission",
            )


# ── Userns checks ────────────────────────────────────────────────────────────

_USERNS_PERM_SET = frozenset(USERNS_PERMISSIONS)
_RE_USERNS_PERMS = re.compile(r"^\s*(?:\(([^)]*)\)|(\S+))?\s*$")


def _check_userns(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, UsernsRuleNode)
    content = node.content.strip().rstrip(",")
    if not content:
        return
    m = _RE_USERNS_PERMS.match(content)
    if not m:
        return
    raw = (m.group(1) or m.group(2) or "").replace(",", " ")
    for perm in raw.split():
        if perm.lower() not in _USERNS_PERM_SET:
            _add(
                ctx.diags,
                ctx.uri,
                node,
                f"Unknown userns permission '{perm}'. Only 'create' is supported.",
                DiagnosticSeverity.Warning,
                "unknown-userns-permission",
            )


# ── Pivot root checks ────────────────────────────────────────────────────────


def _check_pivot_root(node: Node, ctx: DiagContext) -> None:
    """Both ``oldroot`` and the new root path must end with ``/`` since they
    are directories (man apparmor.d §"Pivot Root Rules")."""
    assert isinstance(node, PivotRootRuleNode)
    for label, val in (("oldroot", node.oldroot), ("new root", node.newroot)):
        if val is None:
            continue
        if val.endswith("/"):
            continue
        _add(
            ctx.diags,
            ctx.uri,
            node,
            f"pivot_root {label} '{val}' must end with '/' "
            "(paths refer to directories).",
            DiagnosticSeverity.Warning,
            "pivot-root-trailing-slash",
        )


# ── Block recursion ──────────────────────────────────────────────────────────

_BOOL_VAR_REF = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")


def _check_if_block(node: Node, ctx: DiagContext) -> None:
    """Validate variable references in the condition and recurse into the body.

    Both ``@{var}`` and ``${bool_var}`` references are checked against
    ``ctx.defined_vars`` so unknown identifiers in a conditional surface as
    diagnostics. The trailing ``else``/``else if`` branches are walked via
    the ``else_branch`` chain.
    """
    assert isinstance(node, IfBlockNode)
    branch: Optional[IfBlockNode] = node
    while branch is not None:
        if branch.condition:
            seen: set[str] = set()
            for ref in _VAR_REF.findall(branch.condition):
                if ref in seen or ref in ctx.defined_vars:
                    continue
                seen.add(ref)
                _add(
                    ctx.diags,
                    ctx.uri,
                    branch,
                    f"Variable '{ref}' is used but never defined.",
                    DiagnosticSeverity.Warning,
                    "undefined-variable",
                )
            for ref in _BOOL_VAR_REF.findall(branch.condition):
                if ref in seen or ref in ctx.defined_vars:
                    continue
                seen.add(ref)
                _add(
                    ctx.diags,
                    ctx.uri,
                    branch,
                    f"Boolean variable '{ref}' is used but never defined.",
                    DiagnosticSeverity.Warning,
                    "undefined-bool-variable",
                )
        for child in branch.children:
            _check_node(child, ctx)
        branch = branch.else_branch


def _check_qualifier_block(node: Node, ctx: DiagContext) -> None:
    """Recurse into a qualifier block's body so its rules get the usual checks."""
    assert isinstance(node, QualifierBlockNode)
    for child in node.children:
        _check_node(child, ctx)


# ── Alias checks ─────────────────────────────────────────────────────────────


def _check_alias(node: Node, ctx: DiagContext) -> None:
    assert isinstance(node, AliasNode)
    for label, val in (("source", node.original), ("target", node.replacement)):
        if not val:
            continue
        if val.startswith("/") or val.startswith("@") or val.startswith('"/'):
            continue
        _add(
            ctx.diags,
            ctx.uri,
            node,
            f"alias {label} path '{val}' must be absolute (start with '/').",
            DiagnosticSeverity.Warning,
            "alias-relative-path",
        )


# ── Dispatch table ────────────────────────────────────────────────────────────
# Map each AST node type to the ordered list of checks to run against it.
# Adding a new check is a one-line edit here plus its implementation above;
# the previous long isinstance chain in _check_node is now driven by data.

_VAR_REF_RULE_TYPES: tuple[type[Node], ...] = (
    ChangeHatRuleNode,
    ChangeProfileRuleNode,
    LinkRuleNode,
    AllRuleNode,
)

_CHECKS: dict[type[Node], tuple[_DiagCheck, ...]] = {
    ProfileNode: (_check_profile,),
    CapabilityNode: (
        _check_capability,
        _check_qualifier_conflict,
        _check_var_refs,
    ),
    NetworkNode: (
        _check_network,
        _check_network_semantics,
        _check_qualifier_conflict,
        _check_var_refs,
    ),
    SignalRuleNode: (
        _check_signal,
        _check_qualifier_conflict,
        _check_var_refs,
    ),
    PtraceRuleNode: (_check_ptrace, _check_qualifier_conflict, _check_var_refs),
    FileRuleNode: (
        _check_file_rule,
        _check_qualifier_conflict,
        _check_var_refs,
    ),
    DbusRuleNode: (_check_dbus, _check_qualifier_conflict, _check_var_refs),
    UnixRuleNode: (_check_unix, _check_qualifier_conflict, _check_var_refs),
    MountRuleNode: (
        _check_mount_options,
        _check_qualifier_conflict,
        _check_var_refs,
    ),
    UmountRuleNode: (
        _check_mount_options,
        _check_qualifier_conflict,
        _check_var_refs,
    ),
    RemountRuleNode: (
        _check_mount_options,
        _check_qualifier_conflict,
        _check_var_refs,
    ),
    MqueueRuleNode: (_check_mqueue, _check_qualifier_conflict, _check_var_refs),
    IoUringRuleNode: (
        _check_io_uring,
        _check_qualifier_conflict,
        _check_var_refs,
    ),
    UsernsRuleNode: (_check_userns, _check_qualifier_conflict, _check_var_refs),
    RlimitRuleNode: (_check_rlimit, _check_qualifier_conflict, _check_var_refs),
    PivotRootRuleNode: (
        _check_pivot_root,
        _check_qualifier_conflict,
        _check_var_refs,
    ),
    AliasNode: (_check_alias,),
    ABINode: (_check_abi,),
    IncludeNode: (_check_include,),
    IfBlockNode: (_check_if_block,),
    QualifierBlockNode: (_check_qualifier_block,),
    UnknownRuleNode: (_check_unknown_rule,),
    **{
        cls: (_check_qualifier_conflict, _check_var_refs) for cls in _VAR_REF_RULE_TYPES
    },
}
