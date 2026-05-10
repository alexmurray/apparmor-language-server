"""
Standalone command-line linter for AppArmor profiles.

Runs the same parser and diagnostic checks the language server uses, prints
the resulting diagnostics in a GCC-compatible (or JSON) format, and exits
non-zero when errors are found. Included files are diagnosed under their
own paths so editors can jump to the right location.

Examples:

    apparmor-lint /etc/apparmor.d/usr.bin.foo
    apparmor-lint --no-parser profile.aa
    cat profile.aa | apparmor-lint -
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence
from urllib.parse import unquote, urlparse

from lsprotocol.types import Diagnostic, DiagnosticSeverity

from .diagnostics import get_diagnostics
from .parser import parse_document

# ── Public API ────────────────────────────────────────────────────────────────


def lint_text(
    text: str,
    *,
    uri: str = "file:///<stdin>",
    document_path: Optional[Path] = None,
    search_dirs: Optional[list[Path]] = None,
    apparmor_parser_path: Optional[str] = None,
) -> dict[str, list[Diagnostic]]:
    """Parse and diagnose AppArmor profile *text* in memory.

    Returns the diagnostics dict keyed by URI (the same shape the LSP server
    consumes). When *document_path* is omitted the external ``apparmor_parser``
    cross-check is skipped — useful when the source is not on disk yet.
    """
    doc, errors = parse_document(uri, text)
    return get_diagnostics(
        doc,
        errors,
        search_dirs=search_dirs,
        document_path=document_path,
        apparmor_parser_path=apparmor_parser_path,
    )


def lint_file(
    path: Path,
    *,
    run_apparmor_parser: bool = True,
    search_dirs: Optional[list[Path]] = None,
    apparmor_parser_path: Optional[str] = None,
) -> dict[str, list[Diagnostic]]:
    """Read and lint a profile file. Set ``run_apparmor_parser=False`` to
    disable the external ``apparmor_parser`` cross-check (fast path / no
    sudo / sandboxed)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return lint_text(
        text,
        uri=path.resolve().as_uri(),
        document_path=path if run_apparmor_parser else None,
        search_dirs=search_dirs,
        apparmor_parser_path=apparmor_parser_path,
    )


# ── Output formatting ─────────────────────────────────────────────────────────

_SEVERITY_LABEL: dict[int, str] = {
    DiagnosticSeverity.Error.value: "error",
    DiagnosticSeverity.Warning.value: "warning",
    DiagnosticSeverity.Information.value: "info",
    DiagnosticSeverity.Hint.value: "hint",
}


@dataclass
class LintCounts:
    errors: int = 0
    warnings: int = 0
    info: int = 0
    hints: int = 0

    @property
    def total(self) -> int:
        return self.errors + self.warnings + self.info + self.hints


def _uri_to_display(uri: str) -> str:
    """Convert a ``file://`` URI to a path for display, falling back to the
    raw URI when it doesn't look like a local file."""
    parsed = urlparse(uri)
    if parsed.scheme == "file":
        return unquote(parsed.path) or uri
    return uri


def _severity_label(diag: Diagnostic) -> str:
    sev = diag.severity.value if diag.severity is not None else 0
    return _SEVERITY_LABEL.get(sev, "note")


def _bump(counts: LintCounts, diag: Diagnostic) -> None:
    sev = diag.severity.value if diag.severity is not None else 0
    if sev == DiagnosticSeverity.Error.value:
        counts.errors += 1
    elif sev == DiagnosticSeverity.Warning.value:
        counts.warnings += 1
    elif sev == DiagnosticSeverity.Information.value:
        counts.info += 1
    elif sev == DiagnosticSeverity.Hint.value:
        counts.hints += 1


def _format_pretty(uri: str, diag: Diagnostic) -> str:
    """Emit a GCC-style ``path:line:col: severity: message [code]`` line.

    Line/column numbers are reported 1-based to match every other compiler.
    """
    line = diag.range.start.line + 1
    col = diag.range.start.character + 1
    sev = _severity_label(diag)
    code = f" [{diag.code}]" if diag.code else ""
    src = f" ({diag.source})" if diag.source else ""
    return f"{_uri_to_display(uri)}:{line}:{col}: {sev}: {diag.message}{code}{src}"


def _diag_to_json(uri: str, diag: Diagnostic) -> dict:
    return {
        "path": _uri_to_display(uri),
        "uri": uri,
        "severity": _severity_label(diag),
        "message": diag.message,
        "code": diag.code,
        "source": diag.source,
        "line": diag.range.start.line + 1,
        "column": diag.range.start.character + 1,
        "end_line": diag.range.end.line + 1,
        "end_column": diag.range.end.character + 1,
    }


# ── CLI ──────────────────────────────────────────────────────────────────────


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apparmor-lint",
        description=(
            "Lint AppArmor profile files. Runs the same parser and diagnostic "
            "checks as the language server."
        ),
    )
    p.add_argument(
        "paths",
        nargs="+",
        help="profile files to lint, or '-' to read from stdin",
    )
    p.add_argument(
        "--no-parser",
        dest="run_parser",
        action="store_false",
        help="skip the apparmor_parser cross-check (parser+lint only)",
    )
    p.add_argument(
        "--apparmor-parser",
        dest="apparmor_parser_path",
        default=None,
        help="explicit path to apparmor_parser (default: $PATH lookup)",
    )
    p.add_argument(
        "-I",
        "--include-path",
        dest="include_paths",
        action="append",
        default=[],
        metavar="DIR",
        help="extra directory to search when resolving includes "
        "(may be given multiple times)",
    )
    p.add_argument(
        "--format",
        choices=("pretty", "json"),
        default="pretty",
        help="output format (default: pretty)",
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="only show errors (suppress warnings, info, and hints)",
    )
    return p


def _filter(diags: list[Diagnostic], quiet: bool) -> list[Diagnostic]:
    if not quiet:
        return diags
    return [
        d
        for d in diags
        if d.severity is not None and d.severity.value == DiagnosticSeverity.Error.value
    ]


def _collect_for_path(
    path_arg: str,
    *,
    run_parser: bool,
    apparmor_parser_path: Optional[str],
    search_dirs: Optional[list[Path]],
) -> tuple[dict[str, list[Diagnostic]], Optional[str]]:
    """Read and lint a single CLI path argument.

    Returns ``(diagnostics_by_uri, error_message)``. ``error_message`` is
    populated when the file could not be read; ``diagnostics_by_uri`` is
    empty in that case.
    """
    if path_arg == "-":
        text = sys.stdin.read()
        return (
            lint_text(
                text,
                uri="file:///<stdin>",
                document_path=None,
                search_dirs=search_dirs,
            ),
            None,
        )
    path = Path(path_arg)
    if not path.exists():
        return {}, f"apparmor-lint: {path_arg}: no such file or directory"
    if path.is_dir():
        return {}, f"apparmor-lint: {path_arg}: is a directory"
    try:
        diags = lint_file(
            path,
            run_apparmor_parser=run_parser,
            search_dirs=search_dirs,
            apparmor_parser_path=apparmor_parser_path,
        )
    except OSError as exc:
        return {}, f"apparmor-lint: {path_arg}: {exc}"
    return diags, None


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point for the ``apparmor-lint`` console script.

    Exit code:
      * 0 — no errors (warnings/info/hints permitted)
      * 1 — at least one error-severity diagnostic was emitted
      * 2 — the CLI itself could not run (file missing, bad arg, etc.)
    """
    args = _build_argparser().parse_args(argv)
    search_dirs = [Path(p) for p in args.include_paths] or None

    # Aggregate diagnostics across all input paths so JSON output is a
    # single document and pretty output groups by file.
    aggregated: dict[str, list[Diagnostic]] = {}
    cli_errors: list[str] = []
    for path_arg in args.paths:
        per_path, err = _collect_for_path(
            path_arg,
            run_parser=args.run_parser,
            apparmor_parser_path=args.apparmor_parser_path,
            search_dirs=search_dirs,
        )
        if err is not None:
            cli_errors.append(err)
            continue
        for uri, diags in per_path.items():
            aggregated.setdefault(uri, []).extend(diags)

    counts = LintCounts()
    if args.format == "json":
        records: list[dict] = []
        for uri in sorted(aggregated):
            for diag in _filter(aggregated[uri], args.quiet):
                _bump(counts, diag)
                records.append(_diag_to_json(uri, diag))
        json.dump(records, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for uri in sorted(aggregated):
            for diag in _filter(aggregated[uri], args.quiet):
                _bump(counts, diag)
                print(_format_pretty(uri, diag))

    for msg in cli_errors:
        print(msg, file=sys.stderr)

    if cli_errors:
        return 2
    return 1 if counts.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
