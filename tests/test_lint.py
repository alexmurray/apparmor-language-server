"""
Tests for the standalone ``apparmor-lint`` command.
Run with: pytest tests/test_lint.py -v
"""

from __future__ import annotations

import io
import json

from apparmor_language_server.lint import (
    LintCounts,
    _format_pretty,
    _uri_to_display,
    lint_file,
    lint_text,
    main,
)

CLEAN_PROFILE = """\
profile myapp /usr/bin/myapp flags=(complain) {
  capability net_bind_service,
  /etc/myapp.conf r,
  network inet stream,
}
"""

DIRTY_PROFILE = """\
profile myapp /usr/bin/myapp flags=(complain,kill) {
  capability bad_cap_xyz,
  /etc/myapp.conf rwa,
  network netlink stream,
}
"""


# ── Library API ──────────────────────────────────────────────────────────────


class TestLintTextAPI:
    def test_clean_profile_has_no_errors(self):
        diags = lint_text(CLEAN_PROFILE)
        flat = [d for ds in diags.values() for d in ds]
        errors = [d for d in flat if d.severity and d.severity.value == 1]
        assert errors == []

    def test_dirty_profile_emits_expected_codes(self):
        diags = lint_text(DIRTY_PROFILE)
        codes = {d.code for ds in diags.values() for d in ds}
        assert "conflicting-profile-modes" in codes
        assert "unknown-capability" in codes
        assert "perm-conflict-write-append" in codes
        assert "netlink-type-restricted" in codes


class TestLintFileAPI:
    def test_reads_file_contents(self, tmp_path):
        p = tmp_path / "foo.aa"
        p.write_text(DIRTY_PROFILE)
        diags = lint_file(p, run_apparmor_parser=False)
        codes = {d.code for ds in diags.values() for d in ds}
        assert "unknown-capability" in codes

    def test_apparmor_parser_skipped_when_disabled(self, tmp_path, monkeypatch):
        """``run_apparmor_parser=False`` must not invoke the external binary,
        even when one is on PATH (saves time and avoids privilege issues)."""
        called = []

        def fake_run(*args, **kwargs):
            called.append(args)
            raise AssertionError("apparmor_parser must not be invoked")

        monkeypatch.setattr("subprocess.run", fake_run)
        p = tmp_path / "ok.aa"
        p.write_text(CLEAN_PROFILE)
        lint_file(p, run_apparmor_parser=False)
        assert called == []


# ── Output helpers ───────────────────────────────────────────────────────────


class TestFormatHelpers:
    def test_uri_to_display_decodes_file_uri(self):
        assert _uri_to_display("file:///tmp/foo%20bar.aa") == "/tmp/foo bar.aa"

    def test_uri_to_display_passes_through_other_schemes(self):
        assert _uri_to_display("memory://x") == "memory://x"

    def test_pretty_format_is_gcc_style(self):
        diags = lint_text(DIRTY_PROFILE, uri="file:///tmp/x.aa")
        # Pick any one diagnostic and format it.
        any_diag = next(iter(diags.values()))[0]
        line = _format_pretty("file:///tmp/x.aa", any_diag)
        assert line.startswith("/tmp/x.aa:")
        # path:line:col: severity: message ...
        assert ": error:" in line or ": warning:" in line

    def test_lint_counts_total(self):
        c = LintCounts(errors=2, warnings=1, info=0, hints=3)
        assert c.total == 6


# ── CLI entry point ──────────────────────────────────────────────────────────


def _capture(monkeypatch) -> tuple[io.StringIO, io.StringIO]:
    out = io.StringIO()
    err = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    return out, err


class TestCLI:
    def test_clean_profile_exits_zero(self, tmp_path, monkeypatch):
        p = tmp_path / "ok.aa"
        p.write_text(CLEAN_PROFILE)
        out, _ = _capture(monkeypatch)
        rc = main(["--no-parser", str(p)])
        assert rc == 0
        assert out.getvalue() == ""

    def test_dirty_profile_exits_one_and_prints_diagnostics(
        self, tmp_path, monkeypatch
    ):
        p = tmp_path / "bad.aa"
        p.write_text(DIRTY_PROFILE)
        out, _ = _capture(monkeypatch)
        rc = main(["--no-parser", str(p)])
        assert rc == 1
        text = out.getvalue()
        # Diagnostic lines are GCC-style; the path comes first.
        assert str(p) in text
        assert "unknown-capability" in text
        assert "conflicting-profile-modes" in text

    def test_missing_file_exits_two(self, tmp_path, monkeypatch):
        out, err = _capture(monkeypatch)
        rc = main(["--no-parser", str(tmp_path / "does-not-exist.aa")])
        assert rc == 2
        assert "no such file" in err.getvalue()

    def test_directory_argument_exits_two(self, tmp_path, monkeypatch):
        out, err = _capture(monkeypatch)
        rc = main(["--no-parser", str(tmp_path)])
        assert rc == 2
        assert "is a directory" in err.getvalue()

    def test_quiet_suppresses_warnings(self, tmp_path, monkeypatch):
        # Use a profile that produces a warning but no errors.
        src = "profile x {\n  pivot_root /mnt/root,\n}\n"
        p = tmp_path / "warn.aa"
        p.write_text(src)
        out, _ = _capture(monkeypatch)
        rc = main(["--no-parser", "--quiet", str(p)])
        assert rc == 0
        assert "pivot-root-trailing-slash" not in out.getvalue()

    def test_quiet_keeps_errors(self, tmp_path, monkeypatch):
        p = tmp_path / "bad.aa"
        p.write_text(DIRTY_PROFILE)
        out, _ = _capture(monkeypatch)
        rc = main(["--no-parser", "--quiet", str(p)])
        assert rc == 1
        assert "unknown-capability" in out.getvalue()

    def test_json_output_is_valid_array(self, tmp_path, monkeypatch):
        p = tmp_path / "bad.aa"
        p.write_text(DIRTY_PROFILE)
        out, _ = _capture(monkeypatch)
        rc = main(["--no-parser", "--format", "json", str(p)])
        assert rc == 1
        records = json.loads(out.getvalue())
        assert isinstance(records, list)
        assert any(r["code"] == "unknown-capability" for r in records)
        # Required fields
        sample = records[0]
        for key in ("path", "uri", "severity", "message", "line", "column"):
            assert key in sample

    def test_stdin_input_is_supported(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO(DIRTY_PROFILE))
        out, _ = _capture(monkeypatch)
        rc = main(["--no-parser", "-"])
        assert rc == 1
        assert "<stdin>" in out.getvalue()
        assert "unknown-capability" in out.getvalue()

    def test_multiple_files_aggregated(self, tmp_path, monkeypatch):
        a = tmp_path / "a.aa"
        b = tmp_path / "b.aa"
        a.write_text(CLEAN_PROFILE)
        b.write_text(DIRTY_PROFILE)
        out, _ = _capture(monkeypatch)
        rc = main(["--no-parser", str(a), str(b)])
        assert rc == 1
        text = out.getvalue()
        # Only the dirty file should produce output.
        assert str(b) in text
        # Verify lines are sorted by URI (a < b alphabetically).
        # All output relates to b since a is clean.

    def test_include_search_path_resolves_relative_includes(
        self, tmp_path, monkeypatch
    ):
        absdir = tmp_path / "abstractions"
        absdir.mkdir()
        (absdir / "base").write_text("# empty\n")
        p = tmp_path / "main.aa"
        p.write_text("include <abstractions/base>\nprofile x { /foo r, }\n")
        out, _ = _capture(monkeypatch)
        # Without -I the include resolves to nothing on the test box; supply
        # tmp_path so the resolver finds the abstraction.
        rc = main(
            ["--no-parser", "-I", str(tmp_path), str(p)],
        )
        # Must not emit a missing-include diagnostic.
        assert "missing-include" not in out.getvalue()
        assert rc == 0
