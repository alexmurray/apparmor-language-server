"""
Diagnostics tests for the AppArmor LSP server.
Run with: pytest tests/test_diagnostics.py -v
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from apparmor_language_server.diagnostics import (
    _check_apparmor_parser,
    _find_apparmor_parser,
    _snap_parser_extra_args,
    get_diagnostics,
)
from apparmor_language_server.parser import parse_document

# ── Helpers ───────────────────────────────────────────────────────────────────

SIMPLE_PROFILE = """\
# AppArmor profile for myapp
profile myapp /usr/bin/myapp {
  include <abstractions/base>

  /etc/myapp.conf r,
  /var/log/myapp.log rw,
  file /usr/bin/myapp ix,
  file r /usr/lib/libmyapp.so*,
  owner file rw @{HOME}/.myapp/**,
  deny file r /dev/dri/{,**},
  capability net_bind_service,
  network inet stream,
}
"""


def _all_diags(src: str):
    doc, errors = parse_document("file:///test.aa", src)
    diags = get_diagnostics(doc, errors)
    return [d for sublist in diags.values() for d in sublist]


def _codes(src: str) -> list[int | str | None]:
    return [d.code for d in _all_diags(src)]


# ── Basic validity ────────────────────────────────────────────────────────────


class TestValidProfiles:
    def test_no_diags_on_valid_profile(self):
        doc, errors = parse_document("file:///test.aa", SIMPLE_PROFILE)
        diags = get_diagnostics(doc, errors)
        all_diags = [d for sublist in diags.values() for d in sublist]
        error_diags = [d for d in all_diags if d.severity and d.severity.value <= 1]
        assert len(error_diags) == 0

    def test_no_warning_with_known_network_qualifiers(self):
        src = "profile x {\n  audit network inet stream,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors)
        assert len(diags) == 0, f"Expected no diagnostics, got: {diags}"

    def test_no_warning_with_known_file_qualifiers(self):
        src = "profile x {\n  audit file r /foo,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors)
        assert len(diags) == 0, f"Expected no diagnostics, got: {diags}"


# ── Capability checks ─────────────────────────────────────────────────────────


class TestCapabilityDiagnostics:
    def test_unknown_capability_flagged(self):
        src = "profile x { capability bad_capability_xyz, }\n"
        assert "unknown-capability" in _codes(src)

    def test_duplicate_capability_warning(self):
        src = "profile x {\n  capability kill,\n  capability kill,\n}\n"
        assert "duplicate-capability" in _codes(src)

    def test_audit_deny_capability_no_diagnostic(self):
        src = "profile x {\n  audit deny capability mac_admin,\n}\n"
        codes = _codes(src)
        assert "unknown-keyword" not in codes
        assert "unknown-capability" not in codes

    def test_deny_capability_no_unknown_keyword(self):
        src = "profile x {\n  deny capability block_suspend,\n}\n"
        codes = _codes(src)
        assert "unknown-keyword" not in codes
        assert "unknown-capability" not in codes

    def test_allow_capability_no_diagnostic(self):
        src = "profile x {\n  allow capability,\n}\n"
        codes = _codes(src)
        assert "unknown-keyword" not in codes

    def test_conflicting_capability_warning(self):
        src = "profile x {\n  capability kill,\n  deny capability kill,\n}\n"
        assert "conflicting-capability" in _codes(src)


# ── Network checks ────────────────────────────────────────────────────────────


class TestNetworkDiagnostics:
    def test_unknown_network_family(self):
        src = "profile x {\n  network notafamily,\n}\n"
        assert "unknown-network-qualifier" in _codes(src)

    def test_allow_network_no_diagnostic(self):
        src = "profile x {\n  allow network,\n}\n"
        codes = _codes(src)
        assert "unknown-keyword" not in codes
        assert "unknown-network-qualifier" not in codes


# ── File rule checks ──────────────────────────────────────────────────────────


class TestFileRuleDiagnostics:
    def test_dangerous_exec_warning(self):
        src = "profile x {\n  /usr/bin/sudo ux,\n}\n"
        assert "dangerous-exec" in _codes(src)

    def test_dangerous_exec_no_false_positive_on_rwx(self):
        """'rwx' has no exec transition mode; only the bare-x diagnostic should
        fire — historic substring match incorrectly flagged it as dangerous."""
        src = "profile x {\n  deny /usr/bin/foo rwx,\n}\n"
        codes = _codes(src)
        assert "dangerous-exec" not in codes

    def test_prefer_append_suggestion(self):
        src = "profile x {\n  /var/log/myapp.log w,\n}\n"
        assert "prefer-append" in _codes(src)


# ── Profile checks ────────────────────────────────────────────────────────────


class TestProfileDiagnostics:
    def test_empty_profile_warning(self):
        src = "profile empty { }\n"
        assert "empty-profile" in _codes(src)

    def test_unknown_flag(self):
        src = "profile x flags=(notaflag) {\n  capability kill,\n}\n"
        assert "unknown-flag" in _codes(src)


# ── Signal rule diagnostics ───────────────────────────────────────────────────


class TestSignalDiagnostics:
    def test_deny_signal_no_unknown_keyword(self):
        src = "profile x {\n  deny signal (send) set=(term) peer=unconfined,\n}\n"
        codes = _codes(src)
        assert "unknown-keyword" not in codes

    def test_allow_signal_no_diagnostic(self):
        src = "profile x {\n  allow signal,\n}\n"
        codes = _codes(src)
        assert "unknown-keyword" not in codes

    def test_unknown_signal_permission(self):
        src = "profile x {\n  signal (notaperm),\n}\n"
        assert "unknown-signal-permission" in _codes(src)

    def test_unknown_signal_name(self):
        src = "profile x {\n  signal set=(notasignal),\n}\n"
        assert "unknown-signal-name" in _codes(src)


# ── Variable checks ───────────────────────────────────────────────────────────


class TestVariableDiagnostics:
    def test_undefined_variable_in_file_rule(self):
        src = "profile x {\n  deny file @{UNDEFINED}/** r,\n}\n"
        assert "undefined-variable" in _codes(src)

    def test_defined_variable_no_diagnostic(self):
        src = "@{MYVAR} = /usr/bin\nprofile x {\n  deny file @{MYVAR}/** r,\n}\n"
        codes = _codes(src)
        assert "undefined-variable" not in codes

    def test_undefined_variable_in_exec_target(self):
        """Variables in the file-rule exec target should be checked too."""
        src = "profile x {\n  /usr/bin/foo Px -> @{UNDEFINED_PEER},\n}\n"
        assert "undefined-variable" in _codes(src)

    def test_undefined_variable_in_signal_peer(self):
        src = "profile x {\n  signal (send) peer=@{UNDEFINED_PEER},\n}\n"
        assert "undefined-variable" in _codes(src)

    def test_undefined_variable_in_network_rule(self):
        src = "profile x {\n  network @{UNDEFINED} stream,\n}\n"
        assert "undefined-variable" in _codes(src)

    def test_variable_in_trailing_comment_not_flagged(self):
        """A @{var} reference inside a trailing comment is documentation,
        not a real variable use."""
        src = "profile x {\n  /etc/foo r,  # use @{HOME} here\n}\n"
        codes = _codes(src)
        assert "undefined-variable" not in codes

    def test_variable_only_reported_once_per_rule(self):
        """Even if @{X} appears multiple times in the same rule, only one
        diagnostic should be emitted."""
        from apparmor_language_server.diagnostics import get_diagnostics
        from apparmor_language_server.parser import parse_document

        src = "profile x {\n  @{UNDEF}/a r, @{UNDEF}/b w,\n}\n"
        doc, errs = parse_document("file:///t.aa", src)
        diags = get_diagnostics(doc, errs)
        per_rule = [
            d
            for d in diags.get("file:///t.aa", [])
            if d.code == "undefined-variable"
        ]
        # Two file rules → at most two diagnostics, not four.
        assert len(per_rule) <= 2


# ── Include checks ────────────────────────────────────────────────────────────


class TestIncludeDiagnostics:
    def test_conditional_include_no_diagnostic(self):
        src = "profile x {\n  include if exists <local/nonexistent>\n}\n"
        codes = _codes(src)
        assert "missing-include" not in codes

    def test_non_conditional_missing_include_flagged(self):
        src = "include <totally/nonexistent>\nprofile x { capability kill, }\n"
        codes = _codes(src)
        assert "missing-include" in codes


# ── Network access permission / protocol false positives ──────────────────────


class TestNetworkAccessPermissions:
    def test_network_access_perms_no_false_positive(self):
        src = "profile x {\n  network (send receive) inet,\n}\n"
        codes = _codes(src)
        assert "unknown-network-qualifier" not in codes

    def test_network_protocol_no_false_positive(self):
        src = "profile x {\n  network inet tcp,\n}\n"
        codes = _codes(src)
        assert "unknown-network-qualifier" not in codes


# ── Signal rtmin+N ────────────────────────────────────────────────────────────


class TestSignalRtmin:
    def test_rtmin_plus_n_accepted(self):
        src = "profile x {\n  signal set=(rtmin+5),\n}\n"
        codes = _codes(src)
        assert "unknown-signal-name" not in codes

    def test_signal_read_write_accepted(self):
        src = "profile x {\n  signal (read write) set=(term),\n}\n"
        codes = _codes(src)
        assert "unknown-signal-permission" not in codes


# ── Ptrace permission checks ──────────────────────────────────────────────────


class TestPtraceDiagnostics:
    def test_ptrace_invalid_perm_flagged(self):
        src = "profile x {\n  ptrace (notaperm),\n}\n"
        assert "unknown-ptrace-permission" in _codes(src)

    def test_ptrace_valid_perms_no_diagnostic(self):
        src = "profile x {\n  ptrace (read trace),\n}\n"
        codes = _codes(src)
        assert "unknown-ptrace-permission" not in codes

    def test_ptrace_shorthand_r_accepted(self):
        src = "profile x {\n  ptrace (r),\n}\n"
        codes = _codes(src)
        assert "unknown-ptrace-permission" not in codes

    def test_ptrace_shorthand_rw_accepted(self):
        src = "profile x {\n  ptrace (rw),\n}\n"
        codes = _codes(src)
        assert "unknown-ptrace-permission" not in codes


# ── Profile flag checks ───────────────────────────────────────────────────────


class TestNewProfileFlags:
    def test_default_allow_flag_valid(self):
        src = "profile x flags=(default_allow) {\n  capability kill,\n}\n"
        codes = _codes(src)
        assert "unknown-flag" not in codes

    def test_audit_flag_valid(self):
        src = "profile x flags=(audit) {\n  capability kill,\n}\n"
        codes = _codes(src)
        assert "unknown-flag" not in codes


# ── New rule type diagnostic checks ──────────────────────────────────────────


class TestNewRuleDiagnostics:
    def test_link_rule_no_unknown_keyword(self):
        src = "profile x {\n  link /foo -> /bar,\n}\n"
        codes = _codes(src)
        assert "unknown-keyword" not in codes

    def test_all_rule_no_unknown_keyword(self):
        src = "profile x {\n  all,\n}\n"
        codes = _codes(src)
        assert "unknown-keyword" not in codes

    def test_pux_dangerous_but_not_unknown(self):
        src = "profile x {\n  /usr/bin/foo PUx,\n}\n"
        codes = _codes(src)
        # PUx is dangerous - should get dangerous-exec warning
        assert "dangerous-exec" in codes
        # but should not be unknown
        assert "unknown-keyword" not in codes

    def test_cux_dangerous_but_not_unknown(self):
        src = "profile x {\n  /usr/bin/foo CUx,\n}\n"
        codes = _codes(src)
        assert "dangerous-exec" in codes
        assert "unknown-keyword" not in codes


# ── File permission consistency checks ───────────────────────────────────────


class TestFilePermissionConsistency:
    def test_write_and_append_conflict(self):
        src = "profile x {\n  /var/log/foo wa,\n}\n"
        assert "perm-conflict-write-append" in _codes(src)

    def test_write_and_append_conflict_reversed(self):
        src = "profile x {\n  /var/log/foo aw,\n}\n"
        assert "perm-conflict-write-append" in _codes(src)

    def test_write_without_append_no_conflict(self):
        src = "profile x {\n  /var/log/foo rw,\n}\n"
        assert "perm-conflict-write-append" not in _codes(src)

    def test_append_without_write_no_conflict(self):
        src = "profile x {\n  /var/log/foo ra,\n}\n"
        assert "perm-conflict-write-append" not in _codes(src)

    def test_multiple_exec_modes_flagged(self):
        src = "profile x {\n  /usr/bin/foo pixcx,\n}\n"
        assert "multiple-exec-modes" in _codes(src)

    def test_two_exec_modes_flagged(self):
        src = "profile x {\n  /usr/bin/foo pxix,\n}\n"
        assert "multiple-exec-modes" in _codes(src)

    def test_single_exec_mode_no_error(self):
        src = "profile x {\n  /usr/bin/foo px,\n}\n"
        assert "multiple-exec-modes" not in _codes(src)

    def test_exec_target_without_transition_flagged(self):
        src = "profile x {\n  r /usr/bin/foo -> other_profile,\n}\n"
        assert "exec-target-without-transition" in _codes(src)

    def test_exec_target_with_transition_no_error(self):
        src = "profile x {\n  px /usr/bin/foo -> other_profile,\n}\n"
        assert "exec-target-without-transition" not in _codes(src)

    def test_exec_target_with_ix_no_error(self):
        src = "profile x {\n  ix /usr/bin/foo -> other_profile,\n}\n"
        assert "exec-target-without-transition" not in _codes(src)

    def test_deny_with_exec_transition_flagged(self):
        src = "profile x {\n  deny px /usr/bin/foo,\n}\n"
        assert "deny-with-exec-transition" in _codes(src)

    def test_deny_with_ix_flagged(self):
        src = "profile x {\n  deny ix /usr/bin/foo,\n}\n"
        assert "deny-with-exec-transition" in _codes(src)

    def test_deny_x_no_error(self):
        # bare 'x' with deny is the canonical way to deny execute
        src = "profile x {\n  deny x /usr/bin/foo,\n}\n"
        assert "deny-with-exec-transition" not in _codes(src)

    def test_deny_r_no_error(self):
        src = "profile x {\n  deny r /etc/shadow,\n}\n"
        assert "deny-with-exec-transition" not in _codes(src)

    def test_bare_x_without_deny_flagged(self):
        src = "profile x {\n  /usr/bin/foo x,\n}\n"
        assert "bare-x-without-deny" in _codes(src)

    def test_bare_x_with_r_without_deny_flagged(self):
        src = "profile x {\n  /usr/bin/foo rx,\n}\n"
        assert "bare-x-without-deny" in _codes(src)

    def test_deny_x_not_flagged_as_bare_x(self):
        src = "profile x {\n  deny x /usr/bin/foo,\n}\n"
        assert "bare-x-without-deny" not in _codes(src)

    def test_ix_not_flagged_as_bare_x(self):
        src = "profile x {\n  /usr/bin/foo ix,\n}\n"
        assert "bare-x-without-deny" not in _codes(src)

    def test_px_not_flagged_as_bare_x(self):
        src = "profile x {\n  /usr/bin/foo px,\n}\n"
        assert "bare-x-without-deny" not in _codes(src)

    def test_rix_not_flagged_as_bare_x(self):
        src = "profile x {\n  /usr/bin/foo rix,\n}\n"
        assert "bare-x-without-deny" not in _codes(src)


# ── apparmor_parser integration ───────────────────────────────────────────────

_FAKE_PATH = Path("/fake/profile.aa")
_FAKE_URI = "file:///fake/profile.aa"


def _parser_result(stderr: str, returncode: int = 1) -> MagicMock:
    r = MagicMock()
    r.returncode = returncode
    r.stderr = stderr
    return r


class TestFindApparmorParser:
    def test_empty_configured_path_falls_back_to_which(self):
        with patch("shutil.which", return_value="/usr/sbin/apparmor_parser"):
            assert _find_apparmor_parser("") == "/usr/sbin/apparmor_parser"

    def test_configured_path_returned_when_found(self, tmp_path):
        exe = tmp_path / "apparmor_parser"
        exe.touch()
        assert _find_apparmor_parser(str(exe)) == str(exe)

    def test_configured_path_missing_returns_none(self):
        with patch("shutil.which", return_value=None):
            assert _find_apparmor_parser("/nonexistent/apparmor_parser") is None

    def test_no_binary_anywhere_returns_none(self):
        with patch("shutil.which", return_value=None):
            assert _find_apparmor_parser("") is None


class TestCheckApparmorParser:
    def test_binary_not_found_returns_empty(self):
        with patch(
            "apparmor_language_server.diagnostics._find_apparmor_parser",
            return_value=None,
        ):
            result = _check_apparmor_parser(_FAKE_PATH, _FAKE_URI, None)
        assert result == {}

    def test_returncode_zero_returns_empty(self):
        with patch(
            "apparmor_language_server.diagnostics._find_apparmor_parser",
            return_value="/usr/sbin/apparmor_parser",
        ), patch("subprocess.run", return_value=_parser_result("", returncode=0)):
            result = _check_apparmor_parser(_FAKE_PATH, _FAKE_URI, None)
        assert result == {}

    def test_timeout_returns_empty(self):
        with patch(
            "apparmor_language_server.diagnostics._find_apparmor_parser",
            return_value="/usr/sbin/apparmor_parser",
        ), patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="", timeout=10)):
            result = _check_apparmor_parser(_FAKE_PATH, _FAKE_URI, None)
        assert result == {}

    def test_oserror_returns_empty(self):
        with patch(
            "apparmor_language_server.diagnostics._find_apparmor_parser",
            return_value="/usr/sbin/apparmor_parser",
        ), patch("subprocess.run", side_effect=OSError("permission denied")):
            result = _check_apparmor_parser(_FAKE_PATH, _FAKE_URI, None)
        assert result == {}

    def test_error_with_location_parsed(self):
        stderr = (
            "AppArmor parser error for /fake/profile.aa in profile "
            "/fake/profile.aa at line 3: syntax error, unexpected token\n"
        )
        with patch(
            "apparmor_language_server.diagnostics._find_apparmor_parser",
            return_value="/usr/sbin/apparmor_parser",
        ), patch("subprocess.run", return_value=_parser_result(stderr)), patch.object(
            Path, "exists", return_value=True
        ), patch.object(
            Path, "is_absolute", return_value=True
        ):
            result = _check_apparmor_parser(_FAKE_PATH, _FAKE_URI, None)

        assert _FAKE_URI in result
        diags = result[_FAKE_URI]
        assert len(diags) == 1
        assert diags[0].code == "apparmor-parser-error"
        assert diags[0].source == "apparmor_parser"
        assert diags[0].range.start.line == 2  # 0-based: line 3 → index 2
        assert "syntax error" in diags[0].message

    def test_error_line_is_zero_based(self):
        stderr = (
            "AppArmor parser error for /fake/profile.aa in profile "
            "/fake/profile.aa at line 1: some error\n"
        )
        with patch(
            "apparmor_language_server.diagnostics._find_apparmor_parser",
            return_value="/usr/sbin/apparmor_parser",
        ), patch("subprocess.run", return_value=_parser_result(stderr)), patch.object(
            Path, "exists", return_value=True
        ), patch.object(
            Path, "is_absolute", return_value=True
        ):
            result = _check_apparmor_parser(_FAKE_PATH, _FAKE_URI, None)

        diags = result.get(_FAKE_URI, [])
        assert diags[0].range.start.line == 0

    def test_unresolvable_source_file_falls_back_to_doc_uri(self):
        stderr = (
            "AppArmor parser error for /fake/profile.aa in profile "
            "/nonexistent/abstraction at line 5: bad rule\n"
        )
        with patch(
            "apparmor_language_server.diagnostics._find_apparmor_parser",
            return_value="/usr/sbin/apparmor_parser",
        ), patch("subprocess.run", return_value=_parser_result(stderr)), patch.object(
            Path, "exists", return_value=False
        ):
            result = _check_apparmor_parser(_FAKE_PATH, _FAKE_URI, None)

        # Should attach to the top-level document URI, not the missing path
        assert _FAKE_URI in result
        assert result[_FAKE_URI][0].range.start.line == 0

    def test_unrecognised_lines_do_not_raise(self):
        stderr = "some random garbage line\nanother line\n"
        with patch(
            "apparmor_language_server.diagnostics._find_apparmor_parser",
            return_value="/usr/sbin/apparmor_parser",
        ), patch("subprocess.run", return_value=_parser_result(stderr)):
            result = _check_apparmor_parser(_FAKE_PATH, _FAKE_URI, None)
        assert result == {}

    def test_get_diagnostics_skips_parser_when_no_path(self):
        src = "profile x {\n  capability kill,\n}\n"
        doc, errors = parse_document(_FAKE_URI, src)
        with patch("subprocess.run") as mock_run:
            get_diagnostics(doc, errors, document_path=None)
        mock_run.assert_not_called()

    def test_get_diagnostics_calls_parser_when_path_exists(self, tmp_path):
        profile = tmp_path / "test.aa"
        profile.write_text("profile x {\n  capability kill,\n}\n")
        doc, errors = parse_document(profile.as_uri(), profile.read_text())
        with patch("subprocess.run", return_value=_parser_result("", returncode=0)) as mock_run, patch(
            "apparmor_language_server.diagnostics._find_apparmor_parser",
            return_value="/usr/sbin/apparmor_parser",
        ):
            get_diagnostics(doc, errors, document_path=profile)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[-1] == str(profile)
        assert "-Q" in args
        assert "-K" in args


class TestSnapParserExtraArgs:
    def test_no_snap_env_returns_empty(self, monkeypatch):
        monkeypatch.delenv("SNAP", raising=False)
        assert _snap_parser_extra_args() == []

    def test_snap_env_returns_base_and_config_args(self, monkeypatch):
        monkeypatch.setenv("SNAP", "/snap/apparmor-language-server/current")
        args = _snap_parser_extra_args()
        assert "--base" in args
        assert "--config-file" in args
        base_idx = args.index("--base")
        assert args[base_idx + 1] == "/var/lib/snapd/hostfs/etc/apparmor.d"
        cfg_idx = args.index("--config-file")
        assert args[cfg_idx + 1] == "/var/lib/snapd/hostfs/etc/apparmor/parser.conf"

    def test_snap_args_passed_to_subprocess(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SNAP", "/snap/apparmor-language-server/current")
        profile = tmp_path / "test.aa"
        profile.write_text("profile x {\n  capability kill,\n}\n")
        with (
            patch("subprocess.run", return_value=_parser_result("", returncode=0)) as mock_run,
            patch(
                "apparmor_language_server.diagnostics._find_apparmor_parser",
                return_value="/usr/sbin/apparmor_parser",
            ),
        ):
            _check_apparmor_parser(profile, profile.as_uri(), None)
        args = mock_run.call_args[0][0]
        assert "--base" in args
        assert "--config-file" in args
        assert args[-1] == str(profile)

    def test_no_snap_args_passed_to_subprocess_without_snap(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SNAP", raising=False)
        profile = tmp_path / "test.aa"
        profile.write_text("profile x {\n  capability kill,\n}\n")
        with (
            patch("subprocess.run", return_value=_parser_result("", returncode=0)) as mock_run,
            patch(
                "apparmor_language_server.diagnostics._find_apparmor_parser",
                return_value="/usr/sbin/apparmor_parser",
            ),
        ):
            _check_apparmor_parser(profile, profile.as_uri(), None)
        args = mock_run.call_args[0][0]
        assert "--base" not in args
        assert "--config-file" not in args
