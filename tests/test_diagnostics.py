"""
Diagnostics tests for the AppArmor LSP server.
Run with: pytest tests/test_diagnostics.py -v
"""

from __future__ import annotations

from apparmor_language_server.diagnostics import get_diagnostics
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
