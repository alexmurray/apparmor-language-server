"""
Tests for the AppArmor LSP server components.
Run with: pytest tests/ -v
"""

from __future__ import annotations

import pytest
from apparmor_language_server.completions import get_completions
from apparmor_language_server.diagnostics import get_diagnostics
from apparmor_language_server.formatting import FormatterOptions, format_document
from apparmor_language_server.hover import get_hover
from apparmor_language_server.parser import (
    CapabilityNode,
    FileRuleNode,
    IncludeNode,
    ProfileNode,
    parse_document,
)
from lsprotocol.types import Position

# ── Sample profiles ───────────────────────────────────────────────────────────

SIMPLE_PROFILE = """\
# AppArmor profile for myapp
profile myapp /usr/bin/myapp {
  include <abstractions/base>

  /etc/myapp.conf r,
  /var/log/myapp.log rw,
  capability net_bind_service,
  network inet stream,
}
"""

MULTI_PROFILE = """\
@{HOME} = /home/*/ /root/

profile myapp /usr/bin/myapp {
  include <abstractions/base>
  capability chown dac_override,
  /etc/** r,
}

profile myapp-helper /usr/lib/myapp/helper {
  include <abstractions/base>
  /tmp/** rw,
}
"""

MALFORMED = """\
profile broken {
  capability bad_capability_xyz,
  network notafamily,
  /etc/hosts rwXXXXX,
"""

# ── Parser tests ──────────────────────────────────────────────────────────────


class TestParser:
    def test_simple_profile_parses(self):
        doc, errors = parse_document("file:///test.aa", SIMPLE_PROFILE)
        assert len(doc.profiles) == 1
        assert doc.profiles[0].name == "myapp"

    def test_include_detected(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        assert any(inc.path == "abstractions/base" for inc in doc.includes)

    def test_capability_node(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        profile = doc.profiles[0]
        caps = [c for c in profile.children if isinstance(c, CapabilityNode)]
        assert len(caps) == 1
        assert "net_bind_service" in caps[0].capabilities

    def test_file_rule_node(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        profile = doc.profiles[0]
        files = [c for c in profile.children if isinstance(c, FileRuleNode)]
        assert len(files) >= 1
        paths = {f.path for f in files}
        assert "/etc/myapp.conf" in paths

    def test_variable_definition(self):
        doc, _ = parse_document("file:///test.aa", MULTI_PROFILE)
        assert "@{HOME}" in doc.variables

    def test_multiple_profiles(self):
        doc, _ = parse_document("file:///test.aa", MULTI_PROFILE)
        assert len(doc.profiles) == 2
        names = {p.name for p in doc.profiles}
        assert "myapp" in names
        assert "myapp-helper" in names

    def test_unclosed_profile_creates_error(self):
        doc, errors = parse_document(
            "file:///test.aa", "profile bad {\n  capability kill,\n"
        )
        assert len(errors) >= 1

    def test_network_rule(self):
        doc, _ = parse_document("file:///test.aa", SIMPLE_PROFILE)
        profile = doc.profiles[0]
        from apparmor_language_server.parser import NetworkNode

        nets = [c for c in profile.children if isinstance(c, NetworkNode)]
        assert len(nets) == 1
        assert "inet" in nets[0].rest


# ── Diagnostics tests ─────────────────────────────────────────────────────────


class TestDiagnostics:
    def test_no_diags_on_valid_profile(self):
        doc, errors = parse_document("file:///test.aa", SIMPLE_PROFILE)
        diags = get_diagnostics(doc, errors, SIMPLE_PROFILE)
        # No errors (may have info/warnings)
        error_diags = [d for d in diags if d.severity and d.severity.value <= 1]
        assert len(error_diags) == 0

    def test_unknown_capability_flagged(self):
        src = "profile x { capability bad_capability_xyz, }\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        codes = [d.code for d in diags]
        assert "unknown-capability" in codes

    def test_empty_profile_warning(self):
        src = "profile empty { }\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        codes = [d.code for d in diags]
        assert "empty-profile" in codes

    def test_duplicate_capability_warning(self):
        src = "profile x {\n  capability kill,\n  capability kill,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        codes = [d.code for d in diags]
        assert "duplicate-capability" in codes

    def test_dangerous_exec_warning(self):
        src = "profile x {\n  /usr/bin/sudo ux,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        codes = [d.code for d in diags]
        assert "dangerous-exec" in codes


# ── Completions tests ─────────────────────────────────────────────────────────


class TestCompletions:
    def _complete(self, line: str, char: int):
        pos = Position(line=0, character=char)
        return get_completions(line, pos, "file:///test.aa", [line])

    def test_keyword_completions_at_start(self):
        result = self._complete("  cap", 5)
        labels = {item.label for item in result.items}
        assert "capability" in labels

    def test_capability_completions(self):
        result = self._complete("  capability net", 17)
        labels = {item.label for item in result.items}
        assert "net_admin" in labels
        assert "net_bind_service" in labels

    def test_network_family_completions(self):
        result = self._complete("  network ", 10)
        labels = {item.label for item in result.items}
        assert "inet" in labels
        assert "inet6" in labels

    def test_network_type_completions(self):
        result = self._complete("  network inet ", 15)
        labels = {item.label for item in result.items}
        assert "stream" in labels
        assert "dgram" in labels

    def test_variable_completions(self):
        result = self._complete("  @{HO", 6)
        labels = {item.label for item in result.items}
        assert "@{HOME}" in labels

    def test_include_completions(self):
        result = self._complete("  include <abstractions/", 23)
        labels = {item.label for item in result.items}
        # Should have at least some abstractions
        assert any("abstractions/" in l for l in labels)

    def test_file_perm_completions(self):
        result = self._complete("  /etc/passwd ", 14)
        labels = {item.label for item in result.items}
        # Should offer permission strings
        assert "r" in labels or "rw" in labels


# ── Formatting tests ──────────────────────────────────────────────────────────


class TestFormatting:
    def _format(self, text: str, **kwargs) -> str:
        opts = FormatterOptions(**kwargs)
        edits = format_document(text, opts)
        if not edits:
            return text
        # Apply single whole-doc edit
        return edits[0].new_text

    def test_trailing_whitespace_removed(self):
        src = "profile x {   \n  capability kill,   \n}\n"
        out = self._format(src)
        for line in out.splitlines():
            assert line == line.rstrip(), f"Trailing whitespace on: {line!r}"

    def test_indentation_normalised(self):
        src = "profile x {\ncapability kill,\n}\n"
        out = self._format(src)
        lines = out.splitlines()
        # capability line should be indented
        cap_line = next(l for l in lines if "capability" in l)
        assert cap_line.startswith("  ")

    def test_capabilities_sorted(self):
        src = "profile x {\n  capability sys_admin, chown, kill,\n}\n"
        out = self._format(src, sort_capabilities=True)
        assert "chown, kill, sys_admin" in out

    def test_trailing_comma_added(self):
        src = "profile x {\n  capability kill\n}\n"
        out = self._format(src, ensure_trailing_comma=True)
        assert "capability kill," in out

    def test_hash_include_normalised(self):
        src = "profile x {\n  #include <abstractions/base>\n}\n"
        out = self._format(src, normalize_include=True)
        assert "#include" not in out
        assert "include <abstractions/base>" in out

    def test_multiple_blank_lines_collapsed(self):
        src = "profile x {\n\n\n\n  capability kill,\n}\n"
        out = self._format(src, max_blank_lines=1)
        # Should not have 3+ consecutive blank lines
        assert "\n\n\n" not in out

    def test_no_edit_on_clean_file(self):
        src = "profile x {\n  capability kill,\n}\n"
        # After formatting once, formatting again should produce no edits
        first = self._format(src)
        edits = format_document(first, FormatterOptions())
        assert len(edits) == 0


# ── Hover tests ───────────────────────────────────────────────────────────────


class TestHover:
    def _hover(self, line: str, char: int):
        pos = Position(line=0, character=char)
        return get_hover(line, pos)

    def test_hover_capability(self):
        result = self._hover("  capability net_bind_service,", 15)
        assert result is not None
        assert (
            "net_bind_service" in result.contents.value.lower()
            or "capability" in result.contents.value.lower()
        )

    def test_hover_keyword(self):
        result = self._hover("  network inet stream,", 4)
        assert result is not None
        assert "network" in result.contents.value.lower()

    def test_hover_variable(self):
        result = self._hover("  @{HOME}/** rw,", 5)
        assert result is not None
        assert (
            "HOME" in result.contents.value or "home" in result.contents.value.lower()
        )

    def test_hover_none_on_blank(self):
        result = self._hover("", 0)
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
