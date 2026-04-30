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
    DocumentNode,
    FileRuleNode,
    Range,
    VariableDefNode,
    parse_document,
)
from lsprotocol.types import Position, Range

# ── Sample profiles ───────────────────────────────────────────────────────────

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

MULTILINE_RULES_PROFILE = """\
profile multiline /usr/bin/multiline {
  network
      inet stream,
  dbus (send)
      bus=session
      path=/org/freedesktop/DBus
      interface=org.freedesktop.DBus
      member="{Request,Release}Name"
      peer=(name=org.freedesktop.DBus, label=unconfined),
  capability
      sys_admin
      chown,
}
"""

PROFILE_USING_HOME = """\
include <tunables/home>

profile home-user {
  @{HOME}/ r,
}
"""

# ── Parser tests ──────────────────────────────────────────────────────────────


class TestParser:
    def test_simple_profile_parses(self):
        doc, errors = parse_document("file:///test.aa", SIMPLE_PROFILE)
        assert len(doc.profiles) == 1
        assert doc.profiles[0].name == "myapp"
        assert len(errors) == 0

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
        assert "/usr/bin/myapp" in paths
        assert "/usr/lib/libmyapp.so*" in paths
        assert "@{HOME}/.myapp/**" in paths

        # check qualifiers and permissions on the @{HOME} rule
        home_rule = next(f for f in files if f.path == "@{HOME}/.myapp/**")
        assert "owner" in home_rule.qualifiers
        assert "rw" in home_rule.perms

        # check qualifiers and permissions on the deny rule
        deny_rule = next(f for f in files if f.path == "/dev/dri/{,**}")
        assert "deny" in deny_rule.qualifiers
        assert "r" in deny_rule.perms

    def test_variable_definition(self):
        doc, _ = parse_document("file:///test.aa", MULTI_PROFILE)
        assert "@{HOME}" in doc.variables

    def test_profile_using_home_variable(self):
        doc, errors = parse_document("file:///test.aa", PROFILE_USING_HOME)
        assert any(inc.path == "tunables/home" for inc in doc.includes)
        # The @{HOME} variable should be defined from the included tunables/home file
        found_home_var = False
        for inc in doc.includes:
            if inc.path == "tunables/home":
                for doc in inc.documents:
                    for name, _ in doc.variables.items():
                        if name == "@{HOME}":
                            found_home_var = True
                            break
        assert found_home_var, (
            "Expected @{HOME} variable to be defined from tunables/home"
        )
        assert len(errors) == 0

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

    def test_multiline_network_rule(self):
        doc, errors = parse_document("file:///test.aa", MULTILINE_RULES_PROFILE)
        assert len(errors) == 0
        from apparmor_language_server.parser import NetworkNode

        profile = doc.profiles[0]
        nets = [c for c in profile.children if isinstance(c, NetworkNode)]
        assert len(nets) == 1
        assert "inet" in nets[0].rest
        assert "stream" in nets[0].rest

    def test_multiline_capability_rule(self):
        doc, errors = parse_document("file:///test.aa", MULTILINE_RULES_PROFILE)
        assert len(errors) == 0
        profile = doc.profiles[0]
        caps = [c for c in profile.children if isinstance(c, CapabilityNode)]
        assert len(caps) == 1
        assert "sys_admin" in caps[0].capabilities
        assert "chown" in caps[0].capabilities

    def test_multiline_dbus_rule(self):
        from apparmor_language_server.parser import GenericRuleNode

        doc, errors = parse_document("file:///test.aa", MULTILINE_RULES_PROFILE)
        assert len(errors) == 0
        profile = doc.profiles[0]
        generics = [c for c in profile.children if isinstance(c, GenericRuleNode)]
        dbus_rules = [g for g in generics if g.keyword == "dbus"]
        assert len(dbus_rules) == 1
        assert "bus=session" in dbus_rules[0].content
        assert "peer=(name=org.freedesktop.DBus, label=unconfined)" in dbus_rules[0].content

    def test_multiline_rule_range(self):
        doc, _ = parse_document("file:///test.aa", MULTILINE_RULES_PROFILE)
        from apparmor_language_server.parser import NetworkNode

        profile = doc.profiles[0]
        net = next(c for c in profile.children if isinstance(c, NetworkNode))
        # network rule spans lines 1-2 (0-indexed) within the profile body
        assert net.range.start.line < net.range.end.line


# ── Diagnostics tests ─────────────────────────────────────────────────────────


class TestDiagnostics:
    def test_no_diags_on_valid_profile(self):
        doc, errors = parse_document("file:///test.aa", SIMPLE_PROFILE)
        diags = get_diagnostics(doc, errors, SIMPLE_PROFILE)
        all_diags = [d for sublist in diags.values() for d in sublist]
        # No errors (may have info/warnings)
        error_diags = [d for d in all_diags if d.severity and d.severity.value <= 1]
        assert len(error_diags) == 0

    def test_unknown_capability_flagged(self):
        src = "profile x { capability bad_capability_xyz, }\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        all_diags = [d for sublist in diags.values() for d in sublist]
        codes = [d.code for d in all_diags]
        assert "unknown-capability" in codes

    def test_empty_profile_warning(self):
        src = "profile empty { }\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        all_diags = [d for sublist in diags.values() for d in sublist]
        codes = [d.code for d in all_diags]
        assert "empty-profile" in codes

    def test_duplicate_capability_warning(self):
        src = "profile x {\n  capability kill,\n  capability kill,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        all_diags = [d for sublist in diags.values() for d in sublist]
        codes = [d.code for d in all_diags]
        assert "duplicate-capability" in codes

    def test_dangerous_exec_warning(self):
        src = "profile x {\n  /usr/bin/sudo ux,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        all_diags = [d for sublist in diags.values() for d in sublist]
        codes = [d.code for d in all_diags]
        assert "dangerous-exec" in codes

    def test_unknown_network_family(self):
        src = "profile x {\n  network notafamily,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        all_diags = [d for sublist in diags.values() for d in sublist]
        codes = [d.code for d in all_diags]
        assert "unknown-network-qualifier" in codes

    def test_no_warning_with_known_network_qualifiers(self):
        src = "profile x {\n  audit network inet stream,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        assert len(diags) == 0, f"Expected no diagnostics, got: {diags}"

    def test_no_warning_with_known_file_qualifiers(self):
        src = "profile x {\n  audit file r /foo,\n}\n"
        doc, errors = parse_document("file:///test.aa", src)
        diags = get_diagnostics(doc, errors, src)
        assert len(diags) == 0, f"Expected no diagnostics, got: {diags}"


# ── Completions tests ─────────────────────────────────────────────────────────


class TestCompletions:
    def _complete(
        self,
        line: str,
        char: int | None = None,
        variables: dict[str, VariableDefNode] = {},
    ):
        if char is None:
            char = len(line)
        pos = Position(line=0, character=char)
        doc = DocumentNode(
            uri="file:///test.aa",
            variables=variables,
            all_variables={"file:///test.aa": variables},
        )
        return get_completions(doc, line, pos, "file:///test.aa")

    def test_keyword_completions_at_start(self):
        result = self._complete("  cap")
        labels = {item.label for item in result.items}
        assert "capability" in labels

    def test_capability_completions(self):
        result = self._complete("  capability net")
        labels = {item.label for item in result.items}
        assert "net_admin" in labels
        assert "net_bind_service" in labels

    def test_network_family_completions(self):
        result = self._complete("  network ")
        labels = {item.label for item in result.items}
        assert "inet" in labels
        assert "inet6" in labels

    def test_network_type_completions(self):
        result = self._complete("  network inet ")
        labels = {item.label for item in result.items}
        assert "stream" in labels
        assert "dgram" in labels

    def test_variable_completions(self):
        variables = {
            "@{HOME}": VariableDefNode(
                name="@{HOME}",
                values=["/home/*/", "/root/"],
                range=Range(
                    start=Position(line=0, character=0),
                    end=Position(line=0, character=0),
                ),
                raw="@{HOME} = /home/*/ /root/",
            )
        }
        result = self._complete("  @{HO", None, variables=variables)
        labels = {item.label for item in result.items}
        assert "@{HOME}" in labels

    def test_abi_completions(self):
        result = self._complete("  abi <abi/")
        labels = {item.label for item in result.items}
        # at least one ABI should be offered
        assert len(labels) >= 1
        # all ABI completions should be in the abi/ namespace
        assert all("abi/" in label for label in labels)

    def test_include_completions(self):
        result = self._complete("  include <abstractions/")
        labels = {item.label for item in result.items}
        # Should have at least some abstractions
        assert any("abstractions/" in label for label in labels)

    @pytest.mark.parametrize("line", ["  /etc/passwd ", "  file /etc/passwd r"])
    def test_file_perm_completions(self, line: str):
        result = self._complete(line)
        labels = {item.label for item in result.items}
        # Should offer permission strings
        assert "rw" in labels

    @pytest.mark.parametrize(
        "line",
        [
            "  /etc/apparmo",
            "  file /etc/apparmo",
            "audit /etc/apparmo",
            "audit deny file /etc/apparmo",
        ],
    )
    def test_file_path_completions(self, line: str):
        result = self._complete(line, len(line))
        labels = {item.label for item in result.items}
        # Should offer /etc/apparmor.d as a completion
        assert any("apparmor.d" in label for label in labels)


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
        cap_line = next(label for label in lines if "capability" in label)
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
    def _hover(self, line: str, char: int, variables: dict[str, VariableDefNode] = {}):
        pos = Position(line=0, character=char)
        doc = DocumentNode(
            uri="file:///test.aa",
            variables=variables,
            all_variables={"file:///test.aa": variables},
        )
        return get_hover(doc, line, pos)

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
        variables = {
            "@{HOME}": VariableDefNode(
                name="@{HOME}",
                values=["/home/*/", "/root/"],
                range=Range(
                    start=Position(line=0, character=0),
                    end=Position(line=0, character=0),
                ),
                raw="@{HOME} = /home/*/ /root/",
            )
        }
        result = self._hover("  @{HOME}/** rw,", 5, variables=variables)
        assert result is not None
        assert (
            "HOME" in result.contents.value or "home" in result.contents.value.lower()
        )

    def test_hover_none_on_blank(self):
        result = self._hover("", 0)
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
