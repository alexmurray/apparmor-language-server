"""
Hover tests for the AppArmor LSP server.
Run with: pytest tests/test_hover.py -v
"""

from __future__ import annotations

from typing import Optional

from lsprotocol.types import MarkupContent, Position, Range

from apparmor_language_server.hover import Hover, get_hover
from apparmor_language_server.parser import VariableDefNode, parse_document


def make_var(name: str, values: list[str]) -> VariableDefNode:
    return VariableDefNode(
        name=name,
        values=values,
        range=Range(
            start=Position(line=0, character=0),
            end=Position(line=0, character=0),
        ),
        raw=f"{name} = {' '.join(values)}",
    )


# ── Test helpers ──────────────────────────────────────────────────────────────


def _hover_at(
    text: str,
    line: int,
    char: int,
    variables: dict[str, VariableDefNode] | None = None,
) -> Optional[Hover]:
    """Parse *text*, inject *variables* if given, and hover at (line, char)."""
    doc, _ = parse_document("file:///test.aa", text)
    if variables:
        doc.variables.update(variables)
        # doc.all_variables[uri] IS doc.variables (same dict object from parser),
        # so the update above is sufficient; the assignment below is for clarity.
        doc.all_variables["file:///test.aa"] = doc.variables
    lines = text.splitlines()
    line_text = lines[line] if line < len(lines) else ""
    return get_hover(doc, line_text, Position(line=line, character=char))


def _hover_rule(
    rule: str,
    char: int,
    variables: dict[str, VariableDefNode] | None = None,
) -> Optional[Hover]:
    """Wrap *rule* in a minimal profile block and hover at *char* within it."""
    text = f"profile test {{\n{rule}\n}}"
    return _hover_at(text, 1, char, variables)


def _text(result: Hover) -> str:
    assert isinstance(result.contents, MarkupContent)
    return result.contents.value


def _rule_text(rule: str, char: int, variables: dict[str, VariableDefNode] | None = None) -> str:
    result = _hover_rule(rule, char, variables)
    assert result is not None, f"Expected hover at char {char} of {rule!r}"
    return _text(result)


# ── Keyword hover ─────────────────────────────────────────────────────────────


class TestKeywordHover:
    def test_hover_keyword_network(self):
        # char 4 lands on 'w' of 'network' in "  network inet stream,"
        assert "network" in _rule_text("  network inet stream,", 4).lower()

    def test_hover_none_on_blank(self):
        assert _hover_at("", 0, 0) is None

    def test_hover_userns(self):
        # char 4 lands on 'r' of 'userns'
        assert "userns" in _rule_text("  userns,", 4).lower()

    def test_hover_include_if_exists_at_if(self):
        line = "include if exists <local/myapp>"
        result = _hover_at(line, 0, line.index("if") + 1)
        assert result is not None
        assert "include if exists" in _text(result).lower()

    def test_hover_include_if_exists_at_exists(self):
        line = "include if exists <local/myapp>"
        result = _hover_at(line, 0, line.index("exists") + 2)
        assert result is not None
        assert "include if exists" in _text(result).lower()


# ── Capability hover ──────────────────────────────────────────────────────────


class TestCapabilityHover:
    def test_hover_capability(self):
        # char 15 lands within 'net_bind_service'
        text = _rule_text("  capability net_bind_service,", 15)
        assert "net_bind_service" in text.lower() or "capability" in text.lower()

    def test_hover_capability_chown(self):
        # char 16 lands within 'chown'
        assert "chown" in _rule_text("  capability chown dac_override,", 16).lower()

    def test_hover_capability_keyword(self):
        # char 5 lands on 'a' of 'capability'
        assert "capability" in _rule_text("  capability chown,", 5).lower()


# ── Network hover ─────────────────────────────────────────────────────────────


class TestNetworkHover:
    def test_hover_network_family_inet(self):
        # char 12 lands within 'inet'
        assert "inet" in _rule_text("  network inet stream,", 12).lower()

    def test_hover_network_family_bluetooth(self):
        assert "bluetooth" in _rule_text("  network bluetooth,", 12).lower()

    def test_hover_network_type_stream(self):
        # char 17 lands within 'stream'
        assert "stream" in _rule_text("  network inet stream,", 17).lower()

    def test_hover_network_keyword(self):
        # char 4 lands on 'w' of 'network'
        assert "network" in _rule_text("  network inet stream,", 4).lower()


# ── Profile flag hover ────────────────────────────────────────────────────────


class TestProfileFlagHover:
    def test_hover_profile_flag_complain(self):
        line = "profile myapp /usr/bin/myapp flags=(complain) {"
        char = line.index("complain") + 3
        text = f"{line}\n}}"
        result = _hover_at(text, 0, char)
        assert result is not None
        assert "complain" in _text(result).lower()

    def test_hover_profile_flag_attach_disconnected(self):
        line = "profile myapp /usr/bin/myapp flags=(attach_disconnected) {"
        char = line.index("attach_disconnected") + 5
        text = f"{line}\n}}"
        result = _hover_at(text, 0, char)
        assert result is not None
        assert "attach_disconnected" in _text(result).lower()


# ── Qualifier hover ───────────────────────────────────────────────────────────


class TestQualifierHover:
    def test_hover_deny_qualifier(self):
        # char 4 lands on 'y' of 'deny'
        assert "deny" in _rule_text("  deny /dev/dri/{,**} r,", 4).lower()

    def test_hover_audit_qualifier(self):
        # char 4 lands on 'i' of 'audit'
        assert "audit" in _rule_text("  audit /tmp/** rw,", 4).lower()

    def test_hover_owner_qualifier(self):
        # owner is a file-rule-specific qualifier
        assert "owner" in _rule_text("  owner /home/** rw,", 4).lower()


# ── Ptrace hover ──────────────────────────────────────────────────────────────


class TestPtraceHover:
    def test_hover_ptrace_trace_permission(self):
        # char 13 lands within 'trace' inside the parens
        assert (
            "trace" in _rule_text("  ptrace (trace) peer=@{profile_name},", 13).lower()
        )

    def test_hover_ptrace_read_permission(self):
        assert (
            "read" in _rule_text("  ptrace (read) peer=@{profile_name},", 12).lower()
        )

    def test_hover_ptrace_keyword(self):
        assert "ptrace" in _rule_text("  ptrace (trace),", 4).lower()


# ── Signal hover ──────────────────────────────────────────────────────────────


class TestSignalHover:
    def test_hover_signal_keyword(self):
        assert "signal" in _rule_text("  signal (send) set=(term),", 4).lower()

    def test_hover_signal_permission_send(self):
        # char 11 lands within 'send'
        assert "send" in _rule_text("  signal (send) set=(term),", 11).lower()

    def test_hover_signal_name_term(self):
        # char 22 lands within 'term' in set=(term)
        assert "term" in _rule_text("  signal (send) set=(term),", 22).lower()

    def test_hover_signal_permission_r_is_signal_not_file(self):
        # 'r' inside a signal rule must show a signal permission hover, not file
        result = _rule_text("  signal r set=(term),", 9)
        # should mention signal, not file permissions
        assert "signal" in result.lower()


# ── File permission hover ─────────────────────────────────────────────────────


class TestFilePermissionHover:
    def test_hover_file_permission_r(self):
        # char 14 lands on 'r' permission in "/etc/passwd r,"
        assert "r" in _rule_text("  /etc/passwd r,", 14).lower()

    def test_hover_file_permission_rw(self):
        assert "rw" in _rule_text("  /tmp/myfile rw,", 15).lower()

    def test_hover_file_permission_does_not_fire_in_signal_rule(self):
        # 'r' in a signal rule context must NOT produce a file permission hover
        result = _rule_text("  signal r set=(hup),", 9)
        assert "file" not in result.lower()


# ── Variable hover ────────────────────────────────────────────────────────────


class TestVariableHover:
    def test_hover_variable(self):
        variables = {"@{HOME}": make_var("@{HOME}", ["/home/*/", "/root/"])}
        text = _rule_text("  @{HOME}/** rw,", 5, variables=variables)
        assert "HOME" in text or "home" in text.lower()

    def test_hover_variable_shows_values(self):
        variables = {"@{PROC}": make_var("@{PROC}", ["/proc/"])}
        text = _rule_text("  @{PROC}/self/fd r,", 4, variables=variables)
        assert "/proc/" in text

    def test_hover_variable_in_signal_rule(self):
        variables = {"@{profile_name}": make_var("@{profile_name}", ["myapp"])}
        text = _rule_text(
            "  signal (send) peer=@{profile_name},", 23, variables=variables
        )
        assert "profile_name" in text.lower()
