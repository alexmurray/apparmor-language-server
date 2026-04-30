"""
Hover tests for the AppArmor LSP server.
Run with: pytest tests/test_hover.py -v
"""

from __future__ import annotations

from lsprotocol.types import MarkupContent, Position, Range

from apparmor_language_server.hover import get_hover
from apparmor_language_server.parser import DocumentNode, VariableDefNode


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


def make_doc(variables: dict[str, VariableDefNode] | None = None) -> DocumentNode:
    if variables is None:
        variables = {}
    return DocumentNode(
        uri="file:///test.aa",
        variables=variables,
        all_variables={"file:///test.aa": variables},
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _hover(
    line: str,
    char: int,
    variables: dict[str, VariableDefNode] | None = None,
):
    pos = Position(line=0, character=char)
    doc = make_doc(variables or {})
    return get_hover(doc, line, pos)


def _hover_text(
    line: str, char: int, variables: dict[str, VariableDefNode] | None = None
) -> str:
    result = _hover(line, char, variables)
    assert result is not None
    assert isinstance(result.contents, MarkupContent)
    return result.contents.value


# ── Keyword hover ─────────────────────────────────────────────────────────────


class TestKeywordHover:
    def test_hover_keyword_network(self):
        assert "network" in _hover_text("  network inet stream,", 4).lower()

    def test_hover_none_on_blank(self):
        assert _hover("", 0) is None

    def test_hover_userns(self):
        assert "userns" in _hover_text("  userns,", 4).lower()

    def test_hover_include_if_exists_at_if(self):
        line = "  include if exists <local/myapp>"
        assert "include if exists" in _hover_text(line, line.index("if") + 1).lower()

    def test_hover_include_if_exists_at_exists(self):
        line = "  include if exists <local/myapp>"
        assert (
            "include if exists" in _hover_text(line, line.index("exists") + 2).lower()
        )


# ── Capability hover ──────────────────────────────────────────────────────────


class TestCapabilityHover:
    def test_hover_capability(self):
        text = _hover_text("  capability net_bind_service,", 15)
        assert "net_bind_service" in text.lower() or "capability" in text.lower()

    def test_hover_capability_chown(self):
        assert "chown" in _hover_text("  capability chown dac_override,", 16).lower()


# ── Network hover ─────────────────────────────────────────────────────────────


class TestNetworkHover:
    def test_hover_network_family_inet(self):
        assert "inet" in _hover_text("  network inet stream,", 12).lower()

    def test_hover_network_family_bluetooth(self):
        assert "bluetooth" in _hover_text("  network bluetooth,", 12).lower()


# ── Profile flag hover ────────────────────────────────────────────────────────


class TestProfileFlagHover:
    def test_hover_profile_flag_complain(self):
        line = "profile myapp /usr/bin/myapp flags=(complain) {"
        assert "complain" in _hover_text(line, line.index("complain") + 3).lower()

    def test_hover_profile_flag_attach_disconnected(self):
        line = "profile myapp /usr/bin/myapp flags=(attach_disconnected) {"
        assert (
            "attach_disconnected"
            in _hover_text(line, line.index("attach_disconnected") + 5).lower()
        )


# ── Qualifier hover ───────────────────────────────────────────────────────────


class TestQualifierHover:
    def test_hover_deny_qualifier(self):
        assert "deny" in _hover_text("  deny /dev/dri/{,**} r,", 4).lower()

    def test_hover_audit_qualifier(self):
        assert "audit" in _hover_text("  audit /tmp/** rw,", 4).lower()


# ── Ptrace hover ──────────────────────────────────────────────────────────────


class TestPtraceHover:
    def test_hover_ptrace_trace_permission(self):
        assert (
            "trace" in _hover_text("  ptrace (trace) peer=@{profile_name},", 13).lower()
        )

    def test_hover_ptrace_read_permission(self):
        assert (
            "read" in _hover_text("  ptrace (read) peer=@{profile_name},", 12).lower()
        )


# ── File permission hover ─────────────────────────────────────────────────────


class TestFilePermissionHover:
    def test_hover_file_permission_r(self):
        assert "r" in _hover_text("  /etc/passwd r,", 14).lower()

    def test_hover_file_permission_rw(self):
        assert "rw" in _hover_text("  /tmp/myfile rw,", 15).lower()


# ── Variable hover ────────────────────────────────────────────────────────────


class TestVariableHover:
    def test_hover_variable(self):
        variables = {"@{HOME}": make_var("@{HOME}", ["/home/*/", "/root/"])}
        text = _hover_text("  @{HOME}/** rw,", 5, variables=variables)
        assert "HOME" in text or "home" in text.lower()
