"""
Completions tests for the AppArmor LSP server.
Run with: pytest tests/test_completions.py -v
"""

from __future__ import annotations

import pytest
from lsprotocol.types import Position

from apparmor_language_server.completions import get_completions
from apparmor_language_server.parser import VariableDefNode

from conftest import make_doc, make_var


# ── Helpers ───────────────────────────────────────────────────────────────────


def _complete(
    line: str,
    char: int | None = None,
    variables: dict[str, VariableDefNode] | None = None,
):
    if variables is None:
        variables = {}
    if char is None:
        char = len(line)
    pos = Position(line=0, character=char)
    doc = make_doc(variables)
    return get_completions(doc, line, pos, "file:///test.aa")


# ── Keyword completions ───────────────────────────────────────────────────────


class TestKeywordCompletions:
    def test_keyword_completions_at_start(self):
        result = _complete("  cap")
        labels = {item.label for item in result.items}
        assert "capability" in labels

    def test_deny_triggers_keyword_completions(self):
        result = _complete("  deny ")
        labels = {item.label for item in result.items}
        assert len(labels) > 0

    def test_audit_triggers_keyword_completions(self):
        result = _complete("  audit ")
        labels = {item.label for item in result.items}
        assert len(labels) > 0


# ── Capability completions ────────────────────────────────────────────────────


class TestCapabilityCompletions:
    def test_capability_completions(self):
        result = _complete("  capability net")
        labels = {item.label for item in result.items}
        assert "net_admin" in labels
        assert "net_bind_service" in labels

    def test_capability_completions_no_prefix(self):
        result = _complete("  capability ")
        labels = {item.label for item in result.items}
        assert "kill" in labels
        assert "chown" in labels


# ── Network completions ───────────────────────────────────────────────────────


class TestNetworkCompletions:
    def test_network_family_completions(self):
        result = _complete("  network ")
        labels = {item.label for item in result.items}
        assert "inet" in labels
        assert "inet6" in labels

    def test_network_type_completions(self):
        result = _complete("  network inet ")
        labels = {item.label for item in result.items}
        assert "stream" in labels
        assert "dgram" in labels


# ── Signal completions ────────────────────────────────────────────────────────


class TestSignalCompletions:
    def test_signal_permission_completions(self):
        result = _complete("  signal ")
        labels = {item.label for item in result.items}
        assert "send" in labels
        assert "receive" in labels

    def test_signal_names_after_open_paren(self):
        result = _complete("  signal (")
        labels = {item.label for item in result.items}
        assert "hup" in labels
        assert "term" in labels


# ── Ptrace completions ────────────────────────────────────────────────────────


class TestPtraceCompletions:
    def test_ptrace_permission_completions(self):
        result = _complete("  ptrace (")
        labels = {item.label for item in result.items}
        assert "read" in labels
        assert "trace" in labels

    def test_ptrace_completions_after_space(self):
        result = _complete("  ptrace ")
        labels = {item.label for item in result.items}
        assert "read" in labels
        assert "trace" in labels


# ── Profile flags completions ─────────────────────────────────────────────────


class TestProfileFlagsCompletions:
    def test_profile_flags_completions(self):
        result = _complete("profile myapp /usr/bin/myapp flags=(")
        labels = {item.label for item in result.items}
        assert "complain" in labels
        assert "attach_disconnected" in labels

    def test_profile_flags_completions_partial(self):
        result = _complete("profile myapp /usr/bin/myapp flags=(attach")
        labels = {item.label for item in result.items}
        assert "attach_disconnected" in labels


# ── Variable completions ──────────────────────────────────────────────────────


class TestVariableCompletions:
    def test_variable_completions(self):
        variables = {"@{HOME}": make_var("@{HOME}", ["/home/*/", "/root/"])}
        result = _complete("  @{HO", None, variables=variables)
        labels = {item.label for item in result.items}
        assert "@{HOME}" in labels


# ── ABI completions ───────────────────────────────────────────────────────────


class TestABICompletions:
    def test_abi_completions(self):
        result = _complete("  abi <abi/")
        labels = {item.label for item in result.items}
        assert len(labels) >= 1
        assert all("abi/" in label for label in labels)


# ── Include completions ───────────────────────────────────────────────────────


class TestIncludeCompletions:
    def test_include_completions(self):
        result = _complete("  include <abstractions/")
        labels = {item.label for item in result.items}
        assert any("abstractions/" in label for label in labels)


# ── File permission completions ───────────────────────────────────────────────


class TestFilePermCompletions:
    @pytest.mark.parametrize("line", ["  /etc/passwd ", "  file /etc/passwd r"])
    def test_file_perm_completions(self, line: str):
        result = _complete(line)
        labels = {item.label for item in result.items}
        assert "rw" in labels


# ── Filesystem path completions ───────────────────────────────────────────────


class TestFilePathCompletions:
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
        result = _complete(line, len(line))
        labels = {item.label for item in result.items}
        assert any("apparmor.d" in label for label in labels)


# ── Mount completions ─────────────────────────────────────────────────────────


class TestMountCompletions:
    def test_mount_option_completions(self):
        result = _complete("  mount ")
        labels = {item.label for item in result.items}
        assert "ro" in labels
        assert "rw" in labels

    def test_umount_option_completions(self):
        result = _complete("  umount ")
        labels = {item.label for item in result.items}
        assert "ro" in labels


# ── DBus completions ──────────────────────────────────────────────────────────


class TestDBusCompletions:
    def test_dbus_permission_completions(self):
        result = _complete("  dbus ")
        labels = {item.label for item in result.items}
        assert "send" in labels
        assert "receive" in labels

    def test_dbus_no_completions_after_bus_keyword(self):
        result = _complete("  dbus bus ")
        labels = {item.label for item in result.items}
        assert "system" in labels
        assert "session" in labels


# ── Unix socket completions ───────────────────────────────────────────────────


class TestUnixCompletions:
    def test_unix_permission_completions(self):
        result = _complete("  unix ")
        labels = {item.label for item in result.items}
        assert "create" in labels
        assert "connect" in labels
