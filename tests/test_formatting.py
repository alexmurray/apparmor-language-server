"""
Formatting tests for the AppArmor LSP server.
Run with: pytest tests/test_formatting.py -v
"""

from __future__ import annotations

from apparmor_language_server.formatting import FormatterOptions, format_document

# ── Helpers ───────────────────────────────────────────────────────────────────


def _format(text: str, **kwargs) -> str:
    opts = FormatterOptions(**kwargs)
    edits = format_document(text, opts)
    if not edits:
        return text
    return edits[0].new_text


# ── Formatting tests ──────────────────────────────────────────────────────────


class TestFormatting:
    def test_trailing_whitespace_removed(self):
        src = "profile x {   \n  capability kill,   \n}\n"
        out = _format(src)
        for line in out.splitlines():
            assert line == line.rstrip(), f"Trailing whitespace on: {line!r}"

    def test_indentation_normalised(self):
        src = "profile x {\ncapability kill,\n}\n"
        out = _format(src)
        lines = out.splitlines()
        cap_line = next(label for label in lines if "capability" in label)
        assert cap_line.startswith("  ")

    def test_capabilities_sorted(self):
        src = "profile x {\n  capability sys_admin, chown, kill,\n}\n"
        out = _format(src, sort_capabilities=True)
        assert "chown, kill, sys_admin" in out

    def test_hash_include_normalised(self):
        src = "profile x {\n  #include <abstractions/base>\n}\n"
        out = _format(src, normalize_include=True)
        assert "#include" not in out
        assert "include <abstractions/base>" in out

    def test_multiple_blank_lines_collapsed(self):
        src = "profile x {\n\n\n\n  capability kill,\n}\n"
        out = _format(src, max_blank_lines=1)
        assert "\n\n\n" not in out

    def test_paren_list_sorted(self):
        src = "profile x flags=(mediate_deleted,complain) {\n  capability kill,\n}\n"
        out = _format(src)
        assert "(complain, mediate_deleted)" in out

    def test_no_edit_on_clean_file(self):
        src = "profile x {\n  capability kill,\n}\n"
        first = _format(src)
        edits = format_document(first, FormatterOptions())
        assert len(edits) == 0

    def test_multiline_rule_continuation_indented(self):
        # Continuation lines (no trailing comma) must get extra indent.
        src = (
            "profile x {\n"
            "  dbus (send)\n"
            "  bus=session\n"
            "  path=/org/freedesktop/DBus,\n"
            "}\n"
        )
        out = _format(src)
        lines = out.splitlines()
        dbus_line = next(ln for ln in lines if ln.lstrip().startswith("dbus"))
        bus_line = next(ln for ln in lines if ln.lstrip().startswith("bus="))
        path_line = next(ln for ln in lines if ln.lstrip().startswith("path="))
        assert dbus_line == "  dbus (send)"
        assert bus_line == "      bus=session"
        assert path_line == "      path=/org/freedesktop/DBus,"

    def test_multiline_rule_already_correct_is_idempotent(self):
        src = (
            "profile x {\n"
            "  dbus (send)\n"
            "      bus=session\n"
            "      path=/org/freedesktop/DBus\n"
            "      interface=org.freedesktop.DBus\n"
            '      member="{Request,Release}Name"\n'
            "      peer=(label=unconfined, name=org.freedesktop.DBus),\n"
            "}\n"
        )
        out = _format(src)
        edits = format_document(out, FormatterOptions())
        assert len(edits) == 0

    def test_consecutive_includes_not_indented(self):
        # include lines have no trailing comma but must not trigger continuation.
        src = (
            "profile x {\n"
            "  include <abstractions/foo>\n"
            "  include <abstractions/bar>\n"
            "  capability kill,\n"
            "}\n"
        )
        out = _format(src)
        lines = out.splitlines()
        include_lines = [ln for ln in lines if "include" in ln]
        assert all(ln.startswith("  include") for ln in include_lines)

    def test_hash_include_consecutive_not_indented(self):
        # #include lines normalised to include must not trigger continuation.
        src = (
            "profile x {\n"
            "  #include <abstractions/foo>\n"
            "  #include <abstractions/bar>\n"
            "}\n"
        )
        out = _format(src)
        lines = out.splitlines()
        include_lines = [ln for ln in lines if "include" in ln]
        assert all(ln.startswith("  include") for ln in include_lines)

    def test_multiline_rule_followed_by_normal_rule(self):
        # After the trailing comma, the next rule returns to normal depth.
        src = "profile x {\n  dbus (send)\n  bus=session,\n  capability kill,\n}\n"
        out = _format(src)
        lines = out.splitlines()
        bus_line = next(ln for ln in lines if ln.lstrip().startswith("bus="))
        cap_line = next(ln for ln in lines if ln.lstrip().startswith("capability"))
        assert bus_line == "      bus=session,"
        assert cap_line == "  capability kill,"
