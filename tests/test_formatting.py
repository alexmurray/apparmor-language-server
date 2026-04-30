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

    def test_trailing_comma_added(self):
        src = "profile x {\n  capability kill\n}\n"
        out = _format(src, ensure_trailing_comma=True)
        assert "capability kill," in out

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
