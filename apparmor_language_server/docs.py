"""
AppArmor LSP – shared documentation formatters.

These functions return Markdown strings for AppArmor tokens and nodes.
They are used by both the completion provider and the hover provider so that
both surfaces show identical, consistent documentation.
"""

from __future__ import annotations

from pathlib import Path

from .constants import CAPABILITY_DEFS, EXECUTE_PERMISSIONS, FILE_PERMISSIONS
from .parser import VariableDefNode


def variable_doc(var_name: str, var: VariableDefNode, uri: str) -> str:
    """Markdown documentation for a variable definition or reference."""
    comment_text = " ".join(c.text for c in var.comments)
    body = f"**`{var_name}`**\n\n"
    if comment_text:
        body += comment_text + "\n\n"
    body += f"`{var_name}` = {' '.join(var.values)}\n\nDefined in {Path(uri).name} at line {var.range.start.line + 1}"
    return body


def capability_doc(cap_name: str) -> str:
    """Markdown documentation for a capability name."""
    cap_def = CAPABILITY_DEFS.get(cap_name.lower())
    if cap_def:
        return cap_def.doc
    return f"**Linux capability `{cap_name}`** (`CAP_{cap_name.upper()}`)"


def file_permissions_doc(perm_str: str) -> str:
    """Markdown documentation breaking down each character in *perm_str*."""
    all_perms = sorted(
        set(FILE_PERMISSIONS.keys()) | set(EXECUTE_PERMISSIONS.keys()),
        key=len,
        reverse=True,
    )
    perms: list[str] = []
    i = 0
    while i < len(perm_str):
        for p in all_perms:
            if perm_str.startswith(p, i):
                perms.append(p)
                i += len(p)
                break
        else:
            i += 1
    lines: list[str] = [f"**File permissions `{perm_str}`**\n"]
    for perm in perms:
        desc = FILE_PERMISSIONS.get(perm) or EXECUTE_PERMISSIONS.get(perm)
        if desc:
            lines.append(f"- `{perm}` — {desc}")
    return "\n".join(lines)
