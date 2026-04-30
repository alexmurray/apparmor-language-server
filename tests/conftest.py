"""
Shared helpers for the AppArmor LSP test suite.
"""

from __future__ import annotations

from lsprotocol.types import Position, Range

from apparmor_language_server.parser import DocumentNode, VariableDefNode


def make_var(name: str, values: list[str]) -> VariableDefNode:
    """Build a VariableDefNode for use in completions/hover tests."""
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
    """Build a minimal DocumentNode for completions/hover tests."""
    if variables is None:
        variables = {}
    return DocumentNode(
        uri="file:///test.aa",
        variables=variables,
        all_variables={"file:///test.aa": variables},
    )
