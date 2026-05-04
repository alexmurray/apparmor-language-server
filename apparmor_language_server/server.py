"""
AppArmor Language Server — main server module.

Capabilities exposed
────────────────────
  textDocument/completion          – keywords, permissions, paths, variables
  textDocument/hover               – documentation for keywords/permissions
  textDocument/definition          – go-to for #include targets
  textDocument/documentHighlight   – highlight same capability / variable
  textDocument/formatting          – full-document auto-format
  textDocument/rangeFormatting     – format a selection
  textDocument/publishDiagnostics  – linting (sent on open/change/save)
  workspace/symbol                 – list all profiles across open documents
  textDocument/documentSymbol      – list profiles/rules in current document

Run the server:
  python -m apparmor_language_server          (stdio, for editors)
  python -m apparmor_language_server --tcp    (TCP on 0.0.0.0:2087, for debugging)
"""

from __future__ import annotations

import logging
import os
import re
from typing import Optional

from lsprotocol.types import (
    # Server capabilities
    TEXT_DOCUMENT_COMPLETION,
    TEXT_DOCUMENT_DEFINITION,
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_DID_CLOSE,
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_SAVE,
    TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT,
    TEXT_DOCUMENT_DOCUMENT_SYMBOL,
    TEXT_DOCUMENT_FORMATTING,
    TEXT_DOCUMENT_HOVER,
    TEXT_DOCUMENT_RANGE_FORMATTING,
    TEXT_DOCUMENT_REFERENCES,
    WORKSPACE_SYMBOL,
    # Types
    CompletionList,
    CompletionOptions,
    CompletionParams,
    DefinitionParams,
    DidChangeTextDocumentParams,
    DidCloseTextDocumentParams,
    DidOpenTextDocumentParams,
    DidSaveTextDocumentParams,
    DocumentFormattingParams,
    DocumentHighlight,
    DocumentHighlightKind,
    DocumentHighlightParams,
    DocumentRangeFormattingParams,
    DocumentSymbol,
    DocumentSymbolParams,
    Hover,
    Location,
    Position,
    PublishDiagnosticsParams,
    Range,
    SymbolInformation,
    SymbolKind,
    TextEdit,
    WorkspaceSymbolParams,
)
from pygls.lsp.server import LanguageServer

from .completions import get_completions
from .diagnostics import get_diagnostics
from .formatting import FormatterOptions, format_document
from .hover import get_hover
from .parser import (
    CapabilityNode,
    DocumentNode,
    FileRuleNode,
    IncludeNode,
    NetworkNode,
    Node,
    ParseError,
    ProfileNode,
    VariableDefNode,
    parse_document,
    resolve_include_path,
)

# ── Logging ───────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)

# ── Server ────────────────────────────────────────────────────────────────────

SERVER_NAME = "apparmor-language-server"
SERVER_VERSION = "0.1.0"


class AppArmorLanguageServer(LanguageServer):
    """
    AppArmor Language Server.

    Maintains a per-document cache of parsed ASTs so we don't re-parse on
    every feature request.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(SERVER_NAME, SERVER_VERSION, *args, **kwargs)
        # uri → (DocumentNode, [ParseError])
        self._doc_cache: dict[str, tuple[DocumentNode, list[ParseError]]] = {}

    # ── Cache management ──────────────────────────────────────────────────────

    def parse_and_cache(
        self, uri: str, text: str
    ) -> tuple[DocumentNode, list[ParseError]]:
        result = parse_document(uri, text)
        self._doc_cache[uri] = result
        return result

    def get_cached(self, uri: str) -> Optional[tuple[DocumentNode, list[ParseError]]]:
        return self._doc_cache.get(uri)

    def evict(self, uri: str) -> None:
        self._doc_cache.pop(uri, None)

    # ── Text helpers ──────────────────────────────────────────────────────────

    def get_text(self, uri: str) -> Optional[str]:
        try:
            return self.workspace.get_text_document(uri).source
        except Exception:
            return None

    def _publish_diagnostics(self, uri: str, text: str) -> None:
        doc, errors = self.parse_and_cache(uri, text)
        diags = get_diagnostics(doc, errors)
        for uri, d in diags.items():
            self.text_document_publish_diagnostics(
                PublishDiagnosticsParams(uri=uri, diagnostics=d)
            )


# ── Server instance ───────────────────────────────────────────────────────────

server = AppArmorLanguageServer()


# ── Lifecycle ─────────────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_DID_OPEN)
def did_open(ls: AppArmorLanguageServer, params: DidOpenTextDocumentParams):
    logger.info("Opened: %s", params.text_document.uri)
    ls._publish_diagnostics(params.text_document.uri, params.text_document.text)


@server.feature(TEXT_DOCUMENT_DID_CHANGE)
def did_change(ls: AppArmorLanguageServer, params: DidChangeTextDocumentParams):
    uri = params.text_document.uri
    text = params.content_changes[-1].text
    ls._publish_diagnostics(uri, text)


@server.feature(TEXT_DOCUMENT_DID_SAVE)
def did_save(ls: AppArmorLanguageServer, params: DidSaveTextDocumentParams):
    uri = params.text_document.uri
    text = ls.get_text(uri) or ""
    ls._publish_diagnostics(uri, text)


@server.feature(TEXT_DOCUMENT_DID_CLOSE)
def did_close(ls: AppArmorLanguageServer, params: DidCloseTextDocumentParams):
    ls.evict(params.text_document.uri)


# ── Completion ────────────────────────────────────────────────────────────────


@server.feature(
    TEXT_DOCUMENT_COMPLETION,
    CompletionOptions(
        trigger_characters=[" ", "\t", "/", "@", "<", '"', ",", "("],
    ),
)
def completions(ls: AppArmorLanguageServer, params: CompletionParams) -> CompletionList:
    uri = params.text_document.uri
    position = params.position
    text = ls.get_text(uri) or str("")
    lines = text.splitlines()

    if position.line >= len(lines):
        return CompletionList(is_incomplete=False, items=[])

    line_text = lines[position.line]
    cached = ls.get_cached(uri)
    if cached is None:
        cached = ls.parse_and_cache(uri, text)

    doc, _ = cached
    return get_completions(doc, line_text, position, uri)


# ── Hover ─────────────────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_HOVER)
def hover(ls: AppArmorLanguageServer, params) -> Optional[Hover]:
    uri = params.text_document.uri
    position = params.position
    text = ls.get_text(uri) or ""
    lines = text.splitlines()

    if position.line >= len(lines):
        return None

    line_text = lines[position.line]
    cached = ls.get_cached(uri)
    if cached is None:
        cached = ls.parse_and_cache(uri, text)

    doc, _ = cached
    result = get_hover(doc, line_text, position)
    if result is None:
        return None

    # Adjust the range line number to the actual document line
    hover_range = result.range
    if hover_range:
        result = Hover(
            contents=result.contents,
            range=Range(
                start=Position(position.line, hover_range.start.character),
                end=Position(position.line, hover_range.end.character),
            ),
        )
    return result


# ── Goto Definition ───────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_DEFINITION)
def definition(
    ls: AppArmorLanguageServer, params: DefinitionParams
) -> Optional[list[Location]]:
    uri = params.text_document.uri
    position = params.position
    text = ls.get_text(uri) or ""
    lines = text.splitlines()

    if position.line >= len(lines):
        return None

    line_text = lines[position.line]
    cached = ls.get_cached(uri)
    if cached is None:
        cached = ls.parse_and_cache(uri, text)

    doc, _ = cached

    # Find an ABI node on this line
    if doc.abi and doc.abi.range.start.line == position.line:
        resolved = resolve_include_path(doc.abi.path, uri)
        if resolved is not None:
            target_uri = resolved.as_uri()
            return [
                Location(
                    uri=target_uri,
                    range=Range(
                        start=Position(0, 0),
                        end=Position(0, 0),
                    ),
                )
            ]

    # Find an include node on this line
    for inc in doc.includes:
        if inc.range.start.line == position.line:
            resolved = resolve_include_path(inc.path, uri)
            if resolved is not None:
                target_uri = resolved.as_uri()
                return [
                    Location(
                        uri=target_uri,
                        range=Range(
                            start=Position(0, 0),
                            end=Position(0, 0),
                        ),
                    )
                ]

    word = _word_at_position(line_text, position.character)
    if word:
        # Find a profile name reference
        for profile in doc.profiles:
            if profile.name == word:
                return [
                    Location(
                        uri=uri,
                        range=Range(
                            start=Position(
                                profile.range.start.line, profile.range.start.character
                            ),
                            end=Position(profile.range.start.line, 999),
                        ),
                    )
                ]

        for uri, vars in doc.all_variables.items():
            for name, var in vars.items():
                if name == word:
                    return [
                        Location(
                            uri=uri,
                            range=Range(
                                start=Position(
                                    var.range.start.line,
                                    var.range.start.character,
                                ),
                                end=Position(var.range.start.line, 999),
                            ),
                        )
                    ]

    return None


# ── References ───────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_REFERENCES)
def references(
    ls: AppArmorLanguageServer, params: DefinitionParams
) -> Optional[list[Location]]:
    uri = params.text_document.uri
    position = params.position
    text = ls.get_text(uri) or ""
    lines = text.splitlines()

    if position.line >= len(lines):
        return None

    line_text = lines[position.line]
    if ls.get_cached(uri) is None:
        ls.parse_and_cache(uri, text)

    word = _word_at_position(line_text, position.character)
    if not word:
        return None

    results: list[Location] = []
    pattern = re.compile(re.escape(word))

    for doc_uri in ls._doc_cache:
        doc_text = ls.get_text(doc_uri) or ""
        for line_no, doc_line in enumerate(doc_text.splitlines()):
            for m in pattern.finditer(doc_line):
                if _word_at_position(doc_line, m.start()) == word:
                    results.append(
                        Location(
                            uri=doc_uri,
                            range=Range(
                                start=Position(line_no, m.start()),
                                end=Position(line_no, m.end()),
                            ),
                        )
                    )

    return results


# ── Document Highlights ───────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT)
def highlight(
    ls: AppArmorLanguageServer, params: DocumentHighlightParams
) -> list[DocumentHighlight]:
    uri = params.text_document.uri
    position = params.position
    text = ls.get_text(uri) or ""
    lines = text.splitlines()

    if position.line >= len(lines):
        return []

    line_text = lines[position.line]
    word = _word_at_position(line_text, position.character)
    if not word:
        return []

    results: list[DocumentHighlight] = []
    pattern = re.compile(rf"\b{re.escape(word)}\b")

    for line_no, line in enumerate(lines):
        for m in pattern.finditer(line):
            results.append(
                DocumentHighlight(
                    range=Range(
                        start=Position(line_no, m.start()),
                        end=Position(line_no, m.end()),
                    ),
                    kind=DocumentHighlightKind.Text,
                )
            )

    return results


# ── Document Symbols ──────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_DOCUMENT_SYMBOL)
def document_symbols(
    ls: AppArmorLanguageServer, params: DocumentSymbolParams
) -> list[DocumentSymbol]:
    uri = params.text_document.uri
    text = ls.get_text(uri) or ""
    cached = ls.get_cached(uri)
    if cached is None:
        cached = ls.parse_and_cache(uri, text)

    doc, _ = cached
    return [_profile_to_symbol(p) for p in doc.profiles]


def _profile_to_symbol(profile: ProfileNode) -> DocumentSymbol:
    r = Range(
        start=Position(profile.range.start.line, 0),
        end=Position(profile.range.end.line, 999),
    )
    children = [
        _node_to_symbol(c)
        for c in profile.children
        if not isinstance(c, type(None)) and _node_to_symbol(c) is not None
    ]
    return DocumentSymbol(
        name=profile.name or "(anonymous)",
        kind=SymbolKind.Class if not profile.is_hat else SymbolKind.Module,
        range=r,
        selection_range=r,
        detail="hat" if profile.is_hat else "profile",
        children=[c for c in children if c],
    )


def _node_to_symbol(node: Node) -> Optional[DocumentSymbol]:
    r = Range(
        start=Position(node.range.start.line, 0),
        end=Position(node.range.end.line, 999),
    )
    if isinstance(node, ProfileNode):
        return _profile_to_symbol(node)
    if isinstance(node, CapabilityNode):
        name = "capability " + ", ".join(node.capabilities)
        return DocumentSymbol(
            name=name, kind=SymbolKind.Field, range=r, selection_range=r
        )
    if isinstance(node, FileRuleNode):
        return DocumentSymbol(
            name=f"{node.path} {node.perms}",
            kind=SymbolKind.File,
            range=r,
            selection_range=r,
        )
    if isinstance(node, NetworkNode):
        return DocumentSymbol(
            name=f"network {node.rest}",
            kind=SymbolKind.Interface,
            range=r,
            selection_range=r,
        )
    if isinstance(node, IncludeNode):
        return DocumentSymbol(
            name=f"include <{node.path}>",
            kind=SymbolKind.Module,
            range=r,
            selection_range=r,
        )
    if isinstance(node, VariableDefNode):
        return DocumentSymbol(
            name=node.name,
            kind=SymbolKind.Variable,
            range=r,
            selection_range=r,
        )
    return None


# ── Workspace Symbols ─────────────────────────────────────────────────────────


@server.feature(WORKSPACE_SYMBOL)
def workspace_symbols(
    ls: AppArmorLanguageServer, params: WorkspaceSymbolParams
) -> list[SymbolInformation]:
    query = params.query.lower()
    results: list[SymbolInformation] = []

    for uri, (doc, _) in ls._doc_cache.items():
        for profile in doc.profiles:
            name = profile.name or "(anonymous)"
            if not query or query in name.lower():
                results.append(
                    SymbolInformation(
                        name=name,
                        kind=SymbolKind.Class,
                        location=Location(
                            uri=uri,
                            range=Range(
                                start=Position(profile.range.start.line, 0),
                                end=Position(profile.range.start.line, 999),
                            ),
                        ),
                    )
                )
    return results


# ── Formatting ────────────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_FORMATTING)
def formatting(
    ls: AppArmorLanguageServer, params: DocumentFormattingParams
) -> list[TextEdit]:
    uri = params.text_document.uri
    text = ls.get_text(uri) or ""
    opts = FormatterOptions(
        indent=" " * (params.options.tab_size or 2),
    )
    return format_document(text, opts)


@server.feature(TEXT_DOCUMENT_RANGE_FORMATTING)
def range_formatting(
    ls: AppArmorLanguageServer, params: DocumentRangeFormattingParams
) -> list[TextEdit]:
    uri = params.text_document.uri
    text = ls.get_text(uri) or ""
    lines = text.splitlines(keepends=True)

    rng = params.range
    start_line = rng.start.line
    end_line = min(rng.end.line + 1, len(lines))

    sub_text = "".join(lines[start_line:end_line])
    opts = FormatterOptions(indent=" " * (params.options.tab_size or 2))
    edits = format_document(sub_text, opts)

    # Offset edits to actual line positions
    adjusted: list[TextEdit] = []
    for edit in edits:
        adjusted.append(
            TextEdit(
                range=Range(
                    start=Position(
                        start_line + edit.range.start.line, edit.range.start.character
                    ),
                    end=Position(
                        start_line + edit.range.end.line, edit.range.end.character
                    ),
                ),
                new_text=edit.new_text,
            )
        )
    return adjusted


# ── Utility ───────────────────────────────────────────────────────────────────

_RE_VARIABLE = re.compile(r"@{[A-Za-z0-9_]+}")
_RE_WORD = re.compile(r"[A-Za-z_/][A-Za-z0-9_/.-]*")


def _word_at_position(line: str, ch: int) -> str:
    # first try variables, then fallback to generic words
    for m in _RE_VARIABLE.finditer(line):
        if m.start() <= ch <= m.end():
            return m.group()
    for m in _RE_WORD.finditer(line):
        if m.start() <= ch <= m.end():
            return m.group()
    return ""


# ── Entry point ───────────────────────────────────────────────────────────────


def main():
    import argparse

    # set log level from env var, default to INFO
    logging.basicConfig(
        level=getattr(
            logging, os.getenv("APPARMOR_LSP_LOG_LEVEL", "INFO").upper(), logging.INFO
        ),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    ap = argparse.ArgumentParser(description="AppArmor Language Server")
    ap.add_argument("--tcp", action="store_true", help="Use TCP transport (host:port)")
    ap.add_argument("--host", default="127.0.0.1", help="TCP host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=2087, help="TCP port (default: 2087)")
    args = ap.parse_args()

    if args.tcp:
        logger.info("Starting AppArmor LSP on %s:%d (TCP)", args.host, args.port)
        server.start_tcp(args.host, args.port)
    else:
        logger.info("Starting AppArmor LSP on stdio")
        server.start_io()


if __name__ == "__main__":
    main()
