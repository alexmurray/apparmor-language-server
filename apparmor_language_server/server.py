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
  workspace/didChangeWorkspaceFolders – index and watch workspace folders

Run the server:
  python -m apparmor_language_server          (stdio, for editors)
  python -m apparmor_language_server --tcp    (TCP on 0.0.0.0:2087, for debugging)
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass
from dataclasses import field as _field
from pathlib import Path
from typing import Optional

from lsprotocol.types import (
    # Server capabilities
    INITIALIZED,
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
    WORKSPACE_DID_CHANGE_CONFIGURATION,
    WORKSPACE_DID_CHANGE_WORKSPACE_FOLDERS,
    WORKSPACE_SYMBOL,
    # Types
    CompletionList,
    CompletionOptions,
    CompletionParams,
    DefinitionParams,
    DidChangeConfigurationParams,
    DidChangeTextDocumentParams,
    DidChangeWorkspaceFoldersParams,
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
    InitializedParams,
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

from ._text import code_end as _code_end
from .completions import get_completions
from .constants import DEFAULT_INCLUDE_SEARCH_DIRS
from .diagnostics import get_diagnostics
from .formatting import FormatterOptions, format_document
from .hover import get_hover
from .indexer import WorkspaceIndexer
from .parser import (
    CapabilityNode,
    DocumentNode,
    FileRuleNode,
    IncludeNode,
    NetworkNode,
    Node,
    ParseError,
    Parser,
    ProfileNode,
    VariableDefNode,
    resolve_include_path,
)

# ── Logging ───────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)

# ── Settings ──────────────────────────────────────────────────────────────────


@dataclass
class Settings:
    """Server configuration, populated from workspace/didChangeConfiguration."""

    diagnostics_enable: bool = True
    include_search_paths: list[str] = _field(default_factory=list)
    profiles_subdir: str = "apparmor.d"
    apparmor_parser_path: str = ""

    @classmethod
    def from_raw(cls, raw: object) -> "Settings":
        """Parse from the JSON value carried by DidChangeConfigurationParams."""
        s = cls()
        if not isinstance(raw, dict):
            return s
        apparmor = raw.get("apparmor", {})
        if not isinstance(apparmor, dict):
            return s
        diagnostics = apparmor.get("diagnostics", {})
        if isinstance(diagnostics, dict):
            enabled = diagnostics.get("enable", True)
            if isinstance(enabled, bool):
                s.diagnostics_enable = enabled
        paths = apparmor.get("includeSearchPaths", [])
        if isinstance(paths, list):
            s.include_search_paths = [p for p in paths if isinstance(p, str)]
        subdir = apparmor.get("profilesSubdir", "apparmor.d")
        if isinstance(subdir, str):
            s.profiles_subdir = subdir
        parser_path = apparmor.get("apparmorParserPath", "")
        if isinstance(parser_path, str):
            s.apparmor_parser_path = parser_path
        return s


def _effective_index_path(workspace: Path, profiles_subdir: str) -> Optional[Path]:
    """Return the directory to index within *workspace*, or None if it doesn't exist."""
    if not profiles_subdir or profiles_subdir in (".", ""):
        target = workspace
    else:
        target = workspace / profiles_subdir
    return target if target.is_dir() else None


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
        self._cache_lock: threading.RLock = threading.RLock()
        # True while the background indexer is scanning workspace folders.
        # All result-returning handlers return empty while this is set.
        self._indexing: bool = False
        self._indexer: Optional[WorkspaceIndexer] = None
        self._settings: Settings = Settings()
        self._settings_lock: threading.Lock = threading.Lock()

    # ── Settings helpers ──────────────────────────────────────────────────────

    def _get_search_dirs(self) -> Optional[list[Path]]:
        """Return effective include search dirs, or None to use built-in defaults."""
        with self._settings_lock:
            extra = [Path(p) for p in self._settings.include_search_paths if p]
        if not extra:
            return None
        return extra + DEFAULT_INCLUDE_SEARCH_DIRS

    def _get_apparmor_parser_path(self) -> str:
        with self._settings_lock:
            return self._settings.apparmor_parser_path

    @staticmethod
    def _document_path(uri: str) -> Optional[Path]:
        """Convert a file:// URI to a Path if the file exists on disk."""
        if not uri.startswith("file://"):
            return None
        p = Path(uri.removeprefix("file://"))
        return p if p.exists() else None

    def _republish_all_diagnostics(self) -> None:
        """Re-run and publish diagnostics for every cached document."""
        with self._cache_lock:
            snapshot = list(self._doc_cache.items())
        with self._settings_lock:
            enabled = self._settings.diagnostics_enable
        if not enabled:
            for uri, _ in snapshot:
                self.text_document_publish_diagnostics(
                    PublishDiagnosticsParams(uri=uri, diagnostics=[])
                )
            return
        search_dirs = self._get_search_dirs()
        parser_path = self._get_apparmor_parser_path()
        for uri, (doc, errors) in snapshot:
            # Skip the external apparmor_parser check here: the buffer text
            # may be ahead of the on-disk file, and we don't want to block
            # the configuration handler on N subprocess invocations.
            diags = get_diagnostics(
                doc,
                errors,
                search_dirs,
                document_path=None,
                apparmor_parser_path=parser_path,
            )
            for diag_uri, d in diags.items():
                self.text_document_publish_diagnostics(
                    PublishDiagnosticsParams(uri=diag_uri, diagnostics=d)
                )

    # ── Cache management ──────────────────────────────────────────────────────

    def parse_and_cache(
        self, uri: str, text: str
    ) -> tuple[DocumentNode, list[ParseError]]:
        p = Parser(uri, text, search_dirs=self._get_search_dirs())
        doc = p.parse()
        result = (doc, p.errors)
        with self._cache_lock:
            self._doc_cache[uri] = result
            for inc_uri, inc_result in p.included_docs.items():
                if inc_uri not in self._doc_cache:
                    self._doc_cache[inc_uri] = inc_result
        return result

    def get_cached(self, uri: str) -> Optional[tuple[DocumentNode, list[ParseError]]]:
        with self._cache_lock:
            return self._doc_cache.get(uri)

    def evict(self, uri: str) -> None:
        with self._cache_lock:
            self._doc_cache.pop(uri, None)

    # ── Text helpers ──────────────────────────────────────────────────────────

    def get_text(self, uri: str) -> Optional[str]:
        try:
            return self.workspace.get_text_document(uri).source
        except Exception:
            return None

    def _publish_diagnostics(
        self, uri: str, text: str, run_external: bool = False
    ) -> None:
        """Re-parse *uri* and publish diagnostics.

        ``run_external`` enables the apparmor_parser subprocess check, which
        operates on the on-disk file. Callers should pass ``True`` only for
        save-time events so we don't surface stale parser errors mid-edit
        and don't spawn a subprocess on every keystroke.
        """
        doc, errors = self.parse_and_cache(uri, text)
        with self._settings_lock:
            enabled = self._settings.diagnostics_enable
        if not enabled:
            return
        document_path = self._document_path(uri) if run_external else None
        diags = get_diagnostics(
            doc,
            errors,
            self._get_search_dirs(),
            document_path=document_path,
            apparmor_parser_path=self._get_apparmor_parser_path(),
        )
        for diag_uri, d in diags.items():
            self.text_document_publish_diagnostics(
                PublishDiagnosticsParams(uri=diag_uri, diagnostics=d)
            )


# ── Server instance ───────────────────────────────────────────────────────────

server = AppArmorLanguageServer()


# ── Lifecycle ─────────────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_DID_OPEN)
def did_open(ls: AppArmorLanguageServer, params: DidOpenTextDocumentParams):
    logger.info("Opened: %s", params.text_document.uri)
    ls._publish_diagnostics(
        params.text_document.uri, params.text_document.text, run_external=True
    )


@server.feature(TEXT_DOCUMENT_DID_CHANGE)
def did_change(ls: AppArmorLanguageServer, params: DidChangeTextDocumentParams):
    uri = params.text_document.uri
    logger.debug("Changed: %s", uri)
    # pygls has already applied incremental changes to its workspace state before
    # calling this handler, so get_text() returns the full up-to-date document.
    # params.content_changes[-1].text is only the changed fragment in incremental mode.
    text = ls.get_text(uri) or ""
    ls._publish_diagnostics(uri, text)


@server.feature(TEXT_DOCUMENT_DID_SAVE)
def did_save(ls: AppArmorLanguageServer, params: DidSaveTextDocumentParams):
    uri = params.text_document.uri
    logger.debug("Saved: %s", uri)
    text = ls.get_text(uri) or ""
    ls._publish_diagnostics(uri, text, run_external=True)


@server.feature(TEXT_DOCUMENT_DID_CLOSE)
def did_close(ls: AppArmorLanguageServer, params: DidCloseTextDocumentParams):
    logger.debug("Closed: %s", params.text_document.uri)
    ls.evict(params.text_document.uri)


@server.feature(INITIALIZED)
def initialized(ls: AppArmorLanguageServer, params: InitializedParams) -> None:
    roots = [
        Path(uri.removeprefix("file://"))
        for uri in ls.workspace.folders
        if uri.startswith("file://")
    ]
    with ls._settings_lock:
        profiles_subdir = ls._settings.profiles_subdir
    valid = [
        p
        for root in roots
        if (p := _effective_index_path(root, profiles_subdir)) is not None
    ]
    logger.info("Initialized; indexing %d workspace folder(s)", len(valid))
    if not valid:
        return
    ls._indexer = WorkspaceIndexer(ls)
    ls._indexer.index_and_watch(valid)


@server.feature(WORKSPACE_DID_CHANGE_WORKSPACE_FOLDERS)
def workspace_did_change_folders(
    ls: AppArmorLanguageServer, params: DidChangeWorkspaceFoldersParams
) -> None:
    logger.debug(
        "Workspace folders changed: %d added, %d removed",
        len(params.event.added),
        len(params.event.removed),
    )
    if ls._indexer is None:
        return
    with ls._settings_lock:
        profiles_subdir = ls._settings.profiles_subdir
    for folder in params.event.removed:
        ls._indexer.unwatch_folder(Path(folder.uri.removeprefix("file://")))
    for folder in params.event.added:
        root = Path(folder.uri.removeprefix("file://"))
        target = _effective_index_path(root, profiles_subdir)
        if target is not None:
            ls._indexer.watch_new_folder(target)


@server.feature(WORKSPACE_DID_CHANGE_CONFIGURATION)
def did_change_configuration(
    ls: AppArmorLanguageServer, params: DidChangeConfigurationParams
) -> None:
    with ls._settings_lock:
        old = ls._settings
        ls._settings = Settings.from_raw(params.settings)
        new = ls._settings
    logger.debug(
        "Configuration changed: diagnostics_enable=%s include_search_paths=%s",
        new.diagnostics_enable,
        new.include_search_paths,
    )
    if old != new and not ls._indexing:
        ls._republish_all_diagnostics()


# ── Completion ────────────────────────────────────────────────────────────────


@server.feature(
    TEXT_DOCUMENT_COMPLETION,
    CompletionOptions(
        trigger_characters=[" ", "\t", "/", "@", "<", '"', ",", "("],
    ),
)
def completions(ls: AppArmorLanguageServer, params: CompletionParams) -> CompletionList:
    if ls._indexing:
        return CompletionList(is_incomplete=False, items=[])
    uri = params.text_document.uri
    position = params.position
    logger.debug("Completions: %s line %d", uri, position.line)
    text = ls.get_text(uri) or str("")
    lines = text.splitlines()

    if position.line >= len(lines):
        logger.debug(
            "Position line %d out of range (document has %d lines)",
            position.line,
            len(lines),
        )
        return CompletionList(is_incomplete=False, items=[])

    line_text = lines[position.line]
    cached = ls.get_cached(uri)
    if cached is None:
        cached = ls.parse_and_cache(uri, text)

    doc, _ = cached
    logger.debug(
        "Generating completions for doc with %d profiles, %d includes and %d variables",
        len(doc.profiles),
        len(doc.includes),
        sum(len(vars) for vars in doc.all_variables.values()),
    )
    return get_completions(doc, line_text, position, uri, ls._get_search_dirs())


# ── Hover ─────────────────────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_HOVER)
def hover(ls: AppArmorLanguageServer, params) -> Optional[Hover]:
    if ls._indexing:
        return None
    uri = params.text_document.uri
    position = params.position
    logger.debug("Hover: %s line %d char %d", uri, position.line, position.character)
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
    if ls._indexing:
        return None
    uri = params.text_document.uri
    position = params.position
    logger.debug(
        "Definition: %s line %d char %d", uri, position.line, position.character
    )
    text = ls.get_text(uri) or ""
    lines = text.splitlines()

    if position.line >= len(lines):
        return None

    line_text = lines[position.line]
    cached = ls.get_cached(uri)
    if cached is None:
        cached = ls.parse_and_cache(uri, text)

    doc, _ = cached
    search_dirs = ls._get_search_dirs()

    # Find an ABI node on this line
    if doc.abi and doc.abi.range.start.line == position.line:
        resolved = resolve_include_path(doc.abi.path, uri, search_dirs)
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
            resolved = resolve_include_path(inc.path, uri, search_dirs)
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
        logger.debug("Looking for definition of '%s'", word)
        # Find a profile name reference in any of the profiles or their children
        for profile in doc.profiles + [
            c for p in doc.profiles for c in p.children if isinstance(c, ProfileNode)
        ]:
            if profile.name == word:
                return [
                    Location(
                        uri=uri,
                        range=Range(
                            start=Position(
                                profile.range.start.line, profile.range.start.character
                            ),
                            end=Position(
                                profile.range.start.line, profile.range.end.character
                            ),
                        ),
                    )
                ]

        for def_uri, vars in doc.all_variables.items():
            for name, var in vars.items():
                if name == word:
                    return [
                        Location(
                            uri=def_uri,
                            range=Range(
                                start=Position(
                                    var.range.start.line,
                                    var.range.start.character,
                                ),
                                end=Position(
                                    var.range.start.line, var.range.end.character
                                ),
                            ),
                        )
                    ]

    return None


# ── References ───────────────────────────────────────────────────────


@server.feature(TEXT_DOCUMENT_REFERENCES)
def references(
    ls: AppArmorLanguageServer, params: DefinitionParams
) -> Optional[list[Location]]:
    if ls._indexing:
        return None
    uri = params.text_document.uri
    position = params.position
    logger.debug(
        "References: %s line %d char %d", uri, position.line, position.character
    )
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

    with ls._cache_lock:
        doc_uris = list(ls._doc_cache.keys())
    for doc_uri in doc_uris:
        doc_text = ls.get_text(doc_uri) or ""
        for line_no, doc_line in enumerate(doc_text.splitlines()):
            code_end = _code_end(doc_line)
            for m in pattern.finditer(doc_line):
                if (
                    m.start() < code_end
                    and _word_at_position(doc_line, m.start()) == word
                ):
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
    if ls._indexing:
        return []
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
    if ls._indexing:
        return []
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
        end=Position(profile.range.end.line, profile.range.end.character),
    )
    children = [
        s for s in (_node_to_symbol(c) for c in profile.children) if s is not None
    ]
    return DocumentSymbol(
        name=profile.name or "(anonymous)",
        kind=SymbolKind.Class if not profile.is_hat else SymbolKind.Module,
        range=r,
        selection_range=r,
        detail="hat" if profile.is_hat else "profile",
        children=children,
    )


def _node_to_symbol(node: Node) -> Optional[DocumentSymbol]:
    r = Range(
        start=Position(node.range.start.line, 0),
        end=Position(node.range.end.line, node.range.end.character),
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
    if ls._indexing:
        return []
    query = params.query.lower()
    results: list[SymbolInformation] = []

    with ls._cache_lock:
        cache_snapshot = list(ls._doc_cache.items())
    for uri, (doc, _) in cache_snapshot:
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
                                end=Position(
                                    profile.range.start.line,
                                    len(profile.raw),
                                ),
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
    if ls._indexing:
        return []
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
    if ls._indexing:
        return []
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
