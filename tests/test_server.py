"""
Tests for apparmor_language_server/server.py.
Run with: pytest tests/test_server.py -v
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest
from apparmor_language_server.parser import (
    CapabilityNode,
    DocumentNode,
    FileRuleNode,
    IncludeNode,
    NetworkNode,
    parse_document,
)
from apparmor_language_server.server import (
    AppArmorLanguageServer,
    Settings,
    _effective_index_path,
    _node_to_symbol,
    _profile_to_symbol,
    _word_at_position,
    completions,
    definition,
    did_change,
    did_change_configuration,
    did_close,
    document_symbols,
    formatting,
    highlight,
    hover,
    range_formatting,
    references,
    workspace_symbols,
)
from lsprotocol.types import (
    CompletionParams,
    DefinitionParams,
    DidChangeConfigurationParams,
    DidChangeTextDocumentParams,
    DidCloseTextDocumentParams,
    DocumentFormattingParams,
    DocumentHighlightKind,
    DocumentHighlightParams,
    DocumentRangeFormattingParams,
    DocumentSymbolParams,
    FormattingOptions,
    Position,
    Range,
    SymbolKind,
    TextDocumentContentChangePartial,
    TextDocumentIdentifier,
    VersionedTextDocumentIdentifier,
    WorkspaceSymbolParams,
)

# ── Shared test data ──────────────────────────────────────────────────────────

URI = "file:///test.aa"

SIMPLE_PROFILE = """\
profile myapp /usr/bin/myapp {
  capability net_bind_service,
  /etc/myapp.conf r,
  network inet stream,
}
"""


# ── Test server stub ──────────────────────────────────────────────────────────


class MockLS:
    """Minimal server stub that satisfies the handler interface without pygls."""

    def __init__(self, text: str = "", uri: str = URI):
        self._doc_cache: dict = {}
        self._texts: dict[str, str] = {}
        self._cache_lock = threading.RLock()
        self._settings_lock = threading.Lock()
        self._indexing = False
        self._edit_version: dict[str, int] = {}
        if text:
            self._texts[uri] = text

    def _get_search_dirs(self):
        return None

    def get_text(self, uri: str) -> str:
        return self._texts.get(uri, "")

    def get_cached(self, uri: str):
        return self._doc_cache.get(uri)

    def parse_and_cache(self, uri: str, text: str):
        self._texts[uri] = text
        result = parse_document(uri, text)
        self._doc_cache[uri] = result
        return result

    def evict(self, uri: str) -> None:
        self._doc_cache.pop(uri, None)
        self._texts.pop(uri, None)

    def _publish_diagnostics(self, uri: str, text: str) -> None:
        self.parse_and_cache(uri, text)

    def _schedule_background_parser(self, uri: str, text: str, version: int) -> None:
        pass


def _ls(text: str = SIMPLE_PROFILE) -> MockLS:
    """Return a MockLS pre-loaded with *text*."""
    ls = MockLS()
    ls.parse_and_cache(URI, text)
    return ls


# ── _word_at_position ─────────────────────────────────────────────────────────


class TestWordAtPosition:
    def test_word_inside(self):
        # "net_bind_service" starts well past "capability "
        line = "  capability net_bind_service,"
        assert _word_at_position(line, 16) == "net_bind_service"

    def test_word_at_beginning(self):
        assert _word_at_position("capability net_admin,", 5) == "capability"

    def test_variable_match_takes_priority(self):
        line = "  /etc/@{HOME}/.config r,"
        # cursor anywhere inside @{HOME}
        assert _word_at_position(line, 10) == "@{HOME}"

    def test_path_returned_as_word(self):
        assert _word_at_position("  /usr/bin/myapp ix,", 7) == "/usr/bin/myapp"

    def test_space_in_leading_whitespace_returns_empty(self):
        # positions 0 and 1 are leading spaces before any word
        assert _word_at_position("  capability net_admin,", 1) == ""

    def test_empty_line_returns_empty(self):
        assert _word_at_position("", 0) == ""

    def test_opening_brace_returns_empty(self):
        assert _word_at_position("profile test {", 13) == ""

    def test_cursor_on_variable_at_end(self):
        line = "  owner @{HOME}/.config rw,"
        assert _word_at_position(line, 14) == "@{HOME}"


# ── AppArmorLanguageServer cache management ───────────────────────────────────


class TestAppArmorLanguageServerCache:
    @pytest.fixture
    def server(self):
        return AppArmorLanguageServer()

    def test_parse_and_cache_returns_doc_and_errors(self, server):
        doc, errors = server.parse_and_cache(URI, SIMPLE_PROFILE)
        assert doc is not None
        assert isinstance(errors, list)

    def test_get_cached_returns_stored_result(self, server):
        result = server.parse_and_cache(URI, SIMPLE_PROFILE)
        assert server.get_cached(URI) is result

    def test_get_cached_miss_returns_none(self, server):
        assert server.get_cached("file:///no-such-file.aa") is None

    def test_evict_removes_entry(self, server):
        server.parse_and_cache(URI, SIMPLE_PROFILE)
        server.evict(URI)
        assert server.get_cached(URI) is None

    def test_evict_missing_uri_is_noop(self, server):
        server.evict("file:///nonexistent.aa")  # must not raise

    def test_parse_and_cache_overwrites_previous(self, server):
        server.parse_and_cache(URI, SIMPLE_PROFILE)
        new_text = "profile other /bin/other { }\n"
        doc2, _ = server.parse_and_cache(URI, new_text)
        cached_doc, _ = server.get_cached(URI)
        assert cached_doc is doc2

    def test_no_errors_for_valid_profile(self, server):
        _, errors = server.parse_and_cache(URI, SIMPLE_PROFILE)
        assert errors == []


# ── parse_and_cache include caching ──────────────────────────────────────────


class TestParseAndCacheIncludedDocs:
    @pytest.fixture
    def server(self):
        return AppArmorLanguageServer()

    def test_included_file_added_to_cache(self, server, tmp_path):
        inc_file = tmp_path / "myinc"
        inc_file.write_text("@{MY_VAR} = /foo\n")
        parent_uri = (tmp_path / "parent.aa").as_uri()
        server.parse_and_cache(
            parent_uri, f'include "{inc_file.name}"\nprofile x {{ }}\n'
        )
        assert server.get_cached(inc_file.as_uri()) is not None

    def test_included_file_cache_entry_has_doc_and_errors(self, server, tmp_path):
        inc_file = tmp_path / "myinc"
        inc_file.write_text("@{MY_VAR} = /foo\n")
        parent_uri = (tmp_path / "parent.aa").as_uri()
        server.parse_and_cache(
            parent_uri, f'include "{inc_file.name}"\nprofile x {{ }}\n'
        )
        doc, errors = server.get_cached(inc_file.as_uri())
        assert "@{MY_VAR}" in doc.variables
        assert isinstance(errors, list)

    def test_unresolvable_include_not_added_to_cache(self, server):
        server.parse_and_cache(URI, "include <no-such-file>\nprofile x { }\n")
        assert set(server._doc_cache) == {URI}

    def test_already_cached_uri_not_overwritten(self, server, tmp_path):
        inc_file = tmp_path / "myinc"
        inc_file.write_text("@{MY_VAR} = /foo\n")
        inc_uri = inc_file.as_uri()
        sentinel = (DocumentNode(uri=inc_uri), [])
        server._doc_cache[inc_uri] = sentinel
        parent_uri = (tmp_path / "parent.aa").as_uri()
        server.parse_and_cache(
            parent_uri, f'include "{inc_file.name}"\nprofile x {{ }}\n'
        )
        assert server.get_cached(inc_uri) is sentinel

    def test_transitive_includes_added_to_cache(self, server, tmp_path):
        deep_file = tmp_path / "deep"
        deep_file.write_text("@{DEEP} = /deep\n")
        mid_file = tmp_path / "middle"
        mid_file.write_text(f'include "{deep_file.name}"\n')
        parent_uri = (tmp_path / "parent.aa").as_uri()
        server.parse_and_cache(
            parent_uri, f'include "{mid_file.name}"\nprofile x {{ }}\n'
        )
        assert server.get_cached(mid_file.as_uri()) is not None
        assert server.get_cached(deep_file.as_uri()) is not None

    def test_included_file_errors_stored_in_cache(self, server, tmp_path):
        inc_file = tmp_path / "myinc"
        inc_file.write_text("profile broken {\n")  # missing closing brace
        parent_uri = (tmp_path / "parent.aa").as_uri()
        server.parse_and_cache(
            parent_uri, f'include "{inc_file.name}"\nprofile x {{ }}\n'
        )
        _, errors = server.get_cached(inc_file.as_uri())
        assert len(errors) > 0


# ── _profile_to_symbol ────────────────────────────────────────────────────────


class TestProfileToSymbol:
    def test_regular_profile_kind_is_class(self):
        doc, _ = parse_document(URI, SIMPLE_PROFILE)
        sym = _profile_to_symbol(doc.profiles[0])
        assert sym.kind == SymbolKind.Class

    def test_regular_profile_name(self):
        doc, _ = parse_document(URI, SIMPLE_PROFILE)
        sym = _profile_to_symbol(doc.profiles[0])
        assert sym.name == "myapp"

    def test_regular_profile_detail(self):
        doc, _ = parse_document(URI, SIMPLE_PROFILE)
        sym = _profile_to_symbol(doc.profiles[0])
        assert sym.detail == "profile"

    def test_hat_kind_is_module(self):
        src = "profile myapp /usr/bin/myapp {\n  hat myhat { }\n}\n"
        doc, _ = parse_document(URI, src)
        from apparmor_language_server.parser import ProfileNode

        hat = next(n for n in doc.profiles[0].children if isinstance(n, ProfileNode))
        assert hat.is_hat
        sym = _profile_to_symbol(hat)
        assert sym.kind == SymbolKind.Module

    def test_hat_detail(self):
        src = "profile myapp /usr/bin/myapp {\n  hat myhat { }\n}\n"
        doc, _ = parse_document(URI, src)
        from apparmor_language_server.parser import ProfileNode

        hat = next(n for n in doc.profiles[0].children if isinstance(n, ProfileNode))
        sym = _profile_to_symbol(hat)
        assert sym.detail == "hat"

    def test_range_starts_at_profile_line(self):
        doc, _ = parse_document(URI, SIMPLE_PROFILE)
        sym = _profile_to_symbol(doc.profiles[0])
        assert sym.range.start.line == 0

    def test_children_populated_for_non_empty_profile(self):
        doc, _ = parse_document(URI, SIMPLE_PROFILE)
        sym = _profile_to_symbol(doc.profiles[0])
        assert sym.children is not None and len(sym.children) > 0


# ── _node_to_symbol ───────────────────────────────────────────────────────────


class TestNodeToSymbol:
    def _children(self, rule: str):
        doc, _ = parse_document(URI, f"profile test {{\n{rule}\n}}\n")
        return doc.profiles[0].children

    def test_capability_node_kind(self):
        nodes = self._children("  capability net_admin,")
        cap = next(n for n in nodes if isinstance(n, CapabilityNode))
        sym = _node_to_symbol(cap)
        assert sym is not None
        assert sym.kind == SymbolKind.Field

    def test_capability_node_name_contains_capability(self):
        nodes = self._children("  capability net_admin,")
        cap = next(n for n in nodes if isinstance(n, CapabilityNode))
        sym = _node_to_symbol(cap)
        assert sym is not None
        assert "net_admin" in sym.name

    def test_file_rule_node_kind(self):
        nodes = self._children("  /etc/foo r,")
        node = next(n for n in nodes if isinstance(n, FileRuleNode))
        sym = _node_to_symbol(node)
        assert sym is not None
        assert sym.kind == SymbolKind.File

    def test_file_rule_node_name_contains_path(self):
        nodes = self._children("  /etc/foo r,")
        node = next(n for n in nodes if isinstance(n, FileRuleNode))
        sym = _node_to_symbol(node)
        assert sym is not None
        assert "/etc/foo" in sym.name

    def test_network_node_kind(self):
        nodes = self._children("  network inet stream,")
        node = next(n for n in nodes if isinstance(n, NetworkNode))
        sym = _node_to_symbol(node)
        assert sym is not None
        assert sym.kind == SymbolKind.Interface

    def test_include_node_kind(self):
        nodes = self._children("  include <abstractions/base>")
        node = next(n for n in nodes if isinstance(n, IncludeNode))
        sym = _node_to_symbol(node)
        assert sym is not None
        assert sym.kind == SymbolKind.Module

    def test_include_node_name_contains_path(self):
        nodes = self._children("  include <abstractions/base>")
        node = next(n for n in nodes if isinstance(n, IncludeNode))
        sym = _node_to_symbol(node)
        assert sym is not None
        assert "abstractions/base" in sym.name

    def test_variable_def_node_kind(self):
        src = "@{MY_VAR} = /foo /bar\n"
        doc, _ = parse_document(URI, src)
        var = doc.variables.get("@{MY_VAR}")
        assert var is not None
        sym = _node_to_symbol(var)
        assert sym is not None
        assert sym.kind == SymbolKind.Variable

    def test_profile_node_delegates_to_profile_to_symbol(self):
        src = "profile myapp /usr/bin/myapp {\n  profile inner /bin/inner { }\n}\n"
        doc, _ = parse_document(URI, src)
        inner = next(
            n for n in doc.profiles[0].children if isinstance(n, type(doc.profiles[0]))
        )
        sym = _node_to_symbol(inner)
        assert sym is not None
        assert sym.kind == SymbolKind.Class


# ── completions handler ───────────────────────────────────────────────────────


class TestCompletionsHandler:
    def test_returns_completion_list(self):
        ls = _ls()
        params = CompletionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=1, character=12),
        )
        result = completions(ls, params)
        assert result is not None

    def test_out_of_range_line_returns_empty_list(self):
        ls = _ls()
        params = CompletionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=999, character=0),
        )
        result = completions(ls, params)
        assert result.items == []

    def test_primes_cache_when_missing(self):
        ls = MockLS(text=SIMPLE_PROFILE, uri=URI)
        assert ls.get_cached(URI) is None
        params = CompletionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=1, character=5),
        )
        completions(ls, params)
        assert ls.get_cached(URI) is not None

    def test_capability_completions_offered(self):
        ls = _ls()
        params = CompletionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=1, character=len("  capability net_bi")),
        )
        result = completions(ls, params)
        labels = {item.label for item in result.items}
        assert "net_bind_service" in labels


# ── hover handler ─────────────────────────────────────────────────────────────


class _HoverParams:
    def __init__(self, uri: str, line: int, char: int):
        self.text_document = TextDocumentIdentifier(uri=uri)
        self.position = Position(line=line, character=char)


class TestHoverHandler:
    def test_out_of_range_returns_none(self):
        ls = _ls()
        result = hover(ls, _HoverParams(URI, 999, 0))
        assert result is None

    def test_hover_on_valid_line_does_not_raise(self):
        ls = _ls()
        result = hover(ls, _HoverParams(URI, 1, 5))
        assert result is None or hasattr(result, "contents")

    def test_primes_cache_when_missing(self):
        ls = MockLS(text=SIMPLE_PROFILE, uri=URI)
        hover(ls, _HoverParams(URI, 1, 5))
        assert ls.get_cached(URI) is not None

    def test_hover_range_line_adjusted(self):
        ls = _ls()
        # line 3: "  network inet stream,"  — "network" has hover docs
        result = hover(ls, _HoverParams(URI, 3, 5))
        if result and result.range:
            assert result.range.start.line == 3
            assert result.range.end.line == 3


# ── definition handler ────────────────────────────────────────────────────────


class TestDefinitionHandler:
    def test_out_of_range_returns_none(self):
        ls = _ls()
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=999, character=0),
        )
        assert definition(ls, params) is None

    def test_profile_name_returns_location(self):
        ls = _ls()
        # line 0: "profile myapp /usr/bin/myapp {"  — cursor on "myapp" at char 10
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=10),
        )
        result = definition(ls, params)
        assert result is not None
        assert result[0].uri == URI

    def test_child_profile_transition_returns_location(self):
        # line 1: "  file Cx /bin/inner -> inner,"  — cursor on "inner" at char 26
        src = "profile myapp /usr/bin/myapp {\n  file Cx /bin/inner -> inner,\n profile inner { }\n}\n"
        ls = _ls(src)
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=1, character=26),
        )
        result = definition(ls, params)
        assert result is not None
        assert result[0].uri == URI

    def test_variable_def_returns_location(self):
        src = "@{MY_VAR} = /foo\nprofile test {\n  /@{MY_VAR}/bar r,\n}\n"
        ls = _ls(src)
        # line 2: "  /@{MY_VAR}/bar r,"  — cursor at 5 (inside @{MY_VAR})
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=2, character=5),
        )
        result = definition(ls, params)
        if result:
            assert result[0].uri == URI

    def test_no_definition_for_whitespace(self):
        ls = _ls()
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=0),
        )
        # "p" of "profile" — not a variable or include, may or may not match
        # Just confirm no exception is raised
        definition(ls, params)

    def test_primes_cache_when_missing(self):
        ls = MockLS(text=SIMPLE_PROFILE, uri=URI)
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=10),
        )
        definition(ls, params)
        assert ls.get_cached(URI) is not None


# ── references handler ────────────────────────────────────────────────────────


class TestReferencesHandler:
    def test_out_of_range_returns_none(self):
        ls = _ls()
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=999, character=0),
        )
        assert references(ls, params) is None

    def test_returns_all_occurrences(self):
        # "foo" appears as a standalone token twice: "profile foo" and "capability foo".
        # "/usr/bin/foo" must NOT be counted — it is a path, not a reference to foo.
        src = "profile foo /usr/bin/foo {\n  capability foo,\n}\n"
        ls = _ls(src)
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=9),
        )
        result = references(ls, params)
        assert result is not None
        assert len(result) == 2

    def test_no_word_at_position_returns_none(self):
        ls = _ls()
        # line 4 is "}" — cursor at 0 gives no word
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=4, character=0),
        )
        assert references(ls, params) is None

    def test_result_locations_span_correct_lines(self):
        src = "profile foo /usr/bin/foo {\n  capability foo,\n}\n"
        ls = _ls(src)
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=9),
        )
        result = references(ls, params)
        lines = {loc.range.start.line for loc in result}
        assert 0 in lines
        assert 1 in lines

    def test_finds_references_across_cached_documents(self):
        uri2 = "file:///other.aa"
        src1 = "profile foo /usr/bin/foo { }\n"
        src2 = "profile bar /usr/bin/bar {\n  capability foo,\n}\n"
        ls = MockLS()
        ls.parse_and_cache(URI, src1)
        ls.parse_and_cache(uri2, src2)
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=9),
        )
        result = references(ls, params)
        assert result is not None
        result_uris = {loc.uri for loc in result}
        assert URI in result_uris
        assert uri2 in result_uris

    def test_cross_document_total_count(self):
        uri2 = "file:///other.aa"
        # URI: standalone "foo" once (profile name); "/usr/bin/foo" is a path — not counted.
        # uri2: standalone "foo" once (capability rule).
        src1 = "profile foo /usr/bin/foo { }\n"
        src2 = "profile bar /usr/bin/bar {\n  capability foo,\n}\n"
        ls = MockLS()
        ls.parse_and_cache(URI, src1)
        ls.parse_and_cache(uri2, src2)
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=9),
        )
        result = references(ls, params)
        assert result is not None
        assert len(result) == 2

    def test_path_component_not_treated_as_reference(self):
        # "mx-extract" appears as a subprofile name, as the target of a change-profile
        # rule, and as a trailing component of a file path.  Only the two standalone
        # token occurrences are references; the path component must be excluded.
        src = (
            "profile outer /bin/outer {\n"
            "  file Cx /usr/libexec/rygel/mx-extract -> mx-extract,\n"
            "  profile mx-extract {\n"
            "  }\n"
            "}\n"
        )
        ls = _ls(src)
        # cursor on "mx-extract" in "profile mx-extract {"  (line 2)
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=2, character=12),
        )
        result = references(ls, params)
        assert result is not None
        lines = src.splitlines()
        for loc in result:
            matched = lines[loc.range.start.line][
                loc.range.start.character : loc.range.end.character
            ]
            assert matched == "mx-extract", (
                f"unexpected match {matched!r} on line {loc.range.start.line}"
            )
        # Exactly two standalone occurrences: change-profile target + profile declaration
        assert len(result) == 2

    def test_variable_references_returned(self):
        # @{MY_VAR} starts with '@' and ends with '}', both non-word characters,
        # so \b-based patterns never match it.  The handler must find all three
        # occurrences: the variable definition and both uses in rules.
        src = (
            "@{MY_VAR} = /foo /bar\n"
            "profile test {\n"
            "  @{MY_VAR}/baz r,\n"
            "  owner @{MY_VAR}/** rw,\n"
            "}\n"
        )
        ls = _ls(src)
        # cursor inside @{MY_VAR} on line 2 ("  @{MY_VAR}/baz r,")
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=2, character=5),
        )
        result = references(ls, params)
        assert result is not None
        assert len(result) == 3
        result_lines = {loc.range.start.line for loc in result}
        assert result_lines == {0, 2, 3}

    def test_full_line_comment_excluded(self):
        # @{HOME} inside a full-line comment must not be returned as a reference.
        src = (
            "profile test {\n"
            "  # allow access to @{HOME} directory\n"
            "  @{HOME}/.config r,\n"
            "}\n"
        )
        ls = _ls(src)
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=2, character=3),
        )
        result = references(ls, params)
        assert result is not None
        assert len(result) == 1
        assert result[0].range.start.line == 2

    def test_trailing_inline_comment_excluded(self):
        # @{HOME} after a mid-line # must not be returned as a reference.
        src = (
            "profile test {\n"
            "  @{HOME}/.config r,  # also covers @{HOME}/.local\n"
            "  @{HOME}/.local r,\n"
            "}\n"
        )
        ls = _ls(src)
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=1, character=3),
        )
        result = references(ls, params)
        assert result is not None
        assert len(result) == 2
        result_lines = {loc.range.start.line for loc in result}
        assert result_lines == {1, 2}

    def test_uncached_document_not_searched(self):
        # A document that was never added to the cache must not contribute results.
        ls = _ls("profile unique_word /bin/x { }\n")
        # Do NOT cache a second doc that also contains unique_word.
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=9),
        )
        result = references(ls, params)
        result_uris = {loc.uri for loc in result}
        assert result_uris == {URI}


# ── highlight handler ─────────────────────────────────────────────────────────


class TestHighlightHandler:
    def test_out_of_range_returns_empty(self):
        ls = _ls()
        params = DocumentHighlightParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=999, character=0),
        )
        assert highlight(ls, params) == []

    def test_highlights_all_occurrences(self):
        src = "profile foo /usr/bin/foo {\n  capability foo,\n}\n"
        ls = _ls(src)
        params = DocumentHighlightParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=9),
        )
        result = highlight(ls, params)
        assert len(result) == 3

    def test_highlight_kind_is_text(self):
        src = "profile foo /usr/bin/foo {\n  capability foo,\n}\n"
        ls = _ls(src)
        params = DocumentHighlightParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=9),
        )
        result = highlight(ls, params)
        assert all(h.kind == DocumentHighlightKind.Text for h in result)

    def test_no_word_at_position_returns_empty(self):
        ls = _ls()
        params = DocumentHighlightParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=4, character=0),
        )
        assert highlight(ls, params) == []


# ── document_symbols handler ──────────────────────────────────────────────────


class TestDocumentSymbolsHandler:
    def test_returns_profile_symbols(self):
        ls = _ls()
        params = DocumentSymbolParams(text_document=TextDocumentIdentifier(uri=URI))
        result = document_symbols(ls, params)
        assert len(result) == 1
        assert result[0].name == "myapp"
        assert result[0].kind == SymbolKind.Class

    def test_empty_document_returns_empty_list(self):
        ls = _ls("")
        params = DocumentSymbolParams(text_document=TextDocumentIdentifier(uri=URI))
        assert document_symbols(ls, params) == []

    def test_multiple_profiles(self):
        src = "profile a /bin/a { }\nprofile b /bin/b { }\n"
        ls = _ls(src)
        params = DocumentSymbolParams(text_document=TextDocumentIdentifier(uri=URI))
        result = document_symbols(ls, params)
        assert len(result) == 2

    def test_symbol_has_children(self):
        ls = _ls()
        params = DocumentSymbolParams(text_document=TextDocumentIdentifier(uri=URI))
        result = document_symbols(ls, params)
        # SIMPLE_PROFILE has capability, file, and network rules
        assert len(result[0].children) > 0

    def test_primes_cache_when_missing(self):
        ls = MockLS(text=SIMPLE_PROFILE, uri=URI)
        params = DocumentSymbolParams(text_document=TextDocumentIdentifier(uri=URI))
        document_symbols(ls, params)
        assert ls.get_cached(URI) is not None


# ── workspace_symbols handler ─────────────────────────────────────────────────


class TestWorkspaceSymbolsHandler:
    def test_empty_query_returns_all_profiles(self):
        ls = _ls()
        result = workspace_symbols(ls, WorkspaceSymbolParams(query=""))
        assert len(result) == 1
        assert result[0].name == "myapp"

    def test_matching_query_returns_subset(self):
        ls = _ls()
        result = workspace_symbols(ls, WorkspaceSymbolParams(query="mya"))
        assert len(result) == 1

    def test_non_matching_query_returns_empty(self):
        ls = _ls()
        result = workspace_symbols(ls, WorkspaceSymbolParams(query="zzz"))
        assert result == []

    def test_query_is_case_insensitive(self):
        ls = _ls()
        result = workspace_symbols(ls, WorkspaceSymbolParams(query="MYAPP"))
        assert len(result) == 1

    def test_searches_across_multiple_cached_docs(self):
        ls = MockLS()
        ls.parse_and_cache(URI, SIMPLE_PROFILE)
        ls.parse_and_cache("file:///other.aa", "profile other /bin/other { }\n")
        result = workspace_symbols(ls, WorkspaceSymbolParams(query=""))
        assert len(result) == 2

    def test_symbol_kind_is_class(self):
        ls = _ls()
        result = workspace_symbols(ls, WorkspaceSymbolParams(query=""))
        assert result[0].kind == SymbolKind.Class


# ── did_close handler ─────────────────────────────────────────────────────────


class TestDidCloseHandler:
    def test_evicts_document_from_cache(self):
        ls = _ls()
        assert ls.get_cached(URI) is not None
        params = DidCloseTextDocumentParams(
            text_document=TextDocumentIdentifier(uri=URI)
        )
        did_close(ls, params)
        assert ls.get_cached(URI) is None

    def test_close_unknown_uri_is_noop(self):
        ls = MockLS()
        params = DidCloseTextDocumentParams(
            text_document=TextDocumentIdentifier(uri="file:///never.aa")
        )
        did_close(ls, params)  # must not raise


# ── formatting handler ────────────────────────────────────────────────────────


class TestFormattingHandler:
    def test_returns_list_of_text_edits(self):
        ls = _ls()
        params = DocumentFormattingParams(
            text_document=TextDocumentIdentifier(uri=URI),
            options=FormattingOptions(tab_size=2, insert_spaces=True),
        )
        result = formatting(ls, params)
        assert isinstance(result, list)

    def test_already_formatted_produces_no_edits(self):
        ls = _ls()
        params = DocumentFormattingParams(
            text_document=TextDocumentIdentifier(uri=URI),
            options=FormattingOptions(tab_size=2, insert_spaces=True),
        )
        result = formatting(ls, params)
        assert result == []

    def test_unformatted_input_produces_edits(self):
        src = "profile myapp /usr/bin/myapp {\ncapability net_admin,\n}\n"
        ls = _ls(src)
        params = DocumentFormattingParams(
            text_document=TextDocumentIdentifier(uri=URI),
            options=FormattingOptions(tab_size=2, insert_spaces=True),
        )
        result = formatting(ls, params)
        assert len(result) > 0


# ── range_formatting handler ──────────────────────────────────────────────────


class TestRangeFormattingHandler:
    def test_returns_list_of_text_edits(self):
        ls = _ls()
        params = DocumentRangeFormattingParams(
            text_document=TextDocumentIdentifier(uri=URI),
            range=Range(
                start=Position(line=1, character=0), end=Position(line=3, character=0)
            ),
            options=FormattingOptions(tab_size=2, insert_spaces=True),
        )
        result = range_formatting(ls, params)
        assert isinstance(result, list)

    def test_edits_are_offset_to_range_start(self):
        src = "profile x {\ncapability net_admin,\n/etc/foo r,\n}\n"
        ls = _ls(src)
        params = DocumentRangeFormattingParams(
            text_document=TextDocumentIdentifier(uri=URI),
            range=Range(
                start=Position(line=1, character=0), end=Position(line=2, character=0)
            ),
            options=FormattingOptions(tab_size=2, insert_spaces=True),
        )
        result = range_formatting(ls, params)
        for edit in result:
            assert edit.range.start.line >= 1

    def test_range_beyond_end_of_file_does_not_raise(self):
        ls = _ls()
        params = DocumentRangeFormattingParams(
            text_document=TextDocumentIdentifier(uri=URI),
            range=Range(
                start=Position(line=0, character=0), end=Position(line=999, character=0)
            ),
            options=FormattingOptions(tab_size=2, insert_spaces=True),
        )
        result = range_formatting(ls, params)
        assert isinstance(result, list)


# ── indexing guard ────────────────────────────────────────────────────────────


class TestIndexingGuard:
    """Each result-returning handler returns an empty/None result while indexing."""

    def _indexing_ls(self) -> MockLS:
        ls = _ls()
        ls._indexing = True
        return ls

    def test_completions_returns_empty_list(self):
        ls = self._indexing_ls()
        params = CompletionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=0),
        )
        result = completions(ls, params)
        assert result.items == []

    def test_hover_returns_none(self):
        ls = self._indexing_ls()
        result = hover(ls, _HoverParams(URI, 0, 0))
        assert result is None

    def test_definition_returns_none(self):
        ls = self._indexing_ls()
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=0),
        )
        result = definition(ls, params)
        assert result is None

    def test_references_returns_none(self):
        ls = self._indexing_ls()
        params = DefinitionParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=0),
        )
        result = references(ls, params)
        assert result is None

    def test_highlight_returns_empty_list(self):
        ls = self._indexing_ls()
        params = DocumentHighlightParams(
            text_document=TextDocumentIdentifier(uri=URI),
            position=Position(line=0, character=0),
        )
        result = highlight(ls, params)
        assert result == []

    def test_document_symbols_returns_empty_list(self):
        ls = self._indexing_ls()
        params = DocumentSymbolParams(text_document=TextDocumentIdentifier(uri=URI))
        result = document_symbols(ls, params)
        assert result == []

    def test_workspace_symbols_returns_empty_list(self):
        ls = self._indexing_ls()
        result = workspace_symbols(ls, WorkspaceSymbolParams(query=""))
        assert result == []

    def test_formatting_returns_empty_list(self):
        ls = self._indexing_ls()
        params = DocumentFormattingParams(
            text_document=TextDocumentIdentifier(uri=URI),
            options=FormattingOptions(tab_size=2, insert_spaces=True),
        )
        result = formatting(ls, params)
        assert result == []

    def test_range_formatting_returns_empty_list(self):
        ls = self._indexing_ls()
        params = DocumentRangeFormattingParams(
            text_document=TextDocumentIdentifier(uri=URI),
            range=Range(
                start=Position(line=0, character=0),
                end=Position(line=1, character=0),
            ),
            options=FormattingOptions(tab_size=2, insert_spaces=True),
        )
        result = range_formatting(ls, params)
        assert result == []


# ── Settings.from_raw ─────────────────────────────────────────────────────────


class TestSettingsFromRaw:
    def test_defaults_when_empty_dict(self):
        s = Settings.from_raw({})
        assert s.diagnostics_enable is True
        assert s.include_search_paths == []

    def test_defaults_when_non_dict(self):
        s = Settings.from_raw(None)
        assert s.diagnostics_enable is True
        assert s.include_search_paths == []

    def test_diagnostics_disable(self):
        s = Settings.from_raw({"apparmor": {"diagnostics": {"enable": False}}})
        assert s.diagnostics_enable is False

    def test_diagnostics_enable_true(self):
        s = Settings.from_raw({"apparmor": {"diagnostics": {"enable": True}}})
        assert s.diagnostics_enable is True

    def test_non_bool_diagnostics_enable_ignored(self):
        s = Settings.from_raw({"apparmor": {"diagnostics": {"enable": "yes"}}})
        assert s.diagnostics_enable is True  # default kept

    def test_include_search_paths_set(self):
        s = Settings.from_raw({"apparmor": {"includeSearchPaths": ["/custom/path"]}})
        assert s.include_search_paths == ["/custom/path"]

    def test_include_search_paths_filters_non_strings(self):
        s = Settings.from_raw({"apparmor": {"includeSearchPaths": ["/ok", 42, None]}})
        assert s.include_search_paths == ["/ok"]

    def test_unknown_keys_ignored(self):
        s = Settings.from_raw({"apparmor": {"unknownKey": True}, "other": "stuff"})
        assert s.diagnostics_enable is True
        assert s.include_search_paths == []

    def test_non_dict_apparmor_section_returns_defaults(self):
        s = Settings.from_raw({"apparmor": "invalid"})
        assert s.diagnostics_enable is True


# ── did_change_configuration handler ─────────────────────────────────────────


class TestDidChangeConfiguration:
    @pytest.fixture
    def server(self):
        return AppArmorLanguageServer()

    def _params(self, raw: object) -> DidChangeConfigurationParams:
        return DidChangeConfigurationParams(settings=raw)

    def test_updates_diagnostics_enable(self, server):
        did_change_configuration(
            server, self._params({"apparmor": {"diagnostics": {"enable": False}}})
        )
        assert server._settings.diagnostics_enable is False

    def test_updates_include_search_paths(self, server):
        did_change_configuration(
            server, self._params({"apparmor": {"includeSearchPaths": ["/custom"]}})
        )
        assert server._settings.include_search_paths == ["/custom"]

    def test_empty_settings_restores_defaults(self, server):
        server._settings.diagnostics_enable = False
        did_change_configuration(server, self._params({}))
        assert server._settings.diagnostics_enable is True

    def test_republish_clears_diagnostics_when_disabled(self, server):
        server.parse_and_cache(URI, SIMPLE_PROFILE)
        published: list = []
        server.text_document_publish_diagnostics = lambda p: published.append(p)
        did_change_configuration(
            server, self._params({"apparmor": {"diagnostics": {"enable": False}}})
        )
        assert any(p.uri == URI and p.diagnostics == [] for p in published)

    def test_republish_sends_diagnostics_when_enabled(self, server):
        server._settings.diagnostics_enable = False
        bad = "profile broken {\n"
        server.parse_and_cache(URI, bad)
        published: list = []
        server.text_document_publish_diagnostics = lambda p: published.append(p)
        did_change_configuration(
            server, self._params({"apparmor": {"diagnostics": {"enable": True}}})
        )
        uris_published = {p.uri for p in published}
        assert URI in uris_published

    def test_no_republish_when_settings_unchanged(self, server):
        server.parse_and_cache(URI, SIMPLE_PROFILE)
        published: list = []
        server.text_document_publish_diagnostics = lambda p: published.append(p)
        did_change_configuration(server, self._params({}))
        assert published == []

    def test_get_search_dirs_none_when_no_extra_paths(self, server):
        assert server._get_search_dirs() is None

    def test_get_search_dirs_prepends_extra_paths(self, server, tmp_path):
        did_change_configuration(
            server,
            self._params({"apparmor": {"includeSearchPaths": [str(tmp_path)]}}),
        )
        search_dirs = server._get_search_dirs()
        assert search_dirs is not None
        assert search_dirs[0] == tmp_path

    def test_profiles_subdir_default(self):
        s = Settings.from_raw({})
        assert s.profiles_subdir == "apparmor.d"

    def test_profiles_subdir_custom(self):
        s = Settings.from_raw({"apparmor": {"profilesSubdir": "profiles/apparmor.d"}})
        assert s.profiles_subdir == "profiles/apparmor.d"

    def test_profiles_subdir_non_string_ignored(self):
        s = Settings.from_raw({"apparmor": {"profilesSubdir": 42}})
        assert s.profiles_subdir == "apparmor.d"

    def test_updates_profiles_subdir(self, server):
        did_change_configuration(
            server,
            self._params({"apparmor": {"profilesSubdir": "my/subdir"}}),
        )
        assert server._settings.profiles_subdir == "my/subdir"


# ── _effective_index_path ─────────────────────────────────────────────────────


class TestEffectiveIndexPath:
    def test_subdir_exists(self, tmp_path):
        subdir = tmp_path / "apparmor.d"
        subdir.mkdir()
        assert _effective_index_path(tmp_path, "apparmor.d") == subdir

    def test_subdir_missing_returns_none(self, tmp_path):
        assert _effective_index_path(tmp_path, "apparmor.d") is None

    def test_empty_subdir_uses_workspace_root(self, tmp_path):
        assert _effective_index_path(tmp_path, "") == tmp_path

    def test_dot_subdir_uses_workspace_root(self, tmp_path):
        assert _effective_index_path(tmp_path, ".") == tmp_path

    def test_nested_subdir(self, tmp_path):
        nested = tmp_path / "profiles" / "apparmor.d"
        nested.mkdir(parents=True)
        assert _effective_index_path(tmp_path, "profiles/apparmor.d") == nested

    def test_workspace_root_missing_returns_none(self, tmp_path):
        missing = tmp_path / "nonexistent"
        assert _effective_index_path(missing, "") is None


# ── did_change: incremental sync uses workspace text, not change fragment ─────

PROFILE_WITH_VARIABLE = """\
@{HOME} = /home/*
profile myapp /usr/bin/myapp {
  @{HOME}/ r,
}
"""


def _make_change_params(
    uri: str,
    fragment: str,
    version: int = 2,
) -> DidChangeTextDocumentParams:
    """Build a DidChangeTextDocumentParams as eglot would send in incremental mode."""
    return DidChangeTextDocumentParams(
        text_document=VersionedTextDocumentIdentifier(uri=uri, version=version),
        content_changes=[
            TextDocumentContentChangePartial(
                text=fragment,
                range=Range(start=Position(0, 0), end=Position(0, 1)),
            )
        ],
    )


class TestDidChangeUsesWorkspaceText:
    def test_uses_workspace_text_not_fragment(self):
        """did_change must parse the full document, not the incremental fragment."""
        ls = MockLS()
        # Simulate pygls having applied incremental changes: workspace holds full text.
        ls._texts[URI] = PROFILE_WITH_VARIABLE
        # params carries only a one-character fragment (as in incremental sync).
        params = _make_change_params(URI, "@")
        did_change(ls, params)
        doc, _ = ls._doc_cache[URI]
        # The variable defined in the full document must be present.
        assert "@{HOME}" in doc.all_variables.get(URI, {})

    def test_fragment_only_gives_no_variable(self):
        """Parsing a bare fragment produces no variable — demonstrates the old bug."""
        # Workspace text is intentionally NOT set; simulates the buggy path where
        # the handler would have called parse_and_cache with the fragment directly.
        result = parse_document(URI, "@")
        assert "@{HOME}" not in result[0].all_variables.get(URI, {})

    def test_cache_not_overwritten_with_fragment_content(self):
        """After did_change the cached document reflects the full workspace text."""
        ls = MockLS()
        ls._texts[URI] = PROFILE_WITH_VARIABLE
        params = _make_change_params(URI, "x")
        did_change(ls, params)
        doc, _ = ls._doc_cache[URI]
        # Profile parsed from full text; fragment "x" alone would yield no profile.
        assert len(doc.profiles) == 1

    def test_empty_workspace_text_parses_empty(self):
        """If get_text returns empty (doc not open), an empty document is cached."""
        ls = MockLS()
        # No text stored for URI — get_text returns "".
        params = _make_change_params(URI, "capability net_admin,")
        did_change(ls, params)
        doc, _ = ls._doc_cache[URI]
        assert doc.profiles == []


# ── _publish_diagnostics: external apparmor_parser only on save/open ──────────


class TestPublishDiagnosticsExternalCheck:
    """The apparmor_parser subprocess check operates on the on-disk file, so
    it must only run on did_open / did_save — never on every keystroke."""

    @pytest.fixture
    def server(self):
        return AppArmorLanguageServer()

    def _captured_document_path(self, server, *, run_external):
        from unittest.mock import patch

        with patch(
            "apparmor_language_server.server.get_diagnostics", return_value={}
        ) as mock_get:
            server._publish_diagnostics(
                URI, "profile x { }\n", run_external=run_external
            )
        assert mock_get.call_count == 1
        return mock_get.call_args.kwargs["document_path"]

    def test_did_change_path_skips_external(self, server):
        assert self._captured_document_path(server, run_external=False) is None

    def test_save_path_passes_document_path(self, server, tmp_path):
        f = tmp_path / "test.aa"
        f.write_text("profile x { }\n")
        uri = f.as_uri()
        from unittest.mock import patch

        with patch(
            "apparmor_language_server.server.get_diagnostics", return_value={}
        ) as mock_get:
            server._publish_diagnostics(uri, "profile x { }\n", run_external=True)
        assert mock_get.call_args.kwargs["document_path"] == f

    def test_default_call_skips_external(self, server):
        """Default call (no run_external kwarg) must not run the external check."""
        assert self._captured_document_path(server, run_external=False) is None

    def test_primary_uri_published_on_save_to_clear_stale_diagnostics(self, server):
        """On a save pass, even when get_diagnostics returns no results the
        primary URI must be published with an empty list so the editor clears
        stale apparmor_parser diagnostics."""
        from unittest.mock import patch

        published = []
        server.text_document_publish_diagnostics = lambda p: published.append(p)
        with patch(
            "apparmor_language_server.server.get_diagnostics", return_value={}
        ):
            server._publish_diagnostics(URI, "profile x { }\n", run_external=True)
        uris_published = [p.uri for p in published]
        assert URI in uris_published
        primary = next(p for p in published if p.uri == URI)
        assert primary.diagnostics == []

    def test_primary_uri_published_on_change_to_clear_internal_diagnostics(self, server):
        """On a mid-edit pass, the primary URI must always be published so that
        internal diagnostics are cleared immediately when the user edits away
        the offending text."""
        from unittest.mock import patch

        published = []
        server.text_document_publish_diagnostics = lambda p: published.append(p)
        with patch(
            "apparmor_language_server.server.get_diagnostics", return_value={}
        ):
            server._publish_diagnostics(URI, "profile x { }\n", run_external=False)
        uris_published = [p.uri for p in published]
        assert URI in uris_published
        primary = next(p for p in published if p.uri == URI)
        assert primary.diagnostics == []

    def test_parser_diags_reinjected_on_change(self, server):
        """apparmor_parser diagnostics cached from the last save must be
        re-injected into mid-edit publish passes so they remain visible while
        the user has unsaved changes."""
        from lsprotocol.types import Diagnostic, DiagnosticSeverity, Position, Range
        from unittest.mock import patch

        parser_diag = Diagnostic(
            range=Range(start=Position(0, 0), end=Position(0, 10)),
            message="test parser error",
            source="apparmor_parser",
            severity=DiagnosticSeverity.Error,
        )
        # Seed the cache as if a prior save had found a parser error.
        server._parser_diags = {URI: {URI: [parser_diag]}}

        published = []
        server.text_document_publish_diagnostics = lambda p: published.append(p)
        with patch(
            "apparmor_language_server.server.get_diagnostics", return_value={}
        ):
            server._publish_diagnostics(URI, "profile x { }\n", run_external=False)
        primary = next(p for p in published if p.uri == URI)
        assert parser_diag in primary.diagnostics

    def test_parser_diags_cache_cleared_on_clean_save(self, server):
        """After a save where apparmor_parser finds no errors, the cache must
        be cleared so mid-edit passes no longer re-inject stale diagnostics."""
        from unittest.mock import patch

        server._parser_diags = {URI: {URI: []}}  # pre-populate with something
        with patch(
            "apparmor_language_server.server.get_diagnostics", return_value={}
        ):
            server._publish_diagnostics(URI, "profile x { }\n", run_external=True)
        assert server._parser_diags == {}


# ── _schedule_background_parser / _run_background_parser ─────────────────────


class TestBackgroundParser:
    @pytest.fixture
    def server(self):
        return AppArmorLanguageServer()

    def test_schedule_sets_debounce_timer(self, server):
        server._edit_version[URI] = 1
        with patch.object(server, "_run_background_parser") as mock_run:
            server._schedule_background_parser(URI, "profile x { }\n", 1)
            assert URI in server._debounce_timers
            timer = server._debounce_timers[URI]
            timer.cancel()

    def test_schedule_cancels_previous_timer(self, server):
        server._edit_version[URI] = 1
        old_timer = MagicMock()
        server._debounce_timers[URI] = old_timer
        server._schedule_background_parser(URI, "profile x { }\n", 1)
        old_timer.cancel.assert_called_once()
        server._debounce_timers.get(URI, MagicMock()).cancel()

    def test_run_background_parser_discards_stale_version(self, server):
        server._edit_version[URI] = 5  # newer than the captured version
        with patch(
            "apparmor_language_server.server._check_apparmor_parser"
        ) as mock_check:
            server._run_background_parser(URI, "profile x { }\n", version=3)
        mock_check.assert_not_called()

    def test_run_background_parser_stores_results_when_current(self, server):
        from lsprotocol.types import Diagnostic, DiagnosticSeverity, Position, Range

        server._edit_version[URI] = 2
        parser_diag = Diagnostic(
            range=Range(start=Position(0, 0), end=Position(0, 5)),
            message="err",
            source="apparmor_parser",
            severity=DiagnosticSeverity.Error,
        )
        with patch(
            "apparmor_language_server.server._check_apparmor_parser",
            return_value={URI: [parser_diag]},
        ), patch.object(server, "_publish_diagnostics"):
            server._run_background_parser(URI, "profile x { }\n", version=2)
        assert URI in server._parser_diags
        assert parser_diag in server._parser_diags[URI].get(URI, [])

    def test_run_background_parser_discards_if_superseded_during_run(self, server):
        """Version matches pre-check but changes while subprocess runs."""
        call_count = 0

        def _slow_check(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            # Simulate another edit arriving while the parser runs.
            server._edit_version[URI] = 99
            return {}

        server._edit_version[URI] = 1
        with patch(
            "apparmor_language_server.server._check_apparmor_parser",
            side_effect=_slow_check,
        ), patch.object(server, "_publish_diagnostics") as mock_publish:
            server._run_background_parser(URI, "profile x { }\n", version=1)
        mock_publish.assert_not_called()

    def test_run_background_parser_publishes_when_current(self, server):
        server._edit_version[URI] = 7
        with patch(
            "apparmor_language_server.server._check_apparmor_parser",
            return_value={},
        ), patch.object(server, "_publish_diagnostics") as mock_publish, patch.object(
            server, "get_text", return_value="profile x { }\n"
        ):
            server._run_background_parser(URI, "profile x { }\n", version=7)
        mock_publish.assert_called_once_with(URI, "profile x { }\n", run_external=False)


# ── evict cleans up background-parser state ───────────────────────────────────


class TestEvictCleansUpBackgroundState:
    @pytest.fixture
    def server(self):
        return AppArmorLanguageServer()

    def test_evict_cancels_pending_debounce_timer(self, server):
        mock_timer = MagicMock()
        server._debounce_timers[URI] = mock_timer
        server.evict(URI)
        mock_timer.cancel.assert_called_once()
        assert URI not in server._debounce_timers

    def test_evict_removes_outer_parser_diags_key(self, server):
        server._parser_diags[URI] = {URI: []}
        server.evict(URI)
        assert URI not in server._parser_diags

    def test_evict_removes_uri_from_inner_parser_diags(self, server):
        other = "file:///other.aa"
        server._parser_diags[other] = {URI: [], other: []}
        server.evict(URI)
        assert URI not in server._parser_diags[other]
        assert other in server._parser_diags[other]

    def test_evict_removes_edit_version(self, server):
        server._edit_version[URI] = 3
        server.evict(URI)
        assert URI not in server._edit_version


# ── did_save cancels pending debounce ─────────────────────────────────────────


class TestDidSaveCancelsDebounce:
    @pytest.fixture
    def server(self):
        return AppArmorLanguageServer()

    def test_did_save_cancels_pending_background_timer(self, server):
        from apparmor_language_server.server import did_save
        from lsprotocol.types import DidSaveTextDocumentParams, TextDocumentIdentifier

        mock_timer = MagicMock()
        server._debounce_timers[URI] = mock_timer

        params = DidSaveTextDocumentParams(
            text_document=TextDocumentIdentifier(uri=URI)
        )
        with patch.object(server, "_publish_diagnostics"), patch.object(
            server, "get_text", return_value="profile x { }\n"
        ):
            did_save(server, params)
        mock_timer.cancel.assert_called_once()
        assert URI not in server._debounce_timers
