"""
Tests for apparmor_language_server/server.py.
Run with: pytest tests/test_server.py -v
"""

from __future__ import annotations

import pytest
from lsprotocol.types import (
    CompletionParams,
    DefinitionParams,
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
    TextDocumentIdentifier,
    WorkspaceSymbolParams,
)

from apparmor_language_server.parser import (
    CapabilityNode,
    FileRuleNode,
    IncludeNode,
    NetworkNode,
    parse_document,
)
from apparmor_language_server.server import (
    AppArmorLanguageServer,
    _node_to_symbol,
    _profile_to_symbol,
    _word_at_position,
    completions,
    definition,
    did_close,
    document_symbols,
    formatting,
    highlight,
    hover,
    range_formatting,
    references,
    workspace_symbols,
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
        if text:
            self._texts[uri] = text

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
