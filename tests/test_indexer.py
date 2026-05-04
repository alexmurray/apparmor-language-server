"""
Tests for apparmor_language_server/indexer.py.
Run with: pytest tests/test_indexer.py -v
"""

from __future__ import annotations

import threading
import time

import inotify_simple
from inotify_simple import flags

from apparmor_language_server.indexer import WorkspaceIndexer, _is_hidden
from apparmor_language_server.parser import DocumentNode


# ── Server stub ───────────────────────────────────────────────────────────────


class MockServerForIndexer:
    def __init__(self):
        self._doc_cache: dict = {}
        self._cache_lock = threading.RLock()
        self._indexing = False


# ── Fixtures ──────────────────────────────────────────────────────────────────


import pytest


@pytest.fixture
def mock_server():
    return MockServerForIndexer()


@pytest.fixture
def indexer(mock_server):
    idx = WorkspaceIndexer(mock_server)
    yield idx
    idx.stop()


# ── _is_hidden ────────────────────────────────────────────────────────────────


class TestIsHidden:
    def test_visible_file(self, tmp_path):
        assert not _is_hidden(tmp_path / "visible.aa")

    def test_hidden_file(self, tmp_path):
        assert _is_hidden(tmp_path / ".hidden")

    def test_hidden_subdir(self, tmp_path):
        assert _is_hidden(tmp_path / ".dir" / "file.aa")

    def test_visible_file_in_visible_subdir(self, tmp_path):
        assert not _is_hidden(tmp_path / "subdir" / "file.aa")

    def test_root_slash_not_treated_as_hidden(self):
        from pathlib import Path
        assert not _is_hidden(Path("/etc/apparmor.d/usr.bin.test"))


# ── _index_file ───────────────────────────────────────────────────────────────


class TestIndexFile:
    def test_adds_valid_profile_to_cache(self, tmp_path, indexer, mock_server):
        f = tmp_path / "test.aa"
        f.write_text("profile test /bin/test { }\n")
        indexer._index_file(f)
        assert f.as_uri() in mock_server._doc_cache

    def test_cache_entry_has_document_node(self, tmp_path, indexer, mock_server):
        f = tmp_path / "test.aa"
        f.write_text("profile test /bin/test { }\n")
        indexer._index_file(f)
        doc, errors = mock_server._doc_cache[f.as_uri()]
        assert isinstance(doc, DocumentNode)
        assert isinstance(errors, list)

    def test_skips_already_cached_uri(self, tmp_path, indexer, mock_server):
        f = tmp_path / "test.aa"
        f.write_text("profile test /bin/test { }\n")
        sentinel = (DocumentNode(uri=f.as_uri()), [])
        mock_server._doc_cache[f.as_uri()] = sentinel
        indexer._index_file(f)
        assert mock_server._doc_cache[f.as_uri()] is sentinel

    def test_includes_are_cached_transitively(self, tmp_path, indexer, mock_server):
        inc = tmp_path / "inc"
        inc.write_text("@{VAR} = /foo\n")
        parent = tmp_path / "parent.aa"
        parent.write_text(f'include "{inc.name}"\nprofile x {{ }}\n')
        indexer._index_file(parent)
        assert inc.as_uri() in mock_server._doc_cache


# ── _index_dir ────────────────────────────────────────────────────────────────


class TestIndexDir:
    def test_indexes_all_regular_files(self, tmp_path, indexer, mock_server):
        (tmp_path / "a.aa").write_text("profile a { }\n")
        (tmp_path / "b.aa").write_text("profile b { }\n")
        indexer._index_dir(tmp_path)
        assert (tmp_path / "a.aa").as_uri() in mock_server._doc_cache
        assert (tmp_path / "b.aa").as_uri() in mock_server._doc_cache

    def test_skips_hidden_files(self, tmp_path, indexer, mock_server):
        (tmp_path / ".hidden").write_text("profile h { }\n")
        (tmp_path / "visible.aa").write_text("profile v { }\n")
        indexer._index_dir(tmp_path)
        assert (tmp_path / ".hidden").as_uri() not in mock_server._doc_cache
        assert (tmp_path / "visible.aa").as_uri() in mock_server._doc_cache

    def test_skips_hidden_subdirs(self, tmp_path, indexer, mock_server):
        hidden = tmp_path / ".secret"
        hidden.mkdir()
        (hidden / "file.aa").write_text("profile x { }\n")
        indexer._index_dir(tmp_path)
        assert (hidden / "file.aa").as_uri() not in mock_server._doc_cache

    def test_recurses_into_visible_subdirs(self, tmp_path, indexer, mock_server):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "deep.aa").write_text("profile deep { }\n")
        indexer._index_dir(tmp_path)
        assert (sub / "deep.aa").as_uri() in mock_server._doc_cache


# ── _handle_event ─────────────────────────────────────────────────────────────


class TestHandleEvent:
    FAKE_WD = 99

    def _register_dir(self, indexer, path):
        indexer._wd_to_dir[self.FAKE_WD] = path

    def _event(self, name: str, mask: int) -> inotify_simple.Event:
        return inotify_simple.Event(wd=self.FAKE_WD, mask=mask, cookie=0, name=name)

    def test_close_write_indexes_file(self, tmp_path, indexer, mock_server):
        f = tmp_path / "test.aa"
        f.write_text("profile test { }\n")
        self._register_dir(indexer, tmp_path)
        indexer._handle_event(self._event("test.aa", int(flags.CLOSE_WRITE)))
        assert f.as_uri() in mock_server._doc_cache

    def test_moved_to_indexes_file(self, tmp_path, indexer, mock_server):
        f = tmp_path / "test.aa"
        f.write_text("profile test { }\n")
        self._register_dir(indexer, tmp_path)
        indexer._handle_event(self._event("test.aa", int(flags.MOVED_TO)))
        assert f.as_uri() in mock_server._doc_cache

    def test_delete_evicts_from_cache(self, tmp_path, indexer, mock_server):
        f = tmp_path / "test.aa"
        mock_server._doc_cache[f.as_uri()] = (DocumentNode(uri=f.as_uri()), [])
        self._register_dir(indexer, tmp_path)
        indexer._handle_event(self._event("test.aa", int(flags.DELETE)))
        assert f.as_uri() not in mock_server._doc_cache

    def test_moved_from_evicts_from_cache(self, tmp_path, indexer, mock_server):
        f = tmp_path / "test.aa"
        mock_server._doc_cache[f.as_uri()] = (DocumentNode(uri=f.as_uri()), [])
        self._register_dir(indexer, tmp_path)
        indexer._handle_event(self._event("test.aa", int(flags.MOVED_FROM)))
        assert f.as_uri() not in mock_server._doc_cache

    def test_hidden_file_ignored_on_close_write(self, tmp_path, indexer, mock_server):
        self._register_dir(indexer, tmp_path)
        indexer._handle_event(self._event(".hidden.aa", int(flags.CLOSE_WRITE)))
        assert len(mock_server._doc_cache) == 0

    def test_unknown_wd_is_noop(self, tmp_path, indexer, mock_server):
        event = inotify_simple.Event(wd=9999, mask=int(flags.CLOSE_WRITE), cookie=0, name="x.aa")
        indexer._handle_event(event)  # must not raise

    def test_empty_name_is_noop(self, tmp_path, indexer, mock_server):
        self._register_dir(indexer, tmp_path)
        event = inotify_simple.Event(wd=self.FAKE_WD, mask=int(flags.CLOSE_WRITE), cookie=0, name="")
        indexer._handle_event(event)  # must not raise
        assert len(mock_server._doc_cache) == 0

    def test_isdir_create_adds_watch(self, tmp_path, indexer, mock_server):
        new_dir = tmp_path / "newdir"
        new_dir.mkdir()
        self._register_dir(indexer, tmp_path)
        mask = int(flags.CREATE | flags.ISDIR)
        indexer._handle_event(self._event("newdir", mask))
        assert new_dir in indexer._wd_to_dir.values()


# ── unwatch_folder ────────────────────────────────────────────────────────────


class TestUnwatchFolder:
    def test_removes_watches_under_path(self, tmp_path, indexer):
        sub1 = tmp_path / "a"
        sub2 = tmp_path / "b"
        from pathlib import Path
        other = Path("/tmp")
        # inject fake watch descriptors (rm_watch will fail gracefully via OSError catch)
        indexer._wd_to_dir[1] = tmp_path
        indexer._wd_to_dir[2] = sub1
        indexer._wd_to_dir[3] = sub2
        indexer._wd_to_dir[4] = other
        indexer.unwatch_folder(tmp_path)
        watched = set(indexer._wd_to_dir.values())
        assert tmp_path not in watched
        assert sub1 not in watched
        assert sub2 not in watched
        assert other in watched

    def test_unwatch_nonexistent_path_is_noop(self, tmp_path, indexer):
        from pathlib import Path
        indexer.unwatch_folder(Path("/no/such/path"))  # must not raise


# ── stop ──────────────────────────────────────────────────────────────────────


class TestStop:
    def test_stop_sets_stop_event(self, mock_server):
        idx = WorkspaceIndexer(mock_server)
        assert not idx._stop.is_set()
        idx.stop()
        assert idx._stop.is_set()


# ── index_and_watch ───────────────────────────────────────────────────────────


class TestIndexAndWatch:
    def test_sets_indexing_true_then_false(self, tmp_path, mock_server):
        (tmp_path / "test.aa").write_text("profile test { }\n")
        idx = WorkspaceIndexer(mock_server)
        idx.index_and_watch([tmp_path])
        deadline = time.monotonic() + 5
        while mock_server._indexing and time.monotonic() < deadline:
            time.sleep(0.01)
        idx.stop()
        assert not mock_server._indexing

    def test_files_indexed_after_completion(self, tmp_path, mock_server):
        f = tmp_path / "test.aa"
        f.write_text("profile test { }\n")
        idx = WorkspaceIndexer(mock_server)
        idx.index_and_watch([tmp_path])
        deadline = time.monotonic() + 5
        while mock_server._indexing and time.monotonic() < deadline:
            time.sleep(0.01)
        idx.stop()
        assert f.as_uri() in mock_server._doc_cache
