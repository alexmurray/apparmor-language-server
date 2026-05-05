"""
AppArmor LSP – background workspace indexer and inotify file watcher.

Responsibilities:
  - Walk workspace directories and parse every AppArmor profile found,
    populating AppArmorLanguageServer._doc_cache without re-parsing files
    that are already cached.
  - Watch indexed directories for changes and keep the cache up to date
    as files are created, modified, moved, or deleted.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import inotify_simple
from inotify_simple import flags

from .parser import Parser

if TYPE_CHECKING:
    from .server import AppArmorLanguageServer

logger = logging.getLogger(__name__)

# Watch for file-content changes, new files/dirs, deletions, and renames.
_WATCH_MASK = (
    flags.CLOSE_WRITE | flags.CREATE | flags.DELETE | flags.MOVED_FROM | flags.MOVED_TO
)


def _is_hidden(path: Path) -> bool:
    """Return True if any component of *path* (other than the root "/") starts with "."."""
    return any(part.startswith(".") for part in path.parts if part != "/")


class WorkspaceIndexer:
    """Background indexer and inotify watcher for a workspace."""

    def __init__(self, server: AppArmorLanguageServer) -> None:
        self._server = server
        self._inotify = inotify_simple.INotify()
        # watch-descriptor → directory Path
        self._wd_to_dir: dict[int, Path] = {}
        self._watch_lock = threading.Lock()
        self._stop = threading.Event()

        watcher = threading.Thread(
            target=self._watch_loop, daemon=True, name="apparmor-lsp-watcher"
        )
        watcher.start()

    # ── Public API ────────────────────────────────────────────────────────────

    def index_and_watch(self, paths: list[Path]) -> None:
        """Kick off background indexing + watching for *paths*; returns immediately."""
        logger.debug("Scheduling indexing for %d path(s): %s", len(paths), paths)
        self._server._indexing = True
        t = threading.Thread(
            target=self._index_run,
            args=(paths,),
            daemon=True,
            name="apparmor-lsp-indexer",
        )
        t.start()

    def watch_new_folder(self, path: Path) -> None:
        """Index and watch a newly-discovered folder."""
        self.index_and_watch([path])

    def unwatch_folder(self, path: Path) -> None:
        """Remove all inotify watches whose path starts with *path*."""
        prefix = str(path)
        with self._watch_lock:
            to_remove = [
                wd
                for wd, watched_dir in self._wd_to_dir.items()
                if str(watched_dir).startswith(prefix)
            ]
            logger.debug("Unwatching %s (%d descriptor(s))", path, len(to_remove))
            for wd in to_remove:
                try:
                    self._inotify.rm_watch(wd)
                except OSError:
                    pass
                del self._wd_to_dir[wd]

    def stop(self) -> None:
        """Signal the watcher thread to stop and close the inotify fd."""
        self._stop.set()
        self._inotify.close()

    # ── Indexing ──────────────────────────────────────────────────────────────

    def _index_run(self, paths: list[Path]) -> None:
        """Entry point for the indexer thread. Sets _indexing=False when done."""
        try:
            for path in paths:
                if path.is_dir():
                    self._index_dir(path)
                    self._watch_dir_tree(path)
        finally:
            self._server._indexing = False
            with self._server._cache_lock:
                n = len(self._server._doc_cache)
            logger.debug("Indexing complete; cache now contains %d document(s)", n)

    def _index_dir(self, root: Path) -> None:
        """Recursively index all non-hidden regular files under *root*."""
        try:
            for path in root.rglob("*"):
                if _is_hidden(path):
                    continue
                if path.is_file():
                    self._index_file(path)
        except PermissionError as exc:
            logger.debug("Permission denied scanning %s: %s", root, exc)

    def _index_file(self, path: Path) -> None:
        """Parse *path* and store the result in the server cache if not already present."""
        uri = path.as_uri()

        with self._server._cache_lock:
            if uri in self._server._doc_cache:
                return

        try:
            text = path.read_text(errors="replace")
        except OSError as exc:
            logger.debug("Could not read %s: %s", path, exc)
            return

        try:
            p = Parser(uri, text)
            doc = p.parse()
        except Exception as exc:
            logger.debug("Parse error in %s: %s", path, exc)
            return

        with self._server._cache_lock:
            if uri not in self._server._doc_cache:
                self._server._doc_cache[uri] = (doc, p.errors)
                logger.debug("Cached %s", path)
            for inc_uri, inc_result in p.included_docs.items():
                if inc_uri not in self._server._doc_cache:
                    self._server._doc_cache[inc_uri] = inc_result

    # ── Watching ──────────────────────────────────────────────────────────────

    def _watch_dir_tree(self, root: Path) -> None:
        """Add inotify watches for *root* and all of its subdirectories."""
        self._add_watch(root)
        try:
            for subdir in root.rglob("*"):
                if _is_hidden(subdir):
                    continue
                if subdir.is_dir():
                    self._add_watch(subdir)
        except PermissionError as exc:
            logger.debug("Permission denied watching %s: %s", root, exc)

    def _add_watch(self, path: Path) -> None:
        """Register an inotify watch on *path* if not already watched."""
        with self._watch_lock:
            if path in self._wd_to_dir.values():
                return
            try:
                wd = self._inotify.add_watch(str(path), _WATCH_MASK)
                self._wd_to_dir[wd] = path
                logger.debug("Watching %s (wd=%d)", path, wd)
            except OSError as exc:
                logger.debug("Could not watch %s: %s", path, exc)

    def _watch_loop(self) -> None:
        """Read inotify events in a loop until stopped."""
        while not self._stop.is_set():
            try:
                events = self._inotify.read(timeout=500)
            except (OSError, ValueError):
                if self._stop.is_set():
                    return
                raise
            for event in events:
                try:
                    self._handle_event(event)
                except Exception as exc:
                    logger.debug("Error handling inotify event %s: %s", event, exc)

    def _handle_event(self, event: inotify_simple.Event) -> None:
        """Dispatch a single inotify event to the appropriate handler."""
        with self._watch_lock:
            watch_dir = self._wd_to_dir.get(event.wd)
        if watch_dir is None:
            return

        if not event.name:
            return

        path = watch_dir / event.name

        if _is_hidden(path):
            return

        event_flags = flags.from_mask(event.mask)
        is_dir = flags.ISDIR in event_flags

        if is_dir and flags.CREATE in event_flags:
            logger.debug("New directory: %s", path)
            self._add_watch(path)
        elif not is_dir and (
            flags.CLOSE_WRITE in event_flags or flags.MOVED_TO in event_flags
        ):
            logger.debug("File updated: %s", path)
            self._index_file(path)
        elif not is_dir and (
            flags.DELETE in event_flags or flags.MOVED_FROM in event_flags
        ):
            logger.debug("File removed: %s", path)
            uri = path.as_uri()
            with self._server._cache_lock:
                self._server._doc_cache.pop(uri, None)
