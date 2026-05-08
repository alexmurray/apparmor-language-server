"""Tests for apparmor_language_server.constants."""

from __future__ import annotations

from pathlib import Path

from apparmor_language_server.constants import _compute_include_search_dirs


class TestComputeIncludeSearchDirs:
    def test_without_snap_returns_host_paths(self, monkeypatch):
        monkeypatch.delenv("SNAP", raising=False)
        dirs = _compute_include_search_dirs()
        assert Path("/etc/apparmor.d") in dirs
        assert not any(str(d).startswith("/var/lib/snapd/hostfs") for d in dirs)

    def test_with_snap_prefixes_hostfs(self, monkeypatch):
        monkeypatch.setenv("SNAP", "/snap/apparmor-language-server/current")
        dirs = _compute_include_search_dirs()
        assert Path("/var/lib/snapd/hostfs/etc/apparmor.d") in dirs
        assert not any(str(d) == "/etc/apparmor.d" for d in dirs)

    def test_with_snap_no_host_paths_leaked(self, monkeypatch):
        monkeypatch.setenv("SNAP", "/snap/apparmor-language-server/current")
        dirs = _compute_include_search_dirs()
        assert all(str(d).startswith("/var/lib/snapd/hostfs") for d in dirs)

    def test_returns_independent_list(self, monkeypatch):
        monkeypatch.delenv("SNAP", raising=False)
        a = _compute_include_search_dirs()
        b = _compute_include_search_dirs()
        a.clear()
        assert len(b) > 0
