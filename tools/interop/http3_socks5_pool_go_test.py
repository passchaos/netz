#!/usr/bin/env python3
"""Local Go SDK discovery regressions; no toolchain downloads or builds."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import http3_socks5_pool as pool


class FindGoTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "home"
        self.gopath = self.root / "gopath"
        self.executables: set[str] = set()
        self.run = subprocess.run
        access = os.access
        patches = (
            mock.patch.dict(
                os.environ,
                {"GOPATH": str(self.gopath), "GOTOOLCHAIN": "auto"},
                clear=True,
            ),
            mock.patch.object(pool.Path, "home", return_value=self.home),
            mock.patch.object(pool.shutil, "which", return_value=None),
            mock.patch.object(pool.glob, "glob", return_value=[]),
            mock.patch.object(
                pool.os,
                "access",
                side_effect=lambda path, mode: str(path) in self.executables
                and access(path, mode),
            ),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def go(self, path: Path, version: str, returncode: int = 0) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "if sys.argv[1:] != ['env', 'GOVERSION']: sys.exit(90)\n"
            "if os.environ.get('GOTOOLCHAIN') != 'local': sys.exit(91)\n"
            f"print({version!r})\n"
            f"sys.exit({returncode})\n"
        )
        path.chmod(0o755)
        self.executables.add(str(path.resolve()))
        return path

    def cached(self, root: Path, sdk: str, version: str, returncode: int = 0) -> Path:
        return self.go(
            root / "pkg/mod/golang.org" / f"toolchain@v0.0.1-go{sdk}.linux-amd64/bin/go",
            version,
            returncode,
        )

    def test_selects_supported_cached_sdk_after_invalid_candidate(self) -> None:
        self.cached(self.gopath, "1.99.0", "not a Go version")
        expected = self.cached(self.gopath, "1.26.8", "go1.26.8")
        self.cached(self.gopath, "1.23.9", "go1.23.9")
        self.assertEqual(pool.find_go(), str(expected))

    def test_explicit_go_bin_precedes_path_and_newer_cached_sdk(self) -> None:
        expected = self.go(self.root / "override/go", "go1.24.0")
        other = self.go(self.root / "path/go", "go1.25.0")
        self.cached(self.gopath, "1.26.8", "go1.26.8")
        os.environ["GO_BIN"] = str(expected)
        with mock.patch.object(pool.shutil, "which", return_value=str(other)):
            self.assertEqual(pool.find_go(), str(expected))

    def test_unset_or_empty_gopath_uses_default_home_go_cache(self) -> None:
        expected = self.cached(self.home / "go", "1.24.0", "go1.24.0")
        for value in (None, ""):
            with self.subTest(gopath=value):
                if value is None:
                    os.environ.pop("GOPATH", None)
                else:
                    os.environ["GOPATH"] = value
                self.assertEqual(pool.find_go(), str(expected))

    def test_gopath_searches_each_root_and_respects_explicit_roots(self) -> None:
        first = self.root / "sdk [first]"
        second = self.root / "sdk second"
        self.cached(first, "1.23.9", "go1.23.9")
        expected = self.cached(second, "1.25.0", "go1.25.0")
        self.cached(self.home / "go", "1.26.8", "go1.26.8")
        os.environ["GOPATH"] = os.pathsep.join((str(first), "", str(second)))
        self.assertEqual(pool.find_go(), str(expected))

    def test_old_override_falls_back_and_duplicate_aliases_are_probed_once(self) -> None:
        old = self.cached(self.gopath, "1.23.9", "go1.23.9")
        alias = self.root / "old-go"
        alias.symlink_to(old)
        expected = self.cached(self.gopath, "1.24.0", "go1.24.0")
        os.environ["GO_BIN"] = str(alias)
        with (
            mock.patch.object(pool.shutil, "which", return_value=str(old)),
            mock.patch.object(pool.subprocess, "run", wraps=self.run) as run,
        ):
            self.assertEqual(pool.find_go(), str(expected))
        probes = [call.args[0][0] for call in run.call_args_list]
        self.assertEqual(probes.count(str(old)), 1)
        self.assertEqual(probes.count(str(expected)), 1)

    def test_rejects_old_invalid_and_failed_version_probes(self) -> None:
        for version, returncode in (
            ("go1.23.9", 0),
            ("1.24.0", 0),
            ("go1.24invalid", 0),
            ("go1.24.0 extra", 0),
            ("devel go1.27", 0),
            ("go1.26.8", 1),
        ):
            with self.subTest(version=version, returncode=returncode):
                self.cached(self.gopath, "1.99.0", version, returncode)
                with self.assertRaisesRegex(RuntimeError, "Go 1.24 or newer not found"):
                    pool.find_go()

    def test_skips_nonexecutable_and_invalid_executable_files(self) -> None:
        disabled = self.cached(self.gopath, "1.26.8", "go1.26.8")
        disabled.chmod(0o644)
        invalid = self.cached(self.gopath, "1.25.0", "go1.25.0")
        invalid.write_text("not an executable format\n")
        expected = self.cached(self.gopath, "1.24.0", "go1.24.0")
        self.assertEqual(pool.find_go(), str(expected))


if __name__ == "__main__":
    unittest.main()
