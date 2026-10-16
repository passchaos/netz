#!/usr/bin/env python3
"""Tests for installed Autobahn Testsuite wheel identity validation."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile


MODULE_PATH = Path(__file__).with_name("websocket_autobahn_package_check.py")
SPEC = importlib.util.spec_from_file_location(
    "websocket_autobahn_package_check",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PackageIdentityTests(unittest.TestCase):
    def make_fixture(self, root: Path) -> tuple[Path, Path]:
        wheel = root / "suite.whl"
        package = root / "site" / "autobahntestsuite"
        package.mkdir(parents=True)
        files = {
            "__init__.py": b"VERSION = 'test'\n",
            "case/sample.py": b"CASE = 1\n",
            "testdata/vector.bin": b"\x00\x01\xff",
        }
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("metadata.dist-info/METADATA", b"ignored")
            for relative, data in files.items():
                archive.writestr(f"autobahntestsuite/{relative}", data)
                destination = package / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
        return wheel, package

    def test_matching_package(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            wheel, package = self.make_fixture(Path(raw_root))
            self.assertEqual(3, MODULE.verify_package(wheel, package))

    def test_modified_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            wheel, package = self.make_fixture(Path(raw_root))
            (package / "case" / "sample.py").write_bytes(b"changed")
            with self.assertRaisesRegex(MODULE.PackageIdentityError, "differs"):
                MODULE.verify_package(wheel, package)

    def test_missing_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            wheel, package = self.make_fixture(Path(raw_root))
            (package / "testdata" / "vector.bin").unlink()
            with self.assertRaisesRegex(MODULE.PackageIdentityError, "missing="):
                MODULE.verify_package(wheel, package)

    def test_extra_file_rejected_but_bytecode_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            wheel, package = self.make_fixture(Path(raw_root))
            (package / "__init__.pyc").write_bytes(b"bytecode")
            self.assertEqual(3, MODULE.verify_package(wheel, package))
            (package / "extra.txt").write_bytes(b"extra")
            with self.assertRaisesRegex(MODULE.PackageIdentityError, "extra="):
                MODULE.verify_package(wheel, package)

    def test_symlink_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            wheel, package = self.make_fixture(Path(raw_root))
            (package / "link.py").symlink_to(package / "__init__.py")
            with self.assertRaisesRegex(MODULE.PackageIdentityError, "symlink"):
                MODULE.verify_package(wheel, package)


if __name__ == "__main__":
    unittest.main()
