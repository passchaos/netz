#!/usr/bin/env python3
"""Verify that an installed Autobahn Testsuite tree matches its locked wheel."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import zipfile


PACKAGE_PREFIX = PurePosixPath("autobahntestsuite")
IGNORED_INSTALLED_SUFFIXES = {".pyc", ".pyo"}


class PackageIdentityError(RuntimeError):
    pass


def wheel_package_files(wheel_path: Path) -> dict[PurePosixPath, bytes]:
    files: dict[PurePosixPath, bytes] = {}
    with zipfile.ZipFile(wheel_path) as archive:
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            if not path.parts or path.parts[0] != PACKAGE_PREFIX.name:
                continue
            if info.is_dir():
                continue
            if path.is_absolute() or ".." in path.parts:
                raise PackageIdentityError(f"unsafe wheel path: {info.filename}")
            relative = PurePosixPath(*path.parts[1:])
            if relative in files:
                raise PackageIdentityError(f"duplicate wheel path: {relative}")
            files[relative] = archive.read(info)
    if not files:
        raise PackageIdentityError("wheel contains no Autobahn Testsuite files")
    return files


def installed_package_files(package_dir: Path) -> dict[PurePosixPath, Path]:
    if not package_dir.is_dir() or package_dir.is_symlink():
        raise PackageIdentityError(f"invalid installed package path: {package_dir}")
    files: dict[PurePosixPath, Path] = {}
    for path in package_dir.rglob("*"):
        if path.is_symlink():
            raise PackageIdentityError(f"installed package contains symlink: {path}")
        if not path.is_file() or path.suffix in IGNORED_INSTALLED_SUFFIXES:
            continue
        relative = PurePosixPath(path.relative_to(package_dir).as_posix())
        files[relative] = path
    return files


def verify_package(wheel_path: Path, package_dir: Path) -> int:
    expected = wheel_package_files(wheel_path)
    installed = installed_package_files(package_dir)
    missing = sorted(set(expected) - set(installed))
    extra = sorted(set(installed) - set(expected))
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(map(str, missing)))
        if extra:
            details.append("extra=" + ",".join(map(str, extra)))
        raise PackageIdentityError("installed package file set mismatch: " + "; ".join(details))
    for relative, expected_bytes in expected.items():
        if installed[relative].read_bytes() != expected_bytes:
            raise PackageIdentityError(f"installed package file differs: {relative}")
    return len(expected)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("package_dir", type=Path)
    args = parser.parse_args()
    count = verify_package(args.wheel, args.package_dir)
    print(f"Autobahn package tree verified: files={count}")


if __name__ == "__main__":
    main()
