#!/usr/bin/env python3
"""Validate and build a Netz source release in an isolated directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile


FORBIDDEN_PARTS = {
    ".git",
    ".zig-cache",
    "zig-cache",
    "zig-out",
    "target",
    "__pycache__",
}


def validate_members(members: list[tarfile.TarInfo]) -> str:
    roots: set[str] = set()
    names: set[str] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise RuntimeError(f"unsafe archive path: {member.name}")
        if not (member.isdir() or member.isreg()):
            raise RuntimeError(f"unsupported archive member: {member.name}")
        if any(part in FORBIDDEN_PARTS for part in path.parts):
            raise RuntimeError(f"forbidden archive path: {member.name}")
        if path.suffix == ".pyc":
            raise RuntimeError(f"forbidden bytecode path: {member.name}")
        if member.name in names:
            raise RuntimeError(f"duplicate archive path: {member.name}")
        names.add(member.name)
        roots.add(path.parts[0])
    if len(roots) != 1:
        raise RuntimeError("archive must contain exactly one top-level directory")
    return next(iter(roots))


def verify_layout(root: Path) -> None:
    manifest_path = root / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format_version") != 1 or manifest.get("package") != "netz":
        raise RuntimeError("invalid release manifest")
    expected_root = f"{manifest['package']}-{manifest.get('version', '')}"
    if root.name != expected_root:
        raise RuntimeError(
            f"archive root {root.name!r} does not match manifest {expected_root!r}"
        )
    dependencies = manifest.get("vendored_dependencies", {})
    for name in ("vail", "pbz", "zio"):
        dependency = dependencies.get(name, {})
        expected = f"deps/{name}"
        if dependency.get("path") != expected:
            raise RuntimeError(f"missing vendored dependency metadata: {name}")
        dependency_root = root / expected
        if not (dependency_root / "build.zig").is_file():
            raise RuntimeError(f"missing vendored dependency: {name}")
        if not (dependency_root / "build.zig.zon").is_file():
            raise RuntimeError(f"missing vendored dependency manifest: {name}")
    expected_files = manifest.get("files")
    if not isinstance(expected_files, dict):
        raise RuntimeError("release manifest lacks file hashes")
    actual_files = {
        path.relative_to(root).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if actual_files != expected_files:
        raise RuntimeError("release contents do not match the file manifest")

    package_manifest = (root / "build.zig.zon").read_text(encoding="utf-8")
    for fragment in (
        '.vail = .{ .path = "deps/vail" },',
        '.pbz = .{ .path = "deps/pbz" },',
        '.zio = .{ .path = "deps/zio" },',
        '"RELEASE-MANIFEST.json"',
        '"deps"',
    ):
        if fragment not in package_manifest:
            raise RuntimeError(f"release package manifest lacks {fragment}")
    if (
        '../vail' in package_manifest
        or '../pbz' in package_manifest
        or 'git+https://github.com/lalinsky/zio' in package_manifest
    ):
        raise RuntimeError("release package retains a sibling dependency path")


def verify_archive(archive_path: Path, zig: str) -> None:
    with tempfile.TemporaryDirectory(prefix="netz-release-verify-") as temp_name:
        temp = Path(temp_name)
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            root_name = validate_members(members)
            archive.extractall(temp, filter="data")
        root = temp / root_name
        verify_layout(root)
        subprocess.run(
            [
                zig,
                "build",
                "test-package",
                "-j1",
                "--summary",
                "all",
                "--cache-dir",
                str(temp / "local-cache"),
                "--global-cache-dir",
                str(temp / "global-cache"),
            ],
            cwd=root,
            env={**os.environ, "ZIG_GLOBAL_CACHE_DIR": str(temp / "global-cache")},
            check=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--zig", required=True)
    args = parser.parse_args()
    verify_archive(args.archive, args.zig)


if __name__ == "__main__":
    main()
