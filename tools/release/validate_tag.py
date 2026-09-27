#!/usr/bin/env python3
"""Require a release tag to match build.zig.zon's package version."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
VERSION_FIELD = re.compile(r'^\s*\.version\s*=\s*"([^"]+)"\s*,\s*$', re.MULTILINE)


def package_version(manifest: Path) -> str:
    matches = VERSION_FIELD.findall(manifest.read_text(encoding="utf-8"))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one package version in {manifest}, found {len(matches)}"
        )
    version = matches[0]
    if SEMVER.fullmatch(version) is None:
        raise RuntimeError(f"package version is not semantic: {version!r}")
    return version


def validate(tag: str, manifest: Path) -> str:
    if not tag.startswith("v") or SEMVER.fullmatch(tag[1:]) is None:
        raise RuntimeError(f"release tag is not v<SemVer>: {tag!r}")
    version = package_version(manifest)
    expected = f"v{version}"
    if tag != expected:
        raise RuntimeError(
            f"release tag {tag!r} does not match package version {expected!r}"
        )
    return version


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    version = validate(args.tag, args.manifest)
    print(version)


if __name__ == "__main__":
    main()
