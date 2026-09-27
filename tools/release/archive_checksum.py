#!/usr/bin/env python3
"""Write or verify a SHA-256 sidecar for one release artifact."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re


LINE = re.compile(r"([0-9a-f]{64})  ([^/\r\n]+)\n?\Z")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def write(archive: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        f"{digest(archive)}  {archive.name}\n",
        encoding="ascii",
    )


def verify(archive: Path, checksum: Path) -> None:
    match = LINE.fullmatch(checksum.read_text(encoding="ascii"))
    if match is None:
        raise RuntimeError("invalid SHA-256 sidecar format")
    expected, name = match.groups()
    if name != archive.name:
        raise RuntimeError(
            f"checksum names {name!r}, expected {archive.name!r}"
        )
    actual = digest(archive)
    if actual != expected:
        raise RuntimeError(
            f"archive SHA-256 mismatch: expected {expected}, found {actual}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", type=Path)
    action.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.write is not None:
        write(args.archive, args.write)
    else:
        verify(args.archive, args.verify)


if __name__ == "__main__":
    main()
