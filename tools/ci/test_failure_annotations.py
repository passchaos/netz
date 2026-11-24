#!/usr/bin/env python3
"""Expose bounded Zig test failure contexts through Actions annotations."""
from pathlib import Path
import sys


def annotate(path: Path) -> None:
    lines = path.read_text(errors="replace").splitlines()
    failures = [index for index, line in enumerate(lines) if "error:" in line]
    if not failures:
        failures = [max(0, len(lines) - 40)]
    for index in failures[:12]:
        context = "\n".join(lines[index:index + 14])
        message = context.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print("::error title=Native hostname regression::" + message)


if __name__ == "__main__":
    annotate(Path(sys.argv[1]))
