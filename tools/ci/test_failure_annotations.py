#!/usr/bin/env python3
"""Expose bounded Zig test failure contexts through Actions annotations."""
from pathlib import Path
import re
import sys


def annotate(path: Path) -> None:
    lines = path.read_text(errors="replace").splitlines()
    failures = [
        index
        for index, line in enumerate(lines)
        if "error:" in line or "FAIL (" in line or "panic:" in line
    ]
    if not failures:
        failures = [max(0, len(lines) - 40)]
    for index in failures[:12]:
        start = max(0, index - 1)
        context_lines = lines[start:index + 14]
        if "FAIL (" in lines[index] or "panic:" in lines[index]:
            for previous in range(index, max(-1, index - 40), -1):
                if re.match(r"^\d+/\d+\s", lines[previous]):
                    if previous < start:
                        context_lines.insert(0, lines[previous])
                    break
        context = "\n".join(context_lines)
        message = context.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        title = "Native regression: " + path.stem.replace("-", " ").replace("_", " ")
        print("::error title=" + title + "::" + message)


if __name__ == "__main__":
    annotate(Path(sys.argv[1]))
