#!/usr/bin/env python3
"""Expose bounded Zig test failure contexts through Actions annotations."""
from pathlib import Path
import re
import sys


def logged_error(line: str) -> bool:
    # Zig can fail its runner after otherwise successful tests logged errors.
    # Preserve scoped/default errors as well as allocator-specific diagnostics.
    return bool(re.search(r"(?:\[[^]\r\n]+\] \(err\)|(?:^|\s)error\([^\r\n)]*\)):", line))


def native_crash(line: str) -> bool:
    return bool(
        re.search(
            r"(?:^\s*|\.\.\.\s*)(?:Segmentation fault|Bus error|General protection exception|Illegal instruction|Stack overflow)\b",
            line,
        )
    ) or bool(
        re.search(r"process terminated with signal (?:ABRT|ILL|SEGV|BUS)\b", line)
    )


def annotate(path: Path) -> None:
    lines = path.read_text(errors="replace").splitlines()
    failures = [
        index
        for index, line in enumerate(lines)
        if "error:" in line or "FAIL (" in line or "panic:" in line or logged_error(line) or native_crash(line)
        or "leaked:" in line or "leaked memory" in line or "[gpa] (err)" in line
        or line.startswith(("FAIL:", "ERROR:", "Traceback"))
    ]
    if not failures:
        failures = [max(0, len(lines) - 40)]
    for index in failures[:12]:
        start = max(0, index - 1)
        context_lines = lines[start:index + 14]
        if "FAIL (" in lines[index] or "panic:" in lines[index] or "leaked:" in lines[index] or "[gpa] (err)" in lines[index] or logged_error(lines[index]) or native_crash(lines[index]):
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
