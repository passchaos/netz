#!/usr/bin/env python3
"""Expose bounded Zig test failure contexts through Actions annotations."""
from bisect import bisect_right
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
        re.search(
            r"(?:^\s*|\.\.\.\s*)(?:free\(\):|malloc\(\):|realloc\(\):|double free or corruption|Fatal glibc error:)",
            line,
        )
    ) or bool(
        re.search(r"process terminated with signal (?:ABRT|ILL|SEGV|BUS)\b", line)
    )


def cached_artifact(line: str):
    command = line.strip()
    if command.startswith("failed command:"):
        command = command[len("failed command:"):].strip()
    first = re.match(r'^(?:"([^"]+)"|(\S+))', command)
    if not first or "--cache-dir" not in command:
        return None
    path = first.group(1) or first.group(2)
    artifact = re.search(r"\.zig-cache[\\/]+o[\\/]+([0-9a-f]{16,})[\\/]+([^\\/\s]+)$", path)
    if not artifact:
        return None
    return artifact.group(1), artifact.group(2)


def artifact_runs(lines):
    runs = {}
    active = None
    for index, line in enumerate(lines):
        key = cached_artifact(line)
        if key is not None and not line.strip().startswith("failed command:"):
            active = {"start": index, "tests": []}
            runs.setdefault(key, []).append(active)
        if active is not None and re.match(r"^\d+/\d+\s", line):
            active["tests"].append((index, line))
    return runs


def last_artifact_test(runs, key, index):
    candidates = runs.get(key, [])
    position = bisect_right([run["start"] for run in candidates], index) - 1
    if position < 0:
        return None
    tests = candidates[position]["tests"]
    position = bisect_right([point[0] for point in tests], index) - 1
    return tests[position][1] if position >= 0 else None


def last_active_test(runs, index):
    active = None
    for key, invocations in runs.items():
        for invocation in invocations:
            if invocation["start"] <= index and (active is None or invocation["start"] > active[0]):
                active = invocation["start"], key
    return last_artifact_test(runs, active[1], index) if active is not None else None


def failure_priority(line):
    if "panic:" in line or native_crash(line):
        return 0
    if "FAIL (" in line or logged_error(line) or "leaked" in line or "[gpa] (err)" in line or line.startswith(("FAIL:", "ERROR:")):
        return 1
    return 2


def emit(path, context):
    message = context.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    title = "Native regression: " + path.stem.replace("-", " ").replace("_", " ")
    print("::error title=" + title + "::" + message)


def annotate(path: Path) -> None:
    lines = path.read_text(errors="replace").splitlines()
    if not lines:
        emit(path, "No command output captured for the failed command.")
        return
    runs = artifact_runs(lines)
    failures = [
        index
        for index, line in enumerate(lines)
        if "error:" in line or "FAIL (" in line or "panic:" in line or logged_error(line) or native_crash(line)
        or "leaked:" in line or "leaked memory" in line or "[gpa] (err)" in line
        or line.startswith(("FAIL:", "ERROR:", "Traceback"))
    ]
    if not failures:
        failures = [max(0, len(lines) - 40)]
    failures.sort(key=lambda index: (failure_priority(lines[index]), index))
    for index in failures[:12]:
        start = max(0, index - 1)
        context_lines = lines[start:index + 14]
        failed_artifact = None
        if "process terminated with signal" in lines[index]:
            for offset, line in enumerate(lines[index:index + 14]):
                if line.strip().startswith("failed command:"):
                    failed_artifact = cached_artifact(line)
                    if failed_artifact is not None:
                        context_lines = lines[start:index + offset + 1]
                        if start < index and re.match(r"^\d+/\d+\s", context_lines[0]):
                            context_lines = context_lines[1:]
                    break
        if failed_artifact is not None:
            last_test = last_artifact_test(runs, failed_artifact, index)
            if last_test is not None:
                context_lines.insert(0, "Last visible test for failed artifact: " + last_test)
        elif "FAIL (" in lines[index] or "panic:" in lines[index] or "leaked:" in lines[index] or "[gpa] (err)" in lines[index] or logged_error(lines[index]) or native_crash(lines[index]):
            test_found = False
            for previous in range(index, max(-1, index - 40), -1):
                if re.match(r"^\d+/\d+\s", lines[previous]):
                    test_found = True
                    if previous < start:
                        context_lines.insert(0, lines[previous])
                    break
            if not test_found:
                last_test = last_active_test(runs, index)
                if last_test is not None:
                    context_lines.insert(0, "Last visible test for active artifact: " + last_test)
        emit(path, "\n".join(context_lines))


if __name__ == "__main__":
    annotate(Path(sys.argv[1]))
