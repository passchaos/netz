"""Bounded process-output waits for configured broker scenarios."""

from __future__ import annotations

import os
import select
import subprocess
import time


def wait_process_line(
    process: subprocess.Popen[str],
    needle: str,
    label: str,
    timeout: float = 5,
) -> None:
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    was_blocking = os.get_blocking(descriptor)
    deadline = time.monotonic() + timeout
    observed: list[str] = []
    fragment = ""
    os.set_blocking(descriptor, False)
    try:
        while time.monotonic() < deadline:
            try:
                chunk = process.stdout.readline()
            except BlockingIOError:
                chunk = ""
            if chunk:
                fragment += chunk
                if fragment.endswith("\n"):
                    line = fragment.rstrip("\r\n")
                    fragment = ""
                    observed.append(line)
                    if needle in line:
                        return
                continue
            if process.poll() is not None:
                if fragment:
                    observed.append(fragment)
                    if needle in fragment:
                        return
                break
            remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select(
                [process.stdout],
                [],
                [],
                remaining,
            )
            if not readable:
                break
    finally:
        os.set_blocking(descriptor, was_blocking)
    if fragment:
        observed.append(fragment)
    raise AssertionError(
        f"{label}: did not observe {needle!r}; output={observed!r}"
    )


