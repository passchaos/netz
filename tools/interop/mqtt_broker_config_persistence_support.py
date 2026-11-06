"""Shared wire and process helpers for configured MQTT persistence gates."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
import threading
import time
from typing import Iterator

from mqtt_commit_log_support import packet, read_packet

PERSISTENCE_SHUTDOWN_TIMEOUT = 30


def expect_packet(
    sock: socket.socket,
    expected: bytes,
    label: str,
) -> None:
    first, body = read_packet(sock)
    actual = packet(first, body)
    if actual != expected:
        raise AssertionError(
            f"{label}: expected {expected.hex()}, got {actual.hex()}"
        )


def ping(sock: socket.socket, label: str) -> None:
    sock.sendall(packet(0xC0, b""))
    expect_packet(sock, packet(0xD0, b""), label)


def disconnect(sock: socket.socket) -> None:
    sock.sendall(packet(0xE0, b""))


def shutdown_threads(process: subprocess.Popen[str]) -> str:
    tasks = Path(f"/proc/{process.pid}/task")
    try:
        entries = sorted(tasks.iterdir(), key=lambda path: int(path.name))
    except OSError:
        return "thread state unavailable"
    states = []
    for entry in entries[:128]:
        try:
            name = (entry / "comm").read_text().strip()
            wait = (entry / "wchan").read_text().strip()
        except OSError:
            continue
        states.append(f"{entry.name}:{name}:{wait or 'running'}")
    return ", ".join(states) or "thread state unavailable"


@contextmanager
def configured_broker(
    broker: Path,
    config: Path,
    connection_count: int,
    label: str,
    *,
    shutdown_timeout: float = 5,
) -> Iterator[None]:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    output: list[str] = []
    reader: threading.Thread | None = None
    failure: BaseException | None = None
    try:
        ready = process.stdout.readline().strip()
        expected = f"configured 1 listeners for {connection_count} clients"
        if expected not in ready:
            raise RuntimeError(f"{label} failed to start: {ready}")
        listener = process.stdout.readline().strip()
        if not listener.startswith("mqtt "):
            raise RuntimeError(f"{label} listener missing: {listener}")
        # Keep diagnostics from filling the child's pipe while the fixture
        # exchanges packets or waits for finite broker teardown.
        def drain_output() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                output.append(line)

        reader = threading.Thread(target=drain_output, daemon=True)
        reader.start()
        yield
        started = time.monotonic()
        try:
            return_code = process.wait(timeout=shutdown_timeout)
        except subprocess.TimeoutExpired as error:
            error.add_note(
                f"{label}: shutdown exceeded {shutdown_timeout:g} seconds "
                f"(elapsed={time.monotonic() - started:.3f}s, pid={process.pid}); "
                + shutdown_threads(process)
            )
            raise
        if return_code != 0:
            raise RuntimeError(f"{label} exited {return_code}")
    except BaseException as error:
        failure = error
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if reader is not None:
            reader.join(timeout=2)
            if failure is not None and reader.is_alive():
                failure.add_note(f"{label}: child output reader did not finish")
        if failure is not None:
            remaining = "".join(output).strip()
            if remaining:
                failure.add_note(f"{label}: child output:\n{remaining}")
        if reader is None or not reader.is_alive():
            process.stdout.close()


@contextmanager
def configured_persistent_broker(
    broker: Path,
    config: Path,
    connection_count: int,
    label: str,
) -> Iterator[None]:
    # Final snapshot file and directory fsync run after all MQTT EOF barriers.
    # Observed ext4 journal waits exceeded the five-second connection teardown
    # guard; keep this storage completion allowance separate and bounded.
    with configured_broker(
        broker, config, connection_count, label,
        shutdown_timeout=PERSISTENCE_SHUTDOWN_TIMEOUT,
    ):
        yield
