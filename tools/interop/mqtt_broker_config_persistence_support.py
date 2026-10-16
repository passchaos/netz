"""Shared wire and process helpers for configured MQTT persistence gates."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
from typing import Iterator

from mqtt_commit_log_support import packet, read_packet


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


@contextmanager
def configured_broker(
    broker: Path,
    config: Path,
    connection_count: int,
    label: str,
) -> Iterator[None]:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    try:
        ready = process.stdout.readline().strip()
        expected = f"configured 1 listeners for {connection_count} clients"
        if expected not in ready:
            raise RuntimeError(f"{label} failed to start: {ready}")
        listener = process.stdout.readline().strip()
        if not listener.startswith("mqtt "):
            raise RuntimeError(f"{label} listener missing: {listener}")
        yield
        return_code = process.wait(timeout=5)
        if return_code != 0:
            raise RuntimeError(
                f"{label} exited {return_code}: " + process.stdout.read()
            )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
