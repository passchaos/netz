"""Mosquitto-style zero maximum Keep Alive configuration scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
from typing import Iterator

from mqtt_commit_log_support import (
    connect_packet,
    free_port,
    packet,
    read_packet,
    read_varint,
)


@contextmanager
def _configured_broker(broker: Path, config: Path) -> Iterator[None]:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    try:
        ready = process.stdout.readline().strip()
        if "configured 1 listeners for 2 clients" not in ready:
            raise RuntimeError(f"zero max-keepalive broker failed: {ready}")
        yield
        if process.wait(timeout=5) != 0:
            raise RuntimeError(
                "zero max-keepalive broker failed: "
                + process.stdout.read()
            )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def _connack(sock: socket.socket, protocol: int) -> bytes:
    first, body = read_packet(sock)
    minimum_length = 3 if protocol == 5 else 2
    if first != 0x20 or len(body) < minimum_length or body[1] != 0:
        raise AssertionError(
            f"MQTT {protocol} zero Keep Alive CONNACK mismatch: "
            f"{first:#x} {body.hex()}"
        )
    return body


def _connack_properties(body: bytes) -> bytes:
    length, offset = read_varint(body, 2)
    if offset + length != len(body):
        raise AssertionError("malformed zero Keep Alive CONNACK properties")
    return body[offset:]


def _ping(sock: socket.socket) -> None:
    sock.sendall(packet(0xC0, b""))
    first, body = read_packet(sock)
    if first != 0xD0 or body:
        raise AssertionError(
            f"zero Keep Alive PINGRESP mismatch: {first:#x} {body.hex()}"
        )


def run_zero_maximum_keep_alive_case(
    broker: Path,
    directory: Path,
) -> None:
    port = free_port()
    config = directory / "max-keepalive-zero.conf"
    config.write_text(
        "sys_interval 0\n"
        f"listener {port} 127.0.0.1\n"
        "max_keepalive 0\n"
        "listener_allow_anonymous true\n"
        "max_connections 2\n"
    )
    with _configured_broker(broker, config):
        for protocol in (4, 5):
            client = socket.create_connection(
                ("127.0.0.1", port), timeout=5
            )
            client.settimeout(5)
            try:
                client.sendall(
                    connect_packet(
                        f"max-keepalive-zero-{protocol}",
                        clean_start=True,
                        keep_alive=0,
                        protocol=protocol,
                    )
                )
                connack = _connack(client, protocol)
                if protocol == 5 and b"\x13" in _connack_properties(connack):
                    raise AssertionError(
                        "unlimited max_keepalive advertised Server Keep Alive"
                    )
                _ping(client)
                client.sendall(b"\xe0\x00")
            finally:
                client.close()
