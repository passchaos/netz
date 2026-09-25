"""Mosquitto-style periodic $SYS configuration scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
from typing import Iterator

from mqtt_commit_log_support import (
    connect_client,
    free_port,
    packet,
    qos0_publish_packet,
    read_packet,
    subscribe_packet,
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
        if "configured 1 listeners for 1 clients" not in ready:
            raise RuntimeError(f"sys-interval broker failed to start: {ready}")
        yield
        if process.wait(timeout=5) != 0:
            raise RuntimeError(
                "sys-interval broker failed: " + process.stdout.read()
            )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def _expect(sock: socket.socket, expected: bytes, label: str) -> None:
    first, body = read_packet(sock)
    actual = bytes((first,)) + bytes((len(body),)) + body
    if actual != expected:
        raise AssertionError(
            f"{label}: expected {expected.hex()}, got {actual.hex()}"
        )


def _disconnect(sock: socket.socket) -> None:
    sock.sendall(packet(0xE0, b""))
    try:
        if sock.recv(1):
            raise AssertionError("broker wrote bytes after DISCONNECT")
    except ConnectionResetError:
        pass
    finally:
        sock.close()


def _subscribe(port: int, client_id: str) -> socket.socket:
    client = connect_client(
        port,
        client_id,
        clean_start=True,
        session_present=False,
        protocol=5,
        session_expiry=0,
    )
    client.sendall(
        subscribe_packet(
            1,
            "$SYS/broker/clients/connected",
            subscription_identifier=None,
            qos=0,
            protocol=5,
        )
    )
    _expect(client, packet(0x90, b"\x00\x01\x00\x00"), "system SUBACK")
    return client


def run_system_interval_case(broker: Path, directory: Path) -> None:
    enabled_port = free_port()
    enabled_config = directory / "sys-interval-enabled.conf"
    enabled_config.write_text(
        "sys_interval 1\n"
        f"listener {enabled_port} 127.0.0.1\n"
        "max_topic_alias_broker 0\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    with _configured_broker(broker, enabled_config):
        client = _subscribe(enabled_port, "sys-interval-enabled")
        try:
            _expect(
                client,
                qos0_publish_packet(
                    "$SYS/broker/clients/connected",
                    b"1",
                    retain=False,
                    protocol=5,
                ),
                "periodic system statistic",
            )
            _disconnect(client)
        finally:
            client.close()

    disabled_port = free_port()
    disabled_config = directory / "sys-interval-disabled.conf"
    disabled_config.write_text(
        "sys_interval 0\n"
        f"listener {disabled_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    with _configured_broker(broker, disabled_config):
        client = _subscribe(disabled_port, "sys-interval-disabled")
        try:
            client.settimeout(1.2)
            try:
                first, body = read_packet(client)
            except TimeoutError:
                pass
            else:
                raise AssertionError(
                    "disabled system interval published unexpectedly: "
                    + (bytes((first,)) + body).hex()
                )
            finally:
                client.settimeout(5)
            client.sendall(packet(0xC0, b""))
            _expect(client, packet(0xD0, b""), "disabled system PINGRESP")
            _disconnect(client)
        finally:
            client.close()
