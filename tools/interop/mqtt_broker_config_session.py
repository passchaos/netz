"""Mosquitto-style persistent-client expiration configuration scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
import time
from typing import Iterator

from mqtt_commit_log_support import connect_packet, free_port, read_packet


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
        if "configured 1 listeners for 6 clients" not in ready:
            raise RuntimeError(
                f"persistent-expiration broker failed to start: {ready}"
            )
        yield
        if process.wait(timeout=5) != 0:
            raise RuntimeError(
                "persistent-expiration broker failed: "
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


def _connect(
    port: int,
    client_id: str,
    protocol: int,
    expected_session_present: bool,
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(
        connect_packet(
            client_id,
            clean_start=False,
            protocol=protocol,
            session_expiry=60,
        )
    )
    first, body = read_packet(sock)
    expected_length = 3 if protocol == 5 else 2
    if (
        first != 0x20
        or len(body) < expected_length
        or body[0] != int(expected_session_present)
        or body[1] != 0
    ):
        sock.close()
        raise AssertionError(
            f"MQTT {protocol} persistent CONNACK mismatch: "
            f"{first:#x} {body.hex()}"
        )
    return sock


def _disconnect(sock: socket.socket, protocol: int) -> None:
    sock.sendall(b"\xe0\x00")
    try:
        if sock.recv(1):
            raise AssertionError(
                f"MQTT {protocol} broker wrote bytes after DISCONNECT"
            )
    except ConnectionResetError:
        pass
    finally:
        sock.close()


def run_persistent_client_expiration_case(
    broker: Path,
    directory: Path,
) -> None:
    port = free_port()
    config = directory / "persistent-client-expiration.conf"
    config.write_text(
        "persistent_client_expiration 1s\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 6\n"
    )
    with _configured_broker(broker, config):
        for protocol in (4, 5):
            client_id = f"persistent-expiration-{protocol}"
            first = _connect(port, client_id, protocol, False)
            _disconnect(first, protocol)

            resumed = _connect(port, client_id, protocol, True)
            _disconnect(resumed, protocol)

            # The broker's deadline task expires idle Sessions without
            # requiring another route or CONNECT operation to trigger pruning.
            time.sleep(1.2)
            expired = _connect(port, client_id, protocol, False)
            _disconnect(expired, protocol)
