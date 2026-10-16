"""Mosquitto-style persistent-client expiration configuration scenarios."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Iterator

from mqtt_commit_log_support import connect_packet, free_port, read_packet


FINITE_TEST_ENV = "NETZ_MQTT_CONFIG_FINITE_TEST"


@contextmanager
def _configured_broker(
    broker: Path,
    config: Path,
    connection_count: int = 6,
    listener_count: int = 1,
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
        expected = (
            f"configured {listener_count} listeners for "
            f"{connection_count} clients"
        )
        if expected not in ready:
            raise RuntimeError(
                f"session-policy broker failed to start: {ready}"
            )
        yield
        if process.wait(timeout=5) != 0:
            raise RuntimeError(
                "session-policy broker failed: "
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


@contextmanager
def _continuous_broker(
    broker: Path,
    config: Path,
    listener_count: int,
    global_connection_limit: int,
) -> Iterator[None]:
    environment = os.environ.copy()
    environment.pop(FINITE_TEST_ENV, None)
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
    )
    assert process.stdout is not None
    try:
        ready = process.stdout.readline().strip()
        expected = (
            f"configured {listener_count} listeners "
            f"global_max_connections={global_connection_limit}"
        )
        if expected not in ready:
            raise RuntimeError(
                f"continuous broker failed to start: {ready}"
            )
        yield
        if process.poll() is not None:
            raise RuntimeError(
                "continuous broker exited unexpectedly: "
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
        "listener_allow_anonymous true\n"
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


def run_global_max_clients_case(
    broker: Path,
    directory: Path,
) -> None:
    """Keep connected and offline Sessions inside one global capacity."""
    port = free_port()
    config = directory / "global-max-clients.conf"
    config.write_text(
        "global_max_clients 1\n"
        "persistent_client_expiration 1s\n"
        f"listener {port} 127.0.0.1\n"
        "listener_allow_anonymous true\n"
        "max_connections 5\n"
    )
    with _configured_broker(broker, config, connection_count=5):
        first = _connect(port, "global-limit-held", 5, False)

        refused_v5 = socket.create_connection(("127.0.0.1", port), timeout=5)
        refused_v5.settimeout(5)
        refused_v5.sendall(connect_packet(
            "global-limit-v5",
            clean_start=True,
            protocol=5,
        ))
        packet_type, body = read_packet(refused_v5)
        if packet_type != 0x20 or body != b"\x00\x89\x00":
            raise AssertionError(
                "global client limit did not return MQTT 5 Server Busy: "
                f"{packet_type:02x}{body.hex()}"
            )
        refused_v5.close()

        _disconnect(first, 5)

        resumed = _connect(port, "global-limit-held", 5, True)
        _disconnect(resumed, 5)

        refused_v311 = socket.create_connection(
            ("127.0.0.1", port), timeout=5,
        )
        refused_v311.settimeout(5)
        refused_v311.sendall(connect_packet(
            "global-limit-v311",
            clean_start=True,
            protocol=4,
        ))
        try:
            unexpected = refused_v311.recv(1)
        except ConnectionResetError:
            unexpected = b""
        finally:
            refused_v311.close()
        if unexpected:
            raise AssertionError(
                "global client limit sent an invalid MQTT 3.1.1 response: "
                + unexpected.hex()
            )

        # The first disconnected Session continues to consume capacity until
        # the configured expiry cap releases it through the deadline driver.
        time.sleep(1.2)
        replacement = _connect(port, "global-limit-released", 5, False)
        _disconnect(replacement, 5)


def run_global_max_connections_case(
    broker: Path,
    directory: Path,
) -> None:
    """Bound simultaneous admitted clients across independent listeners."""
    first_port = free_port()
    second_port = free_port()
    while second_port == first_port:
        second_port = free_port()
    config = directory / "global-max-connections.conf"
    config.write_text(
        "global_max_connections 1\n"
        f"listener {first_port} 127.0.0.1\n"
        "listener_allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {second_port} 127.0.0.1\n"
        "listener_allow_anonymous true\n"
        "max_connections 2\n"
    )
    with _continuous_broker(
        broker,
        config,
        listener_count=2,
        global_connection_limit=1,
    ):
        held = _connect(first_port, "global-connection-held", 5, False)

        refused = socket.create_connection(
            ("127.0.0.1", second_port), timeout=5,
        )
        refused.settimeout(5)
        try:
            refused.sendall(connect_packet(
                "global-connection-refused",
                clean_start=True,
                protocol=5,
            ))
            try:
                unexpected = refused.recv(1)
            except ConnectionResetError:
                unexpected = b""
            if unexpected:
                raise AssertionError(
                    "global connection limit sent CONNACK bytes: "
                    + unexpected.hex()
                )
        finally:
            refused.close()

        _disconnect(held, 5)

        # Capacity is live-connection scoped, not Session scoped. Once the
        # first transport closes, another listener can consume the shared slot.
        replacement = _connect(
            second_port,
            "global-connection-released",
            5,
            False,
        )
        _disconnect(replacement, 5)


def run_listener_max_connections_case(
    broker: Path,
    directory: Path,
) -> None:
    """Bound one listener without consuming another listener's capacity."""
    limited_port = free_port()
    sibling_port = free_port()
    while sibling_port == limited_port:
        sibling_port = free_port()
    config = directory / "listener-max-connections.conf"
    config.write_text(
        "global_max_connections 2\n"
        f"listener {limited_port} 127.0.0.1\n"
        "listener_allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {sibling_port} 127.0.0.1\n"
        "listener_allow_anonymous true\n"
        "max_connections 2\n"
    )
    with _continuous_broker(
        broker,
        config,
        listener_count=2,
        global_connection_limit=2,
    ):
        held = _connect(limited_port, "listener-limit-held", 5, False)

        refused = socket.create_connection(
            ("127.0.0.1", limited_port), timeout=5,
        )
        refused.settimeout(5)
        try:
            refused.sendall(connect_packet(
                "listener-limit-refused",
                clean_start=True,
                protocol=5,
            ))
            try:
                unexpected = refused.recv(1)
            except ConnectionResetError:
                unexpected = b""
            if unexpected:
                raise AssertionError(
                    "listener connection limit sent CONNACK bytes: "
                    + unexpected.hex()
                )
        finally:
            refused.close()

        sibling = _connect(
            sibling_port, "listener-limit-sibling", 5, False,
        )
        _disconnect(sibling, 5)
        _disconnect(held, 5)

        # Production config mode is a persistent supervisor, not a finite
        # accept batch derived from the sum of listener limits. This fourth
        # attempt exceeds that former batch size and must still be admitted.
        replacement = _connect(
            limited_port, "listener-limit-replacement", 5, False,
        )
        _disconnect(replacement, 5)
