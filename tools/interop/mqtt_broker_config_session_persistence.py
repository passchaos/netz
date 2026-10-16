"""Mosquitto-derived durable Session snapshot/restart scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
from typing import Iterator

from mqtt_commit_log_support import (
    ack_packet,
    connect_client,
    free_port,
    packet,
    publish_packet,
    qos0_publish_packet,
    read_packet,
    subscribe_packet,
)


_PAYLOAD = b"message"


def _expect_packet(
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


def _ping(sock: socket.socket, label: str) -> None:
    sock.sendall(packet(0xC0, b""))
    _expect_packet(sock, packet(0xD0, b""), label)


def _disconnect(sock: socket.socket) -> None:
    sock.sendall(packet(0xE0, b""))


@contextmanager
def _configured_broker(
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


def _connect(
    port: int,
    client_id: str,
    protocol: int,
    clean_start: bool,
    session_present: bool,
) -> socket.socket:
    return connect_client(
        port,
        client_id,
        clean_start=clean_start,
        session_present=session_present,
        protocol=protocol,
        session_expiry=0 if clean_start else 60,
    )


def _subscribe(
    sock: socket.socket,
    protocol: int,
    topic: str,
    qos: int,
) -> None:
    sock.sendall(subscribe_packet(
        1,
        topic,
        subscription_identifier=None,
        qos=qos,
        protocol=protocol,
    ))
    _expect_packet(
        sock,
        packet(
            0x90,
            b"\x00\x01" + (b"\x00" if protocol == 5 else b"")
            + bytes((qos,)),
        ),
        f"MQTT {protocol} durable SUBACK qos={qos}",
    )


def _publish_offline_queue(
    port: int,
    protocol: int,
    topics: tuple[str, str, str],
) -> None:
    helper = _connect(
        port,
        f"persist-clear-helper-v{protocol}",
        protocol,
        True,
        False,
    )
    try:
        helper.sendall(qos0_publish_packet(
            topics[0],
            _PAYLOAD,
            retain=False,
            protocol=protocol,
        ))
        helper.sendall(publish_packet(
            topics[1],
            _PAYLOAD,
            1,
            qos=1,
            protocol=protocol,
        ))
        _expect_packet(
            helper,
            ack_packet(0x40, 1),
            f"MQTT {protocol} offline publisher PUBACK",
        )
        helper.sendall(publish_packet(
            topics[2],
            _PAYLOAD,
            2,
            qos=2,
            protocol=protocol,
        ))
        _expect_packet(
            helper,
            ack_packet(0x50, 2),
            f"MQTT {protocol} offline publisher PUBREC",
        )
        helper.sendall(ack_packet(0x62, 2))
        _expect_packet(
            helper,
            ack_packet(0x70, 2),
            f"MQTT {protocol} offline publisher PUBCOMP",
        )
        _ping(helper, f"MQTT {protocol} offline publisher barrier")
        _disconnect(helper)
    finally:
        helper.close()


def _expect_restored_queue(
    subscriber: socket.socket,
    protocol: int,
    topics: tuple[str, str, str],
) -> None:
    _expect_packet(
        subscriber,
        publish_packet(
            topics[1],
            _PAYLOAD,
            1,
            qos=1,
            protocol=protocol,
        ),
        f"MQTT {protocol} restored QoS 1 PUBLISH",
    )
    _expect_packet(
        subscriber,
        publish_packet(
            topics[2],
            _PAYLOAD,
            2,
            qos=2,
            protocol=protocol,
        ),
        f"MQTT {protocol} restored QoS 2 PUBLISH",
    )


def _no_subscribers_puback(protocol: int, packet_id: int) -> bytes:
    body = packet_id.to_bytes(2, "big")
    if protocol == 5:
        body += b"\x10"
    return packet(0x40, body)


def _run_clean_start_case(
    broker: Path,
    directory: Path,
    protocol: int,
) -> None:
    port = free_port()
    snapshot = directory / f"clean-start-v{protocol}.db"
    config = directory / f"clean-start-v{protocol}.conf"
    config.write_text(
        "persistence true\n"
        f"persistence_location {directory}\n"
        f"persistence_file {snapshot.name}\n"
        "autosave_interval 0\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_queued_messages 8\n"
        "max_connections 2\n"
    )
    client_id = f"persist-clear-v{protocol}"
    topics = (
        f"persist/clear/v{protocol}/0",
        f"persist/clear/v{protocol}/1",
        f"persist/clear/v{protocol}/2",
    )

    with _configured_broker(
        broker,
        config,
        2,
        f"initial MQTT {protocol} Clean Start broker",
    ):
        subscriber = _connect(
            port,
            client_id,
            protocol,
            False,
            False,
        )
        try:
            for qos, topic in enumerate(topics):
                _subscribe(subscriber, protocol, topic, qos)
            _disconnect(subscriber)
        finally:
            subscriber.close()
        _publish_offline_queue(port, protocol, topics)
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError(
            f"MQTT {protocol} Clean Start snapshot was not written"
        )

    with _configured_broker(
        broker,
        config,
        2,
        f"restored MQTT {protocol} Clean Start broker",
    ):
        resumed = _connect(
            port,
            client_id,
            protocol,
            False,
            True,
        )
        try:
            _expect_restored_queue(resumed, protocol, topics)
            # Keep both transmissions unacknowledged. Clean Start must remove
            # restored outgoing inflight state as well as queued state/routes.
        finally:
            resumed.close()

        clean = _connect(
            port,
            client_id,
            protocol,
            True,
            False,
        )
        try:
            _ping(clean, f"MQTT {protocol} Clean Start queue purge")
            _disconnect(clean)
        finally:
            clean.close()

    with _configured_broker(
        broker,
        config,
        2,
        f"final MQTT {protocol} Clean Start broker",
    ):
        fresh = _connect(
            port,
            client_id,
            protocol,
            False,
            False,
        )
        probe = None
        try:
            _ping(fresh, f"MQTT {protocol} final empty Session")
            probe = _connect(
                port,
                f"persist-clear-probe-v{protocol}",
                protocol,
                True,
                False,
            )
            probe.sendall(publish_packet(
                topics[1],
                b"must-not-route",
                9,
                qos=1,
                protocol=protocol,
            ))
            _expect_packet(
                probe,
                _no_subscribers_puback(protocol, 9),
                f"MQTT {protocol} removed subscription PUBACK",
            )
            _ping(fresh, f"MQTT {protocol} removed subscription barrier")
            _disconnect(probe)
            _disconnect(fresh)
        finally:
            if probe is not None:
                probe.close()
            fresh.close()


def run_persistent_session_clean_start_case(
    broker: Path,
    directory: Path,
) -> None:
    """Persist Clean Start deletion after restoring queued/inflight state.

    MQTT 3.1.1 directly ports Mosquitto's
    15-persist-client-msg-out-clear-v3-1-1.py. MQTT 5 repeats the same three
    broker generations with Clean Start and Session Expiry Interval semantics.
    """
    for protocol in (4, 5):
        _run_clean_start_case(broker, directory, protocol)
