"""Mosquitto-derived retained snapshot/restart integration scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
from typing import Iterator

from mqtt_commit_log_support import (
    connect_client,
    free_port,
    mqtt_string,
    packet,
    read_packet,
    remaining_length,
    subscribe_packet,
)


_TOPIC = "test/retainprop"
_PAYLOAD = b"retained message 1"
_INITIAL_EXPIRY_SECONDS = 60
_MIN_EXPECTED_EXPIRY_SECONDS = 2


def _property_bundle(
    expiry_seconds: int,
    topic_alias: int | None = None,
) -> bytes:
    properties = (
        b"\x01\x01"  # Payload Format Indicator = UTF-8
        + b"\x03" + mqtt_string("plain/text")
        + b"\x08" + mqtt_string("/dev/null")
        + b"\x09" + mqtt_string("2357289375902345")
    )
    for value in ("value4", "value3", "value2", "value1"):
        properties += b"\x26" + mqtt_string("name") + mqtt_string(value)
    if topic_alias is not None:
        properties += b"\x23" + topic_alias.to_bytes(2, "big")
    return properties + b"\x02" + expiry_seconds.to_bytes(4, "big")


def _retained_publish(
    expiry_seconds: int,
    topic_alias: int | None = None,
) -> bytes:
    properties = _property_bundle(expiry_seconds, topic_alias)
    return packet(
        0x31,
        mqtt_string(_TOPIC)
        + remaining_length(len(properties))
        + properties
        + _PAYLOAD,
    )


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
        if "configured 1 listeners for 1 clients" not in ready:
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


def _connect(port: int, client_id: str) -> socket.socket:
    return connect_client(
        port,
        client_id,
        clean_start=True,
        session_present=False,
        protocol=5,
        session_expiry=0,
    )


def _subscribe(sock: socket.socket, label: str) -> None:
    sock.sendall(subscribe_packet(
        1,
        _TOPIC,
        subscription_identifier=None,
        qos=0,
        protocol=5,
    ))
    _expect_packet(
        sock,
        packet(0x90, b"\x00\x01\x00\x00"),
        f"{label} SUBACK",
    )


def _expect_retained_bundle(sock: socket.socket, label: str) -> None:
    first, body = read_packet(sock)
    actual = packet(first, body)
    for expiry_seconds in range(
        _INITIAL_EXPIRY_SECONDS,
        _MIN_EXPECTED_EXPIRY_SECONDS - 1,
        -1,
    ):
        if actual == _retained_publish(expiry_seconds):
            return
    raise AssertionError(
        f"{label}: retained property bundle mismatch: {actual.hex()}"
    )


def run_retained_property_persistence_case(
    broker: Path,
    directory: Path,
) -> None:
    """Preserve the complete MQTT 5 Application Message property bundle.

    This source-locked production-process port extends Mosquitto's
    15-persist-publish-properties-v5-0.py with a second save/restore generation
    so property bytes parsed from one snapshot must be deeply owned before the
    next snapshot is written.
    """
    port = free_port()
    snapshot = directory / "retained-properties.db"
    config = directory / "retained-properties.conf"
    config.write_text(
        "persistence true\n"
        f"persistence_location {directory}\n"
        f"persistence_file {snapshot.name}\n"
        "autosave_interval 0\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )

    with _configured_broker(
        broker,
        config,
        "initial retained-property broker",
    ):
        client = _connect(port, "persist-retain-properties-v5-0")
        try:
            _subscribe(client, "initial retained-property")
            # A PUBLISH would arrive before PINGRESP if stale retained state
            # existed, matching the upstream no-retained-message assertion.
            _ping(client, "initial retained-property empty replay")
            client.sendall(packet(
                0xA2,
                b"\x00\x02\x00" + mqtt_string(_TOPIC),
            ))
            _expect_packet(
                client,
                packet(0xB0, b"\x00\x02\x00\x00"),
                "initial retained-property UNSUBACK",
            )
            # Topic Alias belongs to this Network Connection. It exercises the
            # retained projection but must not appear in either restored
            # PUBLISH expected by _expect_retained_bundle.
            client.sendall(
                _retained_publish(
                    _INITIAL_EXPIRY_SECONDS,
                    topic_alias=1,
                )
            )
            _ping(client, "initial retained-property publish barrier")
            _disconnect(client)
        finally:
            client.close()
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError("retained-property snapshot was not written")

    for generation in (1, 2):
        label = f"retained-property restore {generation}"
        with _configured_broker(broker, config, label):
            client = _connect(
                port,
                f"persist-retain-properties-restore-{generation}",
            )
            try:
                _subscribe(client, label)
                _expect_retained_bundle(client, label)
                _ping(client, f"{label} single replay")
                _disconnect(client)
            finally:
                client.close()
