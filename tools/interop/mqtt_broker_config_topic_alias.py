"""Mosquitto-style listener Topic Alias configuration scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
from typing import Iterator

from mqtt_commit_log_support import (
    free_port,
    mqtt_string,
    packet,
    read_packet,
    read_varint,
    remaining_length,
    subscribe_packet,
)


TOPIC_ALIAS_MAXIMUM = 0x22
TOPIC_ALIAS = 0x23


def _connect_packet(client_id: str, topic_alias_maximum: int | None) -> bytes:
    properties = (
        b""
        if topic_alias_maximum is None
        else bytes((TOPIC_ALIAS_MAXIMUM,))
        + topic_alias_maximum.to_bytes(2, "big")
    )
    body = (
        mqtt_string("MQTT")
        + bytes((5, 0x02, 0, 60, len(properties)))
        + properties
        + mqtt_string(client_id)
    )
    return packet(0x10, body)


def _publish(topic: str, payload: bytes, alias: int | None = None) -> bytes:
    properties = (
        b"" if alias is None
        else bytes((TOPIC_ALIAS,)) + alias.to_bytes(2, "big")
    )
    return packet(
        0x30,
        mqtt_string(topic) + bytes((len(properties),)) + properties + payload,
    )


def _read_raw_packet(sock: socket.socket) -> bytes:
    first, body = read_packet(sock)
    return bytes((first,)) + remaining_length(len(body)) + body


def _connack_properties(sock: socket.socket) -> bytes:
    first, body = read_packet(sock)
    if first != 0x20 or len(body) < 3 or body[:2] != b"\x00\x00":
        actual = bytes((first,)) + body
        raise AssertionError(f"invalid Topic Alias CONNACK: {actual.hex()}")
    length, offset = read_varint(body, 2)
    if offset + length != len(body):
        raise AssertionError("malformed Topic Alias CONNACK properties")
    return body[offset:]


def _topic_alias_maximum(properties: bytes) -> int | None:
    offset = 0
    while offset < len(properties):
        identifier = properties[offset]
        offset += 1
        if identifier in (0x21, TOPIC_ALIAS_MAXIMUM):
            if offset + 2 > len(properties):
                raise AssertionError("truncated two-byte CONNACK property")
            value = int.from_bytes(properties[offset : offset + 2], "big")
            offset += 2
            if identifier == TOPIC_ALIAS_MAXIMUM:
                return value
        elif identifier == 0x27:
            if offset + 4 > len(properties):
                raise AssertionError("truncated four-byte CONNACK property")
            offset += 4
        else:
            raise AssertionError(
                f"unexpected CONNACK property {identifier:#x}"
            )
    return None


def _connect(
    port: int,
    client_id: str,
    topic_alias_maximum: int | None = None,
) -> tuple[socket.socket, bytes]:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(_connect_packet(client_id, topic_alias_maximum))
    return sock, _connack_properties(sock)


def _expect(sock: socket.socket, expected: bytes, label: str) -> None:
    actual = _read_raw_packet(sock)
    if actual != expected:
        raise AssertionError(
            f"{label}: expected {expected.hex()}, got {actual.hex()}"
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
        if "configured 3 listeners for 5 clients" not in ready:
            raise RuntimeError(f"Topic Alias broker failed to start: {ready}")
        yield
        if process.wait(timeout=5) != 0:
            raise RuntimeError(
                "Topic Alias broker failed: " + process.stdout.read()
            )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run_topic_alias_policy_case(broker: Path, directory: Path) -> None:
    limited_port = free_port()
    incoming_disabled_port = free_port()
    outgoing_disabled_port = free_port()
    config = directory / "topic-alias.conf"
    config.write_text(
        f"listener {limited_port} 127.0.0.1\n"
        "max_topic_alias 1\n"
        "max_topic_alias_broker 1\n"
        "listener_allow_anonymous true\n"
        "max_connections 2\n"
        f"listener {incoming_disabled_port} 127.0.0.1\n"
        "max_topic_alias 0\n"
        "max_topic_alias_broker 10\n"
        "listener_allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {outgoing_disabled_port} 127.0.0.1\n"
        "max_topic_alias 10\n"
        "max_topic_alias_broker 0\n"
        "listener_allow_anonymous true\n"
        "max_connections 2\n"
    )

    with _configured_broker(broker, config):
        topic = "configured/topic/alias/one"
        second_topic = "configured/topic/alias/two"
        subscriber, properties = _connect(
            limited_port, "alias-limited-sub", 2
        )
        publisher, publisher_properties = _connect(
            limited_port, "alias-limited-pub"
        )
        try:
            if _topic_alias_maximum(properties) != 1:
                raise AssertionError("listener did not advertise alias maximum 1")
            if _topic_alias_maximum(publisher_properties) != 1:
                raise AssertionError("publisher received wrong alias maximum")
            subscriber.sendall(
                subscribe_packet(
                    1,
                    "configured/topic/alias/#",
                    subscription_identifier=None,
                    qos=0,
                    protocol=5,
                )
            )
            _expect(
                subscriber,
                packet(0x90, b"\x00\x01\x00\x00"),
                "alias SUBACK",
            )

            publisher.sendall(_publish(topic, b"first", 1))
            _expect(
                subscriber,
                _publish(topic, b"first", 1),
                "bounded outgoing alias establishment",
            )
            publisher.sendall(_publish("", b"second", 1))
            _expect(
                subscriber,
                _publish("", b"second", 1),
                "bounded outgoing alias reuse",
            )
            publisher.sendall(_publish(second_topic, b"third"))
            _expect(
                subscriber,
                _publish(second_topic, b"third"),
                "broker alias ceiling",
            )
            publisher.sendall(_publish(topic, b"invalid", 2))
            _expect(publisher, bytes.fromhex("e00194"), "alias limit disconnect")
            subscriber.sendall(packet(0xE0, b""))
        finally:
            publisher.close()
            subscriber.close()

        disabled, properties = _connect(
            incoming_disabled_port, "alias-incoming-disabled", 2
        )
        try:
            if _topic_alias_maximum(properties) is not None:
                raise AssertionError("zero inbound alias limit was advertised")
            disabled.sendall(_publish(topic, b"invalid", 1))
            _expect(disabled, bytes.fromhex("e00194"), "disabled alias disconnect")
        finally:
            disabled.close()

        subscriber, properties = _connect(
            outgoing_disabled_port, "alias-outgoing-disabled-sub", 2
        )
        publisher, _ = _connect(
            outgoing_disabled_port, "alias-outgoing-disabled-pub"
        )
        try:
            if _topic_alias_maximum(properties) != 10:
                raise AssertionError("listener default inbound alias limit drifted")
            subscriber.sendall(
                subscribe_packet(
                    1,
                    topic,
                    subscription_identifier=None,
                    qos=0,
                    protocol=5,
                )
            )
            _expect(
                subscriber,
                packet(0x90, b"\x00\x01\x00\x00"),
                "no-alias SUBACK",
            )
            for payload in (b"first", b"second"):
                publisher.sendall(_publish(topic, payload))
                _expect(
                    subscriber,
                    _publish(topic, payload),
                    "disabled broker alias delivery",
                )
            publisher.sendall(packet(0xE0, b""))
            subscriber.sendall(packet(0xE0, b""))
        finally:
            publisher.close()
            subscriber.close()
