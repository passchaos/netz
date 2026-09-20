#!/usr/bin/env python3
"""Verify MQTT commit-log recovery without a periodic snapshot."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from mqtt_vectors import source_lock


MOSQUITTO_SOURCES = (
    "broker/04-retain-check-source-persist.py",
    "broker/11-message-expiry.py",
    "broker/11-subscription-id.py",
)
SUBSCRIPTION_IDENTIFIER = 53


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("broker", type=Path)
    parser.add_argument(
        "--mosquitto-test-root",
        type=Path,
        help="verify the referenced Mosquitto source before running",
    )
    return parser.parse_args()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def remaining_length(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


def mqtt_string(value: str) -> bytes:
    encoded = value.encode()
    return len(encoded).to_bytes(2, "big") + encoded


def packet(first: int, body: bytes) -> bytes:
    return bytes((first,)) + remaining_length(len(body)) + body


def connect_packet(client_id: str, *, clean_start: bool) -> bytes:
    properties = b"\x11" + (60).to_bytes(4, "big")
    body = (
        mqtt_string("MQTT")
        + bytes((5, 2 if clean_start else 0))
        + (60).to_bytes(2, "big")
        + remaining_length(len(properties))
        + properties
        + mqtt_string(client_id)
    )
    return packet(0x10, body)


def subscribe_packet(
    packet_id: int, topic_filter: str,
    *, subscription_identifier: int | None = SUBSCRIPTION_IDENTIFIER,
    qos: int = 1,
) -> bytes:
    properties = (
        bytes((0x0B, subscription_identifier))
        if subscription_identifier is not None else b""
    )
    return packet(
        0x82,
        packet_id.to_bytes(2, "big")
        + remaining_length(len(properties))
        + properties
        + mqtt_string(topic_filter)
        + bytes((qos,)),
    )


def publish_packet(
    topic: str, payload: bytes, packet_id: int,
    *, expiry_seconds: int | None = None, retain: bool = False,
) -> bytes:
    properties = (
        b"\x02" + expiry_seconds.to_bytes(4, "big")
        if expiry_seconds is not None else b""
    )
    return packet(
        0x33 if retain else 0x32,
        mqtt_string(topic)
        + packet_id.to_bytes(2, "big")
        + remaining_length(len(properties))
        + properties
        + payload,
    )


def qos0_publish_packet(topic: str, payload: bytes, *, retain: bool) -> bytes:
    return packet(
        0x31 if retain else 0x30,
        mqtt_string(topic) + b"\x00" + payload,
    )


def recv_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError("broker closed before a complete packet")
        result.extend(part)
    return bytes(result)


def read_packet(sock: socket.socket) -> tuple[int, bytes]:
    first = recv_exact(sock, 1)[0]
    multiplier = 1
    length = 0
    while True:
        byte = recv_exact(sock, 1)[0]
        length += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            return first, recv_exact(sock, length)
        multiplier *= 128


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    multiplier = 1
    value = 0
    while True:
        if offset >= len(data) or multiplier > 128 * 128 * 128:
            raise AssertionError("malformed MQTT variable byte integer")
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            return value, offset
        multiplier *= 128


def restored_publish(
    sock: socket.socket, *, expected_payload: bytes, expect_expiry: bool
) -> bytes:
    first, body = read_packet(sock)
    if first != 0x32:
        raise AssertionError(f"expected restored QoS 1 PUBLISH: {first:#x}")
    topic_len = int.from_bytes(body[0:2], "big")
    topic_end = 2 + topic_len
    if body[2:topic_end] != b"journal/value":
        raise AssertionError(f"unexpected topic: {body.hex()}")
    packet_id = body[topic_end : topic_end + 2]
    properties_len, property_start = read_varint(body, topic_end + 2)
    property_end = property_start + properties_len
    properties = body[property_start:property_end]
    if expect_expiry:
        expected_suffix = bytes((0x0B, SUBSCRIPTION_IDENTIFIER))
        if len(properties) != 7 or properties[0] != 0x02 or (
            properties[5:] != expected_suffix
        ):
            raise AssertionError(
                f"unexpected restored expiring properties: {body.hex()}"
            )
        remaining_expiry = int.from_bytes(properties[1:5], "big")
        if not 1 <= remaining_expiry < 100:
            raise AssertionError(
                f"Message Expiry was not reduced across restart: "
                f"{remaining_expiry}"
            )
    elif properties != bytes((0x0B, SUBSCRIPTION_IDENTIFIER)):
        raise AssertionError(
            f"unexpected restored non-expiring properties: {body.hex()}"
        )
    if body[property_end:] != expected_payload:
        raise AssertionError(f"unexpected payload: {body.hex()}")
    return packet_id


def connect_client(
    port: int, client_id: str, *, clean_start: bool, session_present: bool
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(connect_packet(client_id, clean_start=clean_start))
    first, body = read_packet(sock)
    if first != 0x20 or body[0] != int(session_present) or body[1] != 0:
        sock.close()
        raise AssertionError(f"unexpected CONNACK: {first:#x} {body.hex()}")
    return sock


def start_broker(
    executable: Path, port: int, journal: Path, connections: int,
    *, extra_args: tuple[str, ...] = (),
) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [
            str(executable),
            f"--bind=127.0.0.1:{port}",
            f"--connections={connections}",
            "--max-queued-deliveries=32",
            "--max-outgoing-inflight=8",
            "--queue-qos0-messages",
            f"--commit-log={journal}",
            *extra_args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    line = process.stdout.readline()
    if "listening" not in line:
        process.kill()
        raise RuntimeError(f"netz broker failed to start: {line.strip()}")
    return process


def stop_broker(process: subprocess.Popen[str]) -> None:
    process.wait(timeout=5)
    if process.returncode != 0:
        assert process.stdout is not None
        raise RuntimeError(
            f"netz broker exited {process.returncode}: "
            + process.stdout.read()
        )


def verify_retained_source_recovery(executable: Path) -> None:
    topic = "retain/check-source"
    payload = b"retained across SIGKILL"
    source_client_id = "journal-retained-writer"
    with tempfile.TemporaryDirectory(prefix="netz-mqtt-retained-journal-") as raw:
        directory = Path(raw)
        source_journal = directory / "source.log"
        source_port = free_port()
        source = start_broker(executable, source_port, source_journal, 1)
        publisher = None
        try:
            publisher = connect_client(
                source_port,
                source_client_id, clean_start=True, session_present=False,
            )
            publisher.sendall(publish_packet(
                topic, payload, 7, retain=True
            ))
            first, body = read_packet(publisher)
            if first != 0x40 or body != b"\x00\x07\x10":
                raise AssertionError(
                    f"unexpected retained PUBACK: {first:#x} {body.hex()}"
                )
            source.kill()
            source.wait(timeout=5)
        finally:
            if publisher is not None:
                publisher.close()
            if source.poll() is None:
                source.kill()
                source.wait()

        denied_journal = directory / "denied.log"
        unchecked_journal = directory / "unchecked.log"
        shutil.copyfile(source_journal, denied_journal)
        shutil.copyfile(source_journal, unchecked_journal)

        cases = (
            ("denied", denied_journal, (), False),
            (
                "unchecked",
                unchecked_journal,
                ("--no-check-retain-source",),
                True,
            ),
        )
        for label, journal, policy_args, expect_replay in cases:
            port = free_port()
            broker = start_broker(
                executable,
                port,
                journal,
                1,
                extra_args=(
                    f"--deny-retained-source-client-id={source_client_id}",
                    *policy_args,
                ),
            )
            subscriber = None
            try:
                subscriber = connect_client(
                    port,
                    f"retained-reader-{label}",
                    clean_start=True,
                    session_present=False,
                )
                subscriber.sendall(subscribe_packet(
                    1, topic, subscription_identifier=None, qos=0
                ))
                first, body = read_packet(subscriber)
                if first != 0x90 or body != b"\x00\x01\x00\x00":
                    raise AssertionError(
                        f"unexpected retained SUBACK {label}: "
                        f"{first:#x} {body.hex()}"
                    )
                if expect_replay:
                    expected = qos0_publish_packet(
                        topic, payload, retain=True
                    )
                    expected_first = expected[0]
                    expected_length, expected_body_offset = read_varint(
                        expected, 1
                    )
                    expected_body = expected[expected_body_offset:]
                    if len(expected_body) != expected_length:
                        raise AssertionError(
                            "invalid expected retained PUBLISH framing"
                        )
                    actual = read_packet(subscriber)
                    if actual != (expected_first, expected_body):
                        raise AssertionError(
                            f"unexpected retained replay {label}: "
                            f"{actual[0]:#x} {actual[1].hex()}"
                        )
                subscriber.sendall(b"\xc0\x00")
                if read_packet(subscriber) != (0xD0, b""):
                    raise AssertionError(
                        f"unexpected retained source result {label}"
                    )
                subscriber.sendall(b"\xe0\x00")
                stop_broker(broker)
            finally:
                if subscriber is not None:
                    subscriber.close()
                if broker.poll() is None:
                    broker.kill()
                    broker.wait()


def main() -> None:
    args = parse_args()
    if args.mosquitto_test_root is not None:
        for source in MOSQUITTO_SOURCES:
            source_lock.verify_source_hash(
                args.mosquitto_test_root / source,
                source_lock.MOSQUITTO_SOURCE_SHA256[source],
            )
    with tempfile.TemporaryDirectory(prefix="netz-mqtt-journal-") as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        source = start_broker(args.broker, port, journal, 2)
        subscriber = publisher = None
        try:
            subscriber = connect_client(
                port, "journal-subscriber",
                clean_start=False, session_present=False,
            )
            subscriber.sendall(subscribe_packet(1, "journal/#"))
            first, body = read_packet(subscriber)
            if first != 0x90 or body[-1:] != b"\x01":
                raise AssertionError(f"unexpected SUBACK: {first:#x} {body.hex()}")
            subscriber.sendall(b"\xe0\x00")
            if subscriber.recv(1) != b"":
                raise AssertionError("subscriber remained open after DISCONNECT")
            subscriber.close()
            subscriber = None

            publisher = connect_client(
                port, "journal-publisher",
                clean_start=True, session_present=False,
            )
            for packet_id, payload, expiry_seconds in (
                (1, b"expires-during-downtime", 5),
                (2, b"survives-with-expiry", 100),
                (3, b"survives-without-expiry", None),
            ):
                publisher.sendall(publish_packet(
                    "journal/value", payload, packet_id,
                    expiry_seconds=expiry_seconds,
                ))
                first, body = read_packet(publisher)
                if first != 0x40 or body[0:2] != packet_id.to_bytes(2, "big"):
                    raise AssertionError(
                        f"unexpected PUBACK {packet_id}: {first:#x} {body.hex()}"
                    )

            # No timer/checkpoint is involved. PUBACK is sent only after the
            # commit record has been fsynced, so SIGKILL immediately after it
            # must still leave the queued delivery recoverable.
            source.kill()
            source.wait(timeout=5)
        finally:
            if subscriber is not None:
                subscriber.close()
            if publisher is not None:
                publisher.close()
            if source.poll() is None:
                source.kill()
                source.wait()

        # Cross the short message's expiry while the broker is stopped.
        time.sleep(6)
        restored_port = free_port()
        restored = start_broker(args.broker, restored_port, journal, 1)
        subscriber = None
        try:
            subscriber = connect_client(
                restored_port, "journal-subscriber",
                clean_start=False, session_present=True,
            )
            expiring_id = restored_publish(
                subscriber, expected_payload=b"survives-with-expiry",
                expect_expiry=True,
            )
            permanent_id = restored_publish(
                subscriber, expected_payload=b"survives-without-expiry",
                expect_expiry=False,
            )
            subscriber.sendall(b"\x40\x04" + expiring_id + b"\x00\x00")
            subscriber.sendall(b"\x40\x04" + permanent_id + b"\x00\x00")
            # PINGRESP must follow the two surviving deliveries. A stale first
            # PUBLISH would be read here instead and fail the exact check.
            subscriber.sendall(b"\xc0\x00")
            if read_packet(subscriber) != (0xD0, b""):
                raise AssertionError("expired PUBLISH survived broker restart")
            subscriber.sendall(b"\xe0\x00")
            restored.wait(timeout=5)
            if restored.returncode != 0:
                assert restored.stdout is not None
                raise RuntimeError(restored.stdout.read())
        finally:
            if subscriber is not None:
                subscriber.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()

    print(
        "MQTT incremental commit-log SIGKILL recovery passed with reduced "
        "Message Expiry and Subscription Identifier "
        f"{SUBSCRIPTION_IDENTIFIER}"
    )
    verify_retained_source_recovery(args.broker)
    print(
        "MQTT retained-source authorization survived commit-log SIGKILL "
        "recovery"
    )


if __name__ == "__main__":
    main()
