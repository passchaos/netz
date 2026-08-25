#!/usr/bin/env python3
"""Verify MQTT commit-log recovery without a periodic snapshot."""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import subprocess
import tempfile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("broker", type=Path)
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


def subscribe_packet(packet_id: int, topic_filter: str) -> bytes:
    return packet(
        0x82,
        packet_id.to_bytes(2, "big")
        + b"\x00"
        + mqtt_string(topic_filter)
        + b"\x01",
    )


def publish_packet(topic: str, payload: bytes, packet_id: int) -> bytes:
    return packet(
        0x32,
        mqtt_string(topic)
        + packet_id.to_bytes(2, "big")
        + b"\x00"
        + payload,
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
    executable: Path, port: int, journal: Path, connections: int
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


def main() -> None:
    args = parse_args()
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
            publisher.sendall(
                publish_packet("journal/value", b"survives-sigkill", 1)
            )
            first, body = read_packet(publisher)
            if first != 0x40 or body[0:2] != b"\x00\x01":
                raise AssertionError(f"unexpected PUBACK: {first:#x} {body.hex()}")

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

        restored_port = free_port()
        restored = start_broker(args.broker, restored_port, journal, 1)
        subscriber = None
        try:
            subscriber = connect_client(
                restored_port, "journal-subscriber",
                clean_start=False, session_present=True,
            )
            first, body = read_packet(subscriber)
            if first >> 4 != 3:
                raise AssertionError(f"expected restored PUBLISH: {first:#x}")
            topic_len = int.from_bytes(body[0:2], "big")
            topic_end = 2 + topic_len
            if body[2:topic_end] != b"journal/value":
                raise AssertionError(f"unexpected topic: {body.hex()}")
            packet_id = body[topic_end : topic_end + 2]
            if body[topic_end + 3 :] != b"survives-sigkill":
                raise AssertionError(f"unexpected payload: {body.hex()}")
            subscriber.sendall(b"\x40\x04" + packet_id + b"\x00\x00")
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

    print("MQTT incremental commit-log SIGKILL recovery passed")


if __name__ == "__main__":
    main()
