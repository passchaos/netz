#!/usr/bin/env python3
"""Verify live MQTT checkpointing and recovery across a broker crash."""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("broker", type=Path)
    return parser.parse_args()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def encode_remaining_length(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        result.append(byte)
        if not value:
            return bytes(result)


def mqtt_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return len(encoded).to_bytes(2, "big") + encoded


def packet(first: int, body: bytes) -> bytes:
    return bytes((first,)) + encode_remaining_length(len(body)) + body


def connect_packet(client_id: str, *, clean_start: bool) -> bytes:
    properties = bytes((0x11,)) + (60).to_bytes(4, "big")
    body = (
        mqtt_string("MQTT")
        + bytes((5, 0x02 if clean_start else 0x00))
        + (60).to_bytes(2, "big")
        + encode_remaining_length(len(properties))
        + properties
        + mqtt_string(client_id)
    )
    return packet(0x10, body)


def subscribe_packet(packet_id: int, topic_filter: str) -> bytes:
    body = (
        packet_id.to_bytes(2, "big")
        + b"\x00"
        + mqtt_string(topic_filter)
        + b"\x01"
    )
    return packet(0x82, body)


def publish_packet(
    topic: str, payload: bytes, *, qos: int, packet_id: int | None = None
) -> bytes:
    if qos not in (0, 1):
        raise ValueError("autosave fixture supports QoS 0/1 only")
    if (qos == 0) != (packet_id is None):
        raise ValueError("Packet Identifier is required exactly for QoS 1")
    body = mqtt_string(topic)
    if packet_id is not None:
        body += packet_id.to_bytes(2, "big")
    body += b"\x00" + payload
    return packet(0x30 | (qos << 1), body)


def recv_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError("broker closed before complete MQTT packet")
        result.extend(part)
    return bytes(result)


def read_packet(sock: socket.socket) -> tuple[int, bytes]:
    first = recv_exact(sock, 1)[0]
    multiplier = 1
    remaining = 0
    while True:
        byte = recv_exact(sock, 1)[0]
        remaining += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            break
        multiplier *= 128
        if multiplier > 128**3:
            raise AssertionError("malformed MQTT Remaining Length")
    return first, recv_exact(sock, remaining)


def connect_client(
    port: int, client_id: str, *, clean_start: bool, session_present: bool
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(connect_packet(client_id, clean_start=clean_start))
    first, body = read_packet(sock)
    if (
        first != 0x20
        or len(body) < 3
        or body[0] != int(session_present)
        or body[1] != 0
    ):
        sock.close()
        raise AssertionError(
            f"unexpected CONNACK: first={first:#x}, body={body.hex()}"
        )
    return sock


def start_broker(
    executable: Path,
    port: int,
    database: Path,
    connections: int,
    *,
    autosave: bool,
) -> subprocess.Popen[str]:
    command = [
        str(executable),
        f"--bind=127.0.0.1:{port}",
        f"--connections={connections}",
        "--max-queued-deliveries=32",
        "--max-outgoing-inflight=8",
        f"--persistence={database}",
    ]
    if autosave:
        command.extend((
            "--no-restore",
            "--autosave-interval-seconds=1",
            "--queue-qos0-messages",
        ))
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    assert process.stdout is not None
    line = process.stdout.readline()
    if "listening" not in line:
        process.kill()
        raise RuntimeError(f"netz broker failed to start: {line.strip()}")
    return process


def checkpoint_identity(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return stat.st_ino, stat.st_mtime_ns


def wait_for_checkpoint(
    path: Path, previous: tuple[int, int] | None
) -> tuple[int, int]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists():
            identity = checkpoint_identity(path)
            if previous is None or identity != previous:
                return identity
        time.sleep(0.05)
    raise AssertionError("timed out waiting for a fresh autosave checkpoint")


def expect_packet_type(sock: socket.socket, packet_type: int, label: str) -> bytes:
    first, body = read_packet(sock)
    if first >> 4 != packet_type:
        raise AssertionError(f"{label}: unexpected packet type {first >> 4}")
    return body


def main() -> None:
    args = parse_args()
    with tempfile.TemporaryDirectory(prefix="netz-mqtt-autosave-") as raw_tmp:
        database = Path(raw_tmp) / "broker.db"
        port = free_port()
        source = start_broker(args.broker, port, database, 2, autosave=True)
        subscriber: socket.socket | None = None
        publisher: socket.socket | None = None
        try:
            baseline = wait_for_checkpoint(database, None)
            subscriber = connect_client(
                port, "autosave-client", clean_start=False, session_present=False
            )
            subscriber.sendall(subscribe_packet(1, "autosave/#"))
            suback = expect_packet_type(subscriber, 9, "SUBACK")
            if suback[-1:] != b"\x01":
                raise AssertionError(f"unexpected SUBACK: {suback.hex()}")
            wait_for_checkpoint(database, baseline)
            subscriber.sendall(b"\xc0\x00")
            if read_packet(subscriber) != (0xD0, b""):
                raise AssertionError("live client failed after autosave")
            # Put the durable Session offline, enqueue a QoS 0 Application
            # Message under the opt-in policy, and wait for a new checkpoint.
            # This is the process-level counterpart to the Store snapshot test:
            # the broker is killed before any reconnect can drain the queue.
            subscriber.sendall(b"\xe0\x00")
            subscriber.close()
            subscriber = None
            publisher = connect_client(
                port,
                "autosave-qos0-publisher",
                clean_start=True,
                session_present=False,
            )
            qos0_baseline = checkpoint_identity(database)
            publisher.sendall(publish_packet(
                "autosave/qos0", b"survives-crash", qos=0
            ))
            publisher.sendall(b"\xc0\x00")
            if read_packet(publisher) != (0xD0, b""):
                raise AssertionError("QoS 0 publisher failed before autosave")
            wait_for_checkpoint(database, qos0_baseline)
            # Simulate a process crash: the final quiescent save must not run.
            source.kill()
            source.wait(timeout=5)
        finally:
            if subscriber is not None:
                subscriber.close()
            if publisher is not None:
                publisher.close()
            if source.poll() is None:
                source.kill()
                source.wait(timeout=5)

        restored_port = free_port()
        restored = start_broker(
            args.broker, restored_port, database, 2, autosave=False
        )
        subscriber = publisher = None
        try:
            subscriber = connect_client(
                restored_port,
                "autosave-client",
                clean_start=False,
                session_present=True,
            )
            qos0_first, qos0_delivery = read_packet(subscriber)
            if qos0_first != 0x30:
                raise AssertionError(
                    f"expected restored QoS 0 PUBLISH, got {qos0_first:#x}"
                )
            qos0_topic_len = int.from_bytes(qos0_delivery[0:2], "big")
            qos0_topic_end = 2 + qos0_topic_len
            if qos0_delivery[2:qos0_topic_end] != b"autosave/qos0":
                raise AssertionError(
                    f"unexpected restored QoS 0 topic: {qos0_delivery.hex()}"
                )
            # MQTT 5 QoS 0 has no Packet Identifier; its property-length byte
            # follows the Topic Name directly. Exact remainder comparison also
            # proves the Application Message survived the crash byte-for-byte.
            if qos0_delivery[qos0_topic_end:] != b"\x00survives-crash":
                raise AssertionError(
                    f"unexpected restored QoS 0 payload: {qos0_delivery.hex()}"
                )
            subscriber.sendall(b"\xc0\x00")
            if read_packet(subscriber) != (0xD0, b""):
                raise AssertionError(
                    "restored QoS 0 was duplicated before PINGRESP"
                )
            publisher = connect_client(
                restored_port,
                "autosave-publisher",
                clean_start=True,
                session_present=False,
            )
            publisher.sendall(publish_packet(
                "autosave/recovered", b"ok", qos=1, packet_id=1
            ))
            puback = expect_packet_type(publisher, 4, "publisher PUBACK")
            if puback[0:2] != b"\x00\x01":
                raise AssertionError(f"unexpected PUBACK: {puback.hex()}")
            delivery = expect_packet_type(subscriber, 3, "restored delivery")
            topic_len = int.from_bytes(delivery[0:2], "big")
            topic_end = 2 + topic_len
            if delivery[2:topic_end] != b"autosave/recovered":
                raise AssertionError(f"unexpected restored topic: {delivery.hex()}")
            delivery_id = delivery[topic_end : topic_end + 2]
            if delivery[-2:] != b"ok":
                raise AssertionError(f"unexpected restored payload: {delivery.hex()}")
            subscriber.sendall(b"\x40\x04" + delivery_id + b"\x00\x00")
            # Finish the new transient publisher first. The restored durable
            # Session owns the second slot until its DISCONNECT is processed.
            publisher.sendall(b"\xe0\x00")
            time.sleep(0.05)
            subscriber.sendall(b"\xe0\x00")
            restored.wait(timeout=5)
            if restored.returncode != 0:
                assert restored.stdout is not None
                raise RuntimeError(
                    f"restored broker exited {restored.returncode}: "
                    + restored.stdout.read()
                )
        finally:
            if subscriber is not None:
                subscriber.close()
            if publisher is not None:
                publisher.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait(timeout=5)

    print("MQTT live autosave Session and queued QoS0 crash recovery passed")


if __name__ == "__main__":
    main()
