"""Mosquitto-style offline queue-limit integration scenarios."""

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
    read_packet,
    read_varint,
    subscribe_packet,
)


def _expect_packet(sock: socket.socket, expected: bytes, label: str) -> None:
    first, body = read_packet(sock)
    expected_length, body_offset = read_varint(expected, 1)
    if (
        first != expected[0]
        or expected_length != len(body)
        or body != expected[body_offset:]
    ):
        actual = bytes((first,)) + body
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


@contextmanager
def _configured_broker(
    broker: Path,
    config: Path,
    expected_ready: str,
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
        if expected_ready not in ready:
            raise RuntimeError(f"queued-limit broker failed to start: {ready}")
        yield
        return_code = process.wait(timeout=5)
        if return_code != 0:
            raise RuntimeError(
                f"queued-limit broker exited {return_code}: "
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


def _run_limit(
    broker: Path,
    directory: Path,
    proto_ver: int,
    label: str,
    directives: str,
) -> None:
    port = free_port()
    config = directory / f"queued-limit-{label}-{proto_ver}.conf"
    config.write_text(
        "max_inflight_messages 1\n"
        + directives
        + f"listener {port} 127.0.0.1\n"
        + "listener_allow_anonymous true\n"
        + "max_connections 3\n"
    )
    with _configured_broker(
        broker, config, "configured 1 listeners for 3 clients"
    ):
        client_id = f"queued-{label}-{proto_ver}"
        topic = f"queued/{label}/{proto_ver}"
        subscriber = connect_client(
            port,
            client_id,
            clean_start=False,
            session_present=False,
            protocol=proto_ver,
            session_expiry=60,
        )
        try:
            subscriber.sendall(
                subscribe_packet(
                    1,
                    topic,
                    subscription_identifier=None,
                    qos=1,
                    protocol=proto_ver,
                )
            )
            expected_suback = packet(
                0x90,
                bytes((0, 1))
                + (b"\x00" if proto_ver == 5 else b"")
                + b"\x01",
            )
            _expect_packet(subscriber, expected_suback, "queued-limit SUBACK")
            _disconnect(subscriber)
        finally:
            subscriber.close()

        publisher = connect_client(
            port,
            f"queued-{label}-publisher-{proto_ver}",
            clean_start=True,
            session_present=False,
            protocol=proto_ver,
        )
        payloads = (b"123456", b"789012", b"dropped")
        try:
            for packet_id, payload in enumerate(payloads, 10):
                publisher.sendall(
                    publish_packet(
                        topic,
                        payload,
                        packet_id,
                        qos=1,
                        protocol=proto_ver,
                    )
                )
                _expect_packet(
                    publisher,
                    ack_packet(0x40, packet_id),
                    f"queued-limit publisher PUBACK {packet_id}",
                )
            _disconnect(publisher)
        finally:
            publisher.close()

        subscriber = connect_client(
            port,
            client_id,
            clean_start=False,
            session_present=True,
            protocol=proto_ver,
            session_expiry=60,
        )
        try:
            for delivery_id, payload in enumerate(payloads[:2], 1):
                _expect_packet(
                    subscriber,
                    publish_packet(
                        topic,
                        payload,
                        delivery_id,
                        qos=1,
                        protocol=proto_ver,
                    ),
                    f"queued-limit delivery {delivery_id}",
                )
                subscriber.sendall(ack_packet(0x40, delivery_id))
            subscriber.sendall(packet(0xC0, b""))
            _expect_packet(
                subscriber,
                packet(0xD0, b""),
                "queued-limit dropped-message barrier",
            )
            _disconnect(subscriber)
        finally:
            subscriber.close()


def run_queued_limits_case(broker: Path, directory: Path) -> None:
    # Source-locked to Mosquitto 5cd254651159's queue-limit implementation and
    # 03-publish-qos1-queued-bytes.py threshold behavior.
    for proto_ver in (4, 5):
        _run_limit(
            broker,
            directory,
            proto_ver,
            "messages",
            "max_queued_messages 2\nmax_queued_bytes 0\n",
        )
        _run_limit(
            broker,
            directory,
            proto_ver,
            "bytes",
            "max_queued_messages 0\nmax_queued_bytes 10\n",
        )
