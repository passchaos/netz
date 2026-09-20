"""Wire and process helpers for MQTT commit-log recovery gates."""

from __future__ import annotations

from pathlib import Path
import socket
import subprocess
import time


SUBSCRIPTION_IDENTIFIER = 53


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


def connect_packet(
    client_id: str, *, clean_start: bool,
    protocol: int = 5,
    session_expiry: int = 60,
    will_topic: str | None = None, will_payload: bytes = b"",
    will_delay: int = 0, will_qos: int = 0, will_retain: bool = False,
) -> bytes:
    if protocol not in (4, 5):
        raise ValueError("protocol must be MQTT 3.1.1 (4) or MQTT 5 (5)")
    properties = b""
    if protocol == 5 and session_expiry:
        properties = b"\x11" + session_expiry.to_bytes(4, "big")
    connect_flags = 2 if clean_start else 0
    payload = mqtt_string(client_id)
    if will_topic is not None:
        connect_flags |= 0x04 | (will_qos << 3)
        if will_retain:
            connect_flags |= 0x20
        if protocol == 4 and will_delay:
            raise ValueError("MQTT 3.1.1 has no Will Delay property")
        will_properties = (
            b"\x18" + will_delay.to_bytes(4, "big")
            if will_delay else b""
        )
        payload += (
            (
                remaining_length(len(will_properties)) + will_properties
                if protocol == 5 else b""
            )
            + mqtt_string(will_topic)
            + len(will_payload).to_bytes(2, "big")
            + will_payload
        )
    variable_header = (
        mqtt_string("MQTT")
        + bytes((protocol, connect_flags))
        + (60).to_bytes(2, "big")
    )
    if protocol == 5:
        variable_header += remaining_length(len(properties)) + properties
    return packet(0x10, variable_header + payload)


def subscribe_packet(
    packet_id: int, topic_filter: str,
    *, subscription_identifier: int | None = SUBSCRIPTION_IDENTIFIER,
    qos: int = 1, protocol: int = 5,
) -> bytes:
    if protocol not in (4, 5):
        raise ValueError("protocol must be MQTT 3.1.1 (4) or MQTT 5 (5)")
    properties = (
        bytes((0x0B, subscription_identifier))
        if protocol == 5 and subscription_identifier is not None else b""
    )
    encoded_properties = (
        remaining_length(len(properties)) + properties
        if protocol == 5 else b""
    )
    return packet(
        0x82,
        packet_id.to_bytes(2, "big")
        + encoded_properties
        + mqtt_string(topic_filter)
        + bytes((qos,)),
    )


def publish_packet(
    topic: str, payload: bytes, packet_id: int,
    *, qos: int = 1, expiry_seconds: int | None = None,
    retain: bool = False, dup: bool = False, protocol: int = 5,
) -> bytes:
    if qos not in (1, 2):
        raise ValueError("publish_packet requires QoS 1 or 2")
    if protocol not in (4, 5):
        raise ValueError("protocol must be MQTT 3.1.1 (4) or MQTT 5 (5)")
    if protocol == 4 and expiry_seconds is not None:
        raise ValueError("MQTT 3.1.1 has no Message Expiry property")
    properties = (
        b"\x02" + expiry_seconds.to_bytes(4, "big")
        if expiry_seconds is not None else b""
    )
    encoded_properties = (
        remaining_length(len(properties)) + properties
        if protocol == 5 else b""
    )
    return packet(
        0x30 | (qos << 1) | (int(dup) << 3) | int(retain),
        mqtt_string(topic)
        + packet_id.to_bytes(2, "big")
        + encoded_properties
        + payload,
    )


def qos0_publish_packet(
    topic: str, payload: bytes, *, retain: bool, protocol: int = 5,
) -> bytes:
    if protocol not in (4, 5):
        raise ValueError("protocol must be MQTT 3.1.1 (4) or MQTT 5 (5)")
    return packet(
        0x31 if retain else 0x30,
        mqtt_string(topic) + (b"\x00" if protocol == 5 else b"") + payload,
    )


def ack_packet(packet_type: int, packet_id: int) -> bytes:
    return packet(packet_type, packet_id.to_bytes(2, "big"))


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


def connect_client(
    port: int, client_id: str, *, clean_start: bool, session_present: bool,
    protocol: int = 5, session_expiry: int = 60,
    will_topic: str | None = None, will_payload: bytes = b"",
    will_delay: int = 0, will_qos: int = 0, will_retain: bool = False,
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(connect_packet(
        client_id,
        clean_start=clean_start,
        protocol=protocol,
        session_expiry=session_expiry,
        will_topic=will_topic,
        will_payload=will_payload,
        will_delay=will_delay,
        will_qos=will_qos,
        will_retain=will_retain,
    ))
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


def wait_for_journal_growth(path: Path, previous_size: int) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size > previous_size:
            return
        time.sleep(0.05)
    raise AssertionError("timed out waiting for a new commit-log record")
