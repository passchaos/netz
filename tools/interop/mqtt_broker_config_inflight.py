"""Mosquitto-style max_inflight_messages integration scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
from typing import Iterator


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _variable_integer(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


def _utf8(value: str) -> bytes:
    encoded = value.encode()
    return len(encoded).to_bytes(2, "big") + encoded


def _mqtt_packet(packet_type: int, body: bytes) -> bytes:
    return bytes((packet_type,)) + _variable_integer(len(body)) + body


def _connect_packet(client_id: str, proto_ver: int) -> bytes:
    body = (
        _utf8("MQTT")
        + bytes((proto_ver, 0x02))
        + bytes((0, 60))
        + (b"\x00" if proto_ver == 5 else b"")
        + _utf8(client_id)
    )
    return _mqtt_packet(0x10, body)


def _subscribe_packet(
    packet_id: int,
    topic: str,
    proto_ver: int,
    qos: int,
) -> bytes:
    return _mqtt_packet(
        0x82,
        packet_id.to_bytes(2, "big")
        + (b"\x00" if proto_ver == 5 else b"")
        + _utf8(topic)
        + bytes((qos,)),
    )


def _publish_packet(
    topic: str,
    payload: bytes,
    qos: int,
    packet_id: int,
    proto_ver: int,
) -> bytes:
    body = _utf8(topic) + packet_id.to_bytes(2, "big")
    if proto_ver == 5:
        body += b"\x00"
    return _mqtt_packet(0x30 | (qos << 1), body + payload)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError("connection closed before complete packet")
        result.extend(part)
    return bytes(result)


def _read_packet(sock: socket.socket) -> bytes:
    result = bytearray(_recv_exact(sock, 1))
    remaining = 0
    multiplier = 1
    for _ in range(4):
        byte = _recv_exact(sock, 1)[0]
        result.append(byte)
        remaining += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            result.extend(_recv_exact(sock, remaining))
            return bytes(result)
        multiplier *= 128
    raise AssertionError("malformed MQTT Remaining Length")


def _decode_variable_integer(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    multiplier = 1
    for _ in range(4):
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            return value, offset
        multiplier *= 128
    raise AssertionError("malformed MQTT variable integer")


def _connack_reason(packet: bytes) -> int:
    if packet[0] != 0x20:
        raise AssertionError(f"expected CONNACK, got {packet.hex()}")
    remaining, offset = _decode_variable_integer(packet, 1)
    if remaining < 2 or offset + remaining != len(packet):
        raise AssertionError(f"malformed CONNACK: {packet.hex()}")
    return packet[offset + 1]


def _connack_properties(packet: bytes) -> bytes:
    if _connack_reason(packet) != 0:
        raise AssertionError("max-inflight CONNECT failed: " + packet.hex())
    remaining, offset = _decode_variable_integer(packet, 1)
    if remaining < 3:
        raise AssertionError(f"malformed MQTT 5 CONNACK: {packet.hex()}")
    length, start = _decode_variable_integer(packet, offset + 2)
    if start + length != len(packet):
        raise AssertionError(f"malformed MQTT 5 CONNACK: {packet.hex()}")
    return packet[start : start + length]


def _assert_receive_maximum(packet: bytes, expected: int) -> None:
    encoded = bytes((0x21,)) + expected.to_bytes(2, "big")
    properties = _connack_properties(packet)
    if not properties.startswith(encoded):
        raise AssertionError(
            f"CONNACK omitted Receive Maximum {expected}: {packet.hex()}"
        )


def _assert_receive_maximum_omitted(packet: bytes) -> None:
    properties = _connack_properties(packet)
    expected = bytes.fromhex("27001e8480220010")
    if properties != expected:
        raise AssertionError(
            "zero max_inflight_messages did not use default Receive Maximum: "
            f"expected {expected.hex()}, got {properties.hex()}"
        )


def _ack_reason(packet: bytes, packet_type: int, packet_id: int) -> int:
    if packet[0] != packet_type:
        raise AssertionError(
            f"expected acknowledgment {packet_type:#x}, got {packet.hex()}"
        )
    remaining, offset = _decode_variable_integer(packet, 1)
    if remaining < 2 or offset + remaining != len(packet):
        raise AssertionError(f"malformed acknowledgment: {packet.hex()}")
    if int.from_bytes(packet[offset : offset + 2], "big") != packet_id:
        raise AssertionError(f"wrong acknowledgment: {packet.hex()}")
    return packet[offset + 2] if remaining > 2 else 0


def _ack_packet(packet_type: int, packet_id: int) -> bytes:
    return _mqtt_packet(packet_type, packet_id.to_bytes(2, "big"))


def _ping(sock: socket.socket) -> None:
    sock.sendall(b"\xc0\x00")
    packet = _read_packet(sock)
    if packet != b"\xd0\x00":
        raise AssertionError(
            "queued PUBLISH crossed inflight barrier: " + packet.hex()
        )


def _close_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


@contextmanager
def _configured_broker(
    broker: Path,
    config: Path,
    expected_ready: str,
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
        if expected_ready not in ready:
            raise RuntimeError(f"{label} failed to start: {ready}")
        yield
        return_code = process.wait(timeout=5)
        if return_code != 0:
            raise RuntimeError(
                f"{label} exited {return_code}: " + process.stdout.read()
            )
    finally:
        _close_process(process)


def _connect(port: int, client_id: str, proto_ver: int) -> socket.socket:
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.settimeout(5)
    client.sendall(_connect_packet(client_id, proto_ver))
    connack = _read_packet(client)
    if proto_ver == 5:
        _assert_receive_maximum(connack, 1)
    elif connack != bytes.fromhex("20020000"):
        raise AssertionError(
            "max-inflight MQTT 3.1.1 CONNECT failed: " + connack.hex()
        )
    return client


def _run_outgoing(broker: Path, directory: Path) -> None:
    port = _free_port()
    config = directory / "max-inflight-outgoing.conf"
    config.write_text(
        "max_inflight_messages 1\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 4\n"
    )
    with _configured_broker(
        broker, config, "configured 1 listeners for 4 clients", "max-inflight"
    ):
        for proto_ver in (5, 4):
            subscriber = _connect(port, f"max-inflight-sub-{proto_ver}", proto_ver)
            publisher = _connect(port, f"max-inflight-pub-{proto_ver}", proto_ver)
            try:
                topic = f"max/inflight/{proto_ver}"
                subscriber.sendall(_subscribe_packet(1, topic, proto_ver, 2))
                expected_suback = bytes.fromhex(
                    "900400010002" if proto_ver == 5 else "9003000102"
                )
                if _read_packet(subscriber) != expected_suback:
                    raise AssertionError(
                        f"max-inflight SUBACK mismatch for MQTT {proto_ver}"
                    )
                publisher.sendall(
                    _publish_packet(topic, b"one", 1, 10, proto_ver)
                    + _publish_packet(topic, b"two", 1, 11, proto_ver)
                )
                if _ack_reason(_read_packet(publisher), 0x40, 10) != 0:
                    raise AssertionError("first max-inflight PUBLISH was rejected")
                if _ack_reason(_read_packet(publisher), 0x40, 11) != 0:
                    raise AssertionError("second max-inflight PUBLISH was rejected")
                if _read_packet(subscriber) != _publish_packet(
                    topic, b"one", 1, 1, proto_ver
                ):
                    raise AssertionError(
                        f"first bounded delivery mismatch for MQTT {proto_ver}"
                    )
                _ping(subscriber)
                subscriber.sendall(bytes.fromhex("40020001"))
                if _read_packet(subscriber) != _publish_packet(
                    topic, b"two", 1, 2, proto_ver
                ):
                    raise AssertionError(
                        f"second bounded delivery mismatch for MQTT {proto_ver}"
                    )
                subscriber.sendall(bytes.fromhex("40020002"))

                for packet_id, payload in ((12, b"three"), (13, b"four")):
                    publisher.sendall(
                        _publish_packet(topic, payload, 2, packet_id, proto_ver)
                    )
                    if _ack_reason(
                        _read_packet(publisher), 0x50, packet_id
                    ) != 0:
                        raise AssertionError(
                            "max-inflight source QoS 2 PUBLISH was rejected"
                        )
                    publisher.sendall(_ack_packet(0x62, packet_id))
                    if _ack_reason(
                        _read_packet(publisher), 0x70, packet_id
                    ) != 0:
                        raise AssertionError(
                            "max-inflight source QoS 2 release failed"
                        )

                if _read_packet(subscriber) != _publish_packet(
                    topic, b"three", 2, 3, proto_ver
                ):
                    raise AssertionError(
                        f"first QoS 2 delivery mismatch for MQTT {proto_ver}"
                    )
                _ping(subscriber)
                subscriber.sendall(_ack_packet(0x50, 3))
                if _read_packet(subscriber) != _ack_packet(0x62, 3):
                    raise AssertionError(
                        f"first QoS 2 PUBREL mismatch for MQTT {proto_ver}"
                    )
                _ping(subscriber)
                subscriber.sendall(_ack_packet(0x70, 3))
                if _read_packet(subscriber) != _publish_packet(
                    topic, b"four", 2, 4, proto_ver
                ):
                    raise AssertionError(
                        f"second QoS 2 delivery mismatch for MQTT {proto_ver}"
                    )
                subscriber.sendall(_ack_packet(0x50, 4))
                if _read_packet(subscriber) != _ack_packet(0x62, 4):
                    raise AssertionError(
                        f"second QoS 2 PUBREL mismatch for MQTT {proto_ver}"
                    )
                subscriber.sendall(_ack_packet(0x70, 4))
                publisher.sendall(bytes.fromhex("e000"))
                subscriber.sendall(bytes.fromhex("e000"))
            finally:
                publisher.close()
                subscriber.close()


def _run_incoming(broker: Path, directory: Path) -> None:
    port = _free_port()
    config = directory / "max-inflight-incoming.conf"
    config.write_text(
        "max_inflight_messages 1\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 2\n"
    )
    with _configured_broker(
        broker, config, "configured 1 listeners for 2 clients", "max-inflight"
    ):
        for proto_ver in (5, 4):
            client = _connect(port, f"max-inflight-in-{proto_ver}", proto_ver)
            try:
                client.sendall(
                    _publish_packet(
                        "max/inflight/in/one", b"one", 2, 1, proto_ver
                    )
                    + _publish_packet(
                        "max/inflight/in/two", b"two", 2, 2, proto_ver
                    )
                )
                if _ack_reason(_read_packet(client), 0x50, 1) != 0:
                    raise AssertionError("first max-inflight QoS 2 PUBLISH failed")
                if proto_ver == 5:
                    packet = _read_packet(client)
                    if packet != bytes.fromhex("e00193"):
                        raise AssertionError(
                            "Receive Maximum violation mismatch: " + packet.hex()
                        )
                else:
                    try:
                        closed = client.recv(1) == b""
                    except ConnectionError:
                        closed = True
                    if not closed:
                        raise AssertionError(
                            "MQTT 3.1.1 Receive Maximum violation was not closed"
                        )
            finally:
                client.close()


def _run_unlimited_mapping(broker: Path, directory: Path) -> None:
    port = _free_port()
    config = directory / "max-inflight-unlimited.conf"
    config.write_text(
        "max_inflight_messages 0\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    with _configured_broker(
        broker,
        config,
        "configured 1 listeners for 1 clients",
        "unlimited max-inflight",
    ):
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.settimeout(5)
        try:
            client.sendall(_connect_packet("max-inflight-unlimited", 5))
            _assert_receive_maximum_omitted(_read_packet(client))
            client.sendall(bytes.fromhex("e000"))
        finally:
            client.close()


def run_max_inflight_messages_case(broker: Path, directory: Path) -> None:
    # Source-locked to Mosquitto 5cd254651159's max-inflight QoS 1/2 tests.
    _run_outgoing(broker, directory)
    _run_incoming(broker, directory)
    _run_unlimited_mapping(broker, directory)
