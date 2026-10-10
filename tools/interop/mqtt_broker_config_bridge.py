"""End-to-end inbound bridge coverage for the production config runner."""

from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import time


FINITE_TEST_ENV = "NETZ_MQTT_CONFIG_FINITE_TEST"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _varint(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        result.append(byte)
        if not value:
            return bytes(result)


def _utf8(value: str) -> bytes:
    encoded = value.encode()
    return len(encoded).to_bytes(2, "big") + encoded


def _packet(first: int, body: bytes) -> bytes:
    return bytes((first,)) + _varint(len(body)) + body


def _connect(client_id: str) -> bytes:
    variable = _utf8("MQTT") + bytes((5, 2)) + (30).to_bytes(2, "big")
    return _packet(0x10, variable + b"\x00" + _utf8(client_id))


def _subscribe(packet_id: int, topic: str, qos: int) -> bytes:
    body = packet_id.to_bytes(2, "big") + b"\x00" + _utf8(topic) + bytes((qos,))
    return _packet(0x82, body)


def _publish(packet_id: int, topic: str, payload: bytes, qos: int) -> bytes:
    body = _utf8(topic) + packet_id.to_bytes(2, "big") + b"\x00" + payload
    return _packet(0x31 | (qos << 1), body)


def _read_exact(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) != length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise EOFError("MQTT peer closed the connection")
        result.extend(chunk)
    return bytes(result)


def _read_varint_socket(sock: socket.socket) -> tuple[int, bytes]:
    value = 0
    multiplier = 1
    encoded = bytearray()
    for _ in range(4):
        byte = _read_exact(sock, 1)[0]
        encoded.append(byte)
        value += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            return value, bytes(encoded)
        multiplier *= 128
    raise AssertionError("overlong MQTT Remaining Length")


def _read_packet(sock: socket.socket) -> bytes:
    first = _read_exact(sock, 1)
    remaining, encoded = _read_varint_socket(sock)
    return first + encoded + _read_exact(sock, remaining)


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    multiplier = 1
    for _ in range(4):
        if offset >= len(data):
            raise AssertionError("truncated MQTT variable integer")
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            return value, offset
        multiplier *= 128
    raise AssertionError("overlong MQTT variable integer")


def _connect_client(port: int, client_id: str) -> socket.socket:
    client = socket.create_connection(("127.0.0.1", port), timeout=10)
    client.settimeout(10)
    client.sendall(_connect(client_id))
    connack = _read_packet(client)
    _, body = _decode_varint(connack, 1)
    if connack[0] != 0x20 or body + 2 > len(connack) or connack[body + 1] != 0:
        client.close()
        raise AssertionError(f"bridge test CONNECT failed: {connack.hex()}")
    return client


def _publish_message(
    client: socket.socket, packet_id: int, payload: bytes, qos: int
) -> None:
    client.sendall(
        _publish(packet_id, "remote/sensors/temperature", payload, qos)
    )
    acknowledgement = _read_packet(client)
    expected_type = 0x40 if qos == 1 else 0x50
    if (
        acknowledgement[0] != expected_type
        or packet_id.to_bytes(2, "big") not in acknowledgement
    ):
        raise AssertionError(
            f"bridge publisher expected QoS {qos} acknowledgement: "
            f"{acknowledgement.hex()}"
        )
    if qos == 2:
        client.sendall(_packet(0x62, packet_id.to_bytes(2, "big")))
        pubcomp = _read_packet(client)
        if pubcomp[0] != 0x70 or packet_id.to_bytes(2, "big") not in pubcomp:
            raise AssertionError(
                f"bridge publisher expected PUBCOMP: {pubcomp.hex()}"
            )


def _expect_mapped_publish(client: socket.socket, payload: bytes) -> None:
    packet = _read_packet(client)
    if packet[0] >> 4 != 3:
        raise AssertionError(f"expected bridged PUBLISH: {packet.hex()}")
    remaining, cursor = _decode_varint(packet, 1)
    end = cursor + remaining
    topic_length = int.from_bytes(packet[cursor : cursor + 2], "big")
    cursor += 2
    topic = packet[cursor : cursor + topic_length].decode()
    cursor += topic_length
    qos = (packet[0] >> 1) & 0x03
    packet_id = None
    if qos != 0:
        packet_id = int.from_bytes(packet[cursor : cursor + 2], "big")
        cursor += 2
    property_length, cursor = _decode_varint(packet, cursor)
    cursor += property_length
    if topic != "local/sensors/temperature" or packet[cursor:end] != payload:
        raise AssertionError(
            f"unexpected bridge mapping topic={topic!r} payload={packet[cursor:end]!r}"
        )
    if packet_id is not None:
        if qos == 1:
            client.sendall(_packet(0x40, packet_id.to_bytes(2, "big")))
        elif qos == 2:
            client.sendall(_packet(0x50, packet_id.to_bytes(2, "big")))
            pubrel = _read_packet(client)
            if pubrel[0] != 0x62 or packet_id.to_bytes(2, "big") not in pubrel:
                raise AssertionError(
                    f"bridge subscriber expected PUBREL: {pubrel.hex()}"
                )
            client.sendall(_packet(0x70, packet_id.to_bytes(2, "big")))
        else:
            raise AssertionError(f"invalid bridged PUBLISH QoS {qos}")


def _wait_for_log(process: subprocess.Popen[bytes], log: Path, marker: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        content = log.read_text(errors="replace") if log.exists() else ""
        if marker in content:
            return
        if process.poll() is not None:
            raise RuntimeError(f"broker exited before {marker!r}: {content}")
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for {marker!r}: {log.read_text()}")


def _start_broker(binary: Path, config: Path, log: Path) -> tuple[subprocess.Popen[bytes], object]:
    output = log.open("wb")
    environment = os.environ.copy()
    environment[FINITE_TEST_ENV] = "1"
    process = subprocess.Popen(
        [str(binary), f"--config={config}"],
        stdout=output,
        stderr=subprocess.STDOUT,
        env=environment,
    )
    return process, output


def _stop(process: subprocess.Popen[bytes], output: object) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    output.close()  # type: ignore[attr-defined]


def _wait_clean(
    process: subprocess.Popen[bytes], output: object, log: Path, label: str
) -> None:
    try:
        code = process.wait(timeout=10)
    finally:
        output.close()  # type: ignore[attr-defined]
    if code != 0:
        raise RuntimeError(f"{label} exited {code}: {log.read_text(errors='replace')}")


def run_inbound_bridge_case(broker: Path, directory: Path) -> None:
    upstream_port = _free_port()
    local_port = _free_port()
    upstream_config = directory / "bridge-upstream.conf"
    upstream_config.write_text(
        f"listener {upstream_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 2\n"
    )
    local_config = directory / "bridge-local.conf"
    local_config.write_text(
        "persistence true\n"
        f"persistence_location {directory}\n"
        "persistence_file bridge-local.db\n"
        f"listener {local_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        "connection upstream\n"
        f"address 127.0.0.1:{upstream_port}\n"
        "topic sensors/# in 2 local/ remote/\n"
        "cleansession false\n"
        "bridge_protocol_version mqttv50\n"
        "bridge_session_expiry_interval 0xFFFFFFFF\n"
        "remote_clientid configured-inbound-bridge\n"
        "restart_timeout 1\n"
    )
    upstream_log = directory / "bridge-upstream.log"
    local_log = directory / "bridge-local.log"
    upstream, upstream_output = _start_broker(
        broker, upstream_config, upstream_log
    )
    local = None
    local_output = None
    subscriber = None
    publisher = None
    try:
        _wait_for_log(upstream, upstream_log, "configured 1 listeners")
        local, local_output = _start_broker(broker, local_config, local_log)
        _wait_for_log(local, local_log, "bridge upstream remote=")

        subscriber = _connect_client(local_port, "configured-bridge-subscriber")
        subscriber.sendall(_subscribe(1, "local/#", 2))
        suback = _read_packet(subscriber)
        if suback[0] != 0x90 or suback[-1] != 2:
            raise AssertionError(f"bridge subscriber expected SUBACK: {suback.hex()}")

        publisher = _connect_client(upstream_port, "configured-bridge-publisher-1")
        _publish_message(publisher, 1, b"before-restart", 1)
        _expect_mapped_publish(subscriber, b"before-restart")
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None

        upstream.kill()
        upstream.wait(timeout=5)
        upstream_output.close()
        upstream_output = None
        if local.poll() is not None:
            raise RuntimeError(
                "configured bridge stopped its local broker after upstream loss: "
                + local_log.read_text(errors="replace")
            )

        upstream, upstream_output = _start_broker(
            broker, upstream_config, upstream_log
        )
        _wait_for_log(upstream, upstream_log, "configured 1 listeners")
        publisher = _connect_client(upstream_port, "configured-bridge-publisher-2")
        _publish_message(publisher, 2, b"after-restart", 2)
        _expect_mapped_publish(subscriber, b"after-restart")
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None

        subscriber.sendall(b"\xe0\x00")
        subscriber.close()
        subscriber = None
        _wait_clean(local, local_output, local_log, "local bridge broker")
        local = None
        local_output = None
        _wait_clean(upstream, upstream_output, upstream_log, "upstream broker")
        upstream_output = None
    finally:
        if publisher is not None:
            publisher.close()
        if subscriber is not None:
            subscriber.close()
        if local is not None and local_output is not None:
            _stop(local, local_output)
        if upstream_output is not None:
            _stop(upstream, upstream_output)
