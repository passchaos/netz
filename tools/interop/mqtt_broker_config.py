#!/usr/bin/env python3
"""Exercise the public broker config through the production example."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile


RUNTIME = "client_io=python-socket server_io=zio-std-io"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("broker", type=Path)
    return parser.parse_args()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def variable_integer(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


def utf8(value: str) -> bytes:
    encoded = value.encode()
    return len(encoded).to_bytes(2, "big") + encoded


def mqtt_packet(packet_type: int, body: bytes) -> bytes:
    return bytes((packet_type,)) + variable_integer(len(body)) + body


def connect_packet(
    client_id: str,
    keep_alive: int = 60,
    username: str | None = None,
    password: str | None = None,
    proto_ver: int = 5,
    will_topic: str | None = None,
    will_payload: bytes = b"",
) -> bytes:
    flags = 0x02
    payload = utf8(client_id)
    if will_topic is not None:
        flags |= 0x04
        if proto_ver == 5:
            payload += b"\x00"
        payload += utf8(will_topic)
        payload += len(will_payload).to_bytes(2, "big") + will_payload
    if username is not None:
        flags |= 0x80
        payload += utf8(username)
    if password is not None:
        flags |= 0x40
        encoded_password = password.encode()
        payload += len(encoded_password).to_bytes(2, "big") + encoded_password
    body = (
        utf8("MQTT")
        + bytes((proto_ver, flags))
        + keep_alive.to_bytes(2, "big")
        + (b"\x00" if proto_ver == 5 else b"")
        + payload
    )
    return mqtt_packet(0x10, body)


def subscribe_packet(
    packet_id: int, topic_filter: str, proto_ver: int = 5
) -> bytes:
    return mqtt_packet(
        0x82,
        packet_id.to_bytes(2, "big")
        + (b"\x00" if proto_ver == 5 else b"")
        + utf8(topic_filter)
        + b"\x00",
    )


def publish_packet(
    topic: str,
    payload: bytes,
    qos: int = 0,
    packet_id: int = 0,
    proto_ver: int = 5,
) -> bytes:
    body = utf8(topic)
    if qos:
        body += packet_id.to_bytes(2, "big")
    return mqtt_packet(
        0x30 | (qos << 1),
        body + (b"\x00" if proto_ver == 5 else b"") + payload,
    )


def recv_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError("connection closed before complete packet")
        result.extend(part)
    return bytes(result)


def read_mqtt_packet(sock: socket.socket) -> bytes:
    result = bytearray(recv_exact(sock, 1))
    remaining = 0
    multiplier = 1
    for _ in range(4):
        byte = recv_exact(sock, 1)[0]
        result.append(byte)
        remaining += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            result.extend(recv_exact(sock, remaining))
            return bytes(result)
        multiplier *= 128
    raise AssertionError("malformed MQTT Remaining Length")


def decode_variable_integer(data: bytes, offset: int) -> tuple[int, int]:
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


def assert_connack_policy(
    packet: bytes, maximum_qos: int, maximum_keep_alive: int | None
) -> None:
    if packet[0] != 0x20:
        raise AssertionError(f"expected CONNACK, got {packet.hex()}")
    remaining, offset = decode_variable_integer(packet, 1)
    if offset + remaining != len(packet) or packet[offset : offset + 2] != b"\x00\x00":
        raise AssertionError(f"unsuccessful CONNACK: {packet.hex()}")
    property_length, offset = decode_variable_integer(packet, offset + 2)
    properties = packet[offset : offset + property_length]
    qos_property = bytes((0x24, maximum_qos))
    if qos_property not in properties:
        raise AssertionError(
            f"CONNACK omitted Maximum QoS {maximum_qos}: {packet.hex()}"
        )
    if maximum_keep_alive is not None:
        keep_alive_property = bytes((0x13,)) + maximum_keep_alive.to_bytes(2, "big")
        if keep_alive_property not in properties:
            raise AssertionError(
                "CONNACK omitted configured Server Keep Alive: " + packet.hex()
            )


def connack_reason(packet: bytes) -> int:
    if packet[0] != 0x20:
        raise AssertionError(f"expected CONNACK, got {packet.hex()}")
    remaining, offset = decode_variable_integer(packet, 1)
    if remaining < 2 or offset + remaining != len(packet):
        raise AssertionError(f"malformed CONNACK: {packet.hex()}")
    return packet[offset + 1]


def puback_reason(packet: bytes, packet_id: int) -> int:
    if packet[0] != 0x40:
        raise AssertionError(f"expected PUBACK, got {packet.hex()}")
    remaining, offset = decode_variable_integer(packet, 1)
    if remaining < 2 or offset + remaining != len(packet):
        raise AssertionError(f"malformed PUBACK: {packet.hex()}")
    if int.from_bytes(packet[offset : offset + 2], "big") != packet_id:
        raise AssertionError(f"wrong PUBACK packet identifier: {packet.hex()}")
    return packet[offset + 2] if remaining > 2 else 0


def expect_no_packet(sock: socket.socket, label: str) -> None:
    previous_timeout = sock.gettimeout()
    sock.settimeout(0.15)
    try:
        packet = read_mqtt_packet(sock)
    except TimeoutError:
        return
    finally:
        sock.settimeout(previous_timeout)
    raise AssertionError(f"{label}: unexpected packet {packet.hex()}")


def mqtt_ping(sock: socket.socket) -> None:
    sock.sendall(b"\xc0\x00")
    response = read_mqtt_packet(sock)
    if response != b"\xd0\x00":
        raise AssertionError(f"expected PINGRESP, got {response.hex()}")


def websocket_mqtt_ping(sock: socket.socket) -> None:
    send_websocket_binary(sock, b"\xc0\x00")
    response = read_websocket_binary(sock)
    if response != b"\xd0\x00":
        raise AssertionError(f"expected WebSocket PINGRESP, got {response.hex()}")


def websocket_connect(
    port: int,
    cafile: Path | None = None,
    certfile: Path | None = None,
    keyfile: Path | None = None,
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    if cafile is not None:
        context = ssl.create_default_context(cafile=str(cafile))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        if certfile is not None:
            if keyfile is None:
                raise AssertionError("client certificate requires a key")
            context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
        sock = context.wrap_socket(sock, server_hostname="localhost")
    key = base64.b64encode(b"netz-config-test").decode()
    request = (
        "GET /mqtt HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: mqtt\r\n\r\n"
    )
    sock.sendall(request.encode())
    response = bytearray()
    while b"\r\n\r\n" not in response:
        response.extend(recv_exact(sock, 1))
        if len(response) > 64 * 1024:
            raise AssertionError("oversized WebSocket response head")
    if not response.startswith(b"HTTP/1.1 101 "):
        raise AssertionError(f"WebSocket Upgrade failed: {response!r}")
    if b"Sec-WebSocket-Protocol: mqtt\r\n" not in response:
        raise AssertionError("WebSocket response omitted MQTT subprotocol")
    return sock


def mqtt_tls_socket(
    port: int,
    cafile: Path,
    certfile: Path,
    keyfile: Path,
) -> ssl.SSLSocket:
    context = ssl.create_default_context(cafile=str(cafile))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    raw.settimeout(5)
    return context.wrap_socket(raw, server_hostname="localhost")


def send_websocket_binary(sock: socket.socket, payload: bytes) -> None:
    mask = b"\x12\x34\x56\x78"
    length = len(payload)
    if length < 126:
        header = bytes((0x82, 0x80 | length))
    elif length <= 0xFFFF:
        header = bytes((0x82, 0xFE)) + length.to_bytes(2, "big")
    else:
        header = bytes((0x82, 0xFF)) + length.to_bytes(8, "big")
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    sock.sendall(header + mask + masked)


def read_websocket_binary(sock: socket.socket) -> bytes:
    first, second = recv_exact(sock, 2)
    if first != 0x82 or second & 0x80:
        raise AssertionError(f"unexpected WebSocket frame: {first:02x}{second:02x}")
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(sock, 8), "big")
    return recv_exact(sock, length)


def run_shared_listener_case(broker: Path, directory: Path) -> None:
    tcp_port = free_port()
    websocket_port = free_port()
    while websocket_port == tcp_port:
        websocket_port = free_port()
    password_file = directory / "shared.pwfile"
    password_file.write_text(
        "user:$7$1000$"
        "h0tqVxBwkB9rKAXukTtffzdbBQtNy1q5FBTDwSW4hucfjpqunBbxW10NVnRk7Cfh0lQndnOv2+k4wJavgz1JNw==$"
        "02ujkUXlKkJGFzlQHNjUgXwG3XRB1mr3vs8NX5teGCJGbN4hdgSpHNHuj47j8r5SHXsO7GeHpmkpPNhLraVVcQ==\n"
    )
    acl_file = directory / "shared.acl"
    acl_file.write_text(
        "topic write tenant/#\n"
        "topic deny tenant/blocked/#\n"
        "user user\n"
        "topic read tenant/#\n"
        "topic deny tenant/hidden/#\n"
        "topic read device/user/#\n"
        "pattern write device/%u/#\n"
        "pattern deny device/%u/blocked\n"
    )
    config = directory / "broker.conf"
    config.write_text(
        "queue_qos0_messages true\n"
        f"password_file {password_file}\n"
        f"acl_file {acl_file}\n"
        f"listener {tcp_port} 127.0.0.1\n"
        "allow_anonymous false\n"
        "max_qos 1\n"
        "max_keepalive 30\n"
        "max_connections 4\n"
        f"listener {websocket_port} 127.0.0.1\n"
        "protocol websockets\n"
        "mount_point tenant/\n"
        "allow_anonymous true\n"
        "max_qos 0\n"
        "max_connections 2\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    expected = (
        "netz MQTT 3.1.1/5 broker configured 2 listeners for 6 clients "
        "server_io=zio-std-io"
    )
    if ready != expected:
        raise RuntimeError(f"configured broker failed to start: {ready}")

    clients: list[socket.socket] = []
    try:
        tcp = socket.create_connection(("127.0.0.1", tcp_port), timeout=5)
        tcp.settimeout(5)
        clients.append(tcp)
        tcp.sendall(
            connect_packet(
                "tcp-subscriber", username="user", password="password"
            )
        )
        assert_connack_policy(read_mqtt_packet(tcp), 1, 30)
        tcp.sendall(subscribe_packet(1, "tenant/#"))
        suback = read_mqtt_packet(tcp)
        if suback != b"\x90\x04\x00\x01\x00\x00":
            raise AssertionError(f"unexpected SUBACK: {suback.hex()}")
        tcp.sendall(subscribe_packet(5, "device/user/#"))
        device_suback = read_mqtt_packet(tcp)
        if device_suback != b"\x90\x04\x00\x05\x00\x00":
            raise AssertionError(
                f"unexpected device SUBACK: {device_suback.hex()}"
            )

        websocket = websocket_connect(websocket_port)
        clients.append(websocket)
        send_websocket_binary(websocket, connect_packet("ws-publisher"))
        assert_connack_policy(read_websocket_binary(websocket), 0, None)
        payload = b"shared broker state"
        send_websocket_binary(websocket, publish_packet("events", payload))
        expected_publish = publish_packet("tenant/events", payload)
        actual_publish = read_mqtt_packet(tcp)
        if actual_publish != expected_publish:
            raise AssertionError(
                "WebSocket-mounted publication did not reach TCP listener: "
                f"expected {expected_publish.hex()}, got {actual_publish.hex()}"
            )

        send_websocket_binary(
            websocket,
            publish_packet("hidden/value", b"read denied"),
        )
        websocket_mqtt_ping(websocket)
        expect_no_packet(tcp, "user-specific read deny")
        send_websocket_binary(
            websocket,
            publish_packet("blocked/value", b"write denied"),
        )
        websocket_mqtt_ping(websocket)
        expect_no_packet(tcp, "anonymous write deny")

        tcp.sendall(
            publish_packet(
                "device/user/status",
                b"allowed by username pattern",
                qos=1,
                packet_id=2,
            )
        )
        expected_pattern_delivery = publish_packet(
            "device/user/status", b"allowed by username pattern"
        )
        pattern_packets = [read_mqtt_packet(tcp), read_mqtt_packet(tcp)]
        if expected_pattern_delivery not in pattern_packets:
            raise AssertionError(
                "username pattern did not permit self-delivery: "
                + ", ".join(packet.hex() for packet in pattern_packets)
            )
        pattern_ack = next(
            (packet for packet in pattern_packets if packet[0] == 0x40),
            None,
        )
        if pattern_ack is None or puback_reason(pattern_ack, 2) != 0:
            raise AssertionError("username pattern did not allow MQTT 5 publish")
        tcp.sendall(
            publish_packet(
                "device/user/blocked",
                b"denied by username pattern",
                qos=1,
                packet_id=3,
            )
        )
        if puback_reason(read_mqtt_packet(tcp), 3) != 0x87:
            raise AssertionError("pattern deny did not reject MQTT 5 publish")
        tcp.sendall(
            publish_packet(
                "unlisted/topic",
                b"default denied",
                qos=1,
                packet_id=4,
            )
        )
        if puback_reason(read_mqtt_packet(tcp), 4) != 0x87:
            raise AssertionError("ACL default deny did not reject MQTT 5 publish")
        rejected_tcp = socket.create_connection(
            ("127.0.0.1", tcp_port), timeout=5
        )
        rejected_tcp.settimeout(5)
        clients.append(rejected_tcp)
        rejected_tcp.sendall(
            connect_packet(
                "tcp-invalid-credentials", username="user", password="wrong"
            )
        )
        rejected_tcp_connack = read_mqtt_packet(rejected_tcp)
        if connack_reason(rejected_tcp_connack) != 0x87:
            raise AssertionError(
                "protected TCP listener accepted invalid credentials: "
                + rejected_tcp_connack.hex()
            )

        denied_will = socket.create_connection(
            ("127.0.0.1", tcp_port), timeout=5
        )
        denied_will.settimeout(5)
        denied_will.sendall(
            connect_packet(
                "denied-will",
                username="user",
                password="password",
                will_topic="tenant/blocked/will",
                will_payload=b"must not leak",
            )
        )
        if connack_reason(read_mqtt_packet(denied_will)) != 0:
            raise AssertionError("CONNECT with denied Will was refused")
        denied_will.close()

        allowed_will = socket.create_connection(
            ("127.0.0.1", tcp_port), timeout=5
        )
        allowed_will.settimeout(5)
        allowed_will.sendall(
            connect_packet(
                "allowed-will",
                username="user",
                password="password",
                will_topic="device/user/will",
                will_payload=b"allowed will",
            )
        )
        if connack_reason(read_mqtt_packet(allowed_will)) != 0:
            raise AssertionError("CONNECT with allowed Will failed")
        allowed_will.close()
        expected_will = publish_packet("device/user/will", b"allowed will")
        actual_will = read_mqtt_packet(tcp)
        if actual_will != expected_will:
            raise AssertionError(
                f"allowed Will mismatch: expected {expected_will.hex()}, "
                f"got {actual_will.hex()}"
            )
        mqtt_ping(tcp)
        expect_no_packet(tcp, "denied Will delivery")

        rejected_websocket = websocket_connect(websocket_port)
        clients.append(rejected_websocket)
        send_websocket_binary(
            rejected_websocket,
            connect_packet(
                "ws-invalid-credentials", username="user", password="wrong"
            ),
        )
        rejected_websocket_connack = read_websocket_binary(rejected_websocket)
        if connack_reason(rejected_websocket_connack) != 0x87:
            raise AssertionError(
                "anonymous listener accepted invalid supplied credentials: "
                + rejected_websocket_connack.hex()
            )
        send_websocket_binary(websocket, b"\xe0\x00")
        tcp.sendall(b"\xe0\x00")
    finally:
        for client in clients:
            client.close()

    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("configured broker did not finish its listener counts")
    if return_code != 0:
        raise RuntimeError(
            f"configured broker exited {return_code}: {process.stdout.read()}"
        )


def run_fail_closed_case(broker: Path, directory: Path) -> None:
    config = directory / "authentication-required.conf"
    config.write_text(
        f"listener {free_port()} 127.0.0.1\n"
        "allow_anonymous false\n"
        "max_connections 1\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if (
        result.returncode == 0
        or "AuthenticationRequired" not in result.stdout
    ):
        raise AssertionError(
            "allow_anonymous false did not fail closed without credentials: "
            + result.stdout
        )


def run_invalid_password_file_case(broker: Path, directory: Path) -> None:
    password_file = directory / "plaintext.pwfile"
    password_file.write_text("user:password\n")
    config = directory / "invalid-password.conf"
    config.write_text(
        f"password_file {password_file}\n"
        f"listener {free_port()} 127.0.0.1\n"
        "allow_anonymous false\n"
        "max_connections 1\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0 or "UnsupportedHash" not in result.stdout:
        raise AssertionError(
            "plaintext password file did not fail closed: " + result.stdout
        )


def run_invalid_acl_file_case(broker: Path, directory: Path) -> None:
    acl_file = directory / "invalid.acl"
    acl_file.write_text("pattern read users/prefix-%u/#\n")
    config = directory / "invalid-acl.conf"
    config.write_text(
        f"acl_file {acl_file}\n"
        f"listener {free_port()} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0 or "InvalidPattern" not in result.stdout:
        raise AssertionError(
            "invalid ACL pattern did not fail before listen: " + result.stdout
        )


def run_acl_v311_case(broker: Path, directory: Path) -> None:
    port = free_port()
    password_file = directory / "v311.pwfile"
    password_file.write_text(
        "user:$7$1000$"
        "h0tqVxBwkB9rKAXukTtffzdbBQtNy1q5FBTDwSW4hucfjpqunBbxW10NVnRk7Cfh0lQndnOv2+k4wJavgz1JNw==$"
        "02ujkUXlKkJGFzlQHNjUgXwG3XRB1mr3vs8NX5teGCJGbN4hdgSpHNHuj47j8r5SHXsO7GeHpmkpPNhLraVVcQ==\n"
    )
    acl_file = directory / "v311.acl"
    acl_file.write_text(
        "user user\n"
        "topic readwrite allowed/#\n"
        "topic deny allowed/blocked\n"
    )
    config = directory / "v311.conf"
    config.write_text(
        f"password_file {password_file}\n"
        f"acl_file {acl_file}\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous false\n"
        "max_connections 1\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 1 clients" not in ready:
        raise RuntimeError(f"MQTT 3.1.1 ACL broker failed to start: {ready}")

    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.settimeout(5)
    try:
        client.sendall(
            connect_packet(
                "acl-v311",
                username="user",
                password="password",
                proto_ver=4,
            )
        )
        if read_mqtt_packet(client) != b"\x20\x02\x00\x00":
            raise AssertionError("MQTT 3.1.1 ACL CONNECT failed")
        client.sendall(subscribe_packet(1, "allowed/#", proto_ver=4))
        if read_mqtt_packet(client) != b"\x90\x03\x00\x01\x00":
            raise AssertionError("MQTT 3.1.1 ACL SUBSCRIBE failed")
        allowed = publish_packet(
            "allowed/value", b"visible", proto_ver=4
        )
        client.sendall(allowed)
        if read_mqtt_packet(client) != allowed:
            raise AssertionError("MQTT 3.1.1 ACL read/write grant failed")
        client.sendall(
            publish_packet(
                "allowed/blocked",
                b"hidden",
                qos=1,
                packet_id=2,
                proto_ver=4,
            )
        )
        if read_mqtt_packet(client) != b"\x40\x02\x00\x02":
            raise AssertionError("MQTT 3.1.1 denied publish ACK mismatch")
        mqtt_ping(client)
        expect_no_packet(client, "MQTT 3.1.1 denied self-delivery")
        client.sendall(b"\xe0\x00")
    finally:
        client.close()

    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("MQTT 3.1.1 ACL broker did not finish")
    if return_code != 0:
        raise RuntimeError(
            f"MQTT 3.1.1 ACL broker exited {return_code}: "
            + process.stdout.read()
        )


def run_authentication_case(broker: Path, directory: Path) -> None:
    port = free_port()
    password_file = directory / "formats.pwfile"
    password_file.write_text(
        "legacy:$6$Ut1cUS9PG8+gC3vn$"
        "tOjCfSJJDe1Alu9HktxxyyzwN4+6mAMSWGRAF9gmMN8pzcGTPVEYYMAZpCEp96Oz2ZRRz5YKM6lPMf1tUbb6zA==\n"
        "pbkdf2:$7$1000$"
        "h0tqVxBwkB9rKAXukTtffzdbBQtNy1q5FBTDwSW4hucfjpqunBbxW10NVnRk7Cfh0lQndnOv2+k4wJavgz1JNw==$"
        "02ujkUXlKkJGFzlQHNjUgXwG3XRB1mr3vs8NX5teGCJGbN4hdgSpHNHuj47j8r5SHXsO7GeHpmkpPNhLraVVcQ==\n"
        "argon:$argon2id$v=19$m=47104,t=1,p=1$"
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw$"
        "PSgS0SQP11eYoUs34zQi0HsTw/P8awxX8kf+94qyd5CziAe0af6Lr3RwOmKNdcSYBa6ZJpy4awdqw2JKUW7u4Q\n"
    )
    config = directory / "authenticated.conf"
    config.write_text(
        f"password_file {password_file}\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous false\n"
        "max_connections 8\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 8 clients" not in ready:
        raise RuntimeError(f"authenticated broker failed to start: {ready}")

    cases = (
        (5, "legacy", "password", 0x00),
        (5, "pbkdf2", "password", 0x00),
        (5, "argon", "password", 0x00),
        (5, "legacy", "wrong", 0x87),
        (5, "unknown", "password", 0x87),
        (5, None, None, 0x87),
        (4, "pbkdf2", "password", 0x00),
        (4, "pbkdf2", "wrong", 0x05),
    )
    for index, (proto_ver, username, password, expected_reason) in enumerate(cases):
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.settimeout(5)
        try:
            client.sendall(
                connect_packet(
                    f"authentication-{index}",
                    username=username,
                    password=password,
                    proto_ver=proto_ver,
                )
            )
            packet = read_mqtt_packet(client)
            actual_reason = connack_reason(packet)
            if actual_reason != expected_reason:
                raise AssertionError(
                    f"authentication case {index}: expected {expected_reason:#x}, "
                    f"received {actual_reason:#x}: {packet.hex()}"
                )
            if expected_reason == 0:
                client.sendall(b"\xe0\x00")
        finally:
            client.close()

    try:
        return_code = process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("authenticated broker did not finish")
    if return_code != 0:
        raise RuntimeError(
            f"authenticated broker exited {return_code}: {process.stdout.read()}"
        )


def run_persistence_case(broker: Path, directory: Path) -> None:
    port = free_port()
    snapshot = directory / "configured.db"
    config = directory / "persistent.conf"
    config.write_text(
        "persistence true\n"
        f"persistence_location {directory}\n"
        f"persistence_file {snapshot.name}\n"
        "autosave_interval 3600\n"
        "autosave_on_changes false\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    for pass_number in (1, 2):
        process = subprocess.Popen(
            [str(broker), f"--config={config}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert process.stdout is not None
        ready = process.stdout.readline().strip()
        if "configured 1 listeners for 1 clients" not in ready:
            raise RuntimeError(
                f"persistent config pass {pass_number} failed: {ready}"
            )
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.settimeout(5)
        try:
            client.sendall(connect_packet(f"persistent-{pass_number}"))
            connack = read_mqtt_packet(client)
            if connack[0] != 0x20:
                raise AssertionError(
                    f"persistent config expected CONNACK: {connack.hex()}"
                )
            client.sendall(b"\xe0\x00")
        finally:
            client.close()
        try:
            return_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError(
                f"persistent config pass {pass_number} did not finish"
            )
        if return_code != 0:
            raise RuntimeError(
                f"persistent config pass {pass_number} exited "
                f"{return_code}: {process.stdout.read()}"
            )
        if not snapshot.is_file() or snapshot.stat().st_size == 0:
            raise AssertionError(
                f"persistent config pass {pass_number} did not save snapshot"
            )


def run_tls_listener_case(broker: Path, directory: Path) -> None:
    tls_port = free_port()
    wss_port = free_port()
    while wss_port == tls_port:
        wss_port = free_port()
    certificate = directory / "server-cert.pem"
    private_key = directory / "server-key.pem"
    subprocess.run(
        [
            "openssl",
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            str(private_key),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(private_key),
            "-sha256",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyCertSign",
            "-out",
            str(certificate),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=True,
    )
    config = directory / "tls.conf"
    config.write_text(
        f"listener {tls_port} 127.0.0.1\n"
        f"certfile {certificate}\n"
        f"keyfile {private_key}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {wss_port} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {certificate}\n"
        f"keyfile {private_key}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 2 listeners for 2 clients" not in ready:
        raise RuntimeError(f"TLS configured broker failed to start: {ready}")

    clients: list[socket.socket] = []
    try:
        openssl = subprocess.run(
            [
                "openssl",
                "s_client",
                "-connect",
                f"127.0.0.1:{tls_port}",
                "-tls1_3",
                "-servername",
                "localhost",
                "-CAfile",
                str(certificate),
                "-verify_hostname",
                "localhost",
                "-verify_return_error",
                "-quiet",
            ],
            input=connect_packet("openssl-config") + b"\xc0\x00\xe0\x00",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        remaining, body_offset = decode_variable_integer(openssl.stdout, 1)
        packet_end = body_offset + remaining
        connack = openssl.stdout[:packet_end]
        response_tail = openssl.stdout[packet_end:]
        if connack_reason(connack) != 0 or response_tail != b"\xd0\x00":
            raise AssertionError(
                "OpenSSL MQTT/TLS CONNECT/PING exchange mismatch: "
                f"got {openssl.stdout.hex()}; "
                + openssl.stderr.decode(errors="replace")
            )

        websocket = websocket_connect(wss_port, certificate)
        clients.append(websocket)
        send_websocket_binary(websocket, connect_packet("wss-config"))
        if connack_reason(read_websocket_binary(websocket)) != 0:
            raise AssertionError("configured WSS CONNECT failed")
        websocket_mqtt_ping(websocket)
        send_websocket_binary(websocket, b"\xe0\x00")
    finally:
        for client in clients:
            client.close()

    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("TLS configured broker did not finish")
    if return_code != 0:
        raise RuntimeError(
            f"TLS configured broker exited {return_code}: "
            + process.stdout.read()
        )


def run_openssl(*arguments: object) -> None:
    subprocess.run(
        ["openssl", *(str(argument) for argument in arguments)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=True,
    )


def create_ca(
    directory: Path,
    name: str,
    common_name: str,
    algorithm: str = "ec",
) -> tuple[Path, Path]:
    key = directory / f"{name}.key"
    certificate = directory / f"{name}.crt"
    if algorithm == "ec":
        run_openssl(
            "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key
        )
    elif algorithm == "rsa":
        run_openssl(
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key,
        )
    else:
        raise AssertionError(f"unsupported CA algorithm {algorithm}")
    run_openssl(
        "req",
        "-new",
        "-x509",
        "-key",
        key,
        "-sha256",
        "-days",
        "1",
        "-subj",
        f"/CN={common_name}",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-out",
        certificate,
    )
    return certificate, key


def create_signed_certificate(
    directory: Path,
    name: str,
    common_name: str | None,
    ca_certificate: Path,
    ca_key: Path,
    serial: int,
    extended_key_usage: str,
    subject_alt_name: str | None = None,
    key_algorithm: str = "ec",
    subject: str | None = None,
) -> tuple[Path, Path]:
    key = directory / f"{name}.key"
    request = directory / f"{name}.csr"
    certificate = directory / f"{name}.crt"
    extensions = directory / f"{name}.ext"
    extension_lines = [
        "basicConstraints=critical,CA:FALSE",
        "keyUsage=critical,digitalSignature",
        f"extendedKeyUsage={extended_key_usage}",
    ]
    if subject_alt_name is not None:
        extension_lines.append(f"subjectAltName={subject_alt_name}")
    extensions.write_text("\n".join(extension_lines) + "\n")
    if key_algorithm == "ec":
        run_openssl(
            "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key
        )
    elif key_algorithm == "rsa":
        run_openssl(
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key,
        )
    else:
        raise AssertionError(f"unsupported key algorithm {key_algorithm}")
    certificate_subject = subject or (
        f"/CN={common_name}" if common_name is not None else "/O=no-common-name"
    )
    run_openssl(
        "req", "-new", "-key", key, "-subj", certificate_subject,
        "-out", request,
    )
    run_openssl(
        "x509",
        "-req",
        "-in",
        request,
        "-CA",
        ca_certificate,
        "-CAkey",
        ca_key,
        "-set_serial",
        serial,
        "-days",
        "1",
        "-sha256",
        "-extfile",
        extensions,
        "-out",
        certificate,
    )
    return certificate, key


def create_crl(
    directory: Path,
    name: str,
    ca_certificate: Path,
    ca_key: Path,
    revoked_certificate: Path,
) -> Path:
    ca_directory = directory / f"{name}-database"
    ca_directory.mkdir()
    (ca_directory / "newcerts").mkdir()
    (ca_directory / "index.txt").write_text("")
    (ca_directory / "serial").write_text("1000\n")
    (ca_directory / "crlnumber").write_text("1000\n")
    config = ca_directory / "openssl.cnf"
    config.write_text(
        "[ ca ]\n"
        "default_ca = CA_default\n"
        "[ CA_default ]\n"
        f"dir = {ca_directory}\n"
        "database = $dir/index.txt\n"
        "new_certs_dir = $dir/newcerts\n"
        f"certificate = {ca_certificate}\n"
        f"private_key = {ca_key}\n"
        "serial = $dir/serial\n"
        "crlnumber = $dir/crlnumber\n"
        "default_md = sha256\n"
        "default_crl_days = 1\n"
        "policy = policy_any\n"
        "[ policy_any ]\n"
        "commonName = optional\n"
    )
    run_openssl(
        "ca",
        "-batch",
        "-config",
        config,
        "-revoke",
        revoked_certificate,
        "-crl_reason",
        "keyCompromise",
    )
    crl = directory / f"{name}.crl"
    run_openssl("ca", "-batch", "-config", config, "-gencrl", "-out", crl)
    return crl


def tamper_pem_crl(source: Path, destination: Path) -> None:
    encoded = "".join(
        line.strip()
        for line in source.read_text().splitlines()
        if not line.startswith("-----")
    )
    der = bytearray(base64.b64decode(encoded))
    if not der:
        raise AssertionError("generated CRL was empty")
    der[-1] ^= 1
    damaged = base64.b64encode(der).decode()
    lines = [damaged[index : index + 64] for index in range(0, len(damaged), 64)]
    destination.write_text(
        "-----BEGIN X509 CRL-----\n"
        + "\n".join(lines)
        + "\n-----END X509 CRL-----\n"
    )


def openssl_mqtt_client(
    port: int,
    server_ca: Path,
    client_certificate: Path | None = None,
    client_key: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    command = [
        "openssl",
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-tls1_3",
        "-servername",
        "localhost",
        "-CAfile",
        str(server_ca),
        "-verify_hostname",
        "localhost",
        "-verify_return_error",
        "-quiet",
    ]
    if client_certificate is not None:
        if client_key is None:
            raise AssertionError("client certificate requires a key")
        command.extend(("-cert", str(client_certificate), "-key", str(client_key)))
    return subprocess.run(
        command,
        input=connect_packet("openssl-mtls") + b"\xc0\x00\xe0\x00",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
    )


def assert_openssl_mqtt_success(result: subprocess.CompletedProcess[bytes]) -> None:
    remaining, body_offset = decode_variable_integer(result.stdout, 1)
    packet_end = body_offset + remaining
    connack = result.stdout[:packet_end]
    response_tail = result.stdout[packet_end:]
    if connack_reason(connack) != 0 or response_tail != b"\xd0\x00":
        raise AssertionError(
            "OpenSSL MQTT/mTLS CONNECT/PING exchange mismatch: "
            f"got {result.stdout.hex()}; "
            + result.stderr.decode(errors="replace")
        )


def openssl_certificate_request_diagnostics(
    port: int,
    server_ca: Path,
    client_certificate: Path,
    client_key: Path,
) -> str:
    result = subprocess.run(
        [
            "openssl",
            "s_client",
            "-connect",
            f"127.0.0.1:{port}",
            "-tls1_3",
            "-servername",
            "localhost",
            "-CAfile",
            str(server_ca),
            "-verify_hostname",
            "localhost",
            "-verify_return_error",
            "-cert",
            str(client_certificate),
            "-key",
            str(client_key),
            "-prexit",
        ],
        input=connect_packet("openssl-ca-names") + b"\xe0\x00",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
    )
    return (result.stdout + result.stderr).decode(errors="replace")


def write_mtls_config(
    path: Path,
    port: int,
    server_certificate: Path,
    server_key: Path,
    client_ca: Path,
    protocol: str = "mqtt",
    crlfile: Path | None = None,
) -> None:
    path.write_text(
        f"listener {port} 127.0.0.1\n"
        + ("protocol websockets\n" if protocol == "websockets" else "")
        + f"certfile {server_certificate}\n"
        + f"keyfile {server_key}\n"
        + f"cafile {client_ca}\n"
        + (f"crlfile {crlfile}\n" if crlfile is not None else "")
        + "require_certificate true\n"
        + "allow_anonymous true\n"
        + "max_connections 1\n"
    )


def run_mtls_rejection_case(
    broker: Path,
    config: Path,
    port: int,
    server_ca: Path,
    expected_error: str,
    client_certificate: Path | None = None,
    client_key: Path | None = None,
) -> None:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 1 clients" not in ready:
        raise RuntimeError(f"mTLS rejection broker failed to start: {ready}")
    result = openssl_mqtt_client(
        port,
        server_ca,
        client_certificate,
        client_key,
    )
    if result.stdout.startswith(b"\x20"):
        raise AssertionError("rejected mTLS client received MQTT CONNACK")
    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("mTLS rejection broker did not finish")
    output = process.stdout.read()
    if return_code == 0 or expected_error not in output:
        raise AssertionError(
            f"mTLS rejection expected {expected_error}, got: " + output
        )


def run_wss_mtls_rejection_case(
    broker: Path,
    config: Path,
    port: int,
    server_ca: Path,
) -> None:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 1 clients" not in ready:
        raise RuntimeError(f"WSS mTLS rejection broker failed to start: {ready}")
    websocket: socket.socket | None = None
    rejected = False
    try:
        websocket = websocket_connect(port, server_ca)
    except (ssl.SSLError, ConnectionError, OSError, TimeoutError, AssertionError):
        rejected = True
    finally:
        if websocket is not None:
            websocket.close()
    if not rejected:
        raise AssertionError("WSS listener accepted a client without a certificate")
    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("WSS mTLS rejection broker did not finish")
    output = process.stdout.read()
    if return_code == 0 or "ClientCertificateRequired" not in output:
        raise AssertionError(
            "WSS missing-certificate rejection mismatch: " + output
        )


def run_mtls_listener_case(broker: Path, directory: Path) -> None:
    server_ca, server_ca_key = create_ca(directory, "server-ca", "Server Root")
    server_certificate, server_key = create_signed_certificate(
        directory,
        "mtls-server",
        "localhost",
        server_ca,
        server_ca_key,
        101,
        "serverAuth",
        "DNS:localhost",
    )
    client_ca, client_ca_key = create_ca(directory, "client-ca", "Client Root")
    client_certificate, client_key = create_signed_certificate(
        directory,
        "trusted-client",
        "trusted-client",
        client_ca,
        client_ca_key,
        201,
        "clientAuth",
    )
    wrong_ca, wrong_ca_key = create_ca(directory, "wrong-ca", "Wrong Root")
    wrong_certificate, wrong_key = create_signed_certificate(
        directory,
        "wrong-client",
        "wrong-client",
        wrong_ca,
        wrong_ca_key,
        301,
        "clientAuth",
    )
    wrong_purpose_certificate, wrong_purpose_key = create_signed_certificate(
        directory,
        "wrong-purpose-client",
        "wrong-purpose-client",
        client_ca,
        client_ca_key,
        202,
        "serverAuth",
    )
    no_identity_certificate, no_identity_key = create_signed_certificate(
        directory,
        "no-identity-client",
        None,
        client_ca,
        client_ca_key,
        203,
        "clientAuth",
    )
    revoked_certificate, revoked_key = create_signed_certificate(
        directory,
        "revoked-client",
        "revoked-client",
        client_ca,
        client_ca_key,
        204,
        "clientAuth",
    )
    client_crl = create_crl(
        directory,
        "client-revocations",
        client_ca,
        client_ca_key,
        revoked_certificate,
    )

    identity_acl = directory / "identity.acl"
    identity_acl.write_text(
        "pattern write cert/%u/#\n"
        "pattern write client/%c/#\n"
    )
    identity_password_file = directory / "identity.pwfile"
    identity_password_file.write_text(
        "password-user:$7$1000$"
        "h0tqVxBwkB9rKAXukTtffzdbBQtNy1q5FBTDwSW4hucfjpqunBbxW10NVnRk7Cfh0lQndnOv2+k4wJavgz1JNw==$"
        "02ujkUXlKkJGFzlQHNjUgXwG3XRB1mr3vs8NX5teGCJGbN4hdgSpHNHuj47j8r5SHXsO7GeHpmkpPNhLraVVcQ==\n"
    )

    tls_port = free_port()
    wss_port = free_port()
    while wss_port == tls_port:
        wss_port = free_port()
    config = directory / "mtls.conf"
    config.write_text(
        f"password_file {identity_password_file}\n"
        f"acl_file {identity_acl}\n"
        f"listener {tls_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {client_ca}\n"
        f"crlfile {client_crl}\n"
        "require_certificate true\n"
        "use_identity_as_username true\n"
        "use_username_as_clientid true\n"
        "allow_anonymous false\n"
        "max_connections 3\n"
        f"listener {wss_port} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {client_ca}\n"
        f"crlfile {client_crl}\n"
        "require_certificate true\n"
        "use_identity_as_username true\n"
        "use_username_as_clientid true\n"
        "allow_anonymous false\n"
        "max_connections 1\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 2 listeners for 4 clients" not in ready:
        raise RuntimeError(f"mTLS configured broker failed to start: {ready}")
    openssl_diagnostics = openssl_certificate_request_diagnostics(
        tls_port,
        server_ca,
        client_certificate,
        client_key,
    )
    if (
        "Acceptable client certificate CA names" not in openssl_diagnostics
        or "CN=Client Root" not in openssl_diagnostics
    ):
        raise AssertionError(
            "OpenSSL did not decode the configured CertificateRequest CA name: "
            + openssl_diagnostics
        )
    openssl_success = openssl_mqtt_client(
        tls_port,
        server_ca,
        client_certificate,
        client_key,
    )
    assert_openssl_mqtt_success(openssl_success)

    tcp_identity = mqtt_tls_socket(
        tls_port,
        server_ca,
        client_certificate,
        client_key,
    )
    try:
        tcp_identity.sendall(
            connect_packet(
                "wire-client-id",
                username="wire-user",
                password="wrong-wire-password",
            )
        )
        if connack_reason(read_mqtt_packet(tcp_identity)) != 0:
            raise AssertionError("certificate identity TCP CONNECT failed")
        tcp_identity.sendall(
            publish_packet(
                "client/trusted-client/status",
                b"mapped client id",
                qos=1,
                packet_id=41,
            )
        )
        if puback_reason(read_mqtt_packet(tcp_identity), 41) != 0x10:
            raise AssertionError(
                "certificate CN was not mapped before use_username_as_clientid"
            )
        tcp_identity.sendall(b"\xe0\x00")
    finally:
        tcp_identity.close()
    websocket = websocket_connect(
        wss_port,
        server_ca,
        client_certificate,
        client_key,
    )
    try:
        send_websocket_binary(
            websocket,
            connect_packet(
                "wss-wire-id",
                username="wss-wire-user",
                password="wrong-wire-password",
            ),
        )
        if connack_reason(read_websocket_binary(websocket)) != 0:
            raise AssertionError("configured WSS mTLS CONNECT failed")
        websocket_mqtt_ping(websocket)
        send_websocket_binary(
            websocket,
            publish_packet(
                "cert/trusted-client/status",
                b"mapped username",
                qos=1,
                packet_id=42,
            ),
        )
        if puback_reason(read_websocket_binary(websocket), 42) != 0x10:
            raise AssertionError(
                "certificate CN did not replace the WSS wire username"
            )
        send_websocket_binary(websocket, b"\xe0\x00")
    finally:
        websocket.close()
    if process.wait(timeout=5) != 0:
        raise RuntimeError("successful mTLS broker exited with an error")

    rejection_cases = (
        ("missing-client", None, None, "ClientCertificateRequired"),
        ("wrong-ca-client", wrong_certificate, wrong_key, "CertificateUntrusted"),
        (
            "wrong-purpose-client",
            wrong_purpose_certificate,
            wrong_purpose_key,
            "CertificateUntrusted",
        ),
        (
            "revoked-client",
            revoked_certificate,
            revoked_key,
            "CertificateUntrusted",
        ),
    )
    for name, certificate, key, expected_error in rejection_cases:
        port = free_port()
        rejected_config = directory / f"{name}.conf"
        write_mtls_config(
            rejected_config,
            port,
            server_certificate,
            server_key,
            client_ca,
            crlfile=client_crl,
        )
        run_mtls_rejection_case(
            broker,
            rejected_config,
            port,
            server_ca,
            expected_error,
            certificate,
            key,
        )

    no_identity_port = free_port()
    no_identity_config = directory / "no-identity.conf"
    write_mtls_config(
        no_identity_config,
        no_identity_port,
        server_certificate,
        server_key,
        client_ca,
        crlfile=client_crl,
    )
    no_identity_text = no_identity_config.read_text().replace(
        "require_certificate true\n",
        "require_certificate true\nuse_identity_as_username true\n",
    )
    no_identity_config.write_text(no_identity_text)
    no_identity_process = subprocess.Popen(
        [str(broker), f"--config={no_identity_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert no_identity_process.stdout is not None
    ready = no_identity_process.stdout.readline().strip()
    if "configured 1 listeners for 1 clients" not in ready:
        raise RuntimeError(f"missing identity broker failed to start: {ready}")
    no_identity_result = openssl_mqtt_client(
        no_identity_port,
        server_ca,
        no_identity_certificate,
        no_identity_key,
    )
    if connack_reason(no_identity_result.stdout) != 0x87:
        raise AssertionError(
            "trusted certificate without CN was not refused: "
            + no_identity_result.stdout.hex()
        )
    if no_identity_process.wait(timeout=5) != 0:
        raise RuntimeError("missing certificate identity refusal failed")

    wss_rejection_port = free_port()
    wss_rejection_config = directory / "missing-wss-client.conf"
    write_mtls_config(
        wss_rejection_config,
        wss_rejection_port,
        server_certificate,
        server_key,
        client_ca,
        "websockets",
        client_crl,
    )
    run_wss_mtls_rejection_case(
        broker,
        wss_rejection_config,
        wss_rejection_port,
        server_ca,
    )

    cleartext_port = free_port()
    invalid_ca_port = free_port()
    while invalid_ca_port == cleartext_port:
        invalid_ca_port = free_port()
    invalid_ca_config = directory / "invalid-client-ca.conf"
    invalid_ca_config.write_text(
        f"listener {cleartext_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {invalid_ca_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {server_certificate}\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    invalid_ca_result = subprocess.run(
        [str(broker), f"--config={invalid_ca_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if (
        invalid_ca_result.returncode == 0
        or "InvalidCertificateAuthority" not in invalid_ca_result.stdout
    ):
        raise AssertionError(
            "non-CA cafile did not fail before listen: "
            + invalid_ca_result.stdout
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", cleartext_port)) == 0:
            raise AssertionError(
                "an earlier listener was bound before client CA validation"
            )

    tampered_crl = directory / "tampered.crl"
    tamper_pem_crl(client_crl, tampered_crl)
    cleartext_port = free_port()
    invalid_crl_port = free_port()
    while invalid_crl_port == cleartext_port:
        invalid_crl_port = free_port()
    invalid_crl_config = directory / "invalid-crl.conf"
    invalid_crl_config.write_text(
        f"listener {cleartext_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {invalid_crl_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {client_ca}\n"
        f"crlfile {tampered_crl}\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    invalid_crl_result = subprocess.run(
        [str(broker), f"--config={invalid_crl_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if (
        invalid_crl_result.returncode == 0
        or "InvalidCrl" not in invalid_crl_result.stdout
    ):
        raise AssertionError(
            "tampered CRL did not fail before listen: "
            + invalid_crl_result.stdout
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", cleartext_port)) == 0:
            raise AssertionError(
                "an earlier listener was bound before CRL validation"
            )


def run_rsa_crl_listener_case(broker: Path, directory: Path) -> None:
    server_ca = directory / "server-ca.crt"
    server_certificate = directory / "mtls-server.crt"
    server_key = directory / "mtls-server.key"
    rsa_ca, rsa_ca_key = create_ca(
        directory,
        "rsa-client-ca",
        "RSA Client Root",
        "rsa",
    )
    rsa_client, rsa_client_key = create_signed_certificate(
        directory,
        "rsa-client",
        "rsa-client",
        rsa_ca,
        rsa_ca_key,
        401,
        "clientAuth",
        key_algorithm="rsa",
    )
    rsa_revoked, rsa_revoked_key = create_signed_certificate(
        directory,
        "rsa-revoked-client",
        "rsa-revoked-client",
        rsa_ca,
        rsa_ca_key,
        402,
        "clientAuth",
        key_algorithm="rsa",
    )
    rsa_crl = create_crl(
        directory,
        "rsa-client-revocations",
        rsa_ca,
        rsa_ca_key,
        rsa_revoked,
    )

    port = free_port()
    config = directory / "rsa-crl.conf"
    write_mtls_config(
        config,
        port,
        server_certificate,
        server_key,
        rsa_ca,
        crlfile=rsa_crl,
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 1 clients" not in ready:
        raise RuntimeError(f"RSA CRL broker failed to start: {ready}")
    assert_openssl_mqtt_success(
        openssl_mqtt_client(
            port,
            server_ca,
            rsa_client,
            rsa_client_key,
        )
    )
    if process.wait(timeout=5) != 0:
        raise RuntimeError("RSA CRL good-client broker exited with an error")

    rejected_port = free_port()
    rejected_config = directory / "rsa-crl-revoked.conf"
    write_mtls_config(
        rejected_config,
        rejected_port,
        server_certificate,
        server_key,
        rsa_ca,
        crlfile=rsa_crl,
    )
    run_mtls_rejection_case(
        broker,
        rejected_config,
        rejected_port,
        server_ca,
        "CertificateUntrusted",
        rsa_revoked,
        rsa_revoked_key,
    )


def run_unsupported_tls_key_case(broker: Path, directory: Path) -> None:
    certificate = directory / "server-cert.pem"
    rsa_key = directory / "rsa-key.pem"
    cleartext_port = free_port()
    tls_port = free_port()
    while tls_port == cleartext_port:
        tls_port = free_port()
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(rsa_key),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=True,
    )
    config = directory / "unsupported-tls-key.conf"
    config.write_text(
        f"listener {cleartext_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {tls_port} 127.0.0.1\n"
        f"certfile {certificate}\n"
        f"keyfile {rsa_key}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0 or "InvalidPrivateKey" not in result.stdout:
        raise AssertionError(
            "unsupported RSA TLS key did not fail before listen: "
            + result.stdout
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", cleartext_port)) == 0:
            raise AssertionError(
                "an earlier cleartext listener was bound before TLS "
                "identity validation completed"
            )


def run_mtls_subject_username_broker(
    broker: Path,
    directory: Path,
    server_ca: Path,
    server_certificate: Path,
    server_key: Path,
    client_ca: Path,
    client_certificate: Path,
    client_key: Path,
    subject_username: str,
    subject_topic: str,
) -> None:
    acl_file = directory / "subject.acl"
    acl_file.write_text(
        "pattern write subject/%u/#\n"
        "pattern write client/%c/#\n"
    )
    tls_port = free_port()
    wss_port = free_port()
    while wss_port == tls_port:
        wss_port = free_port()
    config = directory / "subject.conf"
    config.write_text(
        f"acl_file {acl_file}\n"
        f"listener {tls_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {client_ca}\n"
        "require_certificate true\n"
        "use_subject_as_username true\n"
        "use_username_as_clientid true\n"
        "allow_anonymous false\n"
        "max_connections 1\n"
        f"listener {wss_port} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {client_ca}\n"
        "require_certificate true\n"
        "use_identity_as_username true\n"
        "use_subject_as_username true\n"
        "allow_anonymous false\n"
        "max_connections 1\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 2 listeners for 2 clients" not in ready:
        raise RuntimeError(f"subject identity broker failed to start: {ready}")

    tcp = mqtt_tls_socket(tls_port, server_ca, client_certificate, client_key)
    try:
        tcp.sendall(connect_packet("wire-id", username="wrong-wire-user"))
        if connack_reason(read_mqtt_packet(tcp)) != 0:
            raise AssertionError("certificate Subject TCP CONNECT failed")
        tcp.sendall(
            publish_packet(
                subject_topic, b"mapped full subject", qos=1, packet_id=61
            )
        )
        if puback_reason(read_mqtt_packet(tcp), 61) != 0x10:
            raise AssertionError("RFC2253 Subject did not reach the TCP ACL")
        tcp.sendall(
            publish_packet(
                f"client/{subject_username}/status",
                b"mapped subject client id", qos=1, packet_id=63,
            )
        )
        if puback_reason(read_mqtt_packet(tcp), 63) != 0x10:
            raise AssertionError(
                "RFC2253 Subject did not become the effective Client ID"
            )
        tcp.sendall(bytes.fromhex("e000"))
    finally:
        tcp.close()

    websocket = websocket_connect(
        wss_port, server_ca, client_certificate, client_key
    )
    try:
        send_websocket_binary(
            websocket,
            connect_packet("wss-wire-id", username="wrong-wire-user"),
        )
        if connack_reason(read_websocket_binary(websocket)) != 0:
            raise AssertionError("certificate identity precedence CONNECT failed")
        send_websocket_binary(
            websocket,
            publish_packet(
                "subject/subject-client/status",
                b"CN wins over full subject", qos=1, packet_id=62,
            ),
        )
        if puback_reason(read_websocket_binary(websocket), 62) != 0x10:
            raise AssertionError("CN identity did not take precedence on WSS")
        send_websocket_binary(websocket, bytes.fromhex("e000"))
    finally:
        websocket.close()
    if process.wait(timeout=5) != 0:
        raise RuntimeError(
            "certificate Subject identity broker failed: "
            + process.stdout.read()
        )


def run_mtls_subject_username_case(broker: Path, directory: Path) -> None:
    server_ca, server_ca_key = create_ca(
        directory, "subject-server-ca", "Subject Server Root"
    )
    server_certificate, server_key = create_signed_certificate(
        directory, "subject-server", "localhost", server_ca, server_ca_key,
        601, "serverAuth", "DNS:localhost",
    )
    client_ca, client_ca_key = create_ca(
        directory, "subject-client-ca", "Subject Client Root"
    )
    client_certificate, client_key = create_signed_certificate(
        directory, "subject-client", "subject-client", client_ca,
        client_ca_key, 602, "clientAuth",
        subject="/C=GB/O=Netz/OU=Devices/CN=subject-client",
    )
    subject_username = "CN=subject-client,OU=Devices,O=Netz,C=GB"
    subject_topic = f"subject/{subject_username}/status"

    run_mtls_subject_username_broker(
        broker, directory, server_ca, server_certificate, server_key,
        client_ca, client_certificate, client_key, subject_username,
        subject_topic,
    )


def main() -> None:
    args = parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        run_shared_listener_case(args.broker, directory)
        run_fail_closed_case(args.broker, directory)
        run_invalid_password_file_case(args.broker, directory)
        run_invalid_acl_file_case(args.broker, directory)
        run_acl_v311_case(args.broker, directory)
        run_authentication_case(args.broker, directory)
        run_persistence_case(args.broker, directory)
        run_tls_listener_case(args.broker, directory)
        run_mtls_listener_case(args.broker, directory)
        run_mtls_subject_username_case(args.broker, directory)
        run_rsa_crl_listener_case(args.broker, directory)
        run_unsupported_tls_key_case(args.broker, directory)
    print(
        "MQTT broker config integration passed: strict authentication, "
        "Mosquitto hashes, mixed anonymous policy, shared TCP/WebSocket "
        "state, ACL read/write/deny/pattern policy, mount point, listener "
        "policies, TLS/WSS and required mTLS with OpenSSL verification, "
        "certificate CN/full-Subject identity mapping, P-256/RSA signed CRL revocation, strict TLS "
        "key/CA/EKU/identity/CRL rejection, and snapshot restore "
        + RUNTIME
    )


if __name__ == "__main__":
    main()
