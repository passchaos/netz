#!/usr/bin/env python3
"""Exercise the public broker config through the production example."""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import subprocess
import tempfile
import time

from mqtt_broker_config_inflight import run_max_inflight_messages_case
from mqtt_broker_config_bridge import (
    run_bidirectional_bridge_case,
    run_inbound_bridge_case,
    run_bridge_reload_case,
    run_outbound_bridge_reload_case,
    run_once_bridge_case,
    run_primary_failback_case,
    run_tls_inbound_bridge_case,
)
from mqtt_broker_config_keepalive import run_zero_maximum_keep_alive_case
from mqtt_broker_config_local_session import run_local_clean_session_case
from mqtt_broker_config_outbound import (
    run_bridge_cipher_suite_case,
    run_lazy_outbound_bridge_case,
    run_outbound_bridge_case,
    run_outbound_bridge_protocol_limits_case,
    run_private_bridge_server_case,
)
from mqtt_broker_config_ocsp import run_bridge_ocsp_case
from mqtt_broker_config_protocol import run_accepted_protocol_versions_case
from mqtt_broker_config_proxy import run_proxy_protocol_case
from mqtt_broker_config_queue import run_queued_limits_case
from mqtt_broker_config_session import (
    run_global_max_clients_case,
    run_global_max_connections_case,
    run_listener_max_connections_case,
    run_persistent_client_expiration_case,
)
from mqtt_broker_config_sys import run_system_interval_case
from mqtt_broker_config_topic_alias import run_topic_alias_policy_case
from mqtt_broker_config_origin import run_websocket_origins_case


RUNTIME = "client_io=python-socket server_io=zio-std-io"
FINITE_TEST_ENV = "NETZ_MQTT_CONFIG_FINITE_TEST"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("broker", type=Path)
    return parser.parse_args()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def free_ipv6_port() -> int:
    with socket.socket(socket.AF_INET6) as probe:
        probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        probe.bind(("::1", 0))
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
    will_retain: bool = False,
    clean_start: bool = True,
) -> bytes:
    flags = 0x02 if clean_start else 0x00
    payload = utf8(client_id)
    if will_topic is not None:
        flags |= 0x04
        if will_retain:
            flags |= 0x20
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
        utf8("MQIsdp" if proto_ver == 3 else "MQTT")
        + bytes((proto_ver, flags))
        + keep_alive.to_bytes(2, "big")
        + (b"\x00" if proto_ver == 5 else b"")
        + payload
    )
    return mqtt_packet(0x10, body)


def subscribe_packet(
    packet_id: int,
    topic_filter: str,
    proto_ver: int = 5,
    qos: int = 0,
) -> bytes:
    return mqtt_packet(
        0x82,
        packet_id.to_bytes(2, "big")
        + (b"\x00" if proto_ver == 5 else b"")
        + utf8(topic_filter)
        + bytes((qos,)),
    )


def publish_packet(
    topic: str,
    payload: bytes,
    qos: int = 0,
    packet_id: int = 0,
    proto_ver: int = 5,
    retain: bool = False,
) -> bytes:
    body = utf8(topic)
    if qos:
        body += packet_id.to_bytes(2, "big")
    return mqtt_packet(
        0x30 | (qos << 1) | int(retain),
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


def connack_properties(packet: bytes) -> bytes:
    if packet[0] != 0x20:
        raise AssertionError(f"expected CONNACK, got {packet.hex()}")
    remaining, offset = decode_variable_integer(packet, 1)
    if remaining < 3 or offset + remaining != len(packet):
        raise AssertionError(f"malformed MQTT 5 CONNACK: {packet.hex()}")
    property_length, property_offset = decode_variable_integer(packet, offset + 2)
    properties = packet[property_offset : property_offset + property_length]
    if property_offset + property_length != len(packet):
        raise AssertionError(f"malformed MQTT 5 CONNACK properties: {packet.hex()}")
    return properties


def assigned_client_identifier(packet: bytes) -> str:
    properties = connack_properties(packet)
    if len(properties) < 3 or properties[0] != 0x12:
        raise AssertionError(
            "CONNACK omitted leading Assigned Client Identifier: "
            + packet.hex()
        )
    length = int.from_bytes(properties[1:3], "big")
    if length == 0 or 3 + length > len(properties):
        raise AssertionError(
            "malformed Assigned Client Identifier: " + packet.hex()
        )
    return properties[3 : 3 + length].decode("utf-8")


def acknowledgment_reason(
    packet: bytes, packet_type: int, packet_id: int
) -> int:
    if packet[0] != packet_type:
        raise AssertionError(
            f"expected acknowledgment {packet_type:#x}, got {packet.hex()}"
        )
    remaining, offset = decode_variable_integer(packet, 1)
    if remaining < 2 or offset + remaining != len(packet):
        raise AssertionError(f"malformed acknowledgment: {packet.hex()}")
    if int.from_bytes(packet[offset : offset + 2], "big") != packet_id:
        raise AssertionError(
            f"wrong acknowledgment packet identifier: {packet.hex()}"
        )
    return packet[offset + 2] if remaining > 2 else 0


def puback_reason(packet: bytes, packet_id: int) -> int:
    return acknowledgment_reason(packet, 0x40, packet_id)


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


def wait_process_line(
    process: subprocess.Popen[str],
    needle: str,
    label: str,
    timeout: float = 5,
) -> None:
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    was_blocking = os.get_blocking(descriptor)
    deadline = time.monotonic() + timeout
    observed: list[str] = []
    fragment = ""
    os.set_blocking(descriptor, False)
    try:
        while time.monotonic() < deadline:
            try:
                chunk = process.stdout.readline()
            except BlockingIOError:
                chunk = ""
            if chunk:
                fragment += chunk
                if fragment.endswith("\n"):
                    line = fragment.rstrip("\r\n")
                    fragment = ""
                    observed.append(line)
                    if needle in line:
                        return
                continue
            if process.poll() is not None:
                if fragment:
                    observed.append(fragment)
                    if needle in fragment:
                        return
                break
            remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select(
                [process.stdout],
                [],
                [],
                remaining,
            )
            if not readable:
                break
    finally:
        os.set_blocking(descriptor, was_blocking)
    if fragment:
        observed.append(fragment)
    raise AssertionError(
        f"{label}: did not observe {needle!r}; output={observed!r}"
    )


def read_listener_lines(
    process: subprocess.Popen[str],
    count: int,
    label: str,
) -> list[str]:
    assert process.stdout is not None
    listeners: list[str] = []
    observed: list[str] = []
    while len(listeners) < count:
        line = process.stdout.readline()
        if not line:
            raise AssertionError(
                f"{label}: broker exited before listener lines; "
                f"output={observed!r}"
            )
        stripped = line.strip()
        observed.append(stripped)
        if stripped.startswith(("mqtt ", "mqtts ", "websockets ", "wss ")):
            listeners.append(stripped)
    return listeners


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
    origin: str | None = None,
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
        "Sec-WebSocket-Protocol: mqtt\r\n"
        + (f"Origin: {origin}\r\n" if origin is not None else "")
        + "\r\n"
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


def read_websocket_close_code(sock: socket.socket) -> int:
    first, second = recv_exact(sock, 2)
    if first != 0x88 or second & 0x80:
        raise AssertionError(f"expected WebSocket close, got {first:02x}{second:02x}")
    length = second & 0x7F
    if length != 2:
        raise AssertionError(f"unexpected WebSocket close length {length}")
    return int.from_bytes(recv_exact(sock, 2), "big")


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
        "retain_expiry_interval 1\n"
        "set_tcp_nodelay true\n"
        f"password_file {password_file}\n"
        f"acl_file {acl_file}\n"
        f"listener {tcp_port} 127.0.0.1\n"
        "socket_domain ipv4\n"
        "bind_interface lo\n"
        "allow_anonymous false\n"
        "max_qos 1\n"
        "max_keepalive 30\n"
        "max_connections 4\n"
        f"listener {websocket_port} 127.0.0.1\n"
        "socket_domain ipv4\n"
        "bind_interface lo\n"
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
        "netz MQTT 3.1/3.1.1/5 broker configured 2 listeners for 6 clients "
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


def run_ipv6_socket_domain_case(broker: Path, directory: Path) -> None:
    port = free_ipv6_port()
    config = directory / "ipv6-socket-domain.conf"
    config.write_text(
        f"listener {port}\n"
        "socket_domain ipv6\n"
        "bind_interface lo\n"
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
    if "configured 1 listeners for 1 clients" not in ready:
        raise RuntimeError(f"IPv6-only configured broker failed to start: {ready}")

    ipv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ipv4.settimeout(0.5)
    try:
        try:
            ipv4.connect(("127.0.0.1", port))
        except OSError:
            pass
        else:
            raise AssertionError("socket_domain ipv6 accepted an IPv4 connection")
    finally:
        ipv4.close()

    ipv6 = socket.create_connection(("::1", port), timeout=5)
    ipv6.settimeout(5)
    try:
        ipv6.sendall(connect_packet("ipv6-only"))
        if connack_reason(read_mqtt_packet(ipv6)) != 0:
            raise AssertionError("IPv6-only MQTT CONNECT failed")
        ipv6.sendall(b"\xe0\x00")
    finally:
        ipv6.close()

    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("IPv6-only configured broker did not finish")
    if return_code != 0:
        raise RuntimeError(
            f"IPv6-only configured broker exited {return_code}: "
            + process.stdout.read()
        )


def run_default_dual_socket_domain_case(broker: Path, directory: Path) -> None:
    port = free_port()
    config = directory / "default-dual-socket-domain.conf"
    config.write_text(
        f"listener {port}\n"
        "allow_anonymous true\n"
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
    if "configured 1 listeners for 2 clients" not in ready:
        raise RuntimeError(f"dual-family configured broker failed to start: {ready}")

    clients: list[socket.socket] = []
    try:
        for address in (("127.0.0.1", port), ("::1", port)):
            client = socket.create_connection(address, timeout=5)
            client.settimeout(5)
            clients.append(client)
        for client, client_id in zip(clients, ("dual-v4", "dual-v6")):
            client.sendall(connect_packet(client_id))
            if connack_reason(read_mqtt_packet(client)) != 0:
                raise AssertionError(
                    f"default dual-family MQTT CONNECT failed for {client_id}"
                )
            client.sendall(b"\xe0\x00")
    finally:
        for client in clients:
            client.close()

    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("dual-family configured broker did not finish")
    if return_code != 0:
        raise RuntimeError(
            f"dual-family configured broker exited {return_code}: "
            + process.stdout.read()
        )


def run_per_listener_security_case(broker: Path, directory: Path) -> None:
    first_passwords = directory / "listener-first.pwfile"
    first_passwords.write_text(
        "first:$7$1000$"
        "h0tqVxBwkB9rKAXukTtffzdbBQtNy1q5FBTDwSW4hucfjpqunBbxW10NVnRk7Cfh0lQndnOv2+k4wJavgz1JNw==$"
        "02ujkUXlKkJGFzlQHNjUgXwG3XRB1mr3vs8NX5teGCJGbN4hdgSpHNHuj47j8r5SHXsO7GeHpmkpPNhLraVVcQ==\n"
    )
    second_passwords = directory / "listener-second.pwfile"
    second_passwords.write_text(
        "second:$7$1000$"
        "h0tqVxBwkB9rKAXukTtffzdbBQtNy1q5FBTDwSW4hucfjpqunBbxW10NVnRk7Cfh0lQndnOv2+k4wJavgz1JNw==$"
        "02ujkUXlKkJGFzlQHNjUgXwG3XRB1mr3vs8NX5teGCJGbN4hdgSpHNHuj47j8r5SHXsO7GeHpmkpPNhLraVVcQ==\n"
    )
    first_acl = directory / "listener-first.acl"
    first_acl.write_text("user first\ntopic write first/#\n")
    second_acl = directory / "listener-second.acl"
    second_acl.write_text("user second\ntopic write second/#\n")
    first_port = free_port()
    second_port = free_port()
    while second_port == first_port:
        second_port = free_port()
    config = directory / "per-listener.conf"
    config.write_text(
        "per_listener_settings true\n"
        f"listener {first_port} 127.0.0.1\n"
        f"password_file {first_passwords}\n"
        f"acl_file {first_acl}\n"
        "allow_anonymous false\n"
        "max_connections 3\n"
        f"listener {second_port} 127.0.0.1\n"
        f"password_file {second_passwords}\n"
        f"acl_file {second_acl}\n"
        "allow_anonymous false\n"
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
    if "configured 2 listeners for 5 clients" not in ready:
        raise RuntimeError(f"per-listener broker failed to start: {ready}")

    cases = (
        (first_port, "first", "first/allowed", 0x10),
        (second_port, "first", None, 0x87),
        (second_port, "second", "second/allowed", 0x10),
        (first_port, "second", None, 0x87),
    )
    for index, (port, username, topic, expected_reason) in enumerate(cases):
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.settimeout(5)
        try:
            client.sendall(
                connect_packet(
                    f"per-listener-{index}",
                    username=username,
                    password="password",
                )
            )
            reason = connack_reason(read_mqtt_packet(client))
            if topic is None:
                if reason != expected_reason:
                    raise AssertionError(
                        f"listener accepted foreign credentials: {reason:#x}"
                    )
                continue
            if reason != 0:
                raise AssertionError(
                    f"listener rejected local credentials: {reason:#x}"
                )
            client.sendall(
                publish_packet(topic, b"isolated ACL", qos=1, packet_id=81)
            )
            if puback_reason(read_mqtt_packet(client), 81) != expected_reason:
                raise AssertionError("listener-local ACL did not authorize topic")
            client.sendall(bytes.fromhex("e000"))
        finally:
            client.close()

    acl_denied = socket.create_connection(
        ("127.0.0.1", first_port), timeout=5
    )
    acl_denied.settimeout(5)
    try:
        acl_denied.sendall(
            connect_packet(
                "per-listener-acl-denied",
                username="first",
                password="password",
            )
        )
        if connack_reason(read_mqtt_packet(acl_denied)) != 0:
            raise AssertionError("listener-local ACL client failed CONNECT")
        acl_denied.sendall(
            publish_packet("second/denied", b"isolated", qos=1, packet_id=82)
        )
        if puback_reason(read_mqtt_packet(acl_denied), 82) != 0x87:
            raise AssertionError("listener inherited another listener's ACL")
        acl_denied.sendall(bytes.fromhex("e000"))
    finally:
        acl_denied.close()

    if process.wait(timeout=5) != 0:
        raise RuntimeError(
            "per-listener security broker failed: " + process.stdout.read()
        )

    invalid_port = free_port()
    invalid_config = directory / "per-listener-invalid.conf"
    invalid_config.write_text(
        "per_listener_settings true\n"
        f"listener {invalid_port} 127.0.0.1\n"
        f"password_file {first_passwords}\n"
        "allow_anonymous false\n"
        f"listener {free_port()} 127.0.0.1\n"
        f"password_file {directory / 'missing.pwfile'}\n"
        "allow_anonymous false\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={invalid_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0:
        raise AssertionError("missing listener-local password file was accepted")
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", invalid_port)) == 0:
            raise AssertionError(
                "listener bound before every local security file was loaded"
            )


def run_include_directory_case(broker: Path, directory: Path) -> None:
    include_directory = directory / "listeners.d"
    include_directory.mkdir()
    first_port = free_port()
    second_port = free_port()
    while second_port == first_port:
        second_port = free_port()
    (include_directory / "ignored.txt").write_text("unsupported value\n")
    (include_directory / "a.conf").write_text(
        f"listener {second_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    (include_directory / "A.conf").write_text(
        f"listener {first_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    config = directory / "include-main.conf"
    config.write_text(f"include_dir {include_directory}\n")
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    startup_lines: list[str] = []
    while True:
        line = process.stdout.readline()
        if line == "":
            raise RuntimeError(
                "include_dir broker failed to start: "
                + "".join(startup_lines)
            )
        startup_lines.append(line)
        if "configured 2 listeners for 2 clients" in line:
            break
    listener_lines: list[str] = []
    while len(listener_lines) != 2:
        line = process.stdout.readline()
        if line == "":
            raise RuntimeError(
                "include_dir broker omitted listener records: "
                + "".join(startup_lines + listener_lines)
            )
        if "mqtt " in line and "max_connections=" in line:
            listener_lines.append(line.strip())
    if str(first_port) not in listener_lines[0] or str(second_port) not in listener_lines[1]:
        raise AssertionError(
            "include_dir did not use Mosquitto filename order: "
            + repr(listener_lines)
        )
    for index, port in enumerate((first_port, second_port)):
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.settimeout(5)
        try:
            client.sendall(connect_packet(f"include-dir-{index}"))
            if connack_reason(read_mqtt_packet(client)) != 0:
                raise AssertionError("include_dir listener rejected CONNECT")
            client.sendall(bytes.fromhex("e000"))
        finally:
            client.close()
    if process.wait(timeout=5) != 0:
        raise RuntimeError("include_dir broker exited with an error")

    invalid_port = free_port()
    invalid_directory = directory / "invalid-listeners.d"
    invalid_directory.mkdir()
    (invalid_directory / "10-listener.conf").write_text(
        f"listener {free_port()} 127.0.0.1\nallow_anonymous true\n"
    )
    (invalid_directory / "20-invalid.conf").write_text(
        "unsupported_directive true\n"
    )
    invalid_config = directory / "invalid-include-main.conf"
    invalid_config.write_text(
        f"listener {invalid_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        f"include_dir {invalid_directory}\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={invalid_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0 or "UnsupportedDirective" not in result.stdout:
        raise AssertionError(
            "invalid included config did not fail closed: " + result.stdout
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", invalid_port)) == 0:
            raise AssertionError(
                "listener bound before every included config was validated"
            )


def run_packet_and_message_size_case(broker: Path, directory: Path) -> None:
    packet_port = free_port()
    websocket_port = free_port()
    while websocket_port == packet_port:
        websocket_port = free_port()
    tls_port = free_port()
    while tls_port in (packet_port, websocket_port):
        tls_port = free_port()
    wss_port = free_port()
    while wss_port in (packet_port, websocket_port, tls_port):
        wss_port = free_port()
    server_ca, server_ca_key = create_ca(
        directory,
        "size-server-ca",
        "Size Server Root",
    )
    server_certificate, server_key = create_signed_certificate(
        directory,
        "size-server",
        "localhost",
        server_ca,
        server_ca_key,
        801,
        "serverAuth",
        "DNS:localhost",
    )
    packet_config = directory / "max-packet-size.conf"
    packet_config.write_text(
        "max_packet_size 50\n"
        f"listener {packet_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 2\n"
        f"listener {websocket_port} 127.0.0.1\n"
        "protocol websockets\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {tls_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {wss_port} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    packet_process = subprocess.Popen(
        [str(broker), f"--config={packet_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert packet_process.stdout is not None
    ready = packet_process.stdout.readline().strip()
    if "configured 4 listeners for 5 clients" not in ready:
        raise RuntimeError(f"max-packet-size broker failed to start: {ready}")

    v5 = socket.create_connection(("127.0.0.1", packet_port), timeout=5)
    v5.settimeout(5)
    try:
        v5.sendall(connect_packet("packet-v5"))
        connack = read_mqtt_packet(v5)
        if connack_reason(connack) != 0:
            raise AssertionError("max-packet-size MQTT 5 CONNECT failed")
        expected_property = bytes((0x27, 0, 0, 0, 50))
        if expected_property not in connack_properties(connack):
            raise AssertionError(
                "CONNACK omitted configured Maximum Packet Size: "
                + connack.hex()
            )
        exact = publish_packet("t", b"x" * 44, proto_ver=5)
        oversized = publish_packet("t", b"x" * 45, proto_ver=5)
        if len(exact) != 50 or len(oversized) != 51:
            raise AssertionError("max packet fixture sizes drifted")
        v5.sendall(exact)
        mqtt_ping(v5)
        v5.sendall(oversized)
        disconnect = read_mqtt_packet(v5)
        if disconnect != bytes.fromhex("e00195"):
            raise AssertionError(
                "oversized MQTT 5 packet disconnect mismatch: "
                + disconnect.hex()
            )
    finally:
        v5.close()

    v311 = socket.create_connection(("127.0.0.1", packet_port), timeout=5)
    v311.settimeout(5)
    try:
        v311.sendall(connect_packet("packet-v311", proto_ver=4))
        if read_mqtt_packet(v311) != bytes.fromhex("20020000"):
            raise AssertionError("max-packet-size MQTT 3.1.1 CONNECT failed")
        oversized = publish_packet("t", b"x" * 46, proto_ver=4)
        if len(oversized) != 51:
            raise AssertionError("MQTT 3.1.1 max packet fixture size drifted")
        v311.sendall(oversized)
        try:
            closed = v311.recv(1) == b""
        except ConnectionError:
            closed = True
        if not closed:
            raise AssertionError("oversized MQTT 3.1.1 packet was not closed")
    finally:
        v311.close()

    websocket = websocket_connect(websocket_port)
    try:
        send_websocket_binary(websocket, connect_packet("packet-ws"))
        connack = read_websocket_binary(websocket)
        if bytes((0x27, 0, 0, 0, 50)) not in connack_properties(connack):
            raise AssertionError("WebSocket CONNACK omitted Maximum Packet Size")
        send_websocket_binary(
            websocket,
            publish_packet("t", b"x" * 45, proto_ver=5),
        )
        if read_websocket_close_code(websocket) != 1009:
            raise AssertionError("WebSocket oversized packet close code mismatch")
    finally:
        websocket.close()

    context = ssl.create_default_context(cafile=str(server_ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    raw_tls = socket.create_connection(("127.0.0.1", tls_port), timeout=5)
    raw_tls.settimeout(5)
    tls = context.wrap_socket(raw_tls, server_hostname="localhost")
    try:
        tls.sendall(connect_packet("packet-tls"))
        connack = read_mqtt_packet(tls)
        if bytes((0x27, 0, 0, 0, 50)) not in connack_properties(connack):
            raise AssertionError("TLS CONNACK omitted Maximum Packet Size")
        tls.sendall(publish_packet("t", b"x" * 45, proto_ver=5))
        if read_mqtt_packet(tls) != bytes.fromhex("e00195"):
            raise AssertionError("TLS oversized packet reason mismatch")
    finally:
        tls.close()

    secure_websocket = websocket_connect(wss_port, server_ca)
    try:
        send_websocket_binary(
            secure_websocket,
            connect_packet("packet-wss"),
        )
        connack = read_websocket_binary(secure_websocket)
        if bytes((0x27, 0, 0, 0, 50)) not in connack_properties(connack):
            raise AssertionError("WSS CONNACK omitted Maximum Packet Size")
        send_websocket_binary(
            secure_websocket,
            publish_packet("t", b"x" * 45, proto_ver=5),
        )
        if read_websocket_close_code(secure_websocket) != 1009:
            raise AssertionError("WSS oversized packet close code mismatch")
    finally:
        secure_websocket.close()
    packet_return_code = packet_process.wait(timeout=5)
    packet_output = packet_process.stdout.read()
    if packet_return_code == 0 or "MessageTooLarge" not in packet_output:
        raise RuntimeError(
            "max-packet-size violations were not reported: " + packet_output
        )

    message_port = free_port()
    message_config = directory / "message-size-limit.conf"
    message_config.write_text(
        "message_size_limit 1\n"
        f"listener {message_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 6\n"
    )
    message_process = subprocess.Popen(
        [str(broker), f"--config={message_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert message_process.stdout is not None
    ready = message_process.stdout.readline().strip()
    if "configured 1 listeners for 6 clients" not in ready:
        raise RuntimeError(f"message-size broker failed to start: {ready}")

    for proto_ver in (5, 4):
        subscriber = socket.create_connection(
            ("127.0.0.1", message_port), timeout=5
        )
        publisher = socket.create_connection(
            ("127.0.0.1", message_port), timeout=5
        )
        subscriber.settimeout(5)
        publisher.settimeout(5)
        try:
            subscriber.sendall(connect_packet(f"size-sub-{proto_ver}", proto_ver=proto_ver))
            if connack_reason(read_mqtt_packet(subscriber)) != 0:
                raise AssertionError("message-size subscriber CONNECT failed")
            subscriber.sendall(subscribe_packet(1, "size/topic", proto_ver))
            suback = read_mqtt_packet(subscriber)
            if suback[0] != 0x90:
                raise AssertionError("message-size SUBACK missing")
            publisher.sendall(connect_packet(f"size-pub-{proto_ver}", proto_ver=proto_ver))
            if connack_reason(read_mqtt_packet(publisher)) != 0:
                raise AssertionError("message-size publisher CONNECT failed")

            allowed = publish_packet("size/topic", b"A", proto_ver=proto_ver)
            publisher.sendall(allowed)
            if read_mqtt_packet(subscriber) != allowed:
                raise AssertionError("at-limit payload was not delivered")

            publisher.sendall(
                publish_packet("size/topic", b"AB", proto_ver=proto_ver)
            )
            mqtt_ping(publisher)
            expect_no_packet(subscriber, "oversized QoS 0 payload")
            publisher.sendall(
                publish_packet(
                    "size/topic",
                    b"AB",
                    qos=1,
                    packet_id=2,
                    proto_ver=proto_ver,
                )
            )
            expected_reason = 0x83 if proto_ver == 5 else 0
            if puback_reason(read_mqtt_packet(publisher), 2) != expected_reason:
                raise AssertionError("oversized QoS 1 PUBACK reason mismatch")
            publisher.sendall(
                publish_packet(
                    "size/topic",
                    b"AB",
                    qos=2,
                    packet_id=3,
                    proto_ver=proto_ver,
                )
            )
            if acknowledgment_reason(
                read_mqtt_packet(publisher), 0x50, 3
            ) != expected_reason:
                raise AssertionError("oversized QoS 2 PUBREC reason mismatch")
            if proto_ver == 4:
                publisher.sendall(bytes.fromhex("62020003"))
                if acknowledgment_reason(
                    read_mqtt_packet(publisher), 0x70, 3
                ) != 0:
                    raise AssertionError("oversized QoS 2 PUBCOMP mismatch")
            publisher.sendall(
                publish_packet(
                    "size/topic",
                    b"AB",
                    qos=1,
                    packet_id=3,
                    proto_ver=proto_ver,
                )
            )
            if puback_reason(read_mqtt_packet(publisher), 3) != expected_reason:
                raise AssertionError(
                    "reused packet identifier was not released after rejection"
                )
            mqtt_ping(publisher)
            expect_no_packet(subscriber, "oversized QoS 1/2 payload")
            publisher.sendall(bytes.fromhex("e000"))
            subscriber.sendall(bytes.fromhex("e000"))
        finally:
            publisher.close()
            subscriber.close()

    for proto_ver, expected_reason in ((5, 0x95), (4, 0x05)):
        client = socket.create_connection(("127.0.0.1", message_port), timeout=5)
        client.settimeout(5)
        try:
            client.sendall(
                connect_packet(
                    f"size-will-{proto_ver}",
                    proto_ver=proto_ver,
                    will_topic="size/will",
                    will_payload=b"AB",
                )
            )
            if connack_reason(read_mqtt_packet(client)) != expected_reason:
                raise AssertionError("oversized Will CONNACK reason mismatch")
        finally:
            client.close()
    if message_process.wait(timeout=5) != 0:
        raise RuntimeError(
            "message-size broker failed: " + message_process.stdout.read()
        )


def run_retain_unavailable_case(broker: Path, directory: Path) -> None:
    tcp_port = free_port()
    websocket_port = free_port()
    while websocket_port == tcp_port:
        websocket_port = free_port()
    config = directory / "retain-unavailable.conf"
    config.write_text(
        "retain_available false\n"
        f"listener {tcp_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 4\n"
        f"listener {websocket_port} 127.0.0.1\n"
        "protocol websockets\n"
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
    if "configured 2 listeners for 5 clients" not in ready:
        raise RuntimeError(f"retain-unavailable broker failed to start: {ready}")

    v5 = socket.create_connection(("127.0.0.1", tcp_port), timeout=5)
    v5.settimeout(5)
    try:
        v5.sendall(connect_packet("retain-v5"))
        connack = read_mqtt_packet(v5)
        if bytes((0x25, 0)) not in connack_properties(connack):
            raise AssertionError("CONNACK omitted Retain Available=0")
        v5.sendall(
            publish_packet(
                "retain/topic",
                b"blocked",
                qos=1,
                packet_id=1,
                retain=True,
            )
        )
        if read_mqtt_packet(v5) != bytes.fromhex("e0019a"):
            raise AssertionError("retained MQTT 5 PUBLISH reason mismatch")
    finally:
        v5.close()

    v311 = socket.create_connection(("127.0.0.1", tcp_port), timeout=5)
    v311.settimeout(5)
    try:
        v311.sendall(connect_packet("retain-v311", proto_ver=4))
        if read_mqtt_packet(v311) != bytes.fromhex("20020000"):
            raise AssertionError("retain-unavailable MQTT 3.1.1 CONNECT failed")
        v311.sendall(
            publish_packet(
                "retain/topic",
                b"blocked",
                qos=1,
                packet_id=1,
                proto_ver=4,
                retain=True,
            )
        )
        try:
            closed = v311.recv(1) == b""
        except ConnectionError:
            closed = True
        if not closed:
            raise AssertionError("retained MQTT 3.1.1 PUBLISH was not closed")
    finally:
        v311.close()

    websocket = websocket_connect(websocket_port)
    try:
        send_websocket_binary(websocket, connect_packet("retain-ws"))
        connack = read_websocket_binary(websocket)
        if bytes((0x25, 0)) not in connack_properties(connack):
            raise AssertionError("WebSocket CONNACK omitted Retain Available=0")
        send_websocket_binary(
            websocket,
            publish_packet(
                "retain/topic",
                b"blocked",
                qos=1,
                packet_id=1,
                retain=True,
            ),
        )
        if read_websocket_binary(websocket) != bytes.fromhex("e0019a"):
            raise AssertionError("retained WebSocket PUBLISH reason mismatch")
    finally:
        websocket.close()

    for proto_ver, expected_reason in ((5, 0x9A), (4, 0x05)):
        client = socket.create_connection(("127.0.0.1", tcp_port), timeout=5)
        client.settimeout(5)
        try:
            client.sendall(
                connect_packet(
                    f"retain-will-{proto_ver}",
                    proto_ver=proto_ver,
                    will_topic="retain/will",
                    will_payload=b"blocked",
                    will_retain=True,
                )
            )
            if proto_ver == 5:
                if connack_reason(read_mqtt_packet(client)) != expected_reason:
                    raise AssertionError("retained Will CONNACK reason mismatch")
            else:
                try:
                    closed = client.recv(1) == b""
                except ConnectionError:
                    closed = True
                if not closed:
                    raise AssertionError("retained MQTT 3.1.1 Will was not closed")
        finally:
            client.close()

    return_code = process.wait(timeout=5)
    output = process.stdout.read()
    if return_code == 0 or "InvalidProperty" not in output:
        raise RuntimeError(
            "retain-unavailable Will rejection was not reported: " + output
        )


def run_zero_length_client_id_case(broker: Path, directory: Path) -> None:
    global_tcp_port = free_port()
    global_websocket_port = free_port()
    while global_websocket_port == global_tcp_port:
        global_websocket_port = free_port()
    global_config = directory / "zero-client-id-global.conf"
    global_config.write_text(
        "allow_zero_length_clientid false\n"
        "auto_id_prefix global-\n"
        f"listener {global_tcp_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {global_websocket_port} 127.0.0.1\n"
        "protocol websockets\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    global_process = subprocess.Popen(
        [str(broker), f"--config={global_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert global_process.stdout is not None
    ready = global_process.stdout.readline().strip()
    if "configured 2 listeners for 2 clients" not in ready:
        raise RuntimeError(f"global zero-client-id broker failed: {ready}")

    tcp = socket.create_connection(("127.0.0.1", global_tcp_port), timeout=5)
    tcp.settimeout(5)
    try:
        tcp.sendall(connect_packet(""))
        if connack_reason(read_mqtt_packet(tcp)) != 0x80:
            raise AssertionError(
                "global zero-client-id MQTT 5 refusal reason mismatch"
            )
    finally:
        tcp.close()

    websocket = websocket_connect(global_websocket_port)
    try:
        send_websocket_binary(websocket, connect_packet("", proto_ver=4))
        if read_websocket_binary(websocket) != bytes.fromhex("20020002"):
            raise AssertionError(
                "global zero-client-id MQTT 3.1.1 refusal mismatch"
            )
    finally:
        websocket.close()
    if global_process.wait(timeout=5) != 0:
        raise RuntimeError(
            "global zero-client-id broker failed: "
            + global_process.stdout.read()
        )

    prefix_port = free_port()
    prefix_config = directory / "zero-client-id-prefix.conf"
    prefix_config.write_text(
        "auto_id_prefix global-\n"
        f"listener {prefix_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 2\n"
    )
    prefix_process = subprocess.Popen(
        [str(broker), f"--config={prefix_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert prefix_process.stdout is not None
    ready = prefix_process.stdout.readline().strip()
    if "configured 1 listeners for 2 clients" not in ready:
        raise RuntimeError(f"global client-ID prefix broker failed: {ready}")
    global_clients = [
        socket.create_connection(("127.0.0.1", prefix_port), timeout=5)
        for _ in range(2)
    ]
    try:
        assigned_ids: list[str] = []
        for client in global_clients:
            client.settimeout(5)
            client.sendall(connect_packet(""))
            connack = read_mqtt_packet(client)
            if connack_reason(connack) != 0:
                raise AssertionError("global-prefix CONNECT was refused")
            assigned_ids.append(assigned_client_identifier(connack))
        if any(
            not value.startswith("global-") or len(value) != 43
            for value in assigned_ids
        ) or assigned_ids[0] == assigned_ids[1]:
            raise AssertionError(
                "global prefix did not produce unique assigned identifiers: "
                + repr(assigned_ids)
            )
        for client in global_clients:
            client.sendall(bytes.fromhex("e000"))
    finally:
        for client in global_clients:
            client.close()
    if prefix_process.wait(timeout=5) != 0:
        raise RuntimeError(
            "global client-ID prefix broker failed: "
            + prefix_process.stdout.read()
        )

    denied_port = free_port()
    allowed_port = free_port()
    while allowed_port == denied_port:
        allowed_port = free_port()
    listener_config = directory / "zero-client-id-per-listener.conf"
    listener_config.write_text(
        "per_listener_settings true\n"
        f"listener {denied_port} 127.0.0.1\n"
        "allow_zero_length_clientid false\n"
        "auto_id_prefix denied-\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {allowed_port} 127.0.0.1\n"
        "protocol websockets\n"
        "listener_auto_id_prefix tenant-\n"
        "allow_anonymous true\n"
        "max_connections 4\n"
    )
    listener_process = subprocess.Popen(
        [str(broker), f"--config={listener_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert listener_process.stdout is not None
    ready = listener_process.stdout.readline().strip()
    if "configured 2 listeners for 5 clients" not in ready:
        raise RuntimeError(f"per-listener zero-client-id broker failed: {ready}")

    denied = socket.create_connection(("127.0.0.1", denied_port), timeout=5)
    denied.settimeout(5)
    try:
        denied.sendall(connect_packet(""))
        if connack_reason(read_mqtt_packet(denied)) != 0x80:
            raise AssertionError(
                "per-listener zero-client-id refusal reason mismatch"
            )
    finally:
        denied.close()

    allowed_v5 = websocket_connect(allowed_port)
    second_allowed_v5 = websocket_connect(allowed_port)
    try:
        send_websocket_binary(
            allowed_v5, connect_packet("", clean_start=False)
        )
        connack = read_websocket_binary(allowed_v5)
        if connack_reason(connack) != 0:
            raise AssertionError("zero-client-id MQTT 5 CONNECT was refused")
        assigned = assigned_client_identifier(connack)
        send_websocket_binary(
            second_allowed_v5, connect_packet("", clean_start=False)
        )
        second_connack = read_websocket_binary(second_allowed_v5)
        if connack_reason(second_connack) != 0:
            raise AssertionError("second zero-client-id CONNECT was refused")
        second_assigned = assigned_client_identifier(second_connack)
        if not assigned.startswith("tenant-") or len(assigned) != 43:
            raise AssertionError(
                f"unexpected assigned Client Identifier: {assigned!r}"
            )
        if not second_assigned.startswith("tenant-") or assigned == second_assigned:
            raise AssertionError(
                "listener prefix did not produce unique assigned identifiers: "
                f"{assigned!r}, {second_assigned!r}"
            )
        send_websocket_binary(allowed_v5, bytes.fromhex("e000"))
        send_websocket_binary(second_allowed_v5, bytes.fromhex("e000"))
    finally:
        allowed_v5.close()
        second_allowed_v5.close()

    allowed_v311 = websocket_connect(allowed_port)
    try:
        send_websocket_binary(
            allowed_v311, connect_packet("", proto_ver=4)
        )
        if read_websocket_binary(allowed_v311) != bytes.fromhex("20020000"):
            raise AssertionError(
                "zero-client-id MQTT 3.1.1 CONNECT was refused"
            )
        send_websocket_binary(allowed_v311, bytes.fromhex("e000"))
    finally:
        allowed_v311.close()

    persistent_v311 = websocket_connect(allowed_port)
    try:
        send_websocket_binary(
            persistent_v311,
            connect_packet("", proto_ver=4, clean_start=False),
        )
        if read_websocket_binary(persistent_v311) != bytes.fromhex(
            "20020002"
        ):
            raise AssertionError(
                "persistent zero-client-id MQTT 3.1.1 refusal mismatch"
            )
    finally:
        persistent_v311.close()
    return_code = listener_process.wait(timeout=5)
    output = listener_process.stdout.read()
    if return_code == 0 or "InvalidClientId" not in output:
        raise RuntimeError(
            "per-listener zero-client-id protocol rejection was not reported: "
            + output
        )


def run_auto_client_id_prefix_matrix(broker: Path, directory: Path) -> None:
    # Complete wire-visible matrix from Mosquitto 01-connect-auto-id.py. A
    # listener-local prefix wins over the global prefix; an absent listener
    # prefix inherits the global value or netz's documented default.
    cases = (
        (None, None, None, "auto-", "auto-"),
        (None, None, "new-", "new-", "new-"),
        (None, "port2-", None, "auto-", "port2-"),
        ("port1-", "port2-", None, "port1-", "port2-"),
        ("port1-", "port2-", "global-", "port1-", "port2-"),
        ("port1-", None, "global-", "port1-", "global-"),
    )
    for index, (prefix1, prefix2, global_prefix, expected1, expected2) in (
        enumerate(cases)
    ):
        port1 = free_port()
        port2 = free_port()
        while port2 == port1:
            port2 = free_port()
        lines = []
        if global_prefix is not None:
            lines.append(f"auto_id_prefix {global_prefix}")
        lines.extend((
            f"listener {port1} 127.0.0.1",
            "allow_anonymous true",
            "max_connections 1",
        ))
        if prefix1 is not None:
            lines.append(f"listener_auto_id_prefix {prefix1}")
        lines.extend((
            f"listener {port2} 127.0.0.1",
            "allow_anonymous true",
            "max_connections 1",
        ))
        if prefix2 is not None:
            lines.append(f"listener_auto_id_prefix {prefix2}")
        config_path = directory / f"auto-id-prefix-{index}.conf"
        config_path.write_text("\n".join(lines) + "\n")
        process = subprocess.Popen(
            [str(broker), f"--config={config_path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert process.stdout is not None
        ready = process.stdout.readline().strip()
        if "configured 2 listeners for 2 clients" not in ready:
            raise RuntimeError(f"auto-ID broker case {index} failed: {ready}")

        clients = []
        try:
            assigned_ids = []
            for port, expected_prefix in (
                (port1, expected1),
                (port2, expected2),
            ):
                client = socket.create_connection(
                    ("127.0.0.1", port), timeout=5
                )
                clients.append(client)
                client.settimeout(5)
                client.sendall(connect_packet(""))
                connack = read_mqtt_packet(client)
                if connack_reason(connack) != 0:
                    raise AssertionError(
                        f"auto-ID case {index} CONNECT was refused"
                    )
                assigned = assigned_client_identifier(connack)
                if (
                    not assigned.startswith(expected_prefix)
                    or len(assigned) != len(expected_prefix) + 36
                ):
                    raise AssertionError(
                        f"auto-ID case {index} expected prefix "
                        f"{expected_prefix!r}, got {assigned!r}"
                    )
                assigned_ids.append(assigned)
            if assigned_ids[0] == assigned_ids[1]:
                raise AssertionError(
                    f"auto-ID case {index} reused an identifier"
                )
            for client in clients:
                client.sendall(bytes.fromhex("e000"))
        finally:
            for client in clients:
                client.close()
        if process.wait(timeout=5) != 0:
            raise RuntimeError(
                f"auto-ID broker case {index} failed: "
                + process.stdout.read()
            )


def run_required_client_id_prefix_case(
    broker: Path, directory: Path
) -> None:
    port = free_port()
    config = directory / "required-client-id-prefix.conf"
    config.write_text(
        "clientid_prefixes secure-\n"
        "auto_id_prefix secure-auto-\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 4\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 4 clients" not in ready:
        raise RuntimeError(f"Client ID prefix broker failed: {ready}")

    cases = (
        ("secure-client", 5, 0x00),
        ("other-client", 5, 0x87),
        ("other-v311", 4, 0x05),
        ("", 5, 0x00),
    )
    for client_id, protocol, expected_reason in cases:
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.settimeout(5)
        try:
            client.sendall(connect_packet(client_id, proto_ver=protocol))
            connack = read_mqtt_packet(client)
            actual_reason = connack_reason(connack)
            if actual_reason != expected_reason:
                raise AssertionError(
                    "Client ID prefix refusal mismatch: "
                    f"client_id={client_id!r} protocol={protocol} "
                    f"expected={expected_reason:#x} actual={actual_reason:#x}"
                )
            if client_id == "":
                assigned = assigned_client_identifier(connack)
                if not assigned.startswith("secure-auto-"):
                    raise AssertionError(
                        "assigned Client ID bypassed required prefix: "
                        f"{assigned!r}"
                    )
            if expected_reason == 0:
                client.sendall(bytes.fromhex("e000"))
        finally:
            client.close()

    if process.wait(timeout=5) != 0:
        raise RuntimeError(
            "Client ID prefix broker failed: " + process.stdout.read()
        )


def run_upgrade_outgoing_qos_case(broker: Path, directory: Path) -> None:
    port = free_port()
    config = directory / "upgrade-outgoing-qos.conf"
    config.write_text(
        "upgrade_outgoing_qos true\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 6\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 6 clients" not in ready:
        raise RuntimeError(f"QoS-upgrade broker failed to start: {ready}")

    for proto_ver in (5, 4):
        retained = socket.create_connection(("127.0.0.1", port), timeout=5)
        retained.settimeout(5)
        try:
            retained.sendall(
                connect_packet(f"qos-upgrade-retained-{proto_ver}", proto_ver=proto_ver)
            )
            if connack_reason(read_mqtt_packet(retained)) != 0:
                raise AssertionError("QoS-upgrade retained CONNECT failed")
            topic = f"qos/upgrade/retained/{proto_ver}"
            payload = b"retained qos zero"
            retained.sendall(
                publish_packet(
                    topic, payload, proto_ver=proto_ver, retain=True
                )
            )
            retained.sendall(
                subscribe_packet(1, topic, proto_ver=proto_ver, qos=1)
            )
            suback = read_mqtt_packet(retained)
            expected_suback = bytes.fromhex(
                "900400010001" if proto_ver == 5 else "9003000101"
            )
            if suback != expected_suback:
                raise AssertionError("QoS-upgrade retained SUBACK mismatch")
            expected = publish_packet(
                topic,
                payload,
                qos=1,
                packet_id=1,
                proto_ver=proto_ver,
                retain=True,
            )
            if read_mqtt_packet(retained) != expected:
                raise AssertionError(
                    f"retained QoS upgrade mismatch for MQTT {proto_ver}"
                )
            retained.sendall(bytes.fromhex("40020001"))
            retained.sendall(bytes.fromhex("e000"))
        finally:
            retained.close()

        subscriber = socket.create_connection(("127.0.0.1", port), timeout=5)
        publisher = socket.create_connection(("127.0.0.1", port), timeout=5)
        subscriber.settimeout(5)
        publisher.settimeout(5)
        try:
            subscriber.sendall(
                connect_packet(f"qos-upgrade-sub-{proto_ver}", proto_ver=proto_ver)
            )
            if connack_reason(read_mqtt_packet(subscriber)) != 0:
                raise AssertionError("QoS-upgrade subscriber CONNECT failed")
            topic = f"qos/upgrade/live/{proto_ver}"
            subscriber.sendall(
                subscribe_packet(2, topic, proto_ver=proto_ver, qos=1)
            )
            suback = read_mqtt_packet(subscriber)
            expected_suback = bytes.fromhex(
                "900400020001" if proto_ver == 5 else "9003000201"
            )
            if suback != expected_suback:
                raise AssertionError("QoS-upgrade live SUBACK mismatch")
            publisher.sendall(
                connect_packet(f"qos-upgrade-pub-{proto_ver}", proto_ver=proto_ver)
            )
            if connack_reason(read_mqtt_packet(publisher)) != 0:
                raise AssertionError("QoS-upgrade publisher CONNECT failed")
            payload = b"live qos zero"
            publisher.sendall(
                publish_packet(topic, payload, proto_ver=proto_ver)
            )
            expected = publish_packet(
                topic, payload, qos=1, packet_id=1, proto_ver=proto_ver
            )
            if read_mqtt_packet(subscriber) != expected:
                raise AssertionError(
                    f"live QoS upgrade mismatch for MQTT {proto_ver}"
                )
            subscriber.sendall(bytes.fromhex("40020001"))
            publisher.sendall(bytes.fromhex("e000"))
            subscriber.sendall(bytes.fromhex("e000"))
        finally:
            publisher.close()
            subscriber.close()

    if process.wait(timeout=5) != 0:
        raise RuntimeError(
            "QoS-upgrade broker failed: " + process.stdout.read()
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

    missing_interface = directory / "missing-bind-interface.conf"
    missing_interface.write_text(
        f"listener {free_port()}\n"
        "bind_interface netz-interface-that-does-not-exist\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={missing_interface}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0 or "InterfaceNotFound" not in result.stdout:
        raise AssertionError(
            "missing bind_interface did not fail before serving: "
            + result.stdout
        )

    for value in ("0", "10000001"):
        invalid_expiry = directory / f"invalid-retain-expiry-{value}.conf"
        invalid_expiry.write_text(
            f"retain_expiry_interval {value}\n"
            f"listener {free_port()} 127.0.0.1\n"
            "allow_anonymous true\n"
            "max_connections 1\n"
        )
        result = subprocess.run(
            [str(broker), f"--config={invalid_expiry}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0 or "InvalidInteger" not in result.stdout:
            raise AssertionError(
                "invalid retained expiry interval did not fail closed: "
                + result.stdout
            )

    unsupported_protocol = directory / "unsupported-protocol-version.conf"
    unsupported_protocol.write_text(
        f"listener {free_port()} 127.0.0.1\n"
        "accept_protocol_versions 2\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={unsupported_protocol}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0 or "InvalidInteger" not in result.stdout:
        raise AssertionError(
            "unsupported MQTT protocol level did not fail closed: "
            + result.stdout
        )

    overlong_v31_bridge = directory / "overlong-v31-bridge-client.conf"
    overlong_v31_bridge.write_text(
        f"listener {free_port()} 127.0.0.1\n"
        "allow_anonymous true\n"
        "connection overlong-v31-client\n"
        "address localhost\n"
        "topic # in 0\n"
        "bridge_protocol_version mqttv31\n"
        "remote_clientid abcdefghijklmnopqrstuvwx\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={overlong_v31_bridge}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0 or "InvalidClientId" not in result.stdout:
        raise AssertionError(
            "overlong MQTT 3.1 bridge Client ID did not fail before serving: "
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


def run_security_reload_case(broker: Path, directory: Path) -> None:
    port = free_port()
    password_file = directory / "reload.pwfile"
    acl_file = directory / "reload.acl"
    config = directory / "reload.conf"
    password_hash = (
        "$7$1000$"
        "h0tqVxBwkB9rKAXukTtffzdbBQtNy1q5FBTDwSW4hucfjpqunBbxW10NVnRk7Cfh0lQndnOv2+k4wJavgz1JNw==$"
        "02ujkUXlKkJGFzlQHNjUgXwG3XRB1mr3vs8NX5teGCJGbN4hdgSpHNHuj47j8r5SHXsO7GeHpmkpPNhLraVVcQ=="
    )
    password_file.write_text(
        f"old:{password_hash}\n"
        f"stable:{password_hash}\n"
    )
    acl_file.write_text(
        "user old\n"
        "topic readwrite before/#\n"
        "topic write revoked/will\n"
        "user stable\n"
        "topic read after/#\n"
        "topic read revoked/#\n"
    )
    config.write_text(
        f"password_file {password_file}\n"
        f"acl_file {acl_file}\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous false\n"
        "max_connections 5\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 5 clients" not in ready:
        raise RuntimeError(f"security reload broker failed to start: {ready}")
    listener = process.stdout.readline().strip()
    if not listener.startswith("mqtt "):
        raise RuntimeError(f"security reload listener missing: {listener}")

    def connect(
        client_id: str,
        username: str,
        expected_reason: int,
        will_topic: str | None = None,
        will_payload: bytes = b"",
    ) -> socket.socket:
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.settimeout(5)
        client.sendall(connect_packet(
            client_id,
            username=username,
            password="password",
            will_topic=will_topic,
            will_payload=will_payload,
        ))
        reason = connack_reason(read_mqtt_packet(client))
        if reason != expected_reason:
            client.close()
            raise AssertionError(
                f"security reload {username} expected {expected_reason:#x}, "
                f"received {reason:#x}"
            )
        return client

    def expect_publish_reason(
        client: socket.socket,
        topic: str,
        packet_id: int,
        expected_reason: int,
    ) -> None:
        client.sendall(publish_packet(
            topic, b"reload", qos=1, packet_id=packet_id
        ))
        reason = puback_reason(read_mqtt_packet(client), packet_id)
        if reason != expected_reason:
            raise AssertionError(
                f"security reload publish {topic} expected "
                f"{expected_reason:#x}, received {reason:#x}"
            )

    clients: list[socket.socket] = []
    try:
        old = connect(
            "reload-old-live",
            "old",
            0,
            will_topic="revoked/will",
            will_payload=b"must-not-publish",
        )
        clients.append(old)
        subscriber = connect("reload-stable-subscriber", "stable", 0)
        clients.append(subscriber)
        subscriber.sendall(subscribe_packet(1, "after/#"))
        if read_mqtt_packet(subscriber) != bytes.fromhex("900400010000"):
            raise AssertionError("security reload initial SUBACK mismatch")
        subscriber.sendall(subscribe_packet(2, "revoked/#"))
        if read_mqtt_packet(subscriber) != bytes.fromhex("900400020000"):
            raise AssertionError("security reload Will SUBACK mismatch")
        expect_publish_reason(old, "before/value", 1, 0x10)

        acl_file.write_text(
            "user old\ntopic readwrite after/#\n"
            "topic write revoked/will\n"
            "user stable\ntopic read after/#\n"
            "topic read revoked/#\n"
            "user new\ntopic write after/#\n"
        )
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload completed: source=SIGHUP",
            "successful security reload",
        )
        expect_publish_reason(old, "before/value", 2, 0x87)
        expect_publish_reason(old, "after/value", 3, 0x00)
        if read_mqtt_packet(subscriber) != publish_packet(
            "after/value", b"reload"
        ):
            raise AssertionError(
                "security reload did not update existing subscription ACL"
            )

        password_file.write_text(
            f"stable:{password_hash}\n"
            f"new:{password_hash}\n"
        )
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload completed: source=SIGHUP",
            "successful password reload",
        )
        administrative_disconnect = read_mqtt_packet(old)
        if administrative_disconnect != bytes.fromhex("e00198"):
            raise AssertionError(
                "revoked live credential did not receive MQTT 5 "
                "Administrative Action: " + administrative_disconnect.hex()
            )
        old.close()
        clients.remove(old)
        mqtt_ping(subscriber)
        expect_no_packet(subscriber, "administratively disconnected Will")

        rejected_old = connect("reload-old-rejected", "old", 0x87)
        rejected_old.close()
        new = connect("reload-new", "new", 0)
        clients.append(new)
        expect_publish_reason(new, "after/new", 4, 0x00)
        expected_delivery = publish_packet("after/new", b"reload")
        if read_mqtt_packet(subscriber) != expected_delivery:
            raise AssertionError(
                "security reload did not update existing subscription ACL"
            )

        password_file.write_text(f"third:{password_hash}\n")
        acl_file.write_text("unsupported directive\n")
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload failed: error=InvalidDirective",
            "failed security reload",
        )
        mqtt_ping(new)
        mqtt_ping(subscriber)
        expect_publish_reason(new, "after/still-allowed", 5, 0x00)
        expected_rollback_delivery = publish_packet(
            "after/still-allowed", b"reload"
        )
        if read_mqtt_packet(subscriber) != expected_rollback_delivery:
            raise AssertionError(
                "failed security reload changed existing delivery ACL"
            )

        rejected_third = connect("reload-third-rejected", "third", 0x87)
        rejected_third.close()
        new.sendall(bytes.fromhex("e000"))
        new.close()
        clients.remove(new)
        subscriber.sendall(bytes.fromhex("e000"))
        subscriber.close()
        clients.remove(subscriber)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise RuntimeError("security reload broker did not finish")
    finally:
        for client in clients:
            client.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    if process.returncode != 0:
        raise RuntimeError(
            "security reload broker failed: " + process.stdout.read()
        )


def run_listener_policy_reload_case(broker: Path, directory: Path) -> None:
    first_port = free_port()
    second_port = free_port()
    while second_port == first_port:
        second_port = free_port()
    password_file = directory / "listener-policy-reload.pwfile"
    password_hash = (
        "$7$1000$"
        "h0tqVxBwkB9rKAXukTtffzdbBQtNy1q5FBTDwSW4hucfjpqunBbxW10NVnRk7Cfh0lQndnOv2+k4wJavgz1JNw==$"
        "02ujkUXlKkJGFzlQHNjUgXwG3XRB1mr3vs8NX5teGCJGbN4hdgSpHNHuj47j8r5SHXsO7GeHpmkpPNhLraVVcQ=="
    )
    password_file.write_text(f"stable:{password_hash}\n")
    config = directory / "listener-policy-reload.conf"

    def write_config(
        first_anonymous: bool,
        second_anonymous: bool,
        second_listener_port: int = second_port,
    ) -> None:
        config.write_text(
            "per_listener_settings true\n"
            f"listener {first_port} 127.0.0.1\n"
            f"password_file {password_file}\n"
            f"allow_anonymous {str(first_anonymous).lower()}\n"
            "max_connections 4\n"
            f"listener {second_listener_port} 127.0.0.1\n"
            f"password_file {password_file}\n"
            f"allow_anonymous {str(second_anonymous).lower()}\n"
            "max_connections 4\n"
        )

    def connect(
        port: int,
        client_id: str,
        expected_reason: int,
        username: str | None = None,
        password: str | None = None,
    ) -> socket.socket:
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.settimeout(5)
        client.sendall(
            connect_packet(
                client_id,
                username=username,
                password=password,
            )
        )
        reason = connack_reason(read_mqtt_packet(client))
        if reason != expected_reason:
            client.close()
            raise AssertionError(
                f"listener policy reload {client_id} expected "
                f"{expected_reason:#x}, received {reason:#x}"
            )
        return client

    write_config(True, False)
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 2 listeners for 8 clients" not in ready:
        raise RuntimeError(f"listener policy reload broker failed: {ready}")
    read_listener_lines(process, 2, "listener policy reload startup")

    clients: list[socket.socket] = []
    try:
        existing = connect(first_port, "listener-policy-existing", 0)
        clients.append(existing)
        rejected = connect(second_port, "listener-policy-initial-rejected", 0x87)
        rejected.close()

        write_config(False, True)
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload completed: source=SIGHUP",
            "listener anonymous policy reload",
        )
        mqtt_ping(existing)
        rejected = connect(first_port, "listener-policy-first-rejected", 0x87)
        rejected.close()
        second = connect(second_port, "listener-policy-second-accepted", 0)
        clients.append(second)
        authenticated = connect(
            first_port,
            "listener-policy-authenticated",
            0,
            username="stable",
            password="password",
        )
        clients.append(authenticated)

        invalid_port = free_port()
        while invalid_port in (first_port, second_port):
            invalid_port = free_port()
        write_config(False, False, invalid_port)
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "configuration reload failed: "
            "error=ListenerConfigurationRequiresRestart",
            "listener topology reload rollback",
        )
        rollback = connect(second_port, "listener-policy-rollback", 0)
        clients.append(rollback)
        mqtt_ping(existing)
    finally:
        for client in clients:
            client.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run_server_identity_reload_case(broker: Path, directory: Path) -> None:
    first_ca, first_ca_key = create_ca(
        directory, "identity-reload-first-ca", "Identity Reload First Root"
    )
    first_certificate, first_key = create_signed_certificate(
        directory,
        "identity-reload-first-server",
        "localhost",
        first_ca,
        first_ca_key,
        701,
        "serverAuth",
        "DNS:localhost",
    )
    second_ca, second_ca_key = create_ca(
        directory, "identity-reload-second-ca", "Identity Reload Second Root"
    )
    second_certificate, second_key = create_signed_certificate(
        directory,
        "identity-reload-second-server",
        "localhost",
        second_ca,
        second_ca_key,
        702,
        "serverAuth",
        "DNS:localhost",
    )
    first_key_password = "identity-first-key"
    second_key_password = "identity-second-key"
    first_encrypted_key = directory / "identity-reload-first-encrypted.key"
    second_encrypted_key = directory / "identity-reload-second-encrypted.key"
    run_openssl(
        "pkcs8",
        "-topk8",
        "-in",
        first_key,
        "-out",
        first_encrypted_key,
        "-v2",
        "aes-256-cbc",
        "-iter",
        "10000",
        "-passout",
        f"pass:{first_key_password}",
    )
    run_openssl(
        "pkcs8",
        "-topk8",
        "-in",
        second_key,
        "-out",
        second_encrypted_key,
        "-v2",
        "aes-128-cbc",
        "-v2prf",
        "hmacWithSHA384",
        "-iter",
        "12000",
        "-passout",
        f"pass:{second_key_password}",
    )
    active_certificate = directory / "identity-reload-active.crt"
    active_key = directory / "identity-reload-active.key"
    key_password_file = directory / "identity-reload-key.password"
    active_certificate.write_bytes(first_certificate.read_bytes())
    active_key.write_bytes(first_encrypted_key.read_bytes())
    key_password_file.write_text(first_key_password + "\n")
    password_file = directory / "identity-reload.pwfile"
    password_hash = (
        "$7$1000$"
        "h0tqVxBwkB9rKAXukTtffzdbBQtNy1q5FBTDwSW4hucfjpqunBbxW10NVnRk7Cfh0lQndnOv2+k4wJavgz1JNw==$"
        "02ujkUXlKkJGFzlQHNjUgXwG3XRB1mr3vs8NX5teGCJGbN4hdgSpHNHuj47j8r5SHXsO7GeHpmkpPNhLraVVcQ=="
    )
    password_file.write_text(f"old:{password_hash}\n")

    mqtt_port = free_port()
    websocket_port = free_port()
    while websocket_port == mqtt_port:
        websocket_port = free_port()
    config = directory / "identity-reload.conf"
    config.write_text(
        f"password_file {password_file}\n"
        f"listener {mqtt_port} 127.0.0.1\n"
        f"certfile {active_certificate}\n"
        f"keyfile {active_key}\n"
        f"keyfile_password_file {key_password_file}\n"
        "allow_anonymous false\n"
        "max_connections 16\n"
        f"listener {websocket_port} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {active_certificate}\n"
        f"keyfile {active_key}\n"
        f"keyfile_password_file {key_password_file}\n"
        "allow_anonymous false\n"
        "max_connections 16\n"
    )
    environment = os.environ.copy()
    environment.pop(FINITE_TEST_ENV, None)
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
    )
    assert process.stdout is not None
    wait_process_line(
        process,
        "configured 2 listeners global_max_connections=32",
        "identity reload broker startup",
    )
    listener_lines = read_listener_lines(
        process,
        2,
        "identity reload broker startup",
    )
    if not any(line.startswith("mqtts ") for line in listener_lines):
        raise RuntimeError(f"identity reload MQTT/TLS listener missing: {listener_lines}")
    if not any(line.startswith("wss ") for line in listener_lines):
        raise RuntimeError(f"identity reload WSS listener missing: {listener_lines}")

    def mqtt_connect(
        cafile: Path,
        client_id: str,
        username: str = "old",
        expected_reason: int = 0,
    ) -> ssl.SSLSocket:
        context = ssl.create_default_context(cafile=str(cafile))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        raw = socket.create_connection(("127.0.0.1", mqtt_port), timeout=5)
        raw.settimeout(5)
        try:
            client = context.wrap_socket(raw, server_hostname="localhost")
        except BaseException:
            raw.close()
            raise
        client.sendall(connect_packet(
            client_id,
            username=username,
            password="password",
        ))
        reason = connack_reason(read_mqtt_packet(client))
        if reason != expected_reason:
            client.close()
            raise AssertionError(
                f"identity reload CONNECT for {client_id} expected "
                f"{expected_reason:#x}, received {reason:#x}"
            )
        return client

    def wss_connect(
        cafile: Path,
        client_id: str,
        username: str = "old",
        expected_reason: int = 0,
    ) -> socket.socket:
        client = websocket_connect(websocket_port, cafile)
        send_websocket_binary(client, connect_packet(
            client_id,
            username=username,
            password="password",
        ))
        reason = connack_reason(read_websocket_binary(client))
        if reason != expected_reason:
            client.close()
            raise AssertionError(
                f"identity reload WSS CONNECT for {client_id} expected "
                f"{expected_reason:#x}, received {reason:#x}"
            )
        return client

    def expect_untrusted(connect, label: str) -> None:
        try:
            client = connect()
        except ssl.SSLCertVerificationError:
            return
        client.close()
        raise AssertionError(f"{label}: obsolete CA still trusted a new connection")

    clients: list[socket.socket] = []
    try:
        old_mqtt = mqtt_connect(first_ca, "identity-old-mqtt")
        clients.append(old_mqtt)
        old_wss = wss_connect(first_ca, "identity-old-wss")
        clients.append(old_wss)

        active_certificate.write_bytes(second_certificate.read_bytes())
        active_key.write_bytes(second_encrypted_key.read_bytes())
        key_password_file.write_text(second_key_password + "\n")
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload completed: source=SIGHUP",
            "successful TLS identity reload",
        )
        mqtt_ping(old_mqtt)
        websocket_mqtt_ping(old_wss)

        new_mqtt = mqtt_connect(second_ca, "identity-new-mqtt")
        clients.append(new_mqtt)
        new_wss = wss_connect(second_ca, "identity-new-wss")
        clients.append(new_wss)
        expect_untrusted(
            lambda: mqtt_connect(first_ca, "identity-stale-mqtt"),
            "MQTT/TLS reload",
        )
        expect_untrusted(
            lambda: wss_connect(first_ca, "identity-stale-wss"),
            "WSS reload",
        )

        key_password_file.write_text("wrong-key-password\n")
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload failed: error=InvalidPasswordOrCiphertext",
            "failed encrypted-key password reload",
        )
        password_rollback = mqtt_connect(
            second_ca,
            "identity-password-rollback",
        )
        clients.append(password_rollback)
        key_password_file.write_text(second_key_password + "\n")

        active_certificate.write_text("not a certificate\n")
        password_file.write_text(f"new:{password_hash}\n")
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload failed: error=InvalidPem",
            "failed TLS identity reload",
        )
        rollback_mqtt = mqtt_connect(second_ca, "identity-rollback-mqtt")
        clients.append(rollback_mqtt)
        rollback_wss = wss_connect(second_ca, "identity-rollback-wss")
        clients.append(rollback_wss)
        rejected_new = mqtt_connect(
            second_ca,
            "identity-rollback-new-user",
            username="new",
            expected_reason=0x87,
        )
        rejected_new.close()
        mqtt_ping(old_mqtt)
        websocket_mqtt_ping(old_wss)
    finally:
        for client in clients:
            client.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run_client_ca_reload_case(broker: Path, directory: Path) -> None:
    server_ca, server_ca_key = create_ca(
        directory, "ca-reload-server-ca", "CA Reload Server Root"
    )
    server_certificate, server_key = create_signed_certificate(
        directory,
        "ca-reload-server",
        "localhost",
        server_ca,
        server_ca_key,
        711,
        "serverAuth",
        "DNS:localhost",
    )
    first_ca, first_ca_key = create_ca(
        directory, "ca-reload-first-client-ca", "CA Reload First Client Root"
    )
    first_client, first_key = create_signed_certificate(
        directory,
        "ca-reload-first-client",
        "ca-reload-first-client",
        first_ca,
        first_ca_key,
        712,
        "clientAuth",
    )
    second_ca, second_ca_key = create_ca(
        directory, "ca-reload-second-client-ca", "CA Reload Second Client Root"
    )
    second_client, second_key = create_signed_certificate(
        directory,
        "ca-reload-second-client",
        "ca-reload-second-client",
        second_ca,
        second_ca_key,
        713,
        "clientAuth",
    )
    active_ca = directory / "ca-reload-active-client.crt"
    active_ca.write_bytes(first_ca.read_bytes())
    active_ca_directory = directory / "ca-reload-active-client-dir"
    active_ca_directory.mkdir()
    active_ca_directory_file = active_ca_directory / "client.pem"
    active_ca_directory_file.write_bytes(first_ca.read_bytes())

    mqtt_port = free_port()
    websocket_port = free_port()
    while websocket_port == mqtt_port:
        websocket_port = free_port()
    capath_port = free_port()
    while capath_port in (mqtt_port, websocket_port):
        capath_port = free_port()
    config = directory / "ca-reload.conf"
    config.write_text(
        f"listener {mqtt_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {active_ca}\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 16\n"
        f"listener {capath_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"capath {active_ca_directory}\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 16\n"
        f"listener {websocket_port} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {active_ca}\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 16\n"
    )
    environment = os.environ.copy()
    environment.pop(FINITE_TEST_ENV, None)
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
    )
    assert process.stdout is not None
    wait_process_line(
        process,
        "configured 3 listeners global_max_connections=48",
        "client CA reload broker startup",
    )
    listener_lines = read_listener_lines(
        process,
        3,
        "client CA reload broker startup",
    )
    if sum(line.startswith("mqtts ") for line in listener_lines) != 2:
        raise RuntimeError(f"client CA reload MQTT/TLS listener missing: {listener_lines}")
    if not any(line.startswith("wss ") for line in listener_lines):
        raise RuntimeError(f"client CA reload WSS listener missing: {listener_lines}")

    def mqtt_connect(
        port: int,
        certificate: Path,
        key: Path,
        client_id: str,
    ) -> ssl.SSLSocket:
        client = mqtt_tls_socket(
            port,
            server_ca,
            certificate,
            key,
        )
        client.sendall(connect_packet(client_id))
        if connack_reason(read_mqtt_packet(client)) != 0:
            client.close()
            raise AssertionError(f"client CA reload CONNECT failed for {client_id}")
        return client

    def wss_connect(
        certificate: Path,
        key: Path,
        client_id: str,
    ) -> socket.socket:
        client = websocket_connect(
            websocket_port,
            server_ca,
            certificate,
            key,
        )
        send_websocket_binary(client, connect_packet(client_id))
        if connack_reason(read_websocket_binary(client)) != 0:
            client.close()
            raise AssertionError(f"client CA reload WSS CONNECT failed for {client_id}")
        return client

    def expect_mqtt_rejected(certificate: Path, key: Path, label: str) -> None:
        result = openssl_mqtt_client(
            mqtt_port,
            server_ca,
            certificate,
            key,
        )
        if result.stdout.startswith(b"\x20"):
            raise AssertionError(f"{label}: untrusted MQTT client received CONNACK")

    def expect_capath_rejected(certificate: Path, key: Path, label: str) -> None:
        result = openssl_mqtt_client(
            capath_port,
            server_ca,
            certificate,
            key,
        )
        if result.stdout.startswith(b"\x20"):
            raise AssertionError(f"{label}: untrusted capath client received CONNACK")

    def expect_wss_rejected(certificate: Path, key: Path, label: str) -> None:
        try:
            client = wss_connect(certificate, key, f"{label}-wss")
        except (ssl.SSLError, ConnectionError, AssertionError):
            return
        client.close()
        raise AssertionError(f"{label}: untrusted WSS client received CONNACK")

    clients: list[socket.socket] = []
    try:
        old_mqtt = mqtt_connect(
            mqtt_port,
            first_client,
            first_key,
            "ca-reload-old-mqtt",
        )
        clients.append(old_mqtt)
        old_capath = mqtt_connect(
            capath_port,
            first_client,
            first_key,
            "ca-reload-old-capath",
        )
        clients.append(old_capath)
        old_wss = wss_connect(first_client, first_key, "ca-reload-old-wss")
        clients.append(old_wss)
        expect_mqtt_rejected(second_client, second_key, "initial second CA")
        expect_capath_rejected(second_client, second_key, "initial second CA")
        expect_wss_rejected(second_client, second_key, "initial-second-ca")

        active_ca.write_bytes(second_ca.read_bytes())
        active_ca_directory_file.write_bytes(second_ca.read_bytes())
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload completed: source=SIGHUP",
            "successful client CA reload",
        )
        mqtt_ping(old_mqtt)
        mqtt_ping(old_capath)
        websocket_mqtt_ping(old_wss)
        new_mqtt = mqtt_connect(
            mqtt_port,
            second_client,
            second_key,
            "ca-reload-new-mqtt",
        )
        clients.append(new_mqtt)
        new_capath = mqtt_connect(
            capath_port,
            second_client,
            second_key,
            "ca-reload-new-capath",
        )
        clients.append(new_capath)
        new_wss = wss_connect(
            second_client,
            second_key,
            "ca-reload-new-wss",
        )
        clients.append(new_wss)
        expect_mqtt_rejected(first_client, first_key, "retired first CA")
        expect_capath_rejected(first_client, first_key, "retired first CA")
        expect_wss_rejected(first_client, first_key, "retired-first-ca")
        diagnostics = openssl_certificate_request_diagnostics(
            mqtt_port,
            server_ca,
            second_client,
            second_key,
        )
        if (
            "CN=CA Reload Second Client Root" not in diagnostics
            or "CN=CA Reload First Client Root" in diagnostics
        ):
            raise AssertionError(
                "reloaded CertificateRequest CA names are stale: " + diagnostics
            )

        active_ca.write_text("not a certificate\n")
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload failed: error=InvalidPem",
            "failed client CA reload",
        )
        rollback_mqtt = mqtt_connect(
            mqtt_port,
            second_client,
            second_key,
            "ca-reload-rollback-mqtt",
        )
        clients.append(rollback_mqtt)
        rollback_capath = mqtt_connect(
            capath_port,
            second_client,
            second_key,
            "ca-reload-rollback-capath",
        )
        clients.append(rollback_capath)
        rollback_wss = wss_connect(
            second_client,
            second_key,
            "ca-reload-rollback-wss",
        )
        clients.append(rollback_wss)
    finally:
        for client in clients:
            client.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run_crl_reload_case(broker: Path, directory: Path) -> None:
    server_ca, server_ca_key = create_ca(
        directory, "reload-server-ca", "Reload Server Root"
    )
    server_certificate, server_key = create_signed_certificate(
        directory,
        "reload-mtls-server",
        "localhost",
        server_ca,
        server_ca_key,
        501,
        "serverAuth",
        "DNS:localhost",
    )
    client_ca, client_ca_key = create_ca(
        directory, "reload-client-ca", "Reload Client Root"
    )
    first_client, first_key = create_signed_certificate(
        directory,
        "reload-first-client",
        "reload-first-client",
        client_ca,
        client_ca_key,
        601,
        "clientAuth",
    )
    second_client, second_key = create_signed_certificate(
        directory,
        "reload-second-client",
        "reload-second-client",
        client_ca,
        client_ca_key,
        602,
        "clientAuth",
    )
    active_crl = create_crl(
        directory,
        "reload-active",
        client_ca,
        client_ca_key,
        second_client,
    )
    replacement_crl = create_crl(
        directory,
        "reload-replacement",
        client_ca,
        client_ca_key,
        first_client,
    )
    tampered_crl = directory / "reload-tampered.crl"
    tamper_pem_crl(replacement_crl, tampered_crl)

    port = free_port()
    config = directory / "crl-reload.conf"
    config.write_text(
        f"listener {port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {client_ca}\n"
        f"crlfile {active_crl}\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 8\n"
    )
    environment = os.environ.copy()
    environment.pop(FINITE_TEST_ENV, None)
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners global_max_connections=8" not in ready:
        raise RuntimeError(f"CRL reload broker failed to start: {ready}")
    listener = process.stdout.readline().strip()
    if not listener.startswith("mqtts "):
        raise RuntimeError(f"CRL reload listener missing: {listener}")

    def expect_client(
        certificate: Path,
        key: Path,
        accepted: bool,
        label: str,
    ) -> None:
        result = openssl_mqtt_client(
            port, server_ca, certificate, key
        )
        received_connack = result.stdout.startswith(b"\x20")
        if accepted:
            assert_openssl_mqtt_success(result)
        elif received_connack:
            raise AssertionError(
                f"{label}: revoked client received MQTT CONNACK; "
                + result.stderr.decode(errors="replace")
            )

    try:
        expect_client(first_client, first_key, True, "initial first client")
        expect_client(second_client, second_key, False, "initial second client")

        active_crl.write_bytes(replacement_crl.read_bytes())
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload completed: source=SIGHUP",
            "successful CRL reload",
        )
        expect_client(first_client, first_key, False, "reloaded first client")
        expect_client(second_client, second_key, True, "reloaded second client")

        active_crl.write_bytes(tampered_crl.read_bytes())
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "security reload failed: error=InvalidCrl",
            "failed CRL reload",
        )
        expect_client(
            first_client, first_key, False, "rollback first client"
        )
        expect_client(
            second_client, second_key, True, "rollback second client"
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


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


def run_disabled_autosave_case(broker: Path, directory: Path) -> None:
    for autosave_on_changes in (False, True):
        mode = "changes" if autosave_on_changes else "time"
        port = free_port()
        snapshot = directory / f"disabled-autosave-{mode}.db"
        config = directory / f"disabled-autosave-{mode}.conf"
        topic = f"persistence/disabled-autosave/{mode}"
        payload = f"saved-on-exit-{mode}".encode()
        config.write_text(
            "persistence true\n"
            f"persistence_location {directory}\n"
            f"persistence_file {snapshot.name}\n"
            "autosave_interval 0\n"
            f"autosave_on_changes {str(autosave_on_changes).lower()}\n"
            f"listener {port} 127.0.0.1\n"
            "allow_anonymous true\n"
            "max_connections 1\n"
        )

        def start(pass_name: str) -> subprocess.Popen[str]:
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
                    f"disabled {mode} autosave {pass_name} failed: {ready}"
                )
            listener = process.stdout.readline().strip()
            if not listener.startswith("mqtt "):
                raise RuntimeError(
                    f"disabled {mode} autosave listener missing: {listener}"
                )
            return process

        initial = start("initial broker")
        publisher = socket.create_connection(("127.0.0.1", port), timeout=5)
        publisher.settimeout(5)
        try:
            publisher.sendall(connect_packet(f"disabled-autosave-{mode}"))
            if connack_reason(read_mqtt_packet(publisher)) != 0:
                raise AssertionError(
                    f"disabled {mode} autosave CONNECT failed"
                )
            publisher.sendall(
                publish_packet(topic, payload, retain=True)
            )
            mqtt_ping(publisher)
            if snapshot.exists():
                raise AssertionError(
                    f"disabled {mode} autosave wrote before shutdown"
                )
            os.kill(initial.pid, signal.SIGUSR1)
            deadline = time.monotonic() + 5
            checkpoint_complete = False
            while time.monotonic() < deadline:
                remaining = max(0.0, deadline - time.monotonic())
                readable, _, _ = select.select(
                    [initial.stdout], [], [], remaining
                )
                if not readable:
                    break
                line = initial.stdout.readline().strip()
                if (
                    "persistence checkpoint completed: source=SIGUSR1"
                    in line
                ):
                    checkpoint_complete = True
                    break
                if initial.poll() is not None:
                    break
            if not checkpoint_complete:
                raise AssertionError(
                    f"disabled {mode} autosave ignored SIGUSR1: "
                    + initial.stdout.read()
                )
            if not snapshot.is_file() or snapshot.stat().st_size == 0:
                raise AssertionError(
                    f"disabled {mode} SIGUSR1 checkpoint was empty"
                )
            initial.kill()
            initial.wait(timeout=5)
        finally:
            publisher.close()
            if initial.poll() is None:
                initial.kill()
                initial.wait()

        restored = start("restored broker")
        subscriber = socket.create_connection(("127.0.0.1", port), timeout=5)
        subscriber.settimeout(5)
        try:
            subscriber.sendall(
                connect_packet(f"disabled-autosave-restored-{mode}")
            )
            if connack_reason(read_mqtt_packet(subscriber)) != 0:
                raise AssertionError(
                    f"disabled {mode} autosave restore CONNECT failed"
                )
            subscriber.sendall(subscribe_packet(1, topic))
            if read_mqtt_packet(subscriber) != bytes.fromhex("900400010000"):
                raise AssertionError(
                    f"disabled {mode} autosave restore SUBACK mismatch"
                )
            expected = publish_packet(topic, payload, retain=True)
            if read_mqtt_packet(subscriber) != expected:
                raise AssertionError(
                    f"disabled {mode} autosave did not restore retained state"
                )
            subscriber.sendall(bytes.fromhex("e000"))
        finally:
            subscriber.close()
        if restored.wait(timeout=5) != 0:
            raise RuntimeError(
                f"disabled {mode} autosave restored broker failed: "
                + restored.stdout.read()
            )


def run_autosave_reload_case(broker: Path, directory: Path) -> None:
    port = free_port()
    snapshot = directory / "autosave-reload.db"
    rejected_snapshot = directory / "autosave-reload-rejected.db"
    config = directory / "autosave-reload.conf"
    retained_topic = "persistence/autosave-reload/disabled"
    retained_payload = b"reload-debt"

    def write_config(
        interval: int,
        on_changes: bool,
        persistence_file: str = snapshot.name,
        max_connections: int = 4,
    ) -> None:
        config.write_text(
            "persistence true\n"
            f"persistence_location {directory}\n"
            f"persistence_file {persistence_file}\n"
            f"autosave_interval {interval}\n"
            f"autosave_on_changes {str(on_changes).lower()}\n"
            f"listener {port} 127.0.0.1\n"
            "allow_anonymous true\n"
            f"max_connections {max_connections}\n"
        )

    def wait_snapshot(path: Path, label: str, timeout: float = 5) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.is_file() and path.stat().st_size != 0:
                return
            time.sleep(0.02)
        raise AssertionError(f"{label}: snapshot was not written")

    def expect_no_snapshot(path: Path, label: str) -> None:
        time.sleep(1.3)
        if path.exists():
            raise AssertionError(f"{label}: unexpected snapshot {path}")

    def publish_retained(client: socket.socket, topic: str, payload: bytes) -> None:
        client.sendall(publish_packet(topic, payload, retain=True))
        mqtt_ping(client)

    write_config(0, False)
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 4 clients" not in ready:
        raise RuntimeError(f"autosave reload broker failed to start: {ready}")
    listener = process.stdout.readline().strip()
    if not listener.startswith("mqtt "):
        raise RuntimeError(f"autosave reload listener missing: {listener}")

    publisher = socket.create_connection(("127.0.0.1", port), timeout=5)
    publisher.settimeout(5)
    try:
        publisher.sendall(connect_packet("autosave-reload-publisher"))
        if connack_reason(read_mqtt_packet(publisher)) != 0:
            raise AssertionError("autosave reload publisher CONNECT failed")
        publish_retained(
            publisher,
            "persistence/autosave-reload/baseline",
            b"baseline",
        )
        expect_no_snapshot(snapshot, "initial disabled policy")

        write_config(1, True)
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "persistence autosave reload completed: mode=changes interval=1",
            "change-count autosave reload",
        )
        publish_retained(
            publisher,
            "persistence/autosave-reload/changes",
            b"changes",
        )
        wait_snapshot(snapshot, "change-count autosave")

        snapshot.unlink()
        write_config(1, False)
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "persistence autosave reload completed: mode=time interval=1",
            "periodic autosave reload",
        )
        wait_snapshot(snapshot, "periodic autosave", timeout=3)

        snapshot.unlink()
        write_config(0, False)
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "persistence autosave reload completed: mode=disabled interval=0",
            "disabled autosave reload",
        )
        publish_retained(publisher, retained_topic, retained_payload)
        expect_no_snapshot(snapshot, "reloaded disabled policy")

        write_config(1, True, rejected_snapshot.name)
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "persistence reload failed: "
            "error=PersistenceConfigurationRequiresRestart",
            "non-reloadable persistence target",
        )
        expect_no_snapshot(snapshot, "failed reload rollback")
        if rejected_snapshot.exists():
            raise AssertionError("failed reload wrote the rejected target")

        write_config(1, True)
        os.kill(process.pid, signal.SIGHUP)
        wait_process_line(
            process,
            "persistence autosave reload completed: mode=changes interval=1",
            "restored change-count policy",
        )
        wait_snapshot(snapshot, "change debt after policy restore")
        mqtt_ping(publisher)
    finally:
        publisher.close()
        if process.poll() is None:
            process.kill()
        process.wait()

    write_config(0, False, max_connections=1)
    restored = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert restored.stdout is not None
    ready = restored.stdout.readline().strip()
    if "configured 1 listeners for 1 clients" not in ready:
        raise RuntimeError(f"autosave reload restore failed: {ready}")
    listener = restored.stdout.readline().strip()
    if not listener.startswith("mqtt "):
        raise RuntimeError(f"autosave reload restore listener missing: {listener}")
    subscriber = socket.create_connection(("127.0.0.1", port), timeout=5)
    subscriber.settimeout(5)
    try:
        subscriber.sendall(connect_packet("autosave-reload-restored"))
        if connack_reason(read_mqtt_packet(subscriber)) != 0:
            raise AssertionError("autosave reload restore CONNECT failed")
        subscriber.sendall(subscribe_packet(1, retained_topic))
        if read_mqtt_packet(subscriber) != bytes.fromhex("900400010000"):
            raise AssertionError("autosave reload restore SUBACK mismatch")
        expected = publish_packet(retained_topic, retained_payload, retain=True)
        if read_mqtt_packet(subscriber) != expected:
            raise AssertionError("autosave reload did not restore retained state")
        subscriber.sendall(bytes.fromhex("e000"))
    finally:
        subscriber.close()
    if restored.wait(timeout=5) != 0:
        raise RuntimeError(
            "autosave reload restored broker failed: " + restored.stdout.read()
        )


def run_retain_source_case(broker: Path, directory: Path) -> None:
    for proto_ver in (5, 4):
        for per_listener in (False, True):
            for username in (None, "writer"):
                run_retain_source_scope_case(
                    broker, directory, proto_ver, per_listener, username
                )


def run_retain_source_scope_case(
    broker: Path,
    directory: Path,
    proto_ver: int,
    per_listener: bool,
    username: str | None,
) -> None:
    scope = "listener" if per_listener else "global"
    identity = "anonymous" if username is None else "named"
    source_port = free_port()
    reader_port = free_port()
    while reader_port == source_port:
        reader_port = free_port()
    snapshot = directory / f"retain-source-{scope}-{identity}-{proto_ver}.db"
    source_acl = directory / f"retain-source-{scope}-{identity}-{proto_ver}.acl"
    reader_acl = directory / f"retain-reader-{scope}-{identity}-{proto_ver}.acl"
    config = directory / f"retain-source-{scope}-{identity}-{proto_ver}.conf"
    topic = f"retain/source/{scope}/{identity}/{proto_ver}"
    payload = b"persisted retained source"
    reader_acl.write_text(f"topic read {topic}\n")

    def write_acl(write_allowed: bool) -> None:
        source_acl.write_text(
            ("" if per_listener or username is None else f"topic read {topic}\n")
            + ("" if username is None else f"user {username}\n")
            + f"topic {'readwrite' if write_allowed else 'read'} {topic}\n"
        )

    def write_config(check_source: bool | None) -> None:
        check = (
            ""
            if check_source is None
            else f"check_retain_source {'true' if check_source else 'false'}\n"
        )
        config.write_text(
            ("per_listener_settings true\n" if per_listener else "")
            + check
            + (f"acl_file {source_acl}\n" if not per_listener else "")
            + "persistence true\n"
            + f"persistence_location {directory}\n"
            + f"persistence_file {snapshot.name}\n"
            + f"listener {source_port} 127.0.0.1\n"
            + (f"acl_file {source_acl}\n" if per_listener else "")
            + "allow_anonymous true\n"
            + "max_connections 1\n"
            + f"listener {reader_port} 127.0.0.1\n"
            + "protocol websockets\n"
            + (f"acl_file {reader_acl}\n" if per_listener else "")
            + "allow_anonymous true\n"
            + "max_connections 1\n"
        )

    def start(label: str) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            [str(broker), f"--config={config}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert process.stdout is not None
        ready = process.stdout.readline().strip()
        if "configured 2 listeners for 2 clients" not in ready:
            raise RuntimeError(f"{label} broker failed: {ready}")
        return process

    def connect_source(client_id: str) -> socket.socket:
        client = socket.create_connection(
            ("127.0.0.1", source_port), timeout=5
        )
        client.settimeout(5)
        client.sendall(
            connect_packet(
                client_id, username=username, proto_ver=proto_ver
            )
        )
        if connack_reason(read_mqtt_packet(client)) != 0:
            client.close()
            raise AssertionError("retained-source publisher CONNECT failed")
        return client

    def connect_reader(client_id: str) -> socket.socket:
        client = websocket_connect(reader_port)
        send_websocket_binary(
            client, connect_packet(
                client_id,
                username=None if per_listener else username,
                proto_ver=proto_ver,
            )
        )
        if connack_reason(read_websocket_binary(client)) != 0:
            client.close()
            raise AssertionError("retained-source reader CONNECT failed")
        return client

    write_acl(True)
    write_config(None)
    initial_process = start("retained-source initial")
    publisher = connect_source(f"retain-source-writer-{scope}-{proto_ver}")
    reader = connect_reader(f"retain-source-reader-{scope}-{proto_ver}")
    try:
        publisher.sendall(
            publish_packet(topic, payload, proto_ver=proto_ver, retain=True)
        )
        mqtt_ping(publisher)
        send_websocket_binary(
            reader, subscribe_packet(1, topic, proto_ver=proto_ver)
        )
        expected_suback = bytes.fromhex(
            "900400010000" if proto_ver == 5 else "9003000100"
        )
        if read_websocket_binary(reader) != expected_suback:
            raise AssertionError("retained-source initial SUBACK mismatch")
        expected_publish = publish_packet(
            topic, payload, proto_ver=proto_ver, retain=True
        )
        if read_websocket_binary(reader) != expected_publish:
            raise AssertionError("initial retained replay mismatch")
        publisher.sendall(bytes.fromhex("e000"))
        send_websocket_binary(reader, bytes.fromhex("e000"))
    finally:
        publisher.close()
        reader.close()
    if initial_process.wait(timeout=5) != 0:
        raise RuntimeError(
            "retained-source initial broker failed: "
            + initial_process.stdout.read()
        )
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError("retained-source snapshot was not written")

    write_config(None)
    restored_process = start("retained-source restored")
    source_probe = connect_source(f"retain-source-restored-probe-{scope}-{proto_ver}")
    restored = connect_reader(f"retain-source-restored-{scope}-{proto_ver}")
    try:
        source_probe.sendall(bytes.fromhex("e000"))
        send_websocket_binary(
            restored, subscribe_packet(2, topic, proto_ver=proto_ver)
        )
        expected_suback = bytes.fromhex(
            "900400020000" if proto_ver == 5 else "9003000200"
        )
        if read_websocket_binary(restored) != expected_suback:
            raise AssertionError("retained-source restored SUBACK mismatch")
        expected_publish = publish_packet(
            topic, payload, proto_ver=proto_ver, retain=True
        )
        if read_websocket_binary(restored) != expected_publish:
            raise AssertionError("restored retained source identity mismatch")
        send_websocket_binary(restored, bytes.fromhex("e000"))
    finally:
        source_probe.close()
        restored.close()
    if restored_process.wait(timeout=5) != 0:
        raise RuntimeError(
            "retained-source restored broker failed: "
            + restored_process.stdout.read()
        )

    write_acl(False)
    write_config(None)
    checked_process = start("retained-source checked")
    source_probe = connect_source(f"retain-source-probe-{scope}-{proto_ver}")
    checked = connect_reader(f"retain-source-checked-{scope}-{proto_ver}")
    try:
        source_probe.sendall(bytes.fromhex("e000"))
        send_websocket_binary(
            checked, subscribe_packet(2, topic, proto_ver=proto_ver)
        )
        expected_suback = bytes.fromhex(
            "900400020000" if proto_ver == 5 else "9003000200"
        )
        if read_websocket_binary(checked) != expected_suback:
            raise AssertionError("retained-source checked SUBACK mismatch")
        websocket_mqtt_ping(checked)
        send_websocket_binary(checked, bytes.fromhex("e000"))
    finally:
        source_probe.close()
        checked.close()
    if checked_process.wait(timeout=5) != 0:
        raise RuntimeError(
            "retained-source checked broker failed: "
            + checked_process.stdout.read()
        )

    write_config(False)
    unchecked_process = start("retained-source unchecked")
    source_probe = connect_source(
        f"retain-source-unchecked-probe-{scope}-{proto_ver}"
    )
    unchecked = connect_reader(f"retain-source-unchecked-{scope}-{proto_ver}")
    try:
        source_probe.sendall(bytes.fromhex("e000"))
        send_websocket_binary(
            unchecked, subscribe_packet(3, topic, proto_ver=proto_ver)
        )
        expected_suback = bytes.fromhex(
            "900400030000" if proto_ver == 5 else "9003000300"
        )
        if read_websocket_binary(unchecked) != expected_suback:
            raise AssertionError("retained-source unchecked SUBACK mismatch")
        expected_publish = publish_packet(
            topic, payload, proto_ver=proto_ver, retain=True
        )
        if read_websocket_binary(unchecked) != expected_publish:
            raise AssertionError("disabled source check suppressed replay")
        send_websocket_binary(unchecked, bytes.fromhex("e000"))
    finally:
        source_probe.close()
        unchecked.close()
    if unchecked_process.wait(timeout=5) != 0:
        raise RuntimeError(
            "retained-source unchecked broker failed: "
            + unchecked_process.stdout.read()
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
        "set_tcp_nodelay true\n"
        f"listener {tls_port} 127.0.0.1\n"
        "socket_domain ipv4\n"
        "bind_interface lo\n"
        f"certfile {certificate}\n"
        f"keyfile {private_key}\n"
        "ciphers_tls1.3 TLS_AES_256_GCM_SHA384\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {wss_port} 127.0.0.1\n"
        "socket_domain ipv4\n"
        "bind_interface lo\n"
        "protocol websockets\n"
        "websockets_origin https://secure.example\n"
        f"certfile {certificate}\n"
        f"keyfile {private_key}\n"
        "ciphers_tls1.3 TLS_AES_256_GCM_SHA384\n"
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
                "-ciphersuites",
                "TLS_AES_256_GCM_SHA384",
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

        websocket = websocket_connect(
            wss_port,
            certificate,
            origin="https://secure.example",
        )
        clients.append(websocket)
        if websocket.cipher()[0] != "TLS_AES_256_GCM_SHA384":
            raise AssertionError(
                "configured WSS TLS 1.3 cipher mismatch: "
                f"got {websocket.cipher()[0]}"
            )
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


def run_modern_tls_identity_case(broker: Path, directory: Path) -> None:
    cases = (
        ("p384", "EC", "P-384", "ecdsa_secp384r1_sha384"),
        ("p521", "EC", "P-521", "ecdsa_secp521r1_sha512"),
        ("ed25519", "ED25519", None, "ed25519"),
    )
    for name, algorithm, curve, signature_algorithm in cases:
        certificate = directory / f"{name}-server-cert.pem"
        private_key = directory / f"{name}-server-key.pem"
        key_command = ["genpkey", "-algorithm", algorithm]
        if curve is not None:
            key_command.extend(("-pkeyopt", f"ec_paramgen_curve:{curve}"))
        key_command.extend(("-out", str(private_key)))
        run_openssl(*key_command)
        websocket_private_key = private_key
        if algorithm == "EC":
            websocket_private_key = directory / f"{name}-server-sec1-key.pem"
            run_openssl(
                "pkey",
                "-in",
                private_key,
                "-traditional",
                "-out",
                websocket_private_key,
            )
        run_openssl(
            "req",
            "-new",
            "-x509",
            "-key",
            private_key,
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-out",
            certificate,
        )
        port = free_port()
        websocket_port = free_port()
        while websocket_port == port:
            websocket_port = free_port()
        config = directory / f"{name}-server.conf"
        config.write_text(
            f"listener {port} 127.0.0.1\n"
            f"certfile {certificate}\n"
            f"keyfile {private_key}\n"
            "allow_anonymous true\n"
            "max_connections 1\n"
            f"listener {websocket_port} 127.0.0.1\n"
            "protocol websockets\n"
            f"certfile {certificate}\n"
            f"keyfile {websocket_private_key}\n"
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
        startup_lines: list[str] = []
        while True:
            line = process.stdout.readline()
            if line == "":
                raise RuntimeError(
                    f"{name} TLS broker failed to start: "
                    + "".join(startup_lines)
                )
            startup_lines.append(line)
            if "configured 2 listeners for 2 clients" in line:
                break
        result = openssl_mqtt_client(
            port,
            certificate,
            signature_algorithms=signature_algorithm,
        )
        assert_openssl_mqtt_success(result)
        websocket = websocket_connect(websocket_port, certificate)
        try:
            send_websocket_binary(
                websocket,
                connect_packet(f"{name}-wss"),
            )
            if connack_reason(read_websocket_binary(websocket)) != 0:
                raise AssertionError(f"{name} WSS CONNECT failed")
            send_websocket_binary(websocket, bytes.fromhex("e000"))
        finally:
            websocket.close()
        if process.wait(timeout=5) != 0:
            raise RuntimeError(
                f"{name} TLS broker failed: " + process.stdout.read()
            )

    mismatch_port = free_port()
    mismatch_config = directory / "modern-server-mismatch.conf"
    mismatch_config.write_text(
        f"listener {mismatch_port} 127.0.0.1\n"
        f"certfile {directory / 'p384-server-cert.pem'}\n"
        f"keyfile {directory / 'ed25519-server-key.pem'}\n"
        "allow_anonymous true\n"
    )
    mismatch_result = subprocess.run(
        [str(broker), f"--config={mismatch_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if (
        mismatch_result.returncode == 0
        or "CertificateKeyMismatch" not in mismatch_result.stdout
    ):
        raise AssertionError(
            "cross-algorithm certificate/key mismatch was accepted: "
            + mismatch_result.stdout
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", mismatch_port)) == 0:
            raise AssertionError(
                "listener bound before modern identity mismatch validation"
            )


def run_openssl(*arguments: object) -> None:
    subprocess.run(
        ["openssl", *(str(argument) for argument in arguments)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=True,
    )


def signature_digest_arguments(algorithm: str) -> tuple[str, ...]:
    if algorithm == "ed25519":
        return ()
    if algorithm == "p384":
        return ("-sha384",)
    return ("-sha256",)


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
    elif algorithm == "p384":
        run_openssl(
            "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key
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
    elif algorithm == "ed25519":
        run_openssl("genpkey", "-algorithm", "ED25519", "-out", key)
    else:
        raise AssertionError(f"unsupported CA algorithm {algorithm}")
    run_openssl(
        "req",
        "-new",
        "-x509",
        "-key",
        key,
        *signature_digest_arguments(algorithm),
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
    ca_key_algorithm: str = "ec",
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
    elif key_algorithm == "p384":
        run_openssl(
            "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key
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
    elif key_algorithm == "ed25519":
        run_openssl("genpkey", "-algorithm", "ED25519", "-out", key)
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
        *signature_digest_arguments(ca_key_algorithm),
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
    ca_key_algorithm: str = "ec",
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
        f"default_md = {
            'default' if ca_key_algorithm == 'ed25519'
            else 'sha384' if ca_key_algorithm == 'p384'
            else 'sha256'
        }\n"
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
    signature_algorithms: str | None = None,
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
    if signature_algorithms is not None:
        command.extend(("-sigalgs", signature_algorithms))
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


def run_capath_listener_case(broker: Path, directory: Path) -> None:
    server_ca, server_ca_key = create_ca(
        directory, "capath-server-ca", "Capath Server Root"
    )
    server_certificate, server_key = create_signed_certificate(
        directory,
        "capath-server",
        "localhost",
        server_ca,
        server_ca_key,
        701,
        "serverAuth",
        "DNS:localhost",
    )
    first_ca, first_ca_key = create_ca(
        directory, "capath-client-a-ca", "Capath Client Root A"
    )
    second_ca, second_ca_key = create_ca(
        directory, "capath-client-b-ca", "Capath Client Root B"
    )
    first_certificate, first_key = create_signed_certificate(
        directory,
        "capath-client-a",
        "capath-client-a",
        first_ca,
        first_ca_key,
        702,
        "clientAuth",
    )
    second_certificate, second_key = create_signed_certificate(
        directory,
        "capath-client-b",
        "capath-client-b",
        second_ca,
        second_ca_key,
        703,
        "clientAuth",
    )
    wrong_ca, wrong_ca_key = create_ca(
        directory, "capath-wrong-ca", "Capath Wrong Root"
    )
    wrong_certificate, wrong_key = create_signed_certificate(
        directory,
        "capath-wrong-client",
        "capath-wrong-client",
        wrong_ca,
        wrong_ca_key,
        704,
        "clientAuth",
    )

    ca_directory = directory / "trusted-client-capath"
    ca_directory.mkdir()
    (ca_directory / "a.pem").write_bytes(first_ca.read_bytes())
    (ca_directory / "b.pem").write_bytes(second_ca.read_bytes())
    run_openssl("rehash", ca_directory)
    if not any(entry.is_symlink() for entry in ca_directory.iterdir()):
        raise AssertionError("openssl rehash did not create capath links")

    port = free_port()
    config = directory / "capath.conf"
    config.write_text(
        f"listener {port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"capath {ca_directory}\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 3\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    startup_lines: list[str] = []
    while True:
        line = process.stdout.readline()
        if line == "":
            raise RuntimeError(
                "capath broker failed to start: " + "".join(startup_lines)
            )
        startup_lines.append(line)
        if "configured 1 listeners for 3 clients" in line:
            break
    for certificate, key in (
        (first_certificate, first_key),
        (second_certificate, second_key),
    ):
        result = openssl_mqtt_client(port, server_ca, certificate, key)
        assert_openssl_mqtt_success(result)
    rejected = openssl_mqtt_client(
        port, server_ca, wrong_certificate, wrong_key
    )
    if rejected.stdout.startswith(b"\x20"):
        raise AssertionError("capath accepted an untrusted client certificate")
    if process.wait(timeout=5) == 0:
        raise AssertionError("capath untrusted-client failure was not reported")
    if "CertificateUntrusted" not in process.stdout.read():
        raise AssertionError("capath rejection omitted CertificateUntrusted")

    websocket_config = directory / "capath-websocket.conf"
    websocket_config.write_text(
        f"listener {free_port()} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"capath {ca_directory}\n"
        "allow_anonymous true\n"
    )
    websocket_result = subprocess.run(
        [str(broker), f"--config={websocket_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if (
        websocket_result.returncode == 0
        or "CapathUnsupportedForWebSockets" not in websocket_result.stdout
    ):
        raise AssertionError(
            "WebSocket capath was not rejected explicitly: "
            + websocket_result.stdout
        )

    first_port = free_port()
    invalid_directory = directory / "invalid-client-capath"
    invalid_directory.mkdir()
    (invalid_directory / "broken.pem").write_text("not a certificate\n")
    invalid_config = directory / "invalid-capath.conf"
    invalid_config.write_text(
        f"listener {first_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {free_port()} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"capath {invalid_directory}\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    invalid_result = subprocess.run(
        [str(broker), f"--config={invalid_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if invalid_result.returncode == 0 or "InvalidPem" not in invalid_result.stdout:
        raise AssertionError(
            "malformed later capath did not fail before listen: "
            + invalid_result.stdout
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", first_port)) == 0:
            raise AssertionError(
                "an earlier listener was bound before capath validation"
            )


def run_signed_crl_listener_case(
    broker: Path,
    directory: Path,
    algorithm: str,
) -> None:
    if algorithm not in ("rsa", "p384", "ed25519"):
        raise AssertionError(f"unsupported CRL fixture algorithm {algorithm}")
    server_ca = directory / "server-ca.crt"
    server_certificate = directory / "mtls-server.crt"
    server_key = directory / "mtls-server.key"
    label = {
        "rsa": "RSA",
        "p384": "P-384",
        "ed25519": "Ed25519",
    }[algorithm]
    fixture_name = algorithm.replace("_", "-")
    client_ca, client_ca_key = create_ca(
        directory,
        f"{fixture_name}-client-ca",
        f"{label} Client Root",
        algorithm,
    )
    client, client_key = create_signed_certificate(
        directory,
        f"{fixture_name}-client",
        f"{fixture_name}-client",
        client_ca,
        client_ca_key,
        401,
        "clientAuth",
        key_algorithm=algorithm,
        ca_key_algorithm=algorithm,
    )
    revoked, revoked_key = create_signed_certificate(
        directory,
        f"{fixture_name}-revoked-client",
        f"{fixture_name}-revoked-client",
        client_ca,
        client_ca_key,
        402,
        "clientAuth",
        key_algorithm=algorithm,
        ca_key_algorithm=algorithm,
    )
    crl = create_crl(
        directory,
        f"{fixture_name}-client-revocations",
        client_ca,
        client_ca_key,
        revoked,
        ca_key_algorithm=algorithm,
    )

    port = free_port()
    config = directory / f"{fixture_name}-crl.conf"
    write_mtls_config(
        config,
        port,
        server_certificate,
        server_key,
        client_ca,
        crlfile=crl,
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
        raise RuntimeError(f"{label} CRL broker failed to start: {ready}")
    assert_openssl_mqtt_success(
        openssl_mqtt_client(
            port,
            server_ca,
            client,
            client_key,
        )
    )
    if process.wait(timeout=5) != 0:
        raise RuntimeError(
            f"{label} CRL good-client broker exited with an error"
        )

    rejected_port = free_port()
    rejected_config = directory / f"{fixture_name}-crl-revoked.conf"
    write_mtls_config(
        rejected_config,
        rejected_port,
        server_certificate,
        server_key,
        client_ca,
        crlfile=crl,
    )
    run_mtls_rejection_case(
        broker,
        rejected_config,
        rejected_port,
        server_ca,
        "CertificateUntrusted",
        revoked,
        revoked_key,
    )

    if algorithm not in ("p384", "ed25519"):
        return
    tampered_crl = directory / f"{fixture_name}-tampered.crl"
    tamper_pem_crl(crl, tampered_crl)
    cleartext_port = free_port()
    invalid_crl_port = free_port()
    while invalid_crl_port == cleartext_port:
        invalid_crl_port = free_port()
    invalid_config = directory / f"{fixture_name}-crl-invalid.conf"
    invalid_config.write_text(
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
    invalid_result = subprocess.run(
        [str(broker), f"--config={invalid_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if (
        invalid_result.returncode == 0
        or "InvalidCrl" not in invalid_result.stdout
    ):
        raise AssertionError(
            f"tampered {label} CRL did not fail before listen: "
            + invalid_result.stdout
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", cleartext_port)) == 0:
            raise AssertionError(
                f"an earlier listener was bound before {label} CRL validation"
            )


def run_rsa_tls_identity_case(broker: Path, directory: Path) -> None:
    rsa_key = directory / "rsa-server-pkcs8.key"
    rsa_pkcs1_key = directory / "rsa-server-pkcs1.key"
    rsa_certificate = directory / "rsa-server.crt"
    run_openssl(
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:2048",
        "-out",
        rsa_key,
    )
    run_openssl(
        "pkey",
        "-in",
        rsa_key,
        "-traditional",
        "-out",
        rsa_pkcs1_key,
    )
    run_openssl(
        "req",
        "-new",
        "-x509",
        "-key",
        rsa_key,
        "-sha256",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost",
        "-out",
        rsa_certificate,
    )
    key_password = "netz-encrypted-key"
    key_password_file = directory / "rsa-server.password"
    key_password_file.write_text(key_password + "\n")
    rsa_encrypted_aes256 = directory / "rsa-server-aes256.key"
    rsa_encrypted_aes128 = directory / "rsa-server-aes128.key"
    run_openssl(
        "pkcs8",
        "-topk8",
        "-in",
        rsa_key,
        "-out",
        rsa_encrypted_aes256,
        "-v2",
        "aes-256-cbc",
        "-iter",
        "10000",
        "-passout",
        f"pass:{key_password}",
    )
    run_openssl(
        "pkcs8",
        "-topk8",
        "-in",
        rsa_key,
        "-out",
        rsa_encrypted_aes128,
        "-v2",
        "aes-128-cbc",
        "-v2prf",
        "hmacWithSHA512",
        "-iter",
        "12000",
        "-passout",
        f"pass:{key_password}",
    )

    tls_port = free_port()
    websocket_port = free_port()
    while websocket_port == tls_port:
        websocket_port = free_port()
    encrypted_tls_port = free_port()
    while encrypted_tls_port in (tls_port, websocket_port):
        encrypted_tls_port = free_port()
    encrypted_wss_port = free_port()
    while encrypted_wss_port in (
        tls_port,
        websocket_port,
        encrypted_tls_port,
    ):
        encrypted_wss_port = free_port()
    config = directory / "rsa-tls-key.conf"
    config.write_text(
        f"listener {tls_port} 127.0.0.1\n"
        f"certfile {rsa_certificate}\n"
        f"keyfile {rsa_key}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {encrypted_tls_port} 127.0.0.1\n"
        f"certfile {rsa_certificate}\n"
        f"keyfile {rsa_encrypted_aes256}\n"
        f"keyfile_password_file {key_password_file}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {encrypted_wss_port} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {rsa_certificate}\n"
        f"keyfile {rsa_encrypted_aes128}\n"
        f"keyfile_password_file {key_password_file}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {websocket_port} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {rsa_certificate}\n"
        f"keyfile {rsa_pkcs1_key}\n"
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
    wait_process_line(
        process,
        "configured 4 listeners for 4 clients",
        "RSA TLS broker startup",
    )
    listener_lines = read_listener_lines(process, 4, "RSA TLS broker startup")
    if sum(line.startswith("mqtts ") for line in listener_lines) != 2:
        raise RuntimeError(f"RSA MQTT/TLS listeners missing: {listener_lines}")
    if sum(line.startswith("wss ") for line in listener_lines) != 2:
        raise RuntimeError(f"RSA WSS listener missing: {listener_lines}")

    rsa_result = openssl_mqtt_client(
        tls_port,
        rsa_certificate,
        signature_algorithms="rsa_pss_rsae_sha256",
    )
    assert_openssl_mqtt_success(rsa_result)
    websocket = websocket_connect(websocket_port, rsa_certificate)
    try:
        send_websocket_binary(websocket, connect_packet("rsa-pkcs1-wss"))
        if connack_reason(read_websocket_binary(websocket)) != 0:
            raise AssertionError("RSA PKCS1 WSS CONNECT failed")
        send_websocket_binary(websocket, bytes.fromhex("e000"))
    finally:
        websocket.close()
    encrypted_result = openssl_mqtt_client(
        encrypted_tls_port,
        rsa_certificate,
        signature_algorithms="rsa_pss_rsae_sha256",
    )
    assert_openssl_mqtt_success(encrypted_result)
    encrypted_websocket = websocket_connect(
        encrypted_wss_port,
        rsa_certificate,
    )
    try:
        send_websocket_binary(
            encrypted_websocket,
            connect_packet("rsa-encrypted-wss"),
        )
        if connack_reason(read_websocket_binary(encrypted_websocket)) != 0:
            raise AssertionError("encrypted RSA WSS CONNECT failed")
        send_websocket_binary(encrypted_websocket, bytes.fromhex("e000"))
    finally:
        encrypted_websocket.close()
    if process.wait(timeout=5) != 0:
        raise RuntimeError("RSA TLS broker failed: " + process.stdout.read())

    mismatched_key = directory / "rsa-mismatched.key"
    run_openssl(
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:2048",
        "-out",
        mismatched_key,
    )
    cleartext_port = free_port()
    mismatch_port = free_port()
    while mismatch_port == cleartext_port:
        mismatch_port = free_port()
    mismatch_config = directory / "rsa-tls-key-mismatch.conf"
    mismatch_config.write_text(
        f"listener {cleartext_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {mismatch_port} 127.0.0.1\n"
        f"certfile {rsa_certificate}\n"
        f"keyfile {mismatched_key}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={mismatch_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0 or "CertificateKeyMismatch" not in result.stdout:
        raise AssertionError(
            "mismatched RSA TLS key did not fail before listen: " + result.stdout
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", cleartext_port)) == 0:
            raise AssertionError(
                "an earlier cleartext listener was bound before RSA TLS "
                "identity validation completed"
            )

    wrong_password_file = directory / "rsa-server-wrong.password"
    wrong_password_file.write_text("wrong-password\n")
    password_cleartext_port = free_port()
    password_tls_port = free_port()
    while password_tls_port == password_cleartext_port:
        password_tls_port = free_port()
    password_config = directory / "rsa-tls-key-password-mismatch.conf"
    password_config.write_text(
        f"listener {password_cleartext_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        f"listener {password_tls_port} 127.0.0.1\n"
        f"certfile {rsa_certificate}\n"
        f"keyfile {rsa_encrypted_aes256}\n"
        f"keyfile_password_file {wrong_password_file}\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    result = subprocess.run(
        [str(broker), f"--config={password_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode == 0 or "InvalidPasswordOrCiphertext" not in result.stdout:
        raise AssertionError(
            "wrong encrypted-key password did not fail before listen: "
            + result.stdout
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", password_cleartext_port)) == 0:
            raise AssertionError(
                "an earlier cleartext listener was bound before encrypted "
                "private-key validation completed"
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


def run_optional_client_certificate_case(
    broker: Path, directory: Path
) -> None:
    server_ca, server_ca_key = create_ca(
        directory, "optional-server-ca", "Optional Server Root"
    )
    server_certificate, server_key = create_signed_certificate(
        directory,
        "optional-server",
        "localhost",
        server_ca,
        server_ca_key,
        701,
        "serverAuth",
        "DNS:localhost",
    )
    client_ca, client_ca_key = create_ca(
        directory, "optional-client-ca", "Optional Client Root"
    )
    client_certificate, client_key = create_signed_certificate(
        directory,
        "optional-client",
        "optional-client",
        client_ca,
        client_ca_key,
        702,
        "clientAuth",
    )
    wrong_ca, wrong_ca_key = create_ca(
        directory, "optional-wrong-ca", "Optional Wrong Root"
    )
    wrong_certificate, wrong_key = create_signed_certificate(
        directory,
        "optional-wrong-client",
        "optional-wrong-client",
        wrong_ca,
        wrong_ca_key,
        703,
        "clientAuth",
    )

    tls_port = free_port()
    wss_port = free_port()
    while wss_port == tls_port:
        wss_port = free_port()
    config = directory / "optional-client.conf"
    config.write_text(
        f"listener {tls_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {client_ca}\n"
        "require_certificate false\n"
        "allow_anonymous true\n"
        "max_connections 2\n"
        f"listener {wss_port} 127.0.0.1\n"
        "protocol websockets\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {client_ca}\n"
        "allow_anonymous true\n"
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
    if "configured 2 listeners for 4 clients" not in ready:
        raise RuntimeError(f"optional mTLS broker failed to start: {ready}")

    context = ssl.create_default_context(cafile=str(server_ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    raw = socket.create_connection(("127.0.0.1", tls_port), timeout=5)
    raw.settimeout(5)
    anonymous = context.wrap_socket(raw, server_hostname="localhost")
    try:
        anonymous.sendall(connect_packet("anonymous-tls"))
        if connack_reason(read_mqtt_packet(anonymous)) != 0:
            raise AssertionError("optional mTLS rejected anonymous client")
        mqtt_ping(anonymous)
        anonymous.sendall(bytes.fromhex("e000"))
    finally:
        anonymous.close()

    authenticated = mqtt_tls_socket(
        tls_port, server_ca, client_certificate, client_key
    )
    try:
        authenticated.sendall(connect_packet("authenticated-tls"))
        if connack_reason(read_mqtt_packet(authenticated)) != 0:
            raise AssertionError("optional mTLS rejected trusted certificate")
        mqtt_ping(authenticated)
        authenticated.sendall(bytes.fromhex("e000"))
    finally:
        authenticated.close()

    anonymous_wss = websocket_connect(wss_port, server_ca)
    try:
        send_websocket_binary(anonymous_wss, connect_packet("anonymous-wss"))
        if connack_reason(read_websocket_binary(anonymous_wss)) != 0:
            raise AssertionError("optional WSS mTLS rejected anonymous client")
        websocket_mqtt_ping(anonymous_wss)
        send_websocket_binary(anonymous_wss, bytes.fromhex("e000"))
    finally:
        anonymous_wss.close()

    authenticated_wss = websocket_connect(
        wss_port, server_ca, client_certificate, client_key
    )
    try:
        send_websocket_binary(
            authenticated_wss,
            connect_packet("authenticated-wss"),
        )
        if connack_reason(read_websocket_binary(authenticated_wss)) != 0:
            raise AssertionError("optional WSS mTLS rejected trusted certificate")
        websocket_mqtt_ping(authenticated_wss)
        send_websocket_binary(authenticated_wss, bytes.fromhex("e000"))
    finally:
        authenticated_wss.close()
    if process.wait(timeout=5) != 0:
        raise RuntimeError(
            "optional client certificate broker failed: "
            + process.stdout.read()
        )

    rejection_port = free_port()
    rejected_config = directory / "optional-wrong-client.conf"
    rejected_config.write_text(
        f"listener {rejection_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {client_ca}\n"
        "require_certificate false\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    run_mtls_rejection_case(
        broker,
        rejected_config,
        rejection_port,
        server_ca,
        "CertificateUntrusted",
        wrong_certificate,
        wrong_key,
    )


def main() -> None:
    args = parse_args()
    os.environ[FINITE_TEST_ENV] = "1"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        run_shared_listener_case(args.broker, directory)
        run_ipv6_socket_domain_case(args.broker, directory)
        run_default_dual_socket_domain_case(args.broker, directory)
        run_accepted_protocol_versions_case(args.broker, directory)
        run_proxy_protocol_case(args.broker, directory)
        run_websocket_origins_case(args.broker, directory)
        run_per_listener_security_case(args.broker, directory)
        run_include_directory_case(args.broker, directory)
        run_inbound_bridge_case(args.broker, directory)
        run_bridge_reload_case(args.broker, directory)
        run_outbound_bridge_reload_case(args.broker, directory)
        run_bidirectional_bridge_case(args.broker, directory, 3)
        run_bidirectional_bridge_case(args.broker, directory, 4)
        run_bidirectional_bridge_case(args.broker, directory, 5)
        run_outbound_bridge_case(args.broker, directory)
        run_outbound_bridge_case(args.broker, directory, tls=True)
        run_outbound_bridge_protocol_limits_case(args.broker, directory)
        run_private_bridge_server_case(args.broker, directory)
        run_bridge_cipher_suite_case(args.broker, directory)
        run_bridge_ocsp_case(args.broker, directory)
        run_local_clean_session_case(args.broker, directory)
        run_lazy_outbound_bridge_case(args.broker, directory)
        run_primary_failback_case(args.broker, directory)
        run_once_bridge_case(args.broker, directory)
        run_tls_inbound_bridge_case(args.broker, directory)
        run_packet_and_message_size_case(args.broker, directory)
        run_retain_unavailable_case(args.broker, directory)
        run_zero_length_client_id_case(args.broker, directory)
        run_auto_client_id_prefix_matrix(args.broker, directory)
        run_required_client_id_prefix_case(args.broker, directory)
        run_upgrade_outgoing_qos_case(args.broker, directory)
        run_max_inflight_messages_case(args.broker, directory)
        run_zero_maximum_keep_alive_case(args.broker, directory)
        run_queued_limits_case(args.broker, directory)
        run_topic_alias_policy_case(args.broker, directory)
        run_persistent_client_expiration_case(args.broker, directory)
        run_global_max_clients_case(args.broker, directory)
        run_global_max_connections_case(args.broker, directory)
        run_listener_max_connections_case(args.broker, directory)
        run_system_interval_case(args.broker, directory)
        run_fail_closed_case(args.broker, directory)
        run_invalid_password_file_case(args.broker, directory)
        run_invalid_acl_file_case(args.broker, directory)
        run_acl_v311_case(args.broker, directory)
        run_authentication_case(args.broker, directory)
        run_security_reload_case(args.broker, directory)
        run_listener_policy_reload_case(args.broker, directory)
        run_server_identity_reload_case(args.broker, directory)
        run_client_ca_reload_case(args.broker, directory)
        run_crl_reload_case(args.broker, directory)
        run_persistence_case(args.broker, directory)
        run_disabled_autosave_case(args.broker, directory)
        run_autosave_reload_case(args.broker, directory)
        run_retain_source_case(args.broker, directory)
        run_tls_listener_case(args.broker, directory)
        run_modern_tls_identity_case(args.broker, directory)
        run_mtls_listener_case(args.broker, directory)
        run_capath_listener_case(args.broker, directory)
        run_mtls_subject_username_case(args.broker, directory)
        run_optional_client_certificate_case(args.broker, directory)
        run_signed_crl_listener_case(args.broker, directory, "rsa")
        run_signed_crl_listener_case(args.broker, directory, "p384")
        run_signed_crl_listener_case(args.broker, directory, "ed25519")
        run_rsa_tls_identity_case(args.broker, directory)
    print(
        "MQTT broker config integration passed: strict authentication, "
        "Mosquitto hashes, packet/message/retain/inflight/queue limits, "
        "listener protocol/PROXY/Topic Alias/Origin and WebSocket header limits, "
        "default dual-family, named-interface, and IPv4/IPv6-only "
        "TCP/TLS/WS/WSS listeners, "
        "global client-session plus global/listener live-connection capacity, "
        "persistent-client and "
        "retained-message "
        "expiration, and periodic $SYS policy, "
        "zero-length and MQTT 3.1 Client ID bounds, global/listener auto-ID "
        "prefixes, required Client ID prefix admission, and outgoing QoS policy, ordered "
        "include_dir and global/per-listener security files, "
        "configured cleartext/TLS inbound/outbound bridge prefix mapping, "
        "immediate/lazy SIGHUP bridge reload with cross-subsystem rollback "
        "and client continuity, mTLS, "
        "single-Session bidirectional bridge mapping, "
        "MQTT 3.1/3.1.1/5 bridge receive/alias/packet limits and outgoing RETAIN, "
        "persistent remote-subscription cleanup with interleaved delivery, "
        "private-bridge negotiation with standard MQTT 3.1/3.1.1 fallback, "
        "TLS 1.3 bridge cipher-suite selection, "
        "required TLS 1.3 bridge OCSP stapling, "
        "local Client ID and clean-Session restart isolation, "
        "cleartext/TLS bridge source-address binding and traced TCP keepalive/"
        "TCP_USER_TIMEOUT, "
        "QoS 1/2, lazy threshold/idle lifecycle with restart recovery, "
        "decorrelated-jitter reconnect with stable-period reset, "
        "round-robin failover, primary failback, reconnect, and "
        "retained local/remote state notifications with Last Will plus "
        "disabled one-shot lifecycle, "
        "mixed anonymous policy, shared TCP/WebSocket "
        "state, ACL read/write/deny/pattern policy, mount point, listener "
        "policies, P-256/P-384/P-521/Ed25519/RSA and encrypted PKCS#8 TLS "
        "with OpenSSL verification, "
        "optional/required client certificates, bounded listener/bridge capath trust, "
        "certificate CN/full-Subject identity mapping, "
        "P-256/P-384/RSA/Ed25519 signed CRL revocation, strict TLS "
        "key/CA/EKU/identity/CRL rejection, retained-source ACL replay, "
        "atomic password/ACL with selective live credential revocation and "
        "TLS/WSS identity/key-password/CA/CRL "
        "plus per-listener anonymous admission SIGHUP reload with topology rollback, "
        "dynamic time/change/disabled autosave SIGHUP reload with fixed-target "
        "rollback, disabled-autosave SIGUSR1 checkpoint recovery, and snapshot restore "
        + RUNTIME
    )


if __name__ == "__main__":
    main()
