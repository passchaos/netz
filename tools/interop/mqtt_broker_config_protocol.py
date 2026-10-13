"""Mosquitto-style listener protocol-version policy scenarios."""

from __future__ import annotations

import base64
from pathlib import Path
import socket
import subprocess

from mqtt_commit_log_support import (
    connect_packet,
    free_port,
    read_packet,
)


def _connack_reason(sock: socket.socket) -> int:
    first, body = read_packet(sock)
    if first != 0x20 or len(body) < 2:
        raise AssertionError(f"expected CONNACK, got {first:02x}{body.hex()}")
    return body[1]


def _websocket_connect(port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    key = base64.b64encode(b"netz-proto-test!").decode()
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
        byte = sock.recv(1)
        if not byte:
            raise AssertionError("WebSocket listener closed during Upgrade")
        response.extend(byte)
    if not response.startswith(b"HTTP/1.1 101 "):
        raise AssertionError(f"WebSocket Upgrade failed: {response!r}")
    return sock


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError("connection closed before complete data")
        result.extend(part)
    return bytes(result)


def _send_websocket_binary(sock: socket.socket, payload: bytes) -> None:
    if len(payload) >= 126:
        raise AssertionError("protocol-policy packet exceeded short WS frame")
    mask = b"\x12\x34\x56\x78"
    masked = bytes(
        byte ^ mask[index % len(mask)]
        for index, byte in enumerate(payload)
    )
    sock.sendall(bytes((0x82, 0x80 | len(payload))) + mask + masked)


def _read_websocket_binary(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 2)
    if header[0] != 0x82 or header[1] & 0x80:
        raise AssertionError(f"unexpected WebSocket frame: {header.hex()}")
    length = header[1]
    if length >= 126:
        raise AssertionError("unexpected extended WebSocket frame")
    payload = bytearray()
    while len(payload) < length:
        payload.extend(_recv_exact(sock, length - len(payload)))
    first = payload[0]
    remaining = payload[1]
    if remaining & 0x80 or remaining + 2 != len(payload):
        raise AssertionError(f"unexpected MQTT packet: {payload.hex()}")
    return first, bytes(payload[2:])


def run_accepted_protocol_versions_case(
    broker: Path,
    directory: Path,
) -> None:
    """Strengthen Mosquitto 01-connect-accept-protocol across TCP and WS."""
    tcp_port = free_port()
    websocket_port = free_port()
    config = directory / "accepted-protocol-versions.conf"
    config.write_text(
        f"listener {tcp_port} 127.0.0.1\n"
        "accept_protocol_versions 5\n"
        "allow_anonymous true\n"
        "max_connections 3\n"
        f"listener {websocket_port} 127.0.0.1\n"
        "protocol websockets\n"
        "accept_protocol_versions 3,4\n"
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
    try:
        ready = process.stdout.readline().strip()
        if "configured 2 listeners for 6 clients" not in ready:
            raise RuntimeError(f"protocol-policy broker failed to start: {ready}")

        tcp_v5 = socket.create_connection(("127.0.0.1", tcp_port), timeout=5)
        tcp_v5.settimeout(5)
        tcp_v311 = socket.create_connection(("127.0.0.1", tcp_port), timeout=5)
        tcp_v311.settimeout(5)
        tcp_v31 = socket.create_connection(("127.0.0.1", tcp_port), timeout=5)
        tcp_v31.settimeout(5)
        ws_v31 = _websocket_connect(websocket_port)
        ws_v311 = _websocket_connect(websocket_port)
        ws_v5 = _websocket_connect(websocket_port)
        try:
            tcp_v5.sendall(connect_packet(
                "protocol-tcp-v5", clean_start=True, protocol=5,
            ))
            if _connack_reason(tcp_v5) != 0:
                raise AssertionError("v5-only TCP listener refused MQTT 5")

            tcp_v311.sendall(connect_packet(
                "protocol-tcp-v311", clean_start=True, protocol=4,
            ))
            if _connack_reason(tcp_v311) != 0x01:
                raise AssertionError("v5-only TCP listener accepted MQTT 3.1.1")

            tcp_v31.sendall(connect_packet(
                "protocol-tcp-v31", clean_start=True, protocol=3,
            ))
            if _connack_reason(tcp_v31) != 0x01:
                raise AssertionError("v5-only TCP listener accepted MQTT 3.1")

            _send_websocket_binary(ws_v31, connect_packet(
                "protocol-ws-v31", clean_start=True, protocol=3,
            ))
            if _read_websocket_binary(ws_v31) != (0x20, b"\x00\x00"):
                raise AssertionError("legacy WS listener refused MQTT 3.1")

            _send_websocket_binary(ws_v311, connect_packet(
                "protocol-ws-v311", clean_start=True, protocol=4,
            ))
            if _read_websocket_binary(ws_v311) != (0x20, b"\x00\x00"):
                raise AssertionError("v3.1.1-only WS listener refused MQTT 3.1.1")

            _send_websocket_binary(ws_v5, connect_packet(
                "protocol-ws-v5", clean_start=True, protocol=5,
            ))
            if _read_websocket_binary(ws_v5) != (0x20, b"\x00\x84\x00"):
                raise AssertionError("v3.1.1-only WS listener accepted MQTT 5")

            tcp_v5.sendall(b"\xe0\x00")
            _send_websocket_binary(ws_v31, b"\xe0\x00")
            _send_websocket_binary(ws_v311, b"\xe0\x00")
        finally:
            tcp_v5.close()
            tcp_v311.close()
            tcp_v31.close()
            ws_v31.close()
            ws_v311.close()
            ws_v5.close()

        if process.wait(timeout=5) != 0:
            raise RuntimeError("protocol-policy broker failed: " + process.stdout.read())
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
