"""Mosquitto-style PROXY protocol listener configuration scenarios."""

from __future__ import annotations

import base64
from pathlib import Path
import socket
import subprocess

from mqtt_commit_log_support import connect_packet, free_port, read_packet


PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def _run_broker(broker: Path, config: Path) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 1 clients" not in ready:
        process.terminate()
        process.wait(timeout=2)
        raise RuntimeError(f"PROXY broker failed to start: {ready}")
    return process


def _finish(process: subprocess.Popen[str]) -> None:
    try:
        if process.wait(timeout=5) != 0:
            raise RuntimeError("PROXY broker failed: " + process.stdout.read())
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)


def _websocket_upgrade(sock: socket.socket, port: int) -> None:
    key = base64.b64encode(b"netz-proxy-test!").decode()
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
            raise AssertionError("PROXY WebSocket closed during Upgrade")
        response.extend(byte)
    if not response.startswith(b"HTTP/1.1 101 "):
        raise AssertionError(f"PROXY WebSocket Upgrade failed: {response!r}")


def _send_websocket_binary(sock: socket.socket, payload: bytes) -> None:
    if len(payload) >= 126:
        raise AssertionError("PROXY test packet exceeded short WS frame")
    mask = b"\x12\x34\x56\x78"
    masked = bytes(
        byte ^ mask[index % len(mask)]
        for index, byte in enumerate(payload)
    )
    sock.sendall(bytes((0x82, 0x80 | len(payload))) + mask + masked)


def _recv_websocket_binary(sock: socket.socket) -> bytes:
    header = sock.recv(2)
    if len(header) != 2 or header[0] != 0x82 or header[1] & 0x80:
        raise AssertionError(f"unexpected WebSocket frame: {header.hex()}")
    length = header[1]
    if length >= 126:
        raise AssertionError("unexpected extended WebSocket frame")
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise AssertionError("WebSocket closed before complete MQTT packet")
        result.extend(part)
    return bytes(result)


def run_proxy_protocol_case(broker: Path, directory: Path) -> None:
    """Port Mosquitto's v1 and WebSocket v2 PROXY success scenarios."""
    v1_port = free_port()
    v1_config = directory / "proxy-v1.conf"
    v1_config.write_text(
        f"listener {v1_port} 127.0.0.1\n"
        "enable_proxy_protocol 1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    process = _run_broker(broker, v1_config)
    try:
        with socket.create_connection(("127.0.0.1", v1_port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(
                b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1883\r\n"
                + connect_packet("proxy-v1-config", clean_start=True, protocol=5)
            )
            first, body = read_packet(client)
            if first != 0x20 or len(body) < 2 or body[1] != 0:
                raise AssertionError(f"PROXY v1 CONNACK: {first:02x}{body.hex()}")
            client.sendall(b"\xe0\x00")
        _finish(process)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)

    v2_port = free_port()
    v2_config = directory / "proxy-v2-websocket.conf"
    v2_config.write_text(
        f"listener {v2_port} 127.0.0.1\n"
        "protocol websockets\n"
        "enable_proxy_protocol 2\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    process = _run_broker(broker, v2_config)
    try:
        with socket.create_connection(("127.0.0.1", v2_port), timeout=5) as client:
            client.settimeout(5)
            address = (
                b"\xc0\x00\x02\x05"
                + b"\x7f\x00\x00\x01"
                + b"\x18\x83\x07\x5b"
            )
            client.sendall(
                PROXY_V2_SIGNATURE
                + b"\x21\x11"
                + len(address).to_bytes(2, "big")
                + address
            )
            _websocket_upgrade(client, v2_port)
            _send_websocket_binary(client, connect_packet(
                "proxy-v2-ws-config", clean_start=True, protocol=5,
            ))
            connack = _recv_websocket_binary(client)
            if len(connack) < 4 or connack[0] != 0x20 or connack[3] != 0:
                raise AssertionError(f"PROXY v2 WS CONNACK: {connack.hex()}")
            _send_websocket_binary(client, b"\xe0\x00")
        _finish(process)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)
