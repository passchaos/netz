"""Mosquitto-style WebSocket Origin configuration scenarios."""

from __future__ import annotations

import base64
from pathlib import Path
import socket
import subprocess

from mqtt_commit_log_support import connect_packet, free_port


def _request(port: int, origin: str | None) -> bytes:
    key = base64.b64encode(b"netz-origin-test").decode()
    return (
        "GET /mqtt HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: mqtt\r\n"
        + (f"Origin: {origin}\r\n" if origin is not None else "")
        + "\r\n"
    ).encode()


def _upgrade(port: int, origin: str) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(_request(port, origin))
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(1)
        if not chunk:
            raise AssertionError("allowed Origin closed before Upgrade")
        response.extend(chunk)
    if not response.startswith(b"HTTP/1.1 101 "):
        raise AssertionError(f"allowed Origin response: {response!r}")
    return sock


def _send_websocket_binary(sock: socket.socket, payload: bytes) -> None:
    if len(payload) >= 126:
        raise AssertionError("Origin test packet exceeded short WS frame")
    mask = b"\x12\x34\x56\x78"
    masked = bytes(
        byte ^ mask[index % len(mask)]
        for index, byte in enumerate(payload)
    )
    sock.sendall(bytes((0x82, 0x80 | len(payload))) + mask + masked)


def _read_websocket_binary(sock: socket.socket) -> bytes:
    header = sock.recv(2)
    if len(header) != 2 or header[0] != 0x82 or header[1] & 0x80:
        raise AssertionError(f"unexpected WebSocket frame: {header.hex()}")
    length = header[1]
    if length >= 126:
        raise AssertionError("unexpected extended WebSocket frame")
    payload = bytearray()
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise AssertionError("WebSocket closed before complete MQTT packet")
        payload.extend(chunk)
    return bytes(payload)


def _run_denied(
    broker: Path,
    config: Path,
    port: int,
    origin: str | None,
) -> None:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    try:
        ready = process.stdout.readline().strip()
        if "configured 1 listeners for 1 clients" not in ready:
            raise RuntimeError(f"Origin broker failed to start: {ready}")
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(_request(port, origin))
            if sock.recv(1):
                raise AssertionError("disallowed Origin unexpectedly upgraded")
        return_code = process.wait(timeout=5)
        output = process.stdout.read()
        if return_code == 0 or "InvalidOrigin" not in output:
            raise AssertionError("Origin rejection was not reported: " + output)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)


def run_websocket_origins_case(broker: Path, directory: Path) -> None:
    """Strengthen Mosquitto 13-websocket-bad-origin with two allowed values."""
    port = free_port()
    config = directory / "websocket-origins.conf"
    config.write_text(
        f"listener {port} 127.0.0.1\n"
        "protocol websockets\n"
        "websockets_origin https://first.example\n"
        "websockets_origin https://second.example:8443\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )

    _run_denied(broker, config, port, "https://denied.example")
    _run_denied(broker, config, port, None)

    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    try:
        ready = process.stdout.readline().strip()
        if "configured 1 listeners for 1 clients" not in ready:
            raise RuntimeError(f"Origin broker failed to start: {ready}")
        client = _upgrade(port, "https://second.example:8443")
        try:
            _send_websocket_binary(client, connect_packet(
                "origin-allowed", clean_start=True, protocol=5,
            ))
            connack = _read_websocket_binary(client)
            if len(connack) < 4 or connack[0] != 0x20 or connack[3] != 0:
                raise AssertionError(f"allowed Origin CONNACK: {connack.hex()}")
            _send_websocket_binary(client, b"\xe0\x00")
        finally:
            client.close()
        if process.wait(timeout=5) != 0:
            raise RuntimeError("Origin broker failed: " + process.stdout.read())
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)

    bounded_port = free_port()
    bounded_config = directory / "websocket-headers-size.conf"
    bounded_config.write_text(
        "websockets_headers_size 256\n"
        f"listener {bounded_port} 127.0.0.1\n"
        "protocol websockets\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    process = subprocess.Popen(
        [str(broker), f"--config={bounded_config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    try:
        ready = process.stdout.readline().strip()
        if "configured 1 listeners for 1 clients" not in ready:
            raise RuntimeError(f"header-limit broker failed to start: {ready}")
        with socket.create_connection(
            ("127.0.0.1", bounded_port),
            timeout=5,
        ) as sock:
            sock.settimeout(5)
            oversized = _request(bounded_port, None).replace(
                b"\r\n\r\n",
                b"X-Padding: " + b"x" * 512 + b"\r\n\r\n",
            )
            sock.sendall(oversized)
            try:
                if sock.recv(1):
                    raise AssertionError("oversized Upgrade unexpectedly accepted")
            except ConnectionResetError:
                pass
        return_code = process.wait(timeout=5)
        output = process.stdout.read()
        if return_code == 0 or "HeadersTooLarge" not in output:
            raise AssertionError(
                "WebSocket header limit was not enforced: " + output
            )
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)
