#!/usr/bin/env python3
"""Exercise the Autobahn adapter over real cleartext and TLS sockets."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading


CONCURRENT_CLIENTS = 8
EXPECTED_RUNTIME = "workers=64 server_io=zio-std-io"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def recv_exact(peer: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = peer.recv(length - len(result))
        if not chunk:
            raise AssertionError("connection closed before complete frame")
        result.extend(chunk)
    return bytes(result)


def send_frame(peer: socket.socket, opcode: int, payload: bytes) -> None:
    mask = os.urandom(4)
    if len(payload) <= 125:
        header = bytes((0x80 | opcode, 0x80 | len(payload)))
    elif len(payload) <= 65535:
        header = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack(
            "!H", len(payload)
        )
    else:
        header = bytes((0x80 | opcode, 0x80 | 127)) + struct.pack(
            "!Q", len(payload)
        )
    masked = bytes(
        value ^ mask[index % 4] for index, value in enumerate(payload)
    )
    peer.sendall(header + mask + masked)


def receive_frame(peer: socket.socket) -> tuple[int, bytes]:
    first, second = recv_exact(peer, 2)
    if first & 0x80 == 0 or second & 0x80 != 0:
        raise AssertionError("unexpected server frame flags")
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(peer, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(peer, 8))[0]
    return first & 0x0F, recv_exact(peer, length)


def connect(port: int, use_tls: bool) -> socket.socket:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    raw.settimeout(5)
    if not use_tls:
        return raw
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(raw, server_hostname="localhost")


def upgrade(port: int, use_tls: bool) -> socket.socket:
    peer = connect(port, use_tls)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET /autobahn-smoke HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    peer.sendall(request)
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = peer.recv(4096)
        if not chunk:
            raise AssertionError("connection closed before HTTP Upgrade")
        response.extend(chunk)
    if not response.startswith(b"HTTP/1.1 101 "):
        raise AssertionError(f"unexpected HTTP Upgrade response: {response!r}")
    expected = base64.b64encode(
        hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(
                "ascii"
            )
        ).digest()
    )
    if b"sec-websocket-accept: " + expected.lower() not in response.lower():
        raise AssertionError("invalid Sec-WebSocket-Accept")
    return peer


def exercise_echo(port: int, use_tls: bool, index: int) -> None:
    with upgrade(port, use_tls) as peer:
        text = f"zio-autobahn-{index}".encode("ascii")
        send_frame(peer, 1, text)
        if receive_frame(peer) != (1, text):
            raise AssertionError("text echo mismatch")
        binary = bytes((index, 0, 255, 17))
        send_frame(peer, 2, binary)
        if receive_frame(peer) != (2, binary):
            raise AssertionError("binary echo mismatch")
        ping = f"ping-{index}".encode("ascii")
        send_frame(peer, 9, ping)
        if receive_frame(peer) != (10, ping):
            raise AssertionError("Pong mismatch")
        close = struct.pack("!H", 1000) + b"done"
        send_frame(peer, 8, close)
        if receive_frame(peer) != (8, close):
            raise AssertionError("Close mismatch")


def exercise_protocol_error(port: int, use_tls: bool) -> None:
    with upgrade(port, use_tls) as peer:
        # RFC 6455 requires every client-to-server frame to be masked.
        peer.sendall(b"\x81\x03bad")
        opcode, payload = receive_frame(peer)
        if opcode != 8 or len(payload) < 2:
            raise AssertionError("protocol error did not produce Close")
        if struct.unpack("!H", payload[:2])[0] != 1002:
            raise AssertionError("unexpected protocol-error close code")


def run_mode(server: Path, use_tls: bool) -> None:
    port = free_port()
    command = [str(server), str(port)]
    if use_tls:
        command.append("--tls")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        assert process.stdout is not None
        ready = process.stdout.readline().strip()
        if EXPECTED_RUNTIME not in ready:
            raise AssertionError(f"unexpected server readiness: {ready}")
        errors: list[tuple[int, BaseException]] = []

        def worker(index: int) -> None:
            try:
                exercise_echo(port, use_tls, index)
            except BaseException as error:
                errors.append((index, error))

        threads = [
            threading.Thread(target=worker, args=(index,))
            for index in range(CONCURRENT_CLIENTS)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        if any(thread.is_alive() for thread in threads):
            raise AssertionError("concurrent client did not finish")
        if errors:
            raise AssertionError(f"concurrent client failures: {errors!r}")

        exercise_protocol_error(port, use_tls)
        # A connection-local protocol failure must not stop the listener or
        # poison the reusable supervisor worker.
        exercise_echo(port, use_tls, CONCURRENT_CLIENTS)
        transport = "tls" if use_tls else "cleartext"
        print(
            "Autobahn zio smoke passed: "
            f"transport={transport} concurrent={CONCURRENT_CLIENTS} "
            "protocol_error=isolated recovery_connection=true "
            "workers=64 server_io=zio-std-io"
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("server", type=Path)
    args = parser.parse_args()
    run_mode(args.server, False)
    run_mode(args.server, True)


if __name__ == "__main__":
    main()
