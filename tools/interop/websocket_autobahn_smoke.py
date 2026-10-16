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
import zlib


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


def send_frame(
    peer: socket.socket,
    opcode: int,
    payload: bytes,
    *,
    fin: bool = True,
    rsv1: bool = False,
) -> None:
    mask = os.urandom(4)
    first = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | opcode
    if len(payload) <= 125:
        header = bytes((first, 0x80 | len(payload)))
    elif len(payload) <= 65535:
        header = bytes((first, 0x80 | 126)) + struct.pack("!H", len(payload))
    else:
        header = bytes((first, 0x80 | 127)) + struct.pack("!Q", len(payload))
    masked = bytes(
        value ^ mask[index % 4] for index, value in enumerate(payload)
    )
    peer.sendall(header + mask + masked)


def receive_frame_details(
    peer: socket.socket,
) -> tuple[bool, bool, int, bytes]:
    first, second = recv_exact(peer, 2)
    if first & 0x30 != 0 or second & 0x80 != 0:
        raise AssertionError("unexpected server frame flags")
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(peer, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(peer, 8))[0]
    return (
        first & 0x80 != 0,
        first & 0x40 != 0,
        first & 0x0F,
        recv_exact(peer, length),
    )


def receive_frame(peer: socket.socket) -> tuple[int, bytes]:
    fin, rsv1, opcode, payload = receive_frame_details(peer)
    if not fin or rsv1:
        raise AssertionError("unexpected fragmented or compressed server frame")
    return opcode, payload


def connect(port: int, use_tls: bool) -> socket.socket:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    raw.settimeout(5)
    if not use_tls:
        return raw
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(raw, server_hostname="localhost")


def upgrade(
    port: int,
    use_tls: bool,
    extension_offer: str | None = None,
) -> socket.socket:
    peer = connect(port, use_tls)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    extension_header = (
        f"Sec-WebSocket-Extensions: {extension_offer}\r\n"
        if extension_offer is not None
        else ""
    )
    request = (
        "GET /autobahn-smoke HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"{extension_header}\r\n"
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
    lower_response = response.lower()
    if extension_offer is None:
        if b"sec-websocket-extensions:" in lower_response:
            raise AssertionError("server selected an unsolicited extension")
    else:
        for token in (
            b"permessage-deflate",
            b"client_no_context_takeover",
            b"server_no_context_takeover",
        ):
            if token not in lower_response:
                raise AssertionError(
                    f"missing negotiated extension parameter: {token!r}"
                )
    return peer


def deflate_message(payload: bytes) -> bytes:
    compressor = zlib.compressobj(level=6, wbits=-15)
    encoded = compressor.compress(payload) + compressor.flush(zlib.Z_SYNC_FLUSH)
    if not encoded.endswith(b"\x00\x00\xff\xff"):
        raise AssertionError("raw DEFLATE omitted the RFC 7692 tail")
    return encoded[:-4]


def inflate_message(payload: bytes) -> bytes:
    decompressor = zlib.decompressobj(wbits=-15)
    decoded = decompressor.decompress(payload + b"\x00\x00\xff\xff")
    if decompressor.unconsumed_tail:
        raise AssertionError("compressed echo left unconsumed bytes")
    return decoded


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


def exercise_fragmented_control(port: int, use_tls: bool) -> None:
    with upgrade(port, use_tls) as peer:
        send_frame(peer, 1, b"frag-", fin=False)
        send_frame(peer, 9, b"mid-fragment")
        if receive_frame(peer) != (10, b"mid-fragment"):
            raise AssertionError("fragment-interleaved Pong mismatch")
        send_frame(peer, 0, b"text")
        if receive_frame(peer) != (1, b"frag-text"):
            raise AssertionError("fragmented text echo mismatch")
        close = struct.pack("!H", 1000) + b"fragmented-done"
        send_frame(peer, 8, close)
        if receive_frame(peer) != (8, close):
            raise AssertionError("fragmented connection Close mismatch")


def exercise_invalid_utf8(port: int, use_tls: bool) -> None:
    with upgrade(port, use_tls) as peer:
        send_frame(peer, 1, b"valid-prefix\xf0\x28\x8c\x28")
        opcode, payload = receive_frame(peer)
        if opcode != 8 or len(payload) < 2:
            raise AssertionError("invalid UTF-8 did not produce Close")
        if struct.unpack("!H", payload[:2])[0] != 1007:
            raise AssertionError("unexpected invalid-UTF-8 close code")


def exercise_compression(port: int, use_tls: bool) -> None:
    offer = (
        "permessage-deflate; client_no_context_takeover; "
        "server_no_context_takeover"
    )
    with upgrade(port, use_tls, offer) as peer:
        first_plain = b"compressed-fragment-" * 128
        first_encoded = deflate_message(first_plain)
        split = len(first_encoded) // 2
        send_frame(
            peer,
            1,
            first_encoded[:split],
            fin=False,
            rsv1=True,
        )
        send_frame(peer, 9, b"compressed-ping")
        if receive_frame(peer) != (10, b"compressed-ping"):
            raise AssertionError("compressed-fragment Pong mismatch")
        send_frame(peer, 0, first_encoded[split:])
        fin, rsv1, opcode, payload = receive_frame_details(peer)
        if not fin or not rsv1 or opcode != 1:
            raise AssertionError("compressed fragmented echo flags mismatch")
        if inflate_message(payload) != first_plain:
            raise AssertionError("compressed fragmented echo payload mismatch")

        # Both no-context-takeover parameters require a fresh RFC 7692 history
        # in each direction. Independent zlib objects make that observable.
        second_plain = b"independent-compression-history-" * 96
        send_frame(peer, 1, deflate_message(second_plain), rsv1=True)
        fin, rsv1, opcode, payload = receive_frame_details(peer)
        if not fin or not rsv1 or opcode != 1:
            raise AssertionError("second compressed echo flags mismatch")
        if inflate_message(payload) != second_plain:
            raise AssertionError("second compressed echo payload mismatch")

        close = struct.pack("!H", 1000) + b"compression-done"
        send_frame(peer, 8, close)
        if receive_frame(peer) != (8, close):
            raise AssertionError("compressed connection Close mismatch")


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

        exercise_fragmented_control(port, use_tls)
        exercise_compression(port, use_tls)
        exercise_protocol_error(port, use_tls)
        # A connection-local protocol failure must not stop the listener or
        # poison the reusable supervisor worker.
        exercise_echo(port, use_tls, CONCURRENT_CLIENTS)
        exercise_invalid_utf8(port, use_tls)
        # UTF-8 failure uses a distinct RFC 6455 Close code but must remain
        # equally isolated from the listener and reusable worker pool.
        exercise_echo(port, use_tls, CONCURRENT_CLIENTS + 1)
        transport = "tls" if use_tls else "cleartext"
        print(
            "Autobahn zio smoke passed: "
            f"transport={transport} concurrent={CONCURRENT_CLIENTS} "
            "fragmented_control=true compression_no_context=true "
            "protocol_error=isolated "
            "utf8_error=1007 recovery_connections=2 "
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
