#!/usr/bin/env python3
"""Independent SOCKS5, HTTP(S), WS(S), and MQTT-over-WS(S) peers."""

from __future__ import annotations

import argparse
import base64
import hashlib
from pathlib import Path
import select
import socket
import ssl
import subprocess
import tempfile
import threading

from mqtt_socks5 import create_identity, listener, read_mqtt_packet, recv_exact


def read_head(stream: socket.socket) -> bytes:
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        chunk = stream.recv(4096)
        if not chunk:
            raise EOFError("EOF in HTTP head")
        data.extend(chunk)
        if len(data) > 65536:
            raise AssertionError("HTTP head too large")
    return bytes(data)


def serve_http(
    server: socket.socket,
    context: ssl.SSLContext | None,
    target: bytes,
    body: bytes,
) -> None:
    raw, _ = server.accept()
    with raw:
        stream = context.wrap_socket(raw, server_side=True) if context else raw
        with stream:
            head = read_head(stream)
            if not head.startswith(b"GET " + target + b" HTTP/1.1\r\n"):
                raise AssertionError(f"wrong HTTP request: {head!r}")
            if b"\r\nHost: origin.internal:" not in head:
                raise AssertionError("SOCKS HTTP request lost origin authority")
            stream.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )


def parse_headers(head: bytes) -> tuple[bytes, dict[bytes, bytes]]:
    lines = head[:-4].split(b"\r\n")
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        headers[name.lower()] = value.strip()
    return lines[0], headers


def read_frame(stream: socket.socket) -> tuple[int, bytes]:
    first, second = recv_exact(stream, 2)
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(stream, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(stream, 8), "big")
    if not second & 0x80:
        raise AssertionError("client WebSocket frame was not masked")
    mask = recv_exact(stream, 4)
    encoded = recv_exact(stream, length)
    return opcode, bytes(
        byte ^ mask[index % 4] for index, byte in enumerate(encoded)
    )


def send_frame(stream: socket.socket, opcode: int, payload: bytes) -> None:
    if len(payload) <= 125:
        header = bytes((0x80 | opcode, len(payload)))
    elif len(payload) <= 65535:
        header = bytes((0x80 | opcode, 126)) + len(payload).to_bytes(2, "big")
    else:
        header = bytes((0x80 | opcode, 127)) + len(payload).to_bytes(8, "big")
    stream.sendall(header + payload)


def upgrade(stream: socket.socket, target: bytes, mqtt: bool) -> None:
    request_line, headers = parse_headers(read_head(stream))
    if request_line != b"GET " + target + b" HTTP/1.1":
        raise AssertionError(f"wrong Upgrade target: {request_line!r}")
    if not headers.get(b"host", b"").startswith(b"origin.internal:"):
        raise AssertionError("Upgrade lost origin authority")
    key = headers.get(b"sec-websocket-key")
    if key is None:
        raise AssertionError("missing WebSocket key")
    if mqtt and headers.get(b"sec-websocket-protocol") != b"mqtt":
        raise AssertionError("MQTT WebSocket omitted mqtt subprotocol")
    accept = base64.b64encode(
        hashlib.sha1(
            key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        ).digest()
    )
    response = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept + b"\r\n"
    )
    if mqtt:
        response += b"Sec-WebSocket-Protocol: mqtt\r\n"
    stream.sendall(response + b"\r\n")


def serve_websocket(
    server: socket.socket,
    context: ssl.SSLContext | None,
    expected_payload: bytes,
) -> None:
    raw, _ = server.accept()
    with raw:
        stream = context.wrap_socket(raw, server_side=True) if context else raw
        with stream:
            upgrade(stream, b"/chat", False)
            opcode, payload = read_frame(stream)
            if opcode != 1 or payload != expected_payload:
                raise AssertionError("wrong WebSocket text message")
            send_frame(stream, 1, payload)
            opcode, payload = read_frame(stream)
            if opcode != 9 or payload != b"probe":
                raise AssertionError("wrong WebSocket Ping")
            send_frame(stream, 10, payload)
            opcode, payload = read_frame(stream)
            if opcode != 8:
                raise AssertionError("expected WebSocket Close")
            send_frame(stream, 8, payload)


def serve_mqtt_websocket(
    server: socket.socket,
    context: ssl.SSLContext | None,
    expected_id: bytes,
) -> None:
    raw, _ = server.accept()
    with raw:
        stream = context.wrap_socket(raw, server_side=True) if context else raw
        with stream:
            upgrade(stream, b"/mqtt", True)
            opcode, connect = read_frame(stream)
            if opcode != 2 or connect[0] != 0x10 or expected_id not in connect:
                raise AssertionError("wrong MQTT WebSocket CONNECT")
            send_frame(stream, 2, bytes.fromhex("2003000000"))
            opcode, ping = read_frame(stream)
            if opcode != 2 or ping != bytes.fromhex("c000"):
                raise AssertionError("wrong MQTT WebSocket PINGREQ")
            send_frame(stream, 2, bytes.fromhex("d000"))
            opcode, disconnect = read_frame(stream)
            if opcode != 2 or disconnect != bytes.fromhex("e000"):
                raise AssertionError("wrong MQTT WebSocket DISCONNECT")


def read_socks_target(stream: socket.socket) -> tuple[str, int]:
    version, count = recv_exact(stream, 2)
    methods = recv_exact(stream, count)
    if version != 5 or 0 not in methods:
        raise AssertionError("invalid SOCKS no-auth greeting")
    stream.sendall(bytes((5, 0)))
    version, command, reserved, address_type = recv_exact(stream, 4)
    if (version, command, reserved) != (5, 1, 0) or address_type != 3:
        raise AssertionError("expected remote-DNS SOCKS CONNECT")
    length = recv_exact(stream, 1)[0]
    host = recv_exact(stream, length).decode("ascii")
    port = int.from_bytes(recv_exact(stream, 2), "big")
    return host, port


def relay(client: socket.socket, target_port: int) -> None:
    upstream = socket.create_connection(("127.0.0.1", target_port), timeout=5)
    with upstream:
        client.sendall(bytes((5, 0, 0, 1, 127, 0, 0, 1, 0, 0)))
        while True:
            ready, _, _ = select.select((client, upstream), (), (), 5)
            if not ready:
                raise TimeoutError("SOCKS relay stalled")
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                (upstream if source is client else client).sendall(data)


def serve_proxy(proxy: socket.socket, allowed_ports: set[int]) -> None:
    for _ in range(len(allowed_ports)):
        client, _ = proxy.accept()
        with client:
            host, target_port = read_socks_target(client)
            if host != "origin.internal" or target_port not in allowed_ports:
                raise AssertionError(f"wrong SOCKS target {host}:{target_port}")
            relay(client, target_port)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        ca, cert, key = create_identity(directory, "origin.internal")
        servers = [listener() for _ in range(6)]
        proxy = listener()
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.load_cert_chain(cert, key)
        ports = [server.getsockname()[1] for server in servers]
        errors: list[BaseException] = []

        def run(function, *arguments) -> None:
            try:
                function(*arguments)
            except BaseException as error:
                errors.append(error)

        threads = (
            threading.Thread(target=run, args=(serve_http, servers[0], None, b"/plain", b"http-socks")),
            threading.Thread(target=run, args=(serve_http, servers[1], tls_context, b"/secure", b"https-socks")),
            threading.Thread(target=run, args=(serve_websocket, servers[2], None, b"ws-socks")),
            threading.Thread(target=run, args=(serve_websocket, servers[3], tls_context, b"wss-socks")),
            threading.Thread(target=run, args=(serve_mqtt_websocket, servers[4], None, b"mqtt-ws-socks")),
            threading.Thread(target=run, args=(serve_mqtt_websocket, servers[5], tls_context, b"mqtt-wss-socks")),
            threading.Thread(target=run, args=(serve_proxy, proxy, set(ports))),
        )
        for thread in threads:
            thread.start()
        result = subprocess.run(
            (str(args.client), str(proxy.getsockname()[1]), *(str(value) for value in ports), str(ca)),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
        for thread in threads:
            thread.join(timeout=5)
        for server in (*servers, proxy):
            server.close()
        if any(thread.is_alive() for thread in threads):
            raise TimeoutError("HTTP/WebSocket SOCKS peer did not terminate")
        if result.returncode != 0:
            peer_errors = "\n".join(repr(error) for error in errors)
            raise RuntimeError(result.stdout + "\npeer errors:\n" + peer_errors)
        if errors:
            raise errors[0]
        expected = (
            "HTTP WebSocket SOCKS5 client passed: http=true https=true "
            "ws=true wss=true mqtt_ws=true mqtt_wss=true remote_dns=true "
            "tls_hostname=true deadline=true client_io=zio-std-io"
        )
        if expected not in result.stdout:
            raise AssertionError(f"missing client result: {result.stdout}")
        print(
            "HTTP WebSocket SOCKS5 interoperability passed: http=true "
            "https=true ws=true wss=true mqtt_ws=true mqtt_wss=true "
            "remote_dns=true tls13=true tls_hostname=true deadline=true "
            "client_io=zio-std-io peer_io=python-socket"
        )


if __name__ == "__main__":
    main()
