#!/usr/bin/env python3
"""Independent multi-authority redirects through fresh SOCKS5 tunnels."""

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

from mqtt_socks5 import create_identity, listener, recv_exact
from http_websocket_socks5 import (
    parse_headers,
    read_frame,
    read_head,
    send_frame,
)


def redirect_response(stream: socket.socket, location: str) -> None:
    stream.sendall(
        b"HTTP/1.1 307 Temporary Redirect\r\n"
        b"Content-Length: 0\r\nConnection: close\r\nLocation: "
        + location.encode()
        + b"\r\n\r\n"
    )


def assert_authorization(headers: dict[bytes, bytes], present: bool) -> None:
    actual = headers.get(b"authorization")
    if present and actual != b"Bearer redirect-secret":
        raise AssertionError("redirect origin lost Authorization")
    if not present and actual is not None:
        raise AssertionError("cross-origin Authorization leaked")


def accept_upgrade(
    stream: socket.socket,
    target: bytes,
    mqtt: bool,
    authorization: bool,
) -> None:
    request_line, headers = parse_headers(read_head(stream))
    if request_line != b"GET " + target + b" HTTP/1.1":
        raise AssertionError(f"unexpected Upgrade target {request_line!r}")
    assert_authorization(headers, authorization)
    key = headers.get(b"sec-websocket-key")
    if key is None:
        raise AssertionError("missing WebSocket key")
    if mqtt and headers.get(b"sec-websocket-protocol") != b"mqtt":
        raise AssertionError("missing mqtt subprotocol")
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


def serve_ws_redirect(server: socket.socket, final_port: int) -> None:
    client, _ = server.accept()
    with client:
        request, headers = parse_headers(read_head(client))
        if request != b"GET /start HTTP/1.1":
            raise AssertionError("wrong WS redirect target")
        assert_authorization(headers, True)
        redirect_response(
            client,
            f"ws://origin.internal:{final_port}/final",
        )


def serve_ws_final(server: socket.socket) -> None:
    client, _ = server.accept()
    with client:
        accept_upgrade(client, b"/final", False, False)
        opcode, payload = read_frame(client)
        if opcode != 1 or payload != b"redirect-socks":
            raise AssertionError("wrong redirected WebSocket message")
        send_frame(client, 1, payload)
        opcode, payload = read_frame(client)
        if opcode != 8:
            raise AssertionError("missing redirected WebSocket Close")
        send_frame(client, 8, payload)


def serve_mqtt_redirect(
    server: socket.socket,
    context: ssl.SSLContext,
    final_port: int,
) -> None:
    for _ in range(2):
        raw, _ = server.accept()
        with raw:
            with context.wrap_socket(raw, server_side=True) as client:
                request, headers = parse_headers(read_head(client))
                if request != b"GET /mqtt-start HTTP/1.1":
                    raise AssertionError("wrong MQTT redirect target")
                assert_authorization(headers, True)
                redirect_response(
                    client,
                    f"wss://origin.internal:{final_port}/mqtt",
                )


def serve_mqtt_final(
    server: socket.socket,
    context: ssl.SSLContext,
) -> None:
    for index in range(2):
        raw, _ = server.accept()
        with raw:
            with context.wrap_socket(raw, server_side=True) as client:
                accept_upgrade(client, b"/mqtt", True, False)
                opcode, connect = read_frame(client)
                expected = f"mqtt-socks-reconnect-{index + 1}".encode()
                if opcode != 2 or connect[0] != 0x10 or expected not in connect:
                    raise AssertionError("wrong redirected MQTT CONNECT")
                send_frame(client, 2, bytes.fromhex("2003000000"))
                opcode, ping = read_frame(client)
                if opcode != 2 or ping != bytes.fromhex("c000"):
                    raise AssertionError("wrong redirected MQTT PINGREQ")
                send_frame(client, 2, bytes.fromhex("d000"))
                opcode, disconnect = read_frame(client)
                if opcode != 2 or disconnect != bytes.fromhex("e000"):
                    raise AssertionError("wrong redirected MQTT DISCONNECT")


def read_socks_target(client: socket.socket) -> tuple[str, int]:
    version, count = recv_exact(client, 2)
    methods = recv_exact(client, count)
    if version != 5 or 0 not in methods:
        raise AssertionError("bad SOCKS greeting")
    client.sendall(bytes((5, 0)))
    version, command, reserved, address_type = recv_exact(client, 4)
    if (version, command, reserved, address_type) != (5, 1, 0, 3):
        raise AssertionError("expected remote-DNS SOCKS CONNECT")
    length = recv_exact(client, 1)[0]
    host = recv_exact(client, length).decode()
    target_port = int.from_bytes(recv_exact(client, 2), "big")
    return host, target_port


def relay(client: socket.socket, target_port: int) -> None:
    upstream = socket.create_connection(("127.0.0.1", target_port), timeout=5)
    with upstream:
        client.sendall(bytes((5, 0, 0, 1, 127, 0, 0, 1, 0, 0)))
        while True:
            ready, _, _ = select.select((client, upstream), (), (), 5)
            if not ready:
                raise TimeoutError("redirect SOCKS relay stalled")
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                (upstream if source is client else client).sendall(data)


def serve_proxy(
    proxy: socket.socket,
    expected_ports: tuple[int, ...],
    trace: list[int],
) -> None:
    for expected_port in expected_ports:
        client, _ = proxy.accept()
        with client:
            host, target_port = read_socks_target(client)
            if host != "origin.internal" or target_port != expected_port:
                raise AssertionError(
                    f"SOCKS hop expected origin.internal:{expected_port}, "
                    f"got {host}:{target_port}"
                )
            trace.append(target_port)
            relay(client, target_port)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        ca, cert, key = create_identity(directory, "origin.internal")
        ws_redirect, ws_final, mqtt_redirect, mqtt_final = (
            listener() for _ in range(4)
        )
        proxy = listener()
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.load_cert_chain(cert, key)
        ports = (
            ws_redirect.getsockname()[1],
            ws_final.getsockname()[1],
            mqtt_redirect.getsockname()[1],
            mqtt_final.getsockname()[1],
        )
        expected_hops = (
            ports[0], ports[1],
            ports[2], ports[3],
            ports[2], ports[3],
        )
        trace: list[int] = []
        errors: list[BaseException] = []

        def run(function, *arguments) -> None:
            try:
                function(*arguments)
            except BaseException as error:
                errors.append(error)

        threads = (
            threading.Thread(target=run, args=(serve_ws_redirect, ws_redirect, ports[1])),
            threading.Thread(target=run, args=(serve_ws_final, ws_final)),
            threading.Thread(target=run, args=(serve_mqtt_redirect, mqtt_redirect, tls_context, ports[3])),
            threading.Thread(target=run, args=(serve_mqtt_final, mqtt_final, tls_context)),
            threading.Thread(target=run, args=(serve_proxy, proxy, expected_hops, trace)),
        )
        for thread in threads:
            thread.start()
        result = subprocess.run(
            (
                str(args.client), str(proxy.getsockname()[1]),
                *(str(value) for value in ports), str(ca),
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=25,
            check=False,
        )
        for thread in threads:
            thread.join(timeout=5)
        for server in (ws_redirect, ws_final, mqtt_redirect, mqtt_final, proxy):
            server.close()
        if any(thread.is_alive() for thread in threads):
            raise TimeoutError("redirect peers did not terminate")
        if result.returncode != 0:
            peer_errors = "\n".join(repr(error) for error in errors)
            raise RuntimeError(result.stdout + "\npeer errors:\n" + peer_errors)
        if errors:
            raise errors[0]
        if tuple(trace) != expected_hops:
            raise AssertionError(f"SOCKS hop trace mismatch: {trace}")
        expected = (
            "WebSocket SOCKS5 redirect client passed: ws_redirects=1 "
            "mqtt_reconnect_chains=2 fresh_tunnels=6 remote_dns=true "
            "credentials_isolated=true tls_hostname=true deadline=true "
            "client_io=zio-std-io"
        )
        if expected not in result.stdout:
            raise AssertionError(f"missing client result: {result.stdout}")
        print(
            "WebSocket SOCKS5 redirect interoperability passed: "
            "ws_redirects=1 mqtt_reconnect_chains=2 fresh_tunnels=6 "
            "remote_dns=true credentials_isolated=true tls13=true "
            "tls_hostname=true deadline=true client_io=zio-std-io "
            "peer_io=python-socket"
        )


if __name__ == "__main__":
    main()
