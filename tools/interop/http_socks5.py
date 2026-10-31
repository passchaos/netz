#!/usr/bin/env python3
"""Independent HTTP/1, HTTP/2, redirect, and pool peers behind SOCKS5."""

from __future__ import annotations

import argparse
from pathlib import Path
import select
import socket
import ssl
import subprocess
import tempfile
import threading

from mqtt_socks5 import create_identity, listener, recv_exact
from http_websocket_socks5 import parse_headers, read_head


def response(stream: socket.socket, body: bytes, close: bool) -> None:
    stream.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(body)).encode()
        + (b"\r\nConnection: close" if close else b"")
        + b"\r\n\r\n"
        + body
    )


def serve_redirect(server: socket.socket, final_port: int) -> None:
    client, _ = server.accept()
    with client:
        request, headers = parse_headers(read_head(client))
        if request != b"GET /start HTTP/1.1":
            raise AssertionError("wrong HTTP redirect request")
        if headers.get(b"authorization") != b"Bearer http-redirect-secret":
            raise AssertionError("redirect origin lost Authorization")
        client.sendall(
            b"HTTP/1.1 307 Temporary Redirect\r\nContent-Length: 0\r\n"
            b"Connection: close\r\nLocation: "
            + f"http://origin.internal:{final_port}/final".encode()
            + b"\r\n\r\n"
        )


def serve_final(server: socket.socket) -> None:
    client, _ = server.accept()
    with client:
        request, headers = parse_headers(read_head(client))
        if request != b"GET /final HTTP/1.1":
            raise AssertionError("wrong redirected HTTP target")
        if b"authorization" in headers:
            raise AssertionError("cross-origin HTTP Authorization leaked")
        response(client, b"redirect-final", True)


def read_frame(stream: socket.socket) -> tuple[int, int, int, bytes]:
    header = recv_exact(stream, 9)
    length = int.from_bytes(header[0:3], "big")
    frame_type = header[3]
    flags = header[4]
    stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
    return frame_type, flags, stream_id, recv_exact(stream, length)


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes((frame_type, flags))
        + stream_id.to_bytes(4, "big")
        + payload
    )


def serve_h2(
    server: socket.socket,
    context: ssl.SSLContext,
    response_body: bytes,
) -> None:
    raw, _ = server.accept()
    with raw:
        with context.wrap_socket(raw, server_side=True) as client:
            if client.selected_alpn_protocol() != "h2":
                raise AssertionError("unified client did not negotiate h2")
            client.sendall(frame(4, 0, 0, b""))
            if recv_exact(client, 24) != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
                raise AssertionError("missing HTTP/2 preface")
            request_stream = None
            while request_stream is None:
                frame_type, flags, stream_id, _ = read_frame(client)
                if frame_type == 4 and not flags & 1:
                    client.sendall(frame(4, 1, 0, b""))
                elif frame_type == 1:
                    request_stream = stream_id
            client.sendall(frame(1, 4, request_stream, bytes((0x88,))))
            client.sendall(frame(0, 1, request_stream, response_body))


def serve_pool(server: socket.socket) -> None:
    client, _ = server.accept()
    with client:
        for body in (b"pool-one", b"pool-two"):
            request, headers = parse_headers(read_head(client))
            if request != b"GET /pool HTTP/1.1":
                raise AssertionError("wrong pooled HTTP request")
            if not headers.get(b"host", b"").startswith(b"origin.internal:"):
                raise AssertionError("pooled request lost origin authority")
            response(client, body, False)
        if client.recv(1) != b"":
            raise AssertionError("pooled connection emitted bytes during close")


def read_socks_target(client: socket.socket) -> tuple[str, int]:
    version, count = recv_exact(client, 2)
    methods = recv_exact(client, count)
    if version != 5 or 0 not in methods:
        raise AssertionError("bad SOCKS greeting")
    client.sendall(bytes((5, 0)))
    version, command, reserved, address_type = recv_exact(client, 4)
    if (version, command, reserved, address_type) != (5, 1, 0, 3):
        raise AssertionError("HTTP client did not use remote SOCKS DNS")
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
                raise TimeoutError("HTTP SOCKS relay stalled")
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
                    f"expected origin.internal:{expected_port}, "
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
        redirect, final, h2, direct_h2, pooled = (listener() for _ in range(5))
        proxy = listener()
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.set_alpn_protocols(["h2"])
        tls_context.load_cert_chain(cert, key)
        ports = tuple(
            server.getsockname()[1]
            for server in (redirect, final, h2, direct_h2, pooled)
        )
        trace: list[int] = []
        errors: list[BaseException] = []

        def run(function, *arguments) -> None:
            try:
                function(*arguments)
            except BaseException as error:
                errors.append(error)

        threads = (
            threading.Thread(target=run, args=(serve_redirect, redirect, ports[1])),
            threading.Thread(target=run, args=(serve_final, final)),
            threading.Thread(
                target=run,
                args=(serve_h2, h2, tls_context, b"h2-socks"),
            ),
            threading.Thread(
                target=run,
                args=(serve_h2, direct_h2, tls_context, b"h2-direct-socks"),
            ),
            threading.Thread(target=run, args=(serve_pool, pooled)),
            threading.Thread(target=run, args=(serve_proxy, proxy, ports, trace)),
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
            timeout=20,
            check=False,
        )
        for thread in threads:
            thread.join(timeout=5)
        for server in (redirect, final, h2, direct_h2, pooled, proxy):
            server.close()
        if any(thread.is_alive() for thread in threads):
            raise TimeoutError("HTTP SOCKS peers did not terminate")
        if result.returncode != 0:
            peer_errors = "\n".join(repr(error) for error in errors)
            raise RuntimeError(result.stdout + "\npeer errors:\n" + peer_errors)
        if errors:
            raise errors[0]
        if tuple(trace) != ports:
            raise AssertionError(f"HTTP SOCKS tunnel trace mismatch: {trace}")
        expected = (
            "HTTP SOCKS5 client passed: redirects=1 http1=true http2=true "
            "http2_direct=true alpn=h2 pool_requests=2 pool_tunnels=1 "
            "total_tunnels=5 "
            "remote_dns=true credentials_isolated=true tls_hostname=true "
            "deadline=true client_io=zio-std-io"
        )
        if expected not in result.stdout:
            raise AssertionError(f"missing client result: {result.stdout}")
        print(
            "HTTP SOCKS5 interoperability passed: redirects=1 http1=true "
            "http2=true http2_direct=true alpn=h2 pool_requests=2 "
            "pool_tunnels=1 total_tunnels=5 remote_dns=true "
            "credentials_isolated=true "
            "tls13=true tls_hostname=true deadline=true "
            "client_io=zio-std-io peer_io=python-socket"
        )


if __name__ == "__main__":
    main()
