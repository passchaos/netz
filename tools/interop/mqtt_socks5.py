#!/usr/bin/env python3
"""Independent SOCKS5 peers for native MQTT and certificate-verified TLS."""

from __future__ import annotations

import argparse
from pathlib import Path
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def listener() -> socket.socket:
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(10)
    return server


def recv_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        data = stream.recv(length - len(output))
        if not data:
            raise EOFError("unexpected peer EOF")
        output.extend(data)
    return bytes(output)


def read_mqtt_packet(stream: socket.socket) -> bytes:
    first = recv_exact(stream, 1)
    remaining = 0
    multiplier = 1
    encoded = bytearray(first)
    for _ in range(4):
        byte = recv_exact(stream, 1)[0]
        encoded.append(byte)
        remaining += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            encoded.extend(recv_exact(stream, remaining))
            return bytes(encoded)
        multiplier *= 128
    raise AssertionError("malformed MQTT Remaining Length")


def serve_mqtt(
    server: socket.socket,
    tls: ssl.SSLContext | None,
    expected_ids: tuple[bytes, ...],
) -> None:
    for expected_id in expected_ids:
        raw, _ = server.accept()
        with raw:
            stream = tls.wrap_socket(raw, server_side=True) if tls else raw
            with stream:
                connect = read_mqtt_packet(stream)
                if connect[0] != 0x10:
                    raise AssertionError(
                        f"expected CONNECT, got {connect.hex()}"
                    )
                if expected_id not in connect:
                    raise AssertionError(
                        f"SOCKS target expected {expected_id!r}"
                    )
                stream.sendall(bytes.fromhex("2003000000"))
                if read_mqtt_packet(stream) != bytes.fromhex("c000"):
                    raise AssertionError("expected PINGREQ")
                stream.sendall(bytes.fromhex("d000"))
                if read_mqtt_packet(stream) != bytes.fromhex("e000"):
                    raise AssertionError("expected DISCONNECT")


def read_socks_request(stream: socket.socket) -> tuple[str, int]:
    prefix = recv_exact(stream, 4)
    if prefix[:3] != bytes((5, 1, 0)):
        raise AssertionError(f"bad SOCKS CONNECT prefix: {prefix.hex()}")
    address_type = prefix[3]
    if address_type == 1:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(stream, 4))
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(stream, 16))
    elif address_type == 3:
        length = recv_exact(stream, 1)[0]
        host = recv_exact(stream, length).decode("ascii")
    else:
        raise AssertionError(f"unsupported SOCKS address type {address_type}")
    port = int.from_bytes(recv_exact(stream, 2), "big")
    return host, port


def relay(client: socket.socket, target_port: int, reply: bytes) -> None:
    upstream = socket.create_connection(("127.0.0.1", target_port), timeout=5)
    with upstream:
        client.sendall(reply)
        while True:
            ready, _, _ = select.select((client, upstream), (), (), 5)
            if not ready:
                raise TimeoutError("SOCKS relay stalled")
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                (upstream if source is client else client).sendall(data)


def read_greeting(stream: socket.socket) -> tuple[int, ...]:
    version, count = recv_exact(stream, 2)
    if version != 5 or count == 0:
        raise AssertionError("invalid SOCKS greeting")
    return tuple(recv_exact(stream, count))


def serve_no_auth(proxy: socket.socket, target_port: int) -> None:
    delayed, _ = proxy.accept()
    with delayed:
        if 0 not in read_greeting(delayed):
            raise AssertionError("timeout client omitted no-auth method")
        time.sleep(0.15)
        try:
            delayed.sendall(bytes((5, 0)))
        except OSError:
            pass

    for _ in range(3):
        client, _ = proxy.accept()
        with client:
            if 0 not in read_greeting(client):
                raise AssertionError("client omitted no-auth method")
            client.sendall(bytes((5, 0)))
            host, port = read_socks_request(client)
            if host != "broker.internal" or port != target_port:
                raise AssertionError(f"proxy target mismatch: {host}:{port}")
            relay(
                client,
                target_port,
                bytes((5, 0, 0, 1, 127, 0, 0, 1, 0, 0)),
            )


def authenticate(stream: socket.socket, accept: bool) -> None:
    methods = read_greeting(stream)
    if 2 not in methods:
        raise AssertionError("client omitted username/password method")
    stream.sendall(bytes((5, 2)))
    version, username_len = recv_exact(stream, 2)
    if version != 1 or username_len == 0:
        raise AssertionError("invalid RFC 1929 request")
    username = recv_exact(stream, username_len)
    password_len = recv_exact(stream, 1)[0]
    password = recv_exact(stream, password_len)
    valid = username == b"user" and password == b"pass:word"
    stream.sendall(bytes((1, 0 if accept and valid else 1)))
    if accept and not valid:
        raise AssertionError("valid proxy credentials were not received")


def serve_auth(proxy: socket.socket, target_port: int) -> None:
    rejected, _ = proxy.accept()
    with rejected:
        authenticate(rejected, False)

    for _ in range(2):
        client, _ = proxy.accept()
        with client:
            authenticate(client, True)
            host, port = read_socks_request(client)
            if host != "broker.internal" or port != target_port:
                raise AssertionError(
                    f"TLS proxy target mismatch: {host}:{port}"
                )
            bound = b"proxy.bound"
            relay(
                client,
                target_port,
                bytes((5, 0, 0, 3, len(bound))) + bound + bytes((0, 0)),
            )


def create_identity(
    directory: Path,
    host: str = "broker.internal",
) -> tuple[Path, Path, Path]:
    ca = directory / "ca.pem"
    ca_key = directory / "ca.key"
    key = directory / "server.key"
    csr = directory / "server.csr"
    cert = directory / "server.pem"
    extensions = directory / "server.ext"
    extensions.write_text(
        f"subjectAltName=DNS:{host}\n"
        "extendedKeyUsage=serverAuth\n"
    )
    commands = (
        (
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=Netz SOCKS Test CA", "-days", "1",
            "-keyout", str(ca_key), "-out", str(ca),
        ),
        (
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN={host}", "-keyout", str(key),
            "-out", str(csr),
        ),
        (
            "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
            "-extfile", str(extensions), "-out", str(cert),
        ),
    )
    for command in commands:
        subprocess.run(command, check=True, capture_output=True)
    return ca, cert, key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        ca, cert, key = create_identity(directory)
        clear_server = listener()
        tls_server = listener()
        no_auth_proxy = listener()
        auth_proxy = listener()
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.load_cert_chain(cert, key)

        errors: list[BaseException] = []

        def run(function, *arguments) -> None:
            try:
                function(*arguments)
            except BaseException as error:
                errors.append(error)

        threads = (
            threading.Thread(
                target=run,
                args=(
                    serve_mqtt,
                    clear_server,
                    None,
                    (
                        b"socks-clear",
                        b"socks-auth-fallback",
                        b"socks-reconnect",
                    ),
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    serve_mqtt,
                    tls_server,
                    tls_context,
                    (b"socks-tls", b"socks-tls-reconnect"),
                ),
            ),
            threading.Thread(
                target=run,
                args=(serve_no_auth, no_auth_proxy, clear_server.getsockname()[1]),
            ),
            threading.Thread(
                target=run,
                args=(serve_auth, auth_proxy, tls_server.getsockname()[1]),
            ),
        )
        for thread in threads:
            thread.start()
        result = subprocess.run(
            (
                str(args.client),
                str(no_auth_proxy.getsockname()[1]),
                str(auth_proxy.getsockname()[1]),
                str(clear_server.getsockname()[1]),
                str(tls_server.getsockname()[1]),
                str(ca),
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
        for thread in threads:
            thread.join(timeout=5)
        for server in (clear_server, tls_server, no_auth_proxy, auth_proxy):
            server.close()
        if any(thread.is_alive() for thread in threads):
            raise TimeoutError("SOCKS/MQTT peer did not terminate")
        if errors:
            raise errors[0]
        if result.returncode != 0:
            raise RuntimeError(result.stdout)
        expected = (
            "MQTT SOCKS5 client passed: remote_dns=true no_auth=true "
            "auth_fallback=true "
            "auth=true auth_failure=true timeout=true reconnect=true "
            "tls_reconnect=true tls_verified=true "
            "client_io=zio-std-io"
        )
        if expected not in result.stdout:
            raise AssertionError(f"missing client result: {result.stdout}")
        print(
            "MQTT SOCKS5 interoperability passed: remote_dns=true "
            "no_auth=true auth_fallback=true rfc1929=true "
            "auth_failure=true timeout=true "
            "mqtt=true mqtt_tls13=true reconnect=true tls_reconnect=true "
            "tls_hostname=true "
            "client_io=zio-std-io peer_io=python-socket"
        )


if __name__ == "__main__":
    main()
