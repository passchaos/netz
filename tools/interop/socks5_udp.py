#!/usr/bin/env python3
"""Independent RFC 1928 UDP ASSOCIATE and UDP relay peer."""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import subprocess
import threading

from mqtt_socks5 import listener, recv_exact


def udp_socket() -> socket.socket:
    value = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    value.bind(("127.0.0.1", 0))
    value.settimeout(8)
    return value


def authenticate(stream: socket.socket) -> None:
    version, count = recv_exact(stream, 2)
    methods = recv_exact(stream, count)
    if version != 5 or methods != bytes((2,)):
        raise AssertionError(f"expected strict RFC 1929 offer, got {methods!r}")
    stream.sendall(bytes((5, 2)))
    auth_version, username_length = recv_exact(stream, 2)
    username = recv_exact(stream, username_length)
    password_length = recv_exact(stream, 1)[0]
    password = recv_exact(stream, password_length)
    if auth_version != 1 or username != b"user" or password != b"secret":
        stream.sendall(bytes((1, 1)))
        raise AssertionError("invalid UDP proxy credentials")
    stream.sendall(bytes((1, 0)))


def read_address(data: bytes, offset: int) -> tuple[str, int, int]:
    address_type = data[offset]
    offset += 1
    if address_type == 1:
        host = socket.inet_ntop(socket.AF_INET, data[offset : offset + 4])
        offset += 4
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, data[offset : offset + 16])
        offset += 16
    elif address_type == 3:
        length = data[offset]
        offset += 1
        host = data[offset : offset + length].decode("ascii")
        offset += length
    else:
        raise AssertionError(f"unsupported SOCKS address type {address_type}")
    port = int.from_bytes(data[offset : offset + 2], "big")
    return host, port, offset + 2


def read_associate_request(stream: socket.socket) -> None:
    prefix = recv_exact(stream, 4)
    if prefix != bytes((5, 3, 0, 1)):
        raise AssertionError(f"bad UDP ASSOCIATE prefix: {prefix.hex()}")
    if recv_exact(stream, 6) != bytes(6):
        raise AssertionError("default UDP ASSOCIATE was not wildcard-bound")


def encode_ipv4_datagram(
    source_host: str,
    source_port: int,
    payload: bytes,
    fragment: int = 0,
) -> bytes:
    return (
        bytes((0, 0, fragment, 1))
        + socket.inet_pton(socket.AF_INET, source_host)
        + source_port.to_bytes(2, "big")
        + payload
    )


def serve_echo(echo: socket.socket) -> None:
    for _ in range(2):
        payload, client = echo.recvfrom(65535)
        echo.sendto(b"peer:" + payload, client)


def serve_proxy(
    proxy: socket.socket,
    relay: socket.socket,
    echo_port: int,
) -> None:
    client, _ = proxy.accept()
    with client:
        client.settimeout(8)
        authenticate(client)
        read_associate_request(client)
        relay_port = relay.getsockname()[1]
        client.sendall(
            bytes((5, 0, 0, 1, 0, 0, 0, 0))
            + relay_port.to_bytes(2, "big")
        )

        packet, udp_client = relay.recvfrom(65535)
        if packet[:3] != bytes((0, 0, 0)):
            raise AssertionError(f"bad UDP request prefix: {packet[:3].hex()}")
        host, port, payload_offset = read_address(packet, 3)
        if host != "echo.internal" or port != echo_port:
            raise AssertionError(f"UDP target mismatch: {host}:{port}")
        relay.sendto(packet[payload_offset:], ("127.0.0.1", echo_port))
        echoed, source = relay.recvfrom(65535)
        if source != ("127.0.0.1", echo_port):
            raise AssertionError(f"unexpected echo source: {source}")
        relay.sendto(
            encode_ipv4_datagram(source[0], source[1], b"ignored", fragment=1),
            udp_client,
        )
        relay.sendto(
            encode_ipv4_datagram(source[0], source[1], echoed),
            udp_client,
        )

        endpoint_packet, endpoint_client = relay.recvfrom(65535)
        if endpoint_packet[:3] != bytes((0, 0, 0)):
            raise AssertionError("bad QUIC endpoint SOCKS prefix")
        endpoint_host, endpoint_port, endpoint_payload_offset = read_address(
            endpoint_packet,
            3,
        )
        if endpoint_host != "127.0.0.1" or endpoint_port != echo_port:
            raise AssertionError(
                f"QUIC endpoint target mismatch: {endpoint_host}:{endpoint_port}"
            )
        relay.sendto(
            endpoint_packet[endpoint_payload_offset:],
            (endpoint_host, endpoint_port),
        )
        endpoint_echoed, endpoint_source = relay.recvfrom(65535)
        relay.sendto(
            encode_ipv4_datagram(
                endpoint_source[0],
                endpoint_source[1],
                endpoint_echoed,
            ),
            endpoint_client,
        )
        if client.recv(1) != b"":
            raise AssertionError("UDP association control emitted trailing bytes")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    args = parser.parse_args()
    proxy = listener()
    relay = udp_socket()
    echo = udp_socket()
    errors: list[BaseException] = []

    def run(function, *arguments) -> None:
        try:
            function(*arguments)
        except BaseException as error:
            errors.append(error)

    threads = (
        threading.Thread(target=run, args=(serve_echo, echo)),
        threading.Thread(
            target=run,
            args=(serve_proxy, proxy, relay, echo.getsockname()[1]),
        ),
    )
    for thread in threads:
        thread.start()
    result = subprocess.run(
        (
            str(args.client),
            str(proxy.getsockname()[1]),
            str(echo.getsockname()[1]),
            str(relay.getsockname()[1]),
        ),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
        check=False,
    )
    for thread in threads:
        thread.join(timeout=3)
    proxy.close()
    relay.close()
    echo.close()
    if any(thread.is_alive() for thread in threads):
        raise TimeoutError("SOCKS5 UDP peers did not terminate")
    if result.returncode != 0:
        peer_errors = "\n".join(repr(error) for error in errors)
        raise RuntimeError(result.stdout + "\npeer errors:\n" + peer_errors)
    if errors:
        raise errors[0]
    expected = (
        "SOCKS5 UDP client passed: command=udp-associate auth=strict "
        "remote_dns=true wildcard_reply=true fragments=rejected "
        "control_lifetime=true quic_endpoint=true ecn_gso_gro=fallback "
        "client_io=zio-std-io"
    )
    if expected not in result.stdout:
        raise AssertionError(f"missing client result: {result.stdout}")
    print(
        "SOCKS5 UDP interoperability passed: command=udp-associate "
        "auth=rfc1929 remote_dns=true wildcard_reply=true "
        "fragments=rejected control_lifetime=true "
        "quic_endpoint=true ecn_gso_gro=fallback "
        "client_io=zio-std-io peer_io=python-socket"
    )


if __name__ == "__main__":
    main()
