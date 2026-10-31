#!/usr/bin/env python3
"""Authenticated SOCKS5 relay for the Netz to grpc-cpp TLS gate."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import threading

from mqtt_socks5 import authenticate, listener, read_socks_request, relay


def serve(proxy, origin_port: int) -> None:
    client, _ = proxy.accept()
    with client:
        authenticate(client, True)
        host, port = read_socks_request(client)
        if host != "foo.test.google.fr" or port != origin_port:
            raise AssertionError(f"SOCKS target mismatch: {host}:{port}")
        relay(
            client,
            origin_port,
            bytes((5, 0, 0, 1, 127, 0, 0, 1, 0, 0)),
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    parser.add_argument("origin_port", type=int)
    parser.add_argument("ca_file", type=Path)
    args = parser.parse_args()

    proxy = listener()
    errors: list[BaseException] = []

    def run() -> None:
        try:
            serve(proxy, args.origin_port)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    result = subprocess.run(
        (
            str(args.client),
            str(args.origin_port),
            str(args.ca_file),
            str(proxy.getsockname()[1]),
        ),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    thread.join(timeout=5)
    proxy.close()
    if thread.is_alive():
        raise TimeoutError("gRPC SOCKS5 relay did not terminate")
    if errors:
        raise errors[0]
    if result.returncode != 0:
        raise RuntimeError(result.stdout)
    expected = (
        "netz gRPC tunneled grpc-cpp TLS through SOCKS5: "
        "rpcs=2 remote_dns=true rfc1929=true auth_downgrade=false "
        "tls_identity=foo.test.google.fr certificate_verified=true "
        "alpn=h2 connection_reused=true client_io=zio-std-io "
        "proxy_io=python-socket server_io=grpc-cpp-posix-event-engine"
    )
    if expected not in result.stdout:
        raise AssertionError(f"missing client result: {result.stdout}")
    print(result.stdout, end="")
    print(
        "Python SOCKS5 tunneled netz gRPC TLS: remote_dns=true "
        "rfc1929=true auth_downgrade=false target=foo.test.google.fr "
        "tunnels=1 rpcs=2 connection_reused=true"
    )


if __name__ == "__main__":
    main()
