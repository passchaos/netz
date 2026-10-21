#!/usr/bin/env python3
"""RFC 9220 interoperability through an independent SOCKS5 UDP relay."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import threading

from http3_socks5_pool import (
    authenticate,
    encode_udp_source,
    find_go,
    free_udp_port,
    parse_udp_packet,
    read_request,
    wait_for_log,
)
from mqtt_socks5 import listener


def relay_websocket(
    proxy: socket.socket,
    relay: socket.socket,
    server_port: int,
    stats: dict[str, int],
) -> None:
    control, _ = proxy.accept()
    with control:
        control.settimeout(10)
        authenticate(control)
        command, host, port = read_request(control)
        if command != 3 or host not in ("0.0.0.0", "127.0.0.1") or port == 0:
            raise AssertionError(f"unexpected UDP ASSOCIATE: {command} {host}:{port}")
        relay_port = relay.getsockname()[1]
        control.sendall(
            bytes((5, 0, 0, 1, 0, 0, 0, 0))
            + relay_port.to_bytes(2, "big")
        )
        client_address: tuple[str, int] | None = None
        server_address = ("127.0.0.1", server_port)
        while True:
            ready, _, _ = select.select((control, relay), (), (), 10)
            if not ready:
                raise TimeoutError("RFC 9220 SOCKS relay stalled")
            if control in ready:
                if control.recv(1):
                    raise AssertionError("SOCKS control emitted trailing bytes")
                return
            packet, source = relay.recvfrom(65535)
            if source == server_address:
                if client_address is None:
                    raise AssertionError("server response preceded client datagram")
                relay.sendto(
                    encode_udp_source(source[0], source[1], packet),
                    client_address,
                )
                stats["responses"] += 1
                continue
            target_host, target_port, payload = parse_udp_packet(packet)
            if target_host != "localhost" or target_port != server_port:
                raise AssertionError(
                    f"RFC 9220 proxy target mismatch: {target_host}:{target_port}"
                )
            client_address = source
            stats["remote_dns_packets"] += 1
            relay.sendto(payload, server_address)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    args = parser.parse_args()
    go = find_go()
    module = Path(__file__).resolve().parent / "quic_go_module"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        go_server = directory / "websocket-h3-server"
        subprocess.run(
            (go, "build", "-mod=readonly", "-o", str(go_server), "./websocket_h3"),
            cwd=module,
            env={**os.environ, "GOTOOLCHAIN": "local"},
            check=True,
            timeout=60,
        )
        server_port = free_udp_port()
        ca = directory / "ca.pem"
        server_log = directory / "server.log"
        with server_log.open("w") as output:
            server = subprocess.Popen(
                (
                    str(go_server),
                    "-mode", "server",
                    "-addr", f"127.0.0.1:{server_port}",
                    "-ca-out", str(ca),
                ),
                text=True,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        wait_for_log(
            server,
            server_log,
            "quic-go RFC 9220 server listening=",
        )
        if not ca.is_file():
            raise RuntimeError("quic-go server did not write CA")

        proxy = listener()
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(("127.0.0.1", 0))
        relay.settimeout(10)
        stats = {"remote_dns_packets": 0, "responses": 0}
        errors: list[BaseException] = []

        def run() -> None:
            try:
                relay_websocket(proxy, relay, server_port, stats)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=run)
        thread.start()
        result = subprocess.run(
            (
                str(args.client),
                str(server_port),
                str(ca),
                f"--socks5-port={proxy.getsockname()[1]}",
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=25,
            check=False,
        )
        thread.join(timeout=5)
        proxy.close()
        relay.close()
        if result.returncode != 0 or errors:
            server.kill()
            server.wait()
            raise RuntimeError(
                result.stdout
                + "\npeer errors:\n"
                + "\n".join(repr(error) for error in errors)
                + f"\nstats={stats!r}\nserver:\n"
                + server_log.read_text()
            )
        try:
            server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
            raise TimeoutError(server_log.read_text())
        if thread.is_alive():
            raise TimeoutError("RFC 9220 SOCKS relay did not terminate")
        if server.returncode != 0:
            raise RuntimeError(
                result.stdout
                + "\npeer errors:\n"
                + "\n".join(repr(error) for error in errors)
                + "\nserver:\n"
                + server_log.read_text()
            )
        if stats["remote_dns_packets"] == 0 or stats["responses"] == 0:
            raise AssertionError(f"missing relay traffic: {stats}")
        if "netz RFC 9220 SOCKS5 route passed" not in result.stdout:
            raise AssertionError(result.stdout)
        if "quic-go RFC 9220 server interoperated with netz" not in server_log.read_text():
            raise AssertionError(server_log.read_text())
        print(
            "RFC 9220 SOCKS5 interoperability passed: extended_connect=true "
            "remote_dns=true tls_verified=true fragmented_text=true "
            "permessage_deflate=true ping_pong=true close=1000/done "
            "client_io=zio-std-io server_io=quic-go-netpoll"
        )


if __name__ == "__main__":
    main()
