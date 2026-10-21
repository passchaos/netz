#!/usr/bin/env python3
"""WebTransport interoperability through independent SOCKS5 UDP relays."""

from __future__ import annotations

import argparse
from pathlib import Path
import select
import socket
import subprocess
import threading
import time

from http3_socks5_pool import (
    authenticate,
    encode_udp_source,
    parse_udp_packet,
    read_request,
)
from mqtt_socks5 import listener


def relay_association(
    control: socket.socket,
    server_port: int,
    stats: dict[str, int],
) -> None:
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(("127.0.0.1", 0))
    relay.settimeout(10)
    try:
        relay_port = relay.getsockname()[1]
        control.sendall(
            bytes((5, 0, 0, 1, 0, 0, 0, 0))
            + relay_port.to_bytes(2, "big")
        )
        client_address: tuple[str, int] | None = None
        server_address = ("127.0.0.1", server_port)
        while True:
            ready, _, _ = select.select((control, relay), (), (), 12)
            if not ready:
                raise TimeoutError("WebTransport SOCKS relay stalled")
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
                    f"WebTransport proxy target mismatch: {target_host}:{target_port}"
                )
            client_address = source
            stats["remote_dns_packets"] += 1
            relay.sendto(payload, server_address)
    finally:
        relay.close()
        control.close()


def serve_proxy(
    proxy: socket.socket,
    server_port: int,
    stats: dict[str, int],
) -> None:
    workers: list[threading.Thread] = []
    worker_errors: list[BaseException] = []

    def run(control: socket.socket) -> None:
        try:
            relay_association(control, server_port, stats)
        except BaseException as error:
            worker_errors.append(error)

    for _ in range(2):
        control, _ = proxy.accept()
        control.settimeout(10)
        authenticate(control)
        command, host, port = read_request(control)
        if command != 3 or host not in ("0.0.0.0", "127.0.0.1") or port == 0:
            control.close()
            raise AssertionError(f"unexpected UDP ASSOCIATE: {command} {host}:{port}")
        stats["associations"] += 1
        worker = threading.Thread(target=run, args=(control,))
        worker.start()
        workers.append(worker)
    for worker in workers:
        worker.join(timeout=20)
    if any(worker.is_alive() for worker in workers):
        raise TimeoutError("WebTransport SOCKS relay worker did not terminate")
    if worker_errors:
        raise worker_errors[0]


def wait_for_port(process: subprocess.Popen[str], log: Path) -> int:
    prefix = "WTRANSPORT_PORT="
    for _ in range(300):
        if process.poll() is not None:
            raise RuntimeError(log.read_text())
        if log.exists():
            for line in log.read_text().splitlines():
                if line.startswith(prefix):
                    return int(line.removeprefix(prefix))
        time.sleep(0.05)
    raise TimeoutError(log.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    manifest = root / "tools/interop/webtransport_wtransport/Cargo.toml"
    subprocess.run(
        ("cargo", "build", "--quiet", "--release", "--locked", "--manifest-path", str(manifest)),
        check=True,
        timeout=180,
    )
    rust_peer = manifest.parent / "target/release/netz-webtransport-wtransport"
    server_log = manifest.parent / "target/webtransport-socks5-server.log"
    with server_log.open("w") as output:
        server = subprocess.Popen(
            (str(rust_peer), "server"),
            text=True,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
    server_port = wait_for_port(server, server_log)
    proxy = listener()
    stats = {"associations": 0, "remote_dns_packets": 0, "responses": 0}
    errors: list[BaseException] = []

    def run_proxy() -> None:
        try:
            serve_proxy(proxy, server_port, stats)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=run_proxy)
    thread.start()
    result = subprocess.run(
        (
            str(args.client),
            str(server_port),
            f"--socks5-port={proxy.getsockname()[1]}",
        ),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=40,
        check=False,
    )
    thread.join(timeout=8)
    proxy.close()
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
        server.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()
        raise TimeoutError(server_log.read_text())
    if thread.is_alive():
        raise TimeoutError("WebTransport SOCKS proxy did not terminate")
    if server.returncode != 0:
        raise RuntimeError(server_log.read_text())
    if stats["associations"] != 2 or stats["remote_dns_packets"] == 0 or stats["responses"] == 0:
        raise AssertionError(f"incomplete relay evidence: {stats}")
    if "netz WebTransport SOCKS5 route passed" not in result.stdout:
        raise AssertionError(result.stdout)
    if "wtransport server interop passed" not in server_log.read_text():
        raise AssertionError(server_log.read_text())
    print(
        "WebTransport SOCKS5 interoperability passed: associations=2 "
        "remote_dns=true rejection=404 connect=true datagram=true "
        "bidi=true uni=true reset=73 stop=74 recovery=true reuse=true "
        "peer_close=true client_io=zio-std-io server_io=wtransport-quinn-tokio"
    )


if __name__ == "__main__":
    main()
