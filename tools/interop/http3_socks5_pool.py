#!/usr/bin/env python3
"""HTTPS discovery plus HTTP/3 pool reuse through one SOCKS5 proxy."""

from __future__ import annotations

import argparse
import glob
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from http_websocket_socks5 import parse_headers, read_head
from mqtt_socks5 import create_identity, listener, recv_exact


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as value:
        value.bind(("127.0.0.1", 0))
        return value.getsockname()[1]


def authenticate(stream: socket.socket) -> None:
    version, count = recv_exact(stream, 2)
    methods = recv_exact(stream, count)
    if version != 5 or methods != bytes((2,)):
        raise AssertionError(f"expected strict RFC 1929 offer, got {methods!r}")
    stream.sendall(bytes((5, 2)))
    auth_version, username_len = recv_exact(stream, 2)
    username = recv_exact(stream, username_len)
    password_len = recv_exact(stream, 1)[0]
    password = recv_exact(stream, password_len)
    if auth_version != 1 or username != b"user" or password != b"secret":
        stream.sendall(bytes((1, 1)))
        raise AssertionError("invalid proxy credentials")
    stream.sendall(bytes((1, 0)))


def read_address_stream(stream: socket.socket, address_type: int) -> str:
    if address_type == 1:
        return socket.inet_ntop(socket.AF_INET, recv_exact(stream, 4))
    if address_type == 4:
        return socket.inet_ntop(socket.AF_INET6, recv_exact(stream, 16))
    if address_type == 3:
        length = recv_exact(stream, 1)[0]
        return recv_exact(stream, length).decode("ascii")
    raise AssertionError(f"unsupported SOCKS address type {address_type}")


def read_request(stream: socket.socket) -> tuple[int, str, int]:
    version, command, reserved, address_type = recv_exact(stream, 4)
    if version != 5 or reserved != 0:
        raise AssertionError("invalid SOCKS command prefix")
    host = read_address_stream(stream, address_type)
    port = int.from_bytes(recv_exact(stream, 2), "big")
    return command, host, port


def relay_tcp(client: socket.socket, origin_port: int) -> None:
    with client:
        upstream = socket.create_connection(("127.0.0.1", origin_port), timeout=5)
        with upstream:
            client.sendall(bytes((5, 0, 0, 1, 127, 0, 0, 1, 0, 0)))
            while True:
                ready, _, _ = select.select((client, upstream), (), (), 8)
                if not ready:
                    raise TimeoutError("SOCKS TCP relay stalled")
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is client else client).sendall(data)


def parse_udp_packet(packet: bytes) -> tuple[str, int, bytes]:
    if len(packet) < 4 or packet[:3] != bytes((0, 0, 0)):
        raise AssertionError(f"invalid SOCKS UDP prefix: {packet[:4].hex()}")
    address_type = packet[3]
    offset = 4
    if address_type == 1:
        host = socket.inet_ntop(socket.AF_INET, packet[offset : offset + 4])
        offset += 4
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, packet[offset : offset + 16])
        offset += 16
    elif address_type == 3:
        length = packet[offset]
        offset += 1
        host = packet[offset : offset + length].decode("ascii")
        offset += length
    else:
        raise AssertionError(f"unsupported SOCKS UDP address type {address_type}")
    port = int.from_bytes(packet[offset : offset + 2], "big")
    return host, port, packet[offset + 2 :]


def encode_udp_source(host: str, port: int, payload: bytes) -> bytes:
    return (
        bytes((0, 0, 0, 1))
        + socket.inet_pton(socket.AF_INET, host)
        + port.to_bytes(2, "big")
        + payload
    )


def relay_udp(
    control: socket.socket,
    relay: socket.socket,
    h3_port: int,
    target_hosts: set[str],
    stats: dict[str, int],
) -> None:
    with control:
        relay_port = relay.getsockname()[1]
        control.sendall(
            bytes((5, 0, 0, 1, 0, 0, 0, 0))
            + relay_port.to_bytes(2, "big")
        )
        client_address: tuple[str, int] | None = None
        server_address = ("127.0.0.1", h3_port)
        while True:
            ready, _, _ = select.select((control, relay), (), (), 10)
            if not ready:
                raise TimeoutError("SOCKS UDP relay stalled")
            if control in ready:
                trailing = control.recv(1)
                if trailing:
                    raise AssertionError("UDP control emitted trailing bytes")
                return
            packet, source = relay.recvfrom(65535)
            if source == server_address:
                if client_address is None:
                    raise AssertionError("HTTP/3 response preceded client packet")
                relay.sendto(
                    encode_udp_source(source[0], source[1], packet),
                    client_address,
                )
                stats["responses"] += 1
                continue
            host, port, payload = parse_udp_packet(packet)
            if host not in target_hosts or port != h3_port:
                raise AssertionError(f"HTTP/3 proxy target mismatch: {host}:{port}")
            client_address = source
            stats["remote_dns_packets"] += 1
            stats[f"domain:{host}"] += 1
            relay.sendto(payload, server_address)


def serve_proxy(
    proxy: socket.socket,
    relay: socket.socket,
    origin_routes: dict[tuple[str, int], int],
    h3_port: int,
    target_hosts: set[str],
    trace: list[str],
    stats: dict[str, int],
) -> None:
    workers: list[threading.Thread] = []
    worker_errors: list[BaseException] = []

    def run_worker(function, *arguments) -> None:
        try:
            function(*arguments)
        except BaseException as error:
            worker_errors.append(error)

    for _ in range(4):
        client, _ = proxy.accept()
        client.settimeout(10)
        authenticate(client)
        command, host, port = read_request(client)
        if command == 1:
            target_port = origin_routes.get((host, port))
            if target_port is None:
                raise AssertionError(f"CONNECT target mismatch: {host}:{port}")
            trace.append("connect")
            worker = threading.Thread(
                target=run_worker,
                args=(relay_tcp, client, target_port),
            )
        elif command == 3:
            if host != "0.0.0.0" or port == 0:
                raise AssertionError(f"UDP ASSOCIATE endpoint mismatch: {host}:{port}")
            trace.append("udp-associate")
            worker = threading.Thread(
                target=run_worker,
                args=(relay_udp, client, relay, h3_port, target_hosts, stats),
            )
        else:
            client.close()
            raise AssertionError(f"unexpected SOCKS command {command}")
        worker.start()
        workers.append(worker)
    for worker in workers:
        worker.join(timeout=15)
    if any(worker.is_alive() for worker in workers):
        raise TimeoutError("SOCKS relay worker did not terminate")
    if worker_errors:
        raise worker_errors[0]


def serve_discovery(
    server: socket.socket,
    context: ssl.SSLContext,
    h3_port: int,
    expected_host: str,
    body: bytes,
) -> None:
    raw, _ = server.accept()
    with raw:
        with context.wrap_socket(raw, server_side=True) as client:
            request, headers = parse_headers(read_head(client))
            if request != b"GET /discover HTTP/1.1":
                raise AssertionError(f"wrong discovery request: {request!r}")
            if not headers.get(b"host", b"").startswith(
                expected_host.encode() + b":"
            ):
                raise AssertionError("discovery request lost origin authority")
            client.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nAlt-Svc: h3=\":"
                + str(h3_port).encode()
                + b"\"; ma=60\r\n\r\n"
                + body
            )
            if client.recv(1) != b"":
                raise AssertionError("discovery connection emitted trailing bytes")


def wait_for_log(process: subprocess.Popen[str], log: Path, marker: str) -> None:
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError(log.read_text())
        if log.exists() and marker in log.read_text():
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {marker}: {log.read_text()}")


def find_go() -> str:
    candidates = [os.environ.get("GO_BIN"), shutil.which("go"), "/tmp/go/bin/go"]
    candidates.extend(sorted(glob.glob("/nav_env/Temp/go*/bin/go"), reverse=True))
    candidates.extend(sorted(glob.glob("/tmp/netz-h2spec.*/go/bin/go"), reverse=True))
    seen: set[str] = set()
    for candidate in candidates:
        if candidate is None or candidate in seen or not os.access(candidate, os.X_OK):
            continue
        seen.add(candidate)
        version = subprocess.run(
            (candidate, "env", "GOVERSION"),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        ).stdout.strip()
        try:
            major, minor = (int(value) for value in version.removeprefix("go").split(".")[:2])
        except (ValueError, IndexError):
            continue
        if (major, minor) >= (1, 24):
            return candidate
    raise RuntimeError("Go 1.24 or newer not found")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    args = parser.parse_args()
    go = find_go()
    script_dir = Path(__file__).resolve().parent
    module = script_dir / "quic_go_module"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        origin_hosts = {
            "origin-a.internal",
            "origin-b.internal",
            "origin-c.internal",
        }
        ca, cert, key = create_identity(
            directory,
            (
                "origin-a.internal",
                "origin-b.internal",
                "origin-c.internal",
            ),
        )
        go_server = directory / "http3-socks5-server"
        subprocess.run(
            (go, "build", "-mod=readonly", "-o", str(go_server), "./http3_socks5"),
            cwd=module,
            env={**os.environ, "GOTOOLCHAIN": "local"},
            check=True,
            timeout=60,
        )
        discovery_a = listener()
        discovery_b = listener()
        discovery_c = listener()
        proxy = listener()
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(("127.0.0.1", 0))
        relay.settimeout(10)
        h3_port = free_udp_port()
        authority_a = f"origin-a.internal:{discovery_a.getsockname()[1]}"
        authority_b = f"origin-b.internal:{discovery_b.getsockname()[1]}"
        authority_c = f"origin-c.internal:{discovery_c.getsockname()[1]}"
        go_log = directory / "go-server.log"
        with go_log.open("w") as output:
            go_process = subprocess.Popen(
                (
                    str(go_server),
                    "-addr", f"127.0.0.1:{h3_port}",
                    "-cert", str(cert),
                    "-key", str(key),
                    "-authority", f"{authority_a},{authority_b},{authority_c}",
                ),
                text=True,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        wait_for_log(
            go_process,
            go_log,
            "quic-go SOCKS5 HTTP/3 server listening=",
        )

        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.set_alpn_protocols(["http/1.1"])
        tls_context.load_cert_chain(cert, key)
        errors: list[BaseException] = []
        trace: list[str] = []
        stats = {
            "remote_dns_packets": 0,
            "responses": 0,
            "domain:origin-a.internal": 0,
            "domain:origin-b.internal": 0,
            "domain:origin-c.internal": 0,
        }

        def run(function, *arguments) -> None:
            try:
                function(*arguments)
            except BaseException as error:
                errors.append(error)

        threads = (
            threading.Thread(
                target=run,
                args=(
                    serve_discovery,
                    discovery_a,
                    tls_context,
                    h3_port,
                    "origin-a.internal",
                    b"tcp-discovery-a",
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    serve_discovery,
                    discovery_b,
                    tls_context,
                    h3_port,
                    "origin-b.internal",
                    b"tcp-discovery-b",
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    serve_discovery,
                    discovery_c,
                    tls_context,
                    h3_port,
                    "origin-c.internal",
                    b"tcp-discovery-c",
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    serve_proxy,
                    proxy,
                    relay,
                    {
                        ("origin-a.internal", discovery_a.getsockname()[1]):
                            discovery_a.getsockname()[1],
                        ("origin-b.internal", discovery_b.getsockname()[1]):
                            discovery_b.getsockname()[1],
                        ("origin-c.internal", discovery_c.getsockname()[1]):
                            discovery_c.getsockname()[1],
                    },
                    h3_port,
                    origin_hosts,
                    trace,
                    stats,
                ),
            ),
        )
        for thread in threads:
            thread.start()
        result = subprocess.run(
            (
                str(args.client),
                str(proxy.getsockname()[1]),
                str(discovery_a.getsockname()[1]),
                str(discovery_b.getsockname()[1]),
                str(discovery_c.getsockname()[1]),
                str(h3_port),
                str(ca),
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        for thread in threads:
            thread.join(timeout=5)
        discovery_a.close()
        discovery_b.close()
        discovery_c.close()
        proxy.close()
        relay.close()
        if result.returncode != 0 or errors:
            go_process.kill()
            go_process.wait()
            peer_errors = "\n".join(repr(error) for error in errors)
            raise RuntimeError(
                result.stdout
                + "\npeer errors:\n"
                + peer_errors
                + f"\ntrace={trace!r} stats={stats!r}"
                + "\nGo server:\n"
                + go_log.read_text()
            )
        try:
            go_process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            go_process.kill()
            go_process.wait()
            raise TimeoutError(go_log.read_text())
        if any(thread.is_alive() for thread in threads):
            raise TimeoutError("HTTP/3 SOCKS5 peer did not terminate")
        if go_process.returncode != 0:
            raise RuntimeError(go_log.read_text())
        if trace != ["connect", "udp-associate", "connect", "connect"]:
            raise AssertionError(f"unexpected SOCKS command trace: {trace}")
        if (stats["remote_dns_packets"] == 0 or stats["responses"] == 0 or
            stats["domain:origin-a.internal"] == 0 or
            stats["domain:origin-b.internal"] == 0 or
            stats["domain:origin-c.internal"] == 0):
            raise AssertionError(f"missing UDP relay traffic: {stats}")
        expected = (
            "HTTP/3 SOCKS5 pool passed: origins=3 discovery=http1 "
            "h3_requests=4 udp_associations=1 active_quic_connections=2 "
            "total_quic_connections=4 domain_route_limit=2 "
            "route_churn=true remote_dns=true shared_endpoint=true "
            "tls_verified=true client_io=zio-std-io"
        )
        if expected not in result.stdout:
            raise AssertionError(f"missing client result: {result.stdout}")
        if "quic-go SOCKS5 HTTP/3 server passed" not in go_log.read_text():
            raise AssertionError(go_log.read_text())
        print(
            "HTTP/3 SOCKS5 interoperability passed: origins=3 discovery=http1 "
            "h3_requests=4 tcp_tunnels=3 udp_associations=1 "
            "active_quic_connections=2 total_quic_connections=4 "
            "domain_route_limit=2 route_churn=true remote_dns=true "
            "shared_endpoint=true "
            "tls13=true client_io=zio-std-io server_io=quic-go-netpoll"
        )


if __name__ == "__main__":
    main()
