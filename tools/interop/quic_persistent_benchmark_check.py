#!/usr/bin/env python3
"""Strictly validate persistent raw QUIC echo and aggregate records."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        if token.count("=") != 1:
            raise ValueError(f"malformed token {token!r}")
        key, value = token.split("=", 1)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key):
            raise ValueError(f"invalid field {token!r}")
        if key in result or not value:
            raise ValueError(f"duplicate or empty field {token!r}")
        result[key] = value
    return result


def records(path: Path, kind: str) -> list[dict[str, str]]:
    return [
        row
        for line in path.read_text(encoding="utf-8").splitlines()
        if (row := fields(line)).get("record") == kind
    ]


def integer(row: dict[str, str], key: str, minimum: int = 0) -> int:
    try:
        value = int(row[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {row}") from error
    if value < minimum:
        raise ValueError(f"{key} below {minimum}: {row}")
    return value


def endpoint_implementations(role_pair: str) -> tuple[str, str]:
    pair = {
        "netz-client+quic-go-server": ("netz", "quic-go"),
        "quic-go-client+quic-go-server": ("quic-go", "quic-go"),
        "quic-go-client+netz-server": ("quic-go", "netz"),
        "netz-client+netz-server": ("netz", "netz"),
    }.get(role_pair)
    if pair is None:
        raise ValueError("invalid role pair")
    return pair


def transfer_checksum(bytes_per_stream: int, streams: int, connection: int) -> int:
    return sum(
        (offset * 131 + stream * 17 + connection * 29) & 0xFF
        for stream in range(streams)
        for offset in range(bytes_per_stream)
    ) & ((1 << 64) - 1)


def echo_checksum(rounds: int, payload_bytes: int) -> int:
    return sum(
        (sequence * 17 + offset * 131) & 0xFF
        for sequence in range(rounds)
        for offset in range(payload_bytes)
    ) & ((1 << 64) - 1)


def require_shape(
    row: dict[str, str], *, implementation: str, record_kind: str,
    role_pair: str, mode: str, run: int, server_topology: str,
    shared_receive_batch: int, server_ack_every: int,
    server_ack_delay_us: int,
) -> None:
    shared = server_topology == "shared"
    expected = {
        "implementation": implementation,
        "protocol": "quic-stream",
        "mode": mode,
        "direction": "roundtrip" if mode == "echo" else "upload",
        "role_pair": role_pair,
        "run": str(run),
        "connection_scope": (
            "persistent" if mode == "echo" else
            "parallel-shared-server-endpoint" if shared else
            "parallel-independent-endpoints"
        ),
        "endpoint_topology": (
            "independent-udp" if mode == "echo" else
            "shared-server-udp" if shared else
            "one-udp-socket-per-connection"
        ),
        "benchmark_scope": "same-application-shape",
        "cert_verify": "true",
        "quic_version": "1",
        "gso": "false",
        "gro": "false",
        "completion_exchange_verified": "true",
        "complete": "true",
    }
    if shared:
        expected["server_receive_batch"] = str(shared_receive_batch)
        expected["server_ack_every"] = str(server_ack_every)
        expected["server_ack_delay_us"] = str(server_ack_delay_us)
    for key, value in expected.items():
        if row.get(key) != value:
            raise ValueError(f"{record_kind} {key} mismatch: {row}")
    owner_key = "result_owner" if record_kind == "result" else "endpoint_role"
    owner_value = "client" if record_kind == "result" else "server"
    if row.get(owner_key) != owner_value:
        raise ValueError(f"{record_kind} {owner_key} mismatch: {row}")


def verify(
    *, mode: str, role_pair: str, run: int, connections: int,
    warmup: int, iterations: int, streams: int, bytes_per_stream: int,
    payload_bytes: int, sender: str, client_log: Path, server_log: Path,
    server_topology: str = "independent", shared_receive_batch: int = 32,
    server_ack_every: int = 2, server_ack_delay_us: int = 25000,
) -> None:
    client_impl, server_impl = endpoint_implementations(role_pair)
    if (
        mode not in ("echo", "aggregate") or run <= 0 or connections <= 0
        or warmup < 0 or iterations <= 0 or streams not in (1, 4)
        or bytes_per_stream <= 0 or payload_bytes <= 0
        or sender not in ("client", "server")
        or server_topology not in ("independent", "shared")
        or shared_receive_batch < 1 or shared_receive_batch > 64
        or server_ack_every < 1 or server_ack_every > 64
        or server_ack_delay_us < 0 or server_ack_delay_us > 25000
    ):
        raise ValueError("invalid verifier configuration")
    if mode == "echo" and (connections != 1 or streams != 1 or sender != "client"):
        raise ValueError("invalid echo shape")
    if mode == "aggregate" and (warmup != 0 or iterations != 1):
        raise ValueError("invalid aggregate shape")
    if server_topology == "shared" and (
        mode != "aggregate" or sender != "client"
        or role_pair != "netz-client+netz-server"
    ):
        raise ValueError("invalid shared server topology")
    if server_topology != "shared" and (
        server_ack_every != 2 or server_ack_delay_us != 25000
    ):
        raise ValueError("custom server ACK policy requires shared topology")

    results = records(client_log, "result")
    completions = records(server_log, "server-complete")
    if len(results) != 1 or len(completions) != 1:
        raise ValueError("expected one result and one server completion")
    result, server = results[0], completions[0]
    result_impl = client_impl if mode == "echo" or sender == "client" else server_impl
    require_shape(
        result, implementation=result_impl, record_kind="result",
        role_pair=role_pair, mode=mode, run=run,
        server_topology=server_topology,
        shared_receive_batch=shared_receive_batch,
        server_ack_every=server_ack_every,
        server_ack_delay_us=server_ack_delay_us,
    )
    require_shape(
        server, implementation=server_impl, record_kind="server",
        role_pair=role_pair, mode=mode, run=run,
        server_topology=server_topology,
        shared_receive_batch=shared_receive_batch,
        server_ack_every=server_ack_every,
        server_ack_delay_us=server_ack_delay_us,
    )
    expected_common = {
        "connections": str(connections),
        "streams": str(streams),
        "sender_role": sender,
    }
    for row in (result, server):
        for key, value in expected_common.items():
            if row.get(key) != value:
                raise ValueError(f"{key} mismatch: {row}")
    if integer(server, "connections_complete") != connections:
        raise ValueError("incomplete server connection set")
    if server_topology == "shared":
        receive_calls = integer(server, "server_receive_calls", 1)
        receive_events = integer(server, "server_receive_events", 1)
        max_events = integer(server, "server_receive_max_events", 1)
        received_datagrams = integer(server, "server_received_datagrams", 1)
        integer(
            server, "server_receive_max_datagrams", 1,
        )
        connected_events = integer(server, "server_connected_events", 1)
        packet_events = integer(server, "server_packet_events", 1)
        timer_events = integer(server, "server_timer_events")
        socket_received_datagrams = integer(
            server, "server_socket_received_datagrams", 1,
        )
        integer(server, "server_socket_received_bytes", 1)
        integer(server, "server_socket_sent_datagrams", 1)
        integer(server, "server_socket_sent_bytes", 1)
        if receive_events != connected_events + packet_events + timer_events:
            raise ValueError("shared receive event count mismatch")
        if connected_events != connections:
            raise ValueError("shared connected event count mismatch")
        if receive_events < receive_calls or max_events > shared_receive_batch:
            raise ValueError("invalid shared receive call utilization")
        if received_datagrams != socket_received_datagrams:
            raise ValueError("shared received datagram count mismatch")

    if mode == "echo":
        rounds = warmup + iterations
        total_bytes = rounds * payload_bytes
        measured_bytes = iterations * payload_bytes
        checksum = echo_checksum(rounds, payload_bytes)
        for row in (result, server):
            expected_echo = {
                "warmup": str(warmup), "iterations": str(iterations),
                "payload_bytes": str(payload_bytes),
                "checksum": str(checksum),
            }
            expected_echo["total_bytes"] = str(total_bytes)
            for key, value in expected_echo.items():
                if row.get(key) != value:
                    raise ValueError(f"echo {key} mismatch: {row}")
        if integer(result, "measured_bytes") != measured_bytes:
            raise ValueError("measured byte mismatch")
        latencies = [
            integer(result, key, 1)
            for key in ("min_ns", "p50_ns", "p90_ns", "p99_ns", "p999_ns", "max_ns")
        ]
        if latencies != sorted(latencies):
            raise ValueError("invalid latency ordering")
        total_ns = integer(result, "total_elapsed_ns", 1)
        if integer(result, "mean_ns", 1) != total_ns // iterations:
            raise ValueError("invalid mean latency")
    else:
        per_connection = streams * bytes_per_stream
        total_bytes = connections * per_connection
        checksum = sum(
            transfer_checksum(bytes_per_stream, streams, connection)
            for connection in range(connections)
        ) & ((1 << 64) - 1)
        for row in (result, server):
            for key, value in {
                "bytes_per_stream": str(bytes_per_stream),
                "transferred_bytes": str(total_bytes),
                "checksum": str(checksum),
            }.items():
                if row.get(key) != value:
                    raise ValueError(f"aggregate {key} mismatch: {row}")
        integer(result, "elapsed_ns", 1)
        try:
            throughput = float(result["logical_MiB_s"])
        except (KeyError, ValueError) as error:
            raise ValueError("invalid aggregate throughput") from error
        if throughput <= 0:
            raise ValueError("non-positive aggregate throughput")
        if result.get("timing_scope") != "stream-setup-through-verified-completion":
            raise ValueError("invalid aggregate timing scope")
        for key, value in {
            "warmup": str(warmup), "iterations": str(iterations),
            "payload_bytes": str(payload_bytes),
        }.items():
            if server.get(key) != value:
                raise ValueError(f"aggregate server {key} mismatch")

    print(
        f"protocol=quic-stream mode={mode} role_pair={role_pair} run={run} "
        f"connections={connections} streams={streams} bytes={total_bytes} "
        f"checksum={checksum} complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("echo", "aggregate"), required=True)
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--run", type=int, required=True)
    parser.add_argument("--connections", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--bytes-per-stream", type=int, required=True)
    parser.add_argument("--payload-bytes", type=int, required=True)
    parser.add_argument("--sender", choices=("client", "server"), required=True)
    parser.add_argument(
        "--server-topology", choices=("independent", "shared"),
        default="independent",
    )
    parser.add_argument("--shared-receive-batch", type=int, default=32)
    parser.add_argument("--server-ack-every", type=int, default=2)
    parser.add_argument("--server-ack-delay-us", type=int, default=25000)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    args = parser.parse_args()
    verify(**vars(args))


if __name__ == "__main__":
    main()
