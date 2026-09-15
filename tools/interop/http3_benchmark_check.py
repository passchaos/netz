#!/usr/bin/env python3
"""Strictly validate HTTP/3 benchmark client and server records."""

from __future__ import annotations

import argparse
import math
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
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key) or key in result or not value:
            raise ValueError(f"duplicate or empty field {token!r}")
        result[key] = value
    return result


def stream_checksum(size: int, stream_index: int) -> int:
    return sum((offset * 131 + stream_index * 17) & 0xFF for offset in range(size))


def aggregate_checksum(size: int, streams: int) -> int:
    return sum(stream_checksum(size, index) for index in range(streams)) & ((1 << 64) - 1)


def records(path: Path, kind: str, role_pair: str) -> list[dict[str, str]]:
    found = []
    for line in path.read_text(encoding="utf-8").splitlines():
        item = fields(line)
        if (
            item.get("record") == kind
            and item.get("protocol") == "http3"
            and item.get("role_pair") == role_pair
        ):
            found.append(item)
    return found


def verify(
    *,
    role_pair: str,
    mode: str,
    iterations: int,
    streams: int,
    body_bytes: int,
    quic_version: int,
    warmup: int,
    chunk_bytes: int,
    stream_window: int,
    timeout_ms: int,
    client_log: Path,
    server_log: Path,
) -> None:
    endpoints = {
        "netz-client+quic-go-server": {"client": "netz", "server": "quic-go"},
        "quic-go-client+netz-server": {"client": "quic-go", "server": "netz"},
        "netz-client+netz-server": {"client": "netz", "server": "netz"},
    }.get(role_pair)
    if endpoints is None or mode not in ("upload", "download"):
        raise ValueError("invalid role pair or mode")
    endpoint_io = {
        role: "zio-std-io" if implementation == "netz" else "quic-go-netpoll"
        for role, implementation in endpoints.items()
    }
    if (
        iterations <= 0
        or warmup <= 0
        or warmup > 4096
        or iterations > 4096
        or warmup + iterations > 4096
        or streams not in (1, 4, 16)
        or body_bytes <= 0
        or body_bytes > 1024 * 1024 * 1024
        or chunk_bytes <= 0
        or chunk_bytes > 1024 * 1024
        or chunk_bytes > body_bytes
        or stream_window <= 0
        or stream_window > 1024 * 1024 * 1024
        or timeout_ms <= 0
        or timeout_ms > 10 * 60 * 1000
        or quic_version not in (1, 2)
    ):
        raise ValueError("invalid benchmark validation configuration")
    result_records = records(client_log, "result", role_pair)
    server_records = records(server_log, "server-complete", role_pair)
    config_records = {
        "client": records(client_log, "config", role_pair),
        "server": records(server_log, "config", role_pair),
    }
    sender = "client" if mode == "upload" else "server"
    for role, rows in config_records.items():
        if len(rows) != 1:
            raise ValueError(f"expected one {role} config record, found {len(rows)}")
        config = rows[0]
        expected_config = {
            "implementation": endpoints[role],
            "mode": mode,
            "role_pair": role_pair,
            "endpoint_role": role,
            "sender_role": sender,
            "client_io": endpoint_io["client"],
            "server_io": endpoint_io["server"],
            "connection_scope": "fresh-per-sample",
            "benchmark_scope": "same-application-shape",
            "body_deadline_scope": "sample",
            "warmup": str(warmup),
            "iterations": str(iterations),
            "streams": str(streams),
            "body_bytes": str(body_bytes),
            "application_chunk_requested": str(chunk_bytes),
            "application_chunk_effective": str(min(chunk_bytes, 1152)),
            "stream_window": str(stream_window),
            "connection_window": str(stream_window * max(streams, 8)),
            "timeout_ms": str(timeout_ms),
            "steady_state_mtu": "1280",
            "quic_version": str(quic_version),
            "cipher": "negotiated-unexposed",
            "cert_verify": "true",
            "pacing": "true",
            "gso": "false" if endpoints[role] == "netz" else "implementation-default",
            "gro": "false" if endpoints[role] == "netz" else "implementation-default",
        }
        for key, value in expected_config.items():
            if config.get(key) != value:
                raise ValueError(f"{role} config {key} mismatch: {config}")
    if len(result_records) != iterations:
        raise ValueError(f"expected {iterations} result records, found {len(result_records)}")
    if len(server_records) != iterations:
        raise ValueError(f"expected {iterations} server records, found {len(server_records)}")
    total_bytes = body_bytes * streams
    checksum = aggregate_checksum(body_bytes, streams)
    for source, rows, endpoint_role in (
        ("client", result_records, "client"),
        ("server", server_records, "server"),
    ):
        for sample, record in enumerate(rows, 1):
            expected = {
                "implementation": (
                    endpoints["client" if mode == "upload" else "server"]
                    if source == "client"
                    else endpoints[endpoint_role]
                ),
                "mode": mode,
                "role_pair": role_pair,
                "sender_role": sender,
                "client_io": endpoint_io["client"],
                "server_io": endpoint_io["server"],
                "sample": str(sample),
                "streams": str(streams),
                "body_bytes": str(body_bytes),
                "connection_scope": "fresh-per-sample",
                "benchmark_scope": "same-application-shape",
                "body_deadline_scope": "sample",
                "sent_bytes": str(
                    total_bytes if source == "client" or mode == "download" else 0
                ),
                "received_bytes": str(
                    total_bytes if source == "client" or mode == "upload" else 0
                ),
                "checksum": str(checksum),
                "status": "200",
                "streams_finished": str(streams),
                "per_stream_verified": "true",
                "quic_version": str(quic_version),
                "complete": "true",
            }
            if source == "server":
                expected["endpoint_role"] = "server"
            else:
                expected["endpoint_role"] = "client"
                expected["result_owner"] = "client"
            for key, value in expected.items():
                if record.get(key) != value:
                    raise ValueError(
                        f"{source} sample {sample}: {key}={record.get(key)!r}, expected {value!r}"
                    )
            if source == "client":
                try:
                    elapsed_ns = int(record["elapsed_ns"])
                except (KeyError, ValueError) as error:
                    raise ValueError(f"sample {sample} has invalid elapsed_ns") from error
                if elapsed_ns <= 0:
                    raise ValueError(f"sample {sample} has non-positive elapsed_ns")
                try:
                    throughput = float(record["logical_MiB_s"])
                except (KeyError, ValueError) as error:
                    raise ValueError(f"sample {sample} has invalid throughput") from error
                expected_throughput = total_bytes * 1_000_000_000 / elapsed_ns / (1024 * 1024)
                if (
                    not math.isfinite(throughput)
                    or abs(throughput - expected_throughput) > 0.00051
                ):
                    raise ValueError(f"sample {sample} has throughput mismatch")
    print(
        f"protocol=http3 role_pair={role_pair} mode={mode} samples={iterations} "
        f"streams={streams} body_bytes={body_bytes} total_bytes={total_bytes} "
        f"checksum={checksum} per_stream_verified=true "
        f"quic_version={quic_version} client_io={endpoint_io['client']} "
        f"server_io={endpoint_io['server']} complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--mode", choices=("upload", "download"), required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--streams", type=int, default=1)
    parser.add_argument("--body-bytes", type=int, required=True)
    parser.add_argument("--quic-version", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--chunk-bytes", type=int, required=True)
    parser.add_argument("--stream-window", type=int, required=True)
    parser.add_argument("--timeout-ms", type=int, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    args = parser.parse_args()
    verify(
        role_pair=args.role_pair, mode=args.mode, iterations=args.iterations,
        streams=args.streams, body_bytes=args.body_bytes,
        quic_version=args.quic_version,
        warmup=args.warmup, chunk_bytes=args.chunk_bytes,
        stream_window=args.stream_window, timeout_ms=args.timeout_ms,
        client_log=args.client_log, server_log=args.server_log,
    )


if __name__ == "__main__":
    main()
