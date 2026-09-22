#!/usr/bin/env python3
"""Validate RFC 9220 benchmark shape, completion, and memory evidence."""

from __future__ import annotations

import argparse
import math
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in result:
            raise ValueError(f"duplicate field {key!r} in {line!r}")
        result[key] = value
    return result


def records(path: Path, kind: str, role_pair: str) -> list[dict[str, str]]:
    found = []
    for line in path.read_text(encoding="utf-8").splitlines():
        record = fields(line)
        if record.get("record") == kind and record.get("role_pair") == role_pair:
            found.append(record)
    return found


def integer(record: dict[str, str], key: str, *, positive: bool = False) -> int:
    try:
        value = int(record[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {record}") from error
    if value < 0 or positive and value == 0:
        raise ValueError(f"invalid {key}: {record}")
    return value


def finite_float(record: dict[str, str], key: str) -> float:
    try:
        value = float(record[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {record}") from error
    if not math.isfinite(value):
        raise ValueError(f"non-finite {key}: {record}")
    return value


def expected_checksum(warmup: int, iterations: int, payload_bytes: int) -> int:
    per_round = [
        sum((offset * 131 + round_index * 17) & 0xFF for offset in range(payload_bytes))
        for round_index in range(256)
    ]
    cycles, suffix = divmod(iterations, 256)
    start = warmup % 256
    return cycles * sum(per_round) + sum(
        per_round[(start + index) % 256] for index in range(suffix)
    )


def endpoint_shape(role_pair: str) -> tuple[dict[str, str], dict[str, str]]:
    implementations = {
        "netz-client+quic-go-server": {"client": "netz", "server": "quic-go"},
        "quic-go-client+netz-server": {"client": "quic-go", "server": "netz"},
    }.get(role_pair)
    if implementations is None:
        raise ValueError("invalid WebSocket H3 role pair")
    endpoint_io = {
        role: "zio-std-io" if implementation == "netz" else "quic-go-netpoll"
        for role, implementation in implementations.items()
    }
    return implementations, endpoint_io


def validate_shape(
    record: dict[str, str],
    role_pair: str,
    endpoint_role: str,
    implementation: str,
    endpoint_io: dict[str, str],
    warmup: int,
    iterations: int,
    payload_bytes: int,
    timeout_ms: int,
    quic_version: int,
) -> None:
    expected = {
        "implementation": implementation,
        "protocol": "websocket-h3",
        "transport": "h3",
        "mode": "binary-echo",
        "role_pair": role_pair,
        "endpoint_role": endpoint_role,
        "client_io": endpoint_io["client"],
        "server_io": endpoint_io["server"],
        "connection_scope": "persistent",
        "warmup": str(warmup),
        "iterations": str(iterations),
        "payload_bytes": str(payload_bytes),
        "timeout_ms": str(timeout_ms),
        "quic_version": str(quic_version),
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(
                f"record has {key}={record.get(key)!r}, expected {value!r}"
            )


def read_rss(path: Path) -> int:
    try:
        value = int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError) as error:
        raise ValueError(f"invalid peak RSS file {path}") from error
    if value <= 0:
        raise ValueError(f"non-positive peak RSS in {path}")
    return value


def verify(
    role_pair: str,
    warmup: int,
    iterations: int,
    payload_bytes: int,
    timeout_ms: int,
    quic_version: int,
    client_log: Path,
    server_log: Path,
    client_rss: Path | None = None,
    server_rss: Path | None = None,
    rss_source: str = "gnu-time-maxrss",
) -> None:
    implementations, endpoint_io = endpoint_shape(role_pair)
    if (
        warmup < 0
        or warmup > 100_000
        or iterations <= 0
        or iterations > 1_000_000
        or payload_bytes <= 0
        or payload_bytes > 4096
        or timeout_ms <= 0
        or timeout_ms > 10 * 60 * 1000
        or quic_version not in (1, 2)
    ):
        raise ValueError("invalid WebSocket H3 validation configuration")

    for role, path in (("client", client_log), ("server", server_log)):
        config_records = records(path, "config", role_pair)
        if len(config_records) != 1:
            raise ValueError(
                f"expected one {role} config record, found {len(config_records)}"
            )
        config = config_records[0]
        validate_shape(
            config, role_pair, role, implementations[role], endpoint_io,
            warmup, iterations, payload_bytes, timeout_ms,
            quic_version,
        )
        expected_config = {
            "benchmark_scope": "same-application-shape",
            "stream_window": "1048576",
            "connection_window": "8388608",
            "steady_state_mtu": "1280",
            "cipher": "negotiated-unexposed",
            "cert_verify": "true",
            "compression": "false",
            "netz_gso": "false",
            "netz_gro": "false",
            "quic_go_gso": "implementation-default",
            "quic_go_gro": "implementation-default",
            "pacing": "implementation-specific",
        }
        for key, value in expected_config.items():
            if config.get(key) != value:
                raise ValueError(f"{role} config {key} mismatch: {config}")

    result_records = records(client_log, "result", role_pair)
    server_records = records(server_log, "server-complete", role_pair)
    if len(result_records) != 1 or len(server_records) != 1:
        raise ValueError(
            "expected one result and server completion, found "
            f"{len(result_records)} and {len(server_records)}"
        )
    result = result_records[0]
    server = server_records[0]
    validate_shape(
        result, role_pair, "client", implementations["client"], endpoint_io,
        warmup, iterations, payload_bytes, timeout_ms,
        quic_version,
    )
    validate_shape(
        server, role_pair, "server", implementations["server"], endpoint_io,
        warmup, iterations, payload_bytes, timeout_ms,
        quic_version,
    )
    expected_bytes = iterations * payload_bytes
    checksum = expected_checksum(warmup, iterations, payload_bytes)
    for record in (result, server):
        if record.get("benchmark_scope") != "same-application-shape":
            raise ValueError(f"invalid benchmark scope: {record}")
        for key in ("sent_bytes", "received_bytes"):
            if integer(record, key) != expected_bytes:
                raise ValueError(f"invalid {key}: {record}")
        if integer(record, "checksum") != checksum:
            raise ValueError(f"invalid checksum: {record}")
    elapsed_ns = integer(result, "elapsed_ns", positive=True)
    expected_ns = elapsed_ns / iterations
    expected_rps = iterations * 1_000_000_000 / elapsed_ns
    expected_mib = expected_rps * payload_bytes * 2 / (1024 * 1024)
    for key, expected in (
        ("ns_per_roundtrip", expected_ns),
        ("roundtrips_per_s", expected_rps),
        ("logical_MiB_s", expected_mib),
    ):
        if abs(finite_float(result, key) - expected) > 0.00051:
            raise ValueError(f"{key} mismatch: {result}")
    if result.get("complete") != "true" or server.get("server_complete") != "true":
        raise ValueError("invalid benchmark completion markers")

    print(
        f"protocol=websocket-h3 role_pair={role_pair} warmup={warmup} "
        f"iterations={iterations} payload_bytes={payload_bytes} checksum={checksum} "
        f"quic_version={quic_version} "
        f"client_io={endpoint_io['client']} server_io={endpoint_io['server']} "
        "complete=true"
    )

    if (client_rss is None) != (server_rss is None):
        raise ValueError("both RSS files are required together")
    if client_rss is None:
        return
    if rss_source not in ("gnu-time-maxrss", "busybox-time-maxrss"):
        raise ValueError("invalid RSS source")
    for role, path, rss_path in (
        ("client", client_log, client_rss),
        ("server", server_log, server_rss),
    ):
        memory_records = records(path, "memory", role_pair)
        if len(memory_records) != 1:
            raise ValueError(
                f"expected one memory record in {path}, found {len(memory_records)}"
            )
        memory = memory_records[0]
        implementation = implementations[role]
        validate_shape(
            memory, role_pair, role, implementation, endpoint_io,
            warmup, iterations, payload_bytes, timeout_ms,
            quic_version,
        )
        expected_scope = "netz-explicit" if implementation == "netz" else "go-runtime-heap"
        if (
            memory.get("allocator_scope") != expected_scope
            or memory.get("memory_scope") != "benchmark-run-after-argument-parse"
            or memory.get("complete") != "true"
        ):
            raise ValueError(f"invalid memory scope/completion: {memory}")
        for key in ("alloc_count", "total_allocated_bytes"):
            integer(memory, key, positive=True)
        if implementation == "netz":
            integer(memory, "peak_live_bytes", positive=True)
            if integer(memory, "live_bytes") != 0:
                raise ValueError(f"netz allocator retained live bytes: {memory}")
        else:
            integer(memory, "heap_sys_bytes_end", positive=True)
        excluded = {
            "record", "implementation", "protocol", "transport",
            "mode", "role_pair", "endpoint_role", "client_io",
            "server_io", "connection_scope", "warmup", "iterations",
            "payload_bytes", "timeout_ms", "complete",
        }
        detail = " ".join(
            f"{key}={value}" for key, value in memory.items() if key not in excluded
        )
        print(
            f"record=memory implementation={implementation} protocol=websocket-h3 "
            f"transport=h3 mode=binary-echo role_pair={role_pair} "
            f"endpoint_role={role} client_io={endpoint_io['client']} "
            f"server_io={endpoint_io['server']} connection_scope=persistent "
            f"warmup={warmup} iterations={iterations} payload_bytes={payload_bytes} "
            f"timeout_ms={timeout_ms} rss_scope=whole-process "
            f"rss_source={rss_source} process_peak_rss_kib={read_rss(rss_path)} "
            f"{detail} complete=true"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--payload-bytes", type=int, required=True)
    parser.add_argument("--timeout-ms", type=int, required=True)
    parser.add_argument("--quic-version", type=int, required=True)
    parser.add_argument("--client-log", required=True, type=Path)
    parser.add_argument("--server-log", required=True, type=Path)
    parser.add_argument("--client-rss", type=Path)
    parser.add_argument("--server-rss", type=Path)
    parser.add_argument("--rss-source", default="gnu-time-maxrss")
    args = parser.parse_args()
    verify(
        role_pair=args.role_pair, warmup=args.warmup,
        iterations=args.iterations, payload_bytes=args.payload_bytes,
        timeout_ms=args.timeout_ms, client_log=args.client_log,
        quic_version=args.quic_version,
        server_log=args.server_log, client_rss=args.client_rss,
        server_rss=args.server_rss, rss_source=args.rss_source,
    )


if __name__ == "__main__":
    main()
