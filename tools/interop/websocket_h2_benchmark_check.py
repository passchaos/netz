#!/usr/bin/env python3
"""Validate RFC 8441 benchmark completion and optional memory records."""

from __future__ import annotations

import argparse
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in result:
            raise SystemExit(f"duplicate field {key!r} in {line!r}")
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
        raise SystemExit(f"invalid {key}: {record}") from error
    if value < 0 or positive and value == 0:
        raise SystemExit(f"invalid {key}: {record}")
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


def validate_shape(
    record: dict[str, str],
    role_pair: str,
    endpoint_role: str,
    implementation: str,
    warmup: int,
    iterations: int,
    payload_bytes: int,
) -> None:
    expected = {
        "implementation": implementation,
        "protocol": "websocket-h2",
        "transport": "h2c",
        "mode": "binary-echo",
        "role_pair": role_pair,
        "endpoint_role": endpoint_role,
        "connection_scope": "persistent",
        "warmup": str(warmup),
        "iterations": str(iterations),
        "payload_bytes": str(payload_bytes),
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise SystemExit(f"record has {key}={record.get(key)!r}, expected {value!r}")


def read_rss(path: Path) -> int:
    try:
        value = int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError) as error:
        raise SystemExit(f"invalid peak RSS file {path}") from error
    if value <= 0:
        raise SystemExit(f"non-positive peak RSS in {path}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--payload-bytes", type=int, required=True)
    parser.add_argument("--client-log", required=True, type=Path)
    parser.add_argument("--server-log", required=True, type=Path)
    parser.add_argument("--client-rss", type=Path)
    parser.add_argument("--server-rss", type=Path)
    args = parser.parse_args()

    implementations = {
        "netz-client+hyper-server": {"client": "netz", "server": "hyper"},
        "hyper-client+netz-server": {"client": "hyper", "server": "netz"},
    }.get(args.role_pair)
    if implementations is None or args.warmup < 0 or args.iterations <= 0 or args.payload_bytes <= 0:
        raise SystemExit("invalid WebSocket H2 validation configuration")

    result_records = records(args.client_log, "result", args.role_pair)
    server_records = records(args.server_log, "server-complete", args.role_pair)
    if len(result_records) != 1 or len(server_records) != 1:
        raise SystemExit(
            f"expected one result and server completion, found "
            f"{len(result_records)} and {len(server_records)}"
        )
    result = result_records[0]
    server = server_records[0]
    validate_shape(result, args.role_pair, "client", implementations["client"], args.warmup, args.iterations, args.payload_bytes)
    validate_shape(server, args.role_pair, "server", implementations["server"], args.warmup, args.iterations, args.payload_bytes)
    expected_bytes = args.iterations * args.payload_bytes
    checksum = expected_checksum(args.warmup, args.iterations, args.payload_bytes)
    for record in (result, server):
        for key in ("sent_bytes", "received_bytes"):
            if integer(record, key) != expected_bytes:
                raise SystemExit(f"invalid {key}: {record}")
        if integer(record, "checksum") != checksum:
            raise SystemExit(f"invalid checksum: {record}")
    if result.get("benchmark_scope") != "same-application-shape" or result.get("complete") != "true":
        raise SystemExit(f"invalid result completion: {result}")
    if integer(result, "elapsed_ns", positive=True) <= 0 or server.get("server_complete") != "true":
        raise SystemExit("invalid completion markers")

    print(
        f"protocol=websocket-h2 role_pair={args.role_pair} warmup={args.warmup} "
        f"iterations={args.iterations} payload_bytes={args.payload_bytes} "
        f"checksum={checksum} complete=true"
    )

    if (args.client_rss is None) != (args.server_rss is None):
        raise SystemExit("both RSS files are required together")
    if args.client_rss is None:
        return
    for role, path, rss_path in (
        ("client", args.client_log, args.client_rss),
        ("server", args.server_log, args.server_rss),
    ):
        memory_records = records(path, "memory", args.role_pair)
        if len(memory_records) != 1:
            raise SystemExit(f"expected one memory record in {path}, found {len(memory_records)}")
        memory = memory_records[0]
        implementation = implementations[role]
        validate_shape(memory, args.role_pair, role, implementation, args.warmup, args.iterations, args.payload_bytes)
        expected_scope = "netz-explicit" if implementation == "netz" else "rust-system-requested"
        if memory.get("allocator_scope") != expected_scope:
            raise SystemExit(f"invalid allocator scope: {memory}")
        expected_memory_scope = (
            "benchmark-run-after-argument-parse"
            if implementation == "netz"
            else "process-start-through-runtime-teardown"
        )
        if memory.get("memory_scope") != expected_memory_scope or memory.get("complete") != "true":
            raise SystemExit(f"invalid memory scope/completion: {memory}")
        for key in ("alloc_count", "total_allocated_bytes", "peak_live_bytes"):
            integer(memory, key, positive=True)
        if implementation == "netz" and integer(memory, "live_bytes") != 0:
            raise SystemExit(f"netz allocator retained live bytes: {memory}")
        if implementation == "hyper" and integer(memory, "peak_live_bytes") < integer(memory, "live_bytes_end"):
            raise SystemExit(f"Hyper peak below live bytes: {memory}")
        excluded = {
            "record", "implementation", "protocol", "transport", "mode",
            "role_pair", "endpoint_role", "connection_scope", "warmup",
            "iterations", "payload_bytes", "complete",
        }
        detail = " ".join(f"{key}={value}" for key, value in memory.items() if key not in excluded)
        print(
            f"record=memory implementation={implementation} protocol=websocket-h2 "
            f"transport=h2c mode=binary-echo role_pair={args.role_pair} "
            f"endpoint_role={role} connection_scope=persistent "
            f"warmup={args.warmup} iterations={args.iterations} "
            f"payload_bytes={args.payload_bytes} rss_scope=whole-process "
            f"rss_source=gnu-time-maxrss process_peak_rss_kib={read_rss(rss_path)} "
            f"{detail} complete=true"
        )


if __name__ == "__main__":
    main()
