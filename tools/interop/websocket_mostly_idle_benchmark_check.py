#!/usr/bin/env python3
"""Validate matched mostly-idle WebSocket allocator measurements."""

from __future__ import annotations

import argparse
import statistics
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        if token.count("=") != 1:
            raise ValueError(f"malformed token {token!r}")
        key, value = token.split("=", 1)
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


def integer(row: dict[str, str], key: str, *, positive: bool = False) -> int:
    try:
        value = int(row[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {row}") from error
    if value < 0 or positive and value == 0:
        raise ValueError(f"invalid {key}: {row}")
    return value


def expected_checksum(active: int, iterations: int) -> int:
    total = 0
    for index in range(active):
        seed = index * 17 % 256
        total += iterations * (seed + seed + (seed + 255) % 256)
    return total


def verify_log(
    path: Path,
    implementation: str,
    samples: int,
    connections: int,
    active: int,
    warmup: int,
    iterations: int,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    environment = records(path, "environment")
    runs = records(path, "run")
    results = records(path, "result")
    memory = records(path, "memory")
    rss = records(path, "rss")
    if (
        len(environment) != 1
        or len(runs) != samples
        or len(results) != samples
        or len(memory) != samples
        or len(rss) != samples
    ):
        raise ValueError(
            f"{implementation}: expected 1/{samples}/{samples}/{samples}/{samples} "
            "environment/run/result/memory/rss records, found "
            f"{len(environment)}/{len(runs)}/{len(results)}/{len(memory)}/{len(rss)}"
        )
    role_pair = "netz-self" if implementation == "netz" else "websocket-zig-self"
    server_io = "zio-std-io" if implementation == "netz" else "websocket-zig-worker"
    common = {
        "implementation": implementation,
        "protocol": "websocket-h1",
        "transport": "tcp",
        "role_pair": role_pair,
        "client_io": "zio-std-io",
        "server_io": server_io,
        "benchmark_scope": "mostly-idle-buffer-retention",
        "connections": str(connections),
        "active_connections": str(active),
        "idle_connections": str(connections - active),
        "warmup": str(warmup),
        "iterations": str(iterations),
        "payload_bytes": "4096",
        "payload_schedule": "fixed",
        "send_shape": "contiguous",
        "parts": "1",
        "compression": "false",
        "tcp_nodelay": "true",
        "complete": "true",
    }
    expected_environment = {
        "implementation": implementation,
        "samples": str(samples),
        "schedule": "alternating",
        "connections": str(connections),
        "active_connections": str(active),
        "idle_connections": str(connections - active),
        "warmup": str(warmup),
        "iterations": str(iterations),
        "payload_bytes": "4096",
        "payload_schedule": "fixed",
        "memory_stage": "connections-live-after-workload",
        "rss_scope": "whole-process-lifetime",
        "netz_build_mode": "ReleaseFast",
        "reference_revision": "efa879736bd438bea8b86a91f220ba408de57273",
        "complete": "true",
    }
    for key, value in expected_environment.items():
        if environment[0].get(key) != value:
            raise ValueError(f"{implementation} environment {key} mismatch")
    for key in ("netz_binary_sha256", "reference_binary_sha256"):
        value = environment[0].get(key, "")
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError(f"{implementation} environment invalid {key}")
    for key in ("host", "arch", "kernel", "zig"):
        if not environment[0].get(key):
            raise ValueError(f"{implementation} environment missing {key}")
    for sample, run in enumerate(runs, 1):
        expected_order = 1 if (sample % 2 == 1) == (implementation == "netz") else 2
        if run != {
            "record": "run",
            "sample": str(sample),
            "implementation": implementation,
            "order": str(expected_order),
            "complete": "true",
        }:
            raise ValueError(f"{implementation} invalid run record {run}")
    for sample, row in enumerate(rss, 1):
        expected_rss = {
            "record": "rss",
            "sample": str(sample),
            "implementation": implementation,
            "process_scope": "client+server",
            "rss_scope": "whole-process-lifetime",
            "complete": "true",
        }
        for key, value in expected_rss.items():
            if row.get(key) != value:
                raise ValueError(f"{implementation} sample {sample}: invalid RSS {key}")
        if row.get("rss_source") not in ("gnu-time-maxrss", "busybox-time-maxrss"):
            raise ValueError(f"{implementation} sample {sample}: invalid RSS source")
        integer(row, "process_peak_rss_kib", positive=True)
    checksum = expected_checksum(active, iterations)
    logical_bytes = active * iterations * 4096 * 2
    for sample, (result, mem) in enumerate(zip(results, memory), 1):
        for row in (result, mem):
            for key, value in common.items():
                if row.get(key) != value:
                    raise ValueError(
                        f"{implementation} sample {sample}: "
                        f"{key}={row.get(key)!r}, expected {value!r}"
                    )
            if integer(row, "checksum") != checksum:
                raise ValueError(f"{implementation} sample {sample}: checksum mismatch")
        if result.get("connection_scope") != "persistent":
            raise ValueError(f"{implementation} sample {sample}: non-persistent result")
        if integer(result, "logical_bytes") != logical_bytes:
            raise ValueError(f"{implementation} sample {sample}: logical byte mismatch")
        if integer(result, "elapsed_ns", positive=True) <= 0:
            raise ValueError(f"{implementation} sample {sample}: invalid elapsed time")
        expected_memory = {
            "process_scope": "client+server",
            "memory_stage": "connections-live-after-workload",
            "tcp_nodelay": "true",
            "allocator_scope": "explicit-library-and-harness",
        }
        for key, value in expected_memory.items():
            if mem.get(key) != value:
                raise ValueError(
                    f"{implementation} sample {sample}: "
                    f"{key}={mem.get(key)!r}, expected {value!r}"
                )
        allocated = integer(mem, "total_allocated_bytes", positive=True)
        freed = integer(mem, "total_freed_bytes")
        live = integer(mem, "live_bytes", positive=True)
        peak = integer(mem, "peak_live_bytes", positive=True)
        if allocated - freed != live or peak < live or peak > allocated:
            raise ValueError(f"{implementation} sample {sample}: inconsistent memory totals")
        integer(mem, "alloc_count", positive=True)
        for key in ("free_count", "resize_count", "remap_count"):
            integer(mem, key)
    return memory, rss, environment[0]


def verify(
    netz_log: Path,
    reference_log: Path,
    samples: int,
    connections: int,
    active: int,
    warmup: int,
    iterations: int,
) -> None:
    if (
        samples <= 0
        or samples % 2 == 0
        or connections <= 1
        or active <= 0
        or active >= connections
        or warmup < 0
        or iterations <= 0
    ):
        raise ValueError("invalid mostly-idle benchmark configuration")
    netz, netz_rss, netz_environment = verify_log(
        netz_log, "netz", samples, connections, active, warmup, iterations
    )
    reference, reference_rss, reference_environment = verify_log(
        reference_log,
        "websocket-zig",
        samples,
        connections,
        active,
        warmup,
        iterations,
    )
    for key in ("netz_binary_sha256", "reference_binary_sha256"):
        if netz_environment[key] != reference_environment[key]:
            raise ValueError(f"environment {key} differs between implementations")
    for key in ("host", "arch", "kernel", "zig", "rss_scope"):
        if netz_environment[key] != reference_environment[key]:
            raise ValueError(f"environment {key} differs between implementations")
    netz_live = [integer(row, "live_bytes", positive=True) for row in netz]
    reference_live = [integer(row, "live_bytes", positive=True) for row in reference]
    netz_peak = [integer(row, "peak_live_bytes", positive=True) for row in netz]
    reference_peak = [integer(row, "peak_live_bytes", positive=True) for row in reference]
    netz_live_median = int(statistics.median(netz_live))
    reference_live_median = int(statistics.median(reference_live))
    netz_peak_median = int(statistics.median(netz_peak))
    reference_peak_median = int(statistics.median(reference_peak))
    netz_rss_median = int(statistics.median(
        integer(row, "process_peak_rss_kib", positive=True) for row in netz_rss
    ))
    reference_rss_median = int(statistics.median(
        integer(row, "process_peak_rss_kib", positive=True) for row in reference_rss
    ))
    rss_sources = {row["rss_source"] for row in netz_rss + reference_rss}
    if len(rss_sources) != 1:
        raise ValueError("mixed RSS sources")
    rss_source = next(iter(rss_sources))
    print(
        f"protocol=websocket-h1 workload=mostly-idle-buffer-retention "
        f"samples={samples} connections={connections} active_connections={active} "
        f"idle_connections={connections - active} warmup={warmup} "
        f"iterations={iterations} payload_bytes=4096 "
        f"netz_live_median_bytes={netz_live_median} "
        f"reference_live_median_bytes={reference_live_median} "
        f"reference_over_netz_live={reference_live_median / netz_live_median:.3f} "
        f"netz_peak_median_bytes={netz_peak_median} "
        f"reference_peak_median_bytes={reference_peak_median} "
        f"reference_over_netz_peak={reference_peak_median / netz_peak_median:.3f} "
        f"netz_process_peak_rss_median_kib={netz_rss_median} "
        f"reference_process_peak_rss_median_kib={reference_rss_median} "
        f"reference_over_netz_rss={reference_rss_median / netz_rss_median:.3f} "
        f"rss_source={rss_source} "
        "rss_scope=whole-process-lifetime "
        "memory_stage=connections-live-after-workload "
        "allocator_scope=explicit-library-and-harness complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--netz-log", type=Path, required=True)
    parser.add_argument("--reference-log", type=Path, required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--connections", type=int, required=True)
    parser.add_argument("--active-connections", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    args = parser.parse_args()
    verify(
        args.netz_log,
        args.reference_log,
        args.samples,
        args.connections,
        args.active_connections,
        args.warmup,
        args.iterations,
    )


if __name__ == "__main__":
    main()
