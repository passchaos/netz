#!/usr/bin/env python3
"""Validate matched netz/Hyper HTTP/2 cancellation-race benchmarks."""

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


def verify(
    client_log: Path,
    server_log: Path,
    implementation: str,
    samples: int,
    warmup: int,
    iterations: int,
) -> tuple[list[int], list[int], list[dict[str, str]], dict[str, str]]:
    environments = records(client_log, "environment")
    runs = records(client_log, "run")
    result_rows = records(client_log, "result")
    memory_rows = records(client_log, "memory")
    rss_rows = records(client_log, "rss")
    server_rows = records(server_log, "server-complete")
    if len(environments) != 1 or not all(
        len(rows) == samples for rows in (runs, result_rows, memory_rows, rss_rows, server_rows)
    ):
        raise ValueError(f"{implementation}: incomplete sample records")
    environment = environments[0]
    expected_environment = {
        "implementation": implementation,
        "samples": str(samples),
        "schedule": "alternating",
        "warmup": str(warmup),
        "iterations": str(iterations),
        "stream_window": "8192",
        "connection_window": "65535",
        "offered_bytes": "131072",
        "canceled_bytes": "8192",
        "sibling_bytes": "16384",
        "netz_build_mode": "ReleaseFast",
        "hyper_revision": "084473f728f9d07b3be5845475aa2f62ed9ff579",
        "complete": "true",
    }
    for key, value in expected_environment.items():
        if environment.get(key) != value:
            raise ValueError(f"{implementation}: environment {key} mismatch")
    for key in (
        "host", "arch", "kernel", "zig", "rustc",
    ):
        if not environment.get(key):
            raise ValueError(f"{implementation}: environment missing {key}")
    client_cpu = integer(environment, "client_cpu")
    server_cpu = integer(environment, "server_cpu")
    if client_cpu == server_cpu:
        raise ValueError(f"{implementation}: client and server CPUs overlap")
    for key in (
        "netz_binary_sha256",
        "hyper_client_binary_sha256",
        "hyper_server_binary_sha256",
        "hyper_lock_sha256",
    ):
        value = environment.get(key, "")
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError(f"{implementation}: invalid environment {key}")
    for sample, row in enumerate(runs, 1):
        expected_order = 1 if (sample % 2 == 1) == (implementation == "netz") else 2
        if row != {
            "record": "run",
            "sample": str(sample),
            "implementation": implementation,
            "order": str(expected_order),
            "complete": "true",
        }:
            raise ValueError(f"{implementation}: invalid run record {row}")

    client_io = "zio-std-io" if implementation == "netz" else "hyper-tokio"
    common = {
        "protocol": "http2",
        "transport": "h2c",
        "mode": "cancellation-race",
        "server_implementation": "hyper",
        "client_io": client_io,
        "server_io": "hyper-tokio",
        "complete": "true",
    }
    expected_result = {
        **common,
        "implementation": implementation,
        "connection_scope": "persistent",
        "benchmark_scope": "same-server-behavior",
        "warmup": str(warmup),
        "iterations": str(iterations),
        "stream_window": "8192",
        "connection_window": "65535",
        "offered_bytes": "131072",
        "canceled_bytes": "8192",
        "sibling_bytes": "16384",
        "completed_batches": str(iterations),
        "reuse_requests": "1",
        "cancellation_observation": "server-body-drop-gated-sibling",
        "sibling_concurrent": "true",
    }
    expected_checksum = iterations * (8192 + 16384)
    elapsed: list[int] = []
    for sample, row in enumerate(result_rows, 1):
        for key, value in expected_result.items():
            if row.get(key) != value:
                raise ValueError(f"{implementation} sample {sample}: {key} mismatch")
        if integer(row, "checksum") != expected_checksum:
            raise ValueError(f"{implementation} sample {sample}: checksum mismatch")
        total = integer(row, "elapsed_ns", positive=True)
        if integer(row, "ns_per_batch") != total // iterations:
            raise ValueError(f"{implementation} sample {sample}: ns_per_batch mismatch")
        if integer(row, "batches_per_s") != iterations * 1_000_000_000 // total:
            raise ValueError(f"{implementation} sample {sample}: batches_per_s mismatch")
        elapsed.append(total)

    allocator_scope = "netz-explicit" if implementation == "netz" else "rust-system-requested"
    peaks: list[int] = []
    for sample, row in enumerate(memory_rows, 1):
        for key, value in {
            **common,
            "implementation": implementation,
            "memory_scope": "client-process-through-reuse",
            "allocator_scope": allocator_scope,
        }.items():
            if row.get(key) != value:
                raise ValueError(f"{implementation} sample {sample}: memory {key} mismatch")
        allocated = integer(row, "total_allocated_bytes", positive=True)
        freed = integer(row, "total_freed_bytes")
        live = integer(row, "live_bytes", positive=True)
        peak = integer(row, "peak_live_bytes", positive=True)
        if allocated - freed != live or peak < live or peak > allocated:
            raise ValueError(f"{implementation} sample {sample}: inconsistent memory totals")
        integer(row, "alloc_count", positive=True)
        integer(row, "free_count")
        if implementation == "netz":
            integer(row, "resize_count")
            integer(row, "remap_count")
        else:
            integer(row, "realloc_count")
        peaks.append(peak)

    for sample, row in enumerate(rss_rows, 1):
        expected = {
            "record": "rss",
            "sample": str(sample),
            "implementation": implementation,
            "process_scope": "client",
            "rss_scope": "whole-process-lifetime",
            "complete": "true",
        }
        for key, value in expected.items():
            if row.get(key) != value:
                raise ValueError(f"{implementation} sample {sample}: RSS {key} mismatch")
        if row.get("rss_source") not in ("gnu-time-maxrss", "busybox-time-maxrss"):
            raise ValueError(f"{implementation} sample {sample}: invalid RSS source")
        integer(row, "process_peak_rss_kib", positive=True)

    expected_server = {
        "implementation": "hyper",
        "protocol": "http2",
        "transport": "h2c",
        "mode": "cancellation-race",
        "server_io": "hyper-tokio",
        "stream_window": "8192",
        "connection_window": "65535",
        "offered_bytes": "131072",
        "canceled_bytes": "8192",
        "sibling_bytes": "16384",
        "batches": str(warmup + iterations),
        "cancellations_observed": str(warmup + iterations),
        "siblings_completed": str(warmup + iterations),
        "reuse_requests": "1",
        "complete": "true",
    }
    for sample, row in enumerate(server_rows, 1):
        for key, value in expected_server.items():
            if row.get(key) != value:
                raise ValueError(f"{implementation} server sample {sample}: {key} mismatch")
    return elapsed, peaks, rss_rows, environment


def verify_pair(
    netz_client_log: Path,
    netz_server_log: Path,
    hyper_client_log: Path,
    hyper_server_log: Path,
    samples: int,
    warmup: int,
    iterations: int,
) -> None:
    if samples <= 0 or samples % 2 == 0 or warmup < 0 or iterations <= 0:
        raise ValueError("invalid cancellation benchmark configuration")
    netz_elapsed, netz_peaks, netz_rss, netz_environment = verify(
        netz_client_log, netz_server_log, "netz", samples, warmup, iterations
    )
    hyper_elapsed, hyper_peaks, hyper_rss, hyper_environment = verify(
        hyper_client_log, hyper_server_log, "hyper", samples, warmup, iterations
    )
    for key in (
        "host", "arch", "kernel", "zig", "rustc",
        "client_cpu", "server_cpu", "netz_binary_sha256",
        "hyper_client_binary_sha256", "hyper_server_binary_sha256",
        "hyper_lock_sha256",
    ):
        if netz_environment[key] != hyper_environment[key]:
            raise ValueError(f"environment {key} differs between implementations")
    netz_median = int(statistics.median(netz_elapsed))
    hyper_median = int(statistics.median(hyper_elapsed))
    netz_rss_median = int(statistics.median(
        integer(row, "process_peak_rss_kib", positive=True) for row in netz_rss
    ))
    hyper_rss_median = int(statistics.median(
        integer(row, "process_peak_rss_kib", positive=True) for row in hyper_rss
    ))
    rss_sources = {row["rss_source"] for row in netz_rss + hyper_rss}
    if len(rss_sources) != 1:
        raise ValueError("mixed RSS sources")
    print(
        "protocol=http2 workload=cancellation-race server=hyper "
        f"samples={samples} warmup={warmup} iterations={iterations} "
        f"netz_median_total_ns={netz_median} hyper_median_total_ns={hyper_median} "
        f"netz_median_ns_per_batch={netz_median // iterations} "
        f"hyper_median_ns_per_batch={hyper_median // iterations} "
        f"hyper_over_netz={hyper_median / netz_median:.3f} "
        f"netz_peak_live_median_bytes={int(statistics.median(netz_peaks))} "
        f"hyper_peak_live_median_bytes={int(statistics.median(hyper_peaks))} "
        f"netz_process_peak_rss_median_kib={netz_rss_median} "
        f"hyper_process_peak_rss_median_kib={hyper_rss_median} "
        f"rss_source={next(iter(rss_sources))} "
        "cancellation_observation=server-body-drop-gated-sibling "
        "sibling_reuse=true complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--netz-client-log", type=Path, required=True)
    parser.add_argument("--netz-server-log", type=Path, required=True)
    parser.add_argument("--hyper-client-log", type=Path, required=True)
    parser.add_argument("--hyper-server-log", type=Path, required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    args = parser.parse_args()
    verify_pair(
        args.netz_client_log,
        args.netz_server_log,
        args.hyper_client_log,
        args.hyper_server_log,
        args.samples,
        args.warmup,
        args.iterations,
    )


if __name__ == "__main__":
    main()
