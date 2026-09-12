#!/usr/bin/env python3
"""Strict verifier for fresh-connection cross-process QUIC handshakes."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        if token.count("=") != 1:
            continue
        key, value = token.split("=", 1)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key):
            raise ValueError(f"invalid field {token!r}")
        if not value or key in result:
            raise ValueError(f"empty or duplicate field {token!r}")
        result[key] = value
    return result


def records(path: Path, record_type: str) -> list[dict[str, str]]:
    return [
        row
        for line in path.read_text(encoding="utf-8").splitlines()
        if (row := fields(line)).get("record") == record_type
    ]


def integer(row: dict[str, str], key: str, minimum: int = 0) -> int:
    try:
        value = int(row[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {row}") from error
    if value < minimum:
        raise ValueError(f"{key} below {minimum}: {row}")
    return value


def percentile(sorted_values: list[int], percent: int) -> int:
    return sorted_values[min(len(sorted_values) - 1, len(sorted_values) * percent // 100)]


def verify(
    *,
    role_pair: str,
    samples: int,
    warmup: int,
    iterations: int,
    client_log: Path,
    server_log: Path,
) -> None:
    implementations = {
        "netz-client+quic-go-server": ("netz", "quic-go"),
        "quic-go-client+quic-go-server": ("quic-go", "quic-go"),
        "quic-go-client+netz-server": ("quic-go", "netz"),
        "netz-client+netz-server": ("netz", "netz"),
    }.get(role_pair)
    if implementations is None or samples < 1 or samples % 2 == 0:
        raise ValueError("invalid role pair or sample count")
    if warmup < 0 or iterations < 1:
        raise ValueError("invalid iteration shape")
    client_impl, server_impl = implementations
    total_connections = warmup + iterations
    expected_checksum = total_connections * (total_connections - 1) // 2
    expected_common = {
        "protocol": "quic-v1",
        "mode": "handshake",
        "role_pair": role_pair,
        "warmup": str(warmup),
        "iterations": str(iterations),
        "connections": str(total_connections),
        "echo_bytes": str(total_connections * 32),
        "checksum": str(expected_checksum),
        "complete": "true",
    }
    results = records(client_log, "result")
    completions = records(server_log, "server-complete")
    sample_rows = records(client_log, "handshake-sample")
    if len(results) != samples or len(completions) != samples:
        raise ValueError("missing result or server completion records")
    if len(sample_rows) != samples * iterations:
        raise ValueError("incorrect handshake sample count")

    p50_values: list[int] = []
    p99_values: list[int] = []
    total_values: list[int] = []
    for outer_run in range(1, samples + 1):
        matching_results = [row for row in results if row.get("run") == str(outer_run)]
        matching_servers = [row for row in completions if row.get("run") == str(outer_run)]
        matching_samples = [row for row in sample_rows if row.get("run") == str(outer_run)]
        if len(matching_results) != 1 or len(matching_servers) != 1 or len(matching_samples) != iterations:
            raise ValueError(f"run {outer_run}: duplicate or missing records")
        result = matching_results[0]
        server = matching_servers[0]
        for label, row, implementation in (
            ("result", result, client_impl),
            ("server", server, server_impl),
        ):
            if row.get("implementation") != implementation:
                raise ValueError(f"run {outer_run} {label}: implementation mismatch")
            for key, value in expected_common.items():
                if row.get(key) != value:
                    raise ValueError(f"run {outer_run} {label}: {key} mismatch")
        for key, value in {
            "timing_scope": "client-connect-only",
            "verification": "certificate",
            "key_exchange": "x25519",
            "cipher": "aes-128-gcm-sha256",
            "echo_verified": "true",
        }.items():
            if result.get(key) != value:
                raise ValueError(f"run {outer_run}: {key} mismatch")
        if server.get("echo_verified") != "true" or server.get("peer_close") != "true":
            raise ValueError(f"run {outer_run}: incomplete server proof")

        measured: list[int] = []
        seen: set[int] = set()
        for row in matching_samples:
            for key, value in {
                "implementation": client_impl, "protocol": "quic-v1",
                "mode": "handshake", "role_pair": role_pair,
                "verified": "true",
            }.items():
                if row.get(key) != value:
                    raise ValueError(f"run {outer_run}: sample {key} mismatch")
            sample_number = integer(row, "sample", 1)
            if sample_number > iterations or sample_number in seen:
                raise ValueError(f"run {outer_run}: invalid sample number")
            seen.add(sample_number)
            measured.append(integer(row, "elapsed_ns", 1))
        measured.sort()
        total = sum(measured)
        p50 = percentile(measured, 50)
        p99 = percentile(measured, 99)
        if integer(result, "total_elapsed_ns", 1) != total:
            raise ValueError(f"run {outer_run}: elapsed sum mismatch")
        if integer(result, "p50_ns", 1) != p50 or integer(result, "p99_ns", 1) != p99:
            raise ValueError(f"run {outer_run}: percentile mismatch")
        p50_values.append(p50)
        p99_values.append(p99)
        total_values.append(total)

    p50_ns = sorted(p50_values)[samples // 2]
    p99_ns = sorted(p99_values)[samples // 2]
    total_ns = sorted(total_values)[samples // 2]
    rate = iterations * 1_000_000_000 / total_ns
    print(
        f"protocol=quic-v1 mode=handshake role_pair={role_pair} samples={samples} "
        f"warmup={warmup} iterations={iterations} p50_ns={p50_ns} p99_ns={p99_ns} "
        f"median_total_elapsed_ns={total_ns} "
        f"connects_per_second_from_timed_sum={rate:.1f} "
        f"checksum={expected_checksum} complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    args = parser.parse_args()
    verify(
        role_pair=args.role_pair, samples=args.samples, warmup=args.warmup,
        iterations=args.iterations, client_log=args.client_log, server_log=args.server_log,
    )


if __name__ == "__main__":
    main()

