#!/usr/bin/env python3
"""Strict verifier for fresh-connection cross-process QUIC handshakes."""

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
    timeout_ms: int,
    client_log: Path,
    server_log: Path,
) -> None:
    implementations = {
        "netz-client+quic-go-server": ("netz", "quic-go"),
        "quic-go-client+quic-go-server": ("quic-go", "quic-go"),
        "quic-go-client+netz-server": ("quic-go", "netz"),
        "netz-client+quinn-server": ("netz", "quinn"),
        "quinn-client+quinn-server": ("quinn", "quinn"),
        "quinn-client+netz-server": ("quinn", "netz"),
        "netz-client+netz-server": ("netz", "netz"),
    }.get(role_pair)
    if implementations is None or samples < 1 or samples % 2 == 0:
        raise ValueError("invalid role pair or sample count")
    if (
        warmup < 0 or warmup > 4096 or iterations < 1 or iterations > 4096
        or timeout_ms < 1 or timeout_ms > 600_000
    ):
        raise ValueError("invalid iteration shape")
    client_impl, server_impl = implementations
    client_io = io_name(client_impl)
    server_io = io_name(server_impl)
    total_connections = warmup + iterations
    expected_checksum = total_connections * (total_connections - 1) // 2
    expected_common = {
        "protocol": "quic-v1",
        "mode": "handshake",
        "role_pair": role_pair,
        "warmup": str(warmup),
        "iterations": str(iterations),
        "client_io": client_io,
        "server_io": server_io,
        "timeout_ms": str(timeout_ms),
        "connections": str(total_connections),
        "echo_bytes": str(total_connections * 32),
        "checksum": str(expected_checksum),
        "complete": "true",
    }
    results = records(client_log, "result")
    completions = records(server_log, "server-complete")
    sample_rows = records(client_log, "handshake-sample")
    cache_rows = records(client_log, "trust-cache")
    if len(results) != samples or len(completions) != samples:
        raise ValueError("missing result or server completion records")
    if len(sample_rows) != samples * iterations:
        raise ValueError("incorrect handshake sample count")
    if len(cache_rows) != (samples if client_impl == "netz" else 0):
        raise ValueError("incorrect trust-cache record count")

    p50_values: list[int] = []
    p99_values: list[int] = []
    total_values: list[int] = []
    traffic_values: dict[str, list[int]] = {key: [] for key in (
        "connect_tx_datagrams", "connect_tx_bytes",
        "connect_rx_datagrams", "connect_rx_bytes",
    )}
    phase_values: dict[str, list[int]] = {key: [] for key in (
        "pre_trust_ns", "trust_ns", "post_trust_ns",
    )}
    for outer_run in range(1, samples + 1):
        matching_results = [row for row in results if row.get("run") == str(outer_run)]
        matching_servers = [row for row in completions if row.get("run") == str(outer_run)]
        matching_samples = [row for row in sample_rows if row.get("run") == str(outer_run)]
        if len(matching_results) != 1 or len(matching_servers) != 1 or len(matching_samples) != iterations:
            raise ValueError(f"run {outer_run}: duplicate or missing records")
        if client_impl == "netz":
            matching_cache = [
                row for row in cache_rows if row.get("run") == str(outer_run)
            ]
            if len(matching_cache) != 1:
                raise ValueError(f"run {outer_run}: missing trust-cache record")
            expect_cache = {
                "role_pair": role_pair, "mode": "enabled",
                "capacity": "64", "hits": str(total_connections - 1),
                "misses": "1", "complete": "true",
            }
            for key, value in expect_cache.items():
                if matching_cache[0].get(key) != value:
                    raise ValueError(f"run {outer_run}: trust-cache {key} mismatch")
        result = matching_results[0]
        server = matching_servers[0]
        for label, row, implementation in (
            ("result", result, client_impl),
            ("server", server, server_impl),
        ):
            if row.get("implementation") != implementation:
                raise ValueError(f"run {outer_run} {label}: implementation mismatch")
            expected_role = "client" if label == "result" else "server"
            if row.get("endpoint_role") != expected_role:
                raise ValueError(f"run {outer_run} {label}: endpoint role mismatch")
            for key, value in expected_common.items():
                if row.get(key) != value:
                    raise ValueError(f"run {outer_run} {label}: {key} mismatch")
        expected_result_fields = {
            "timing_scope": "client-connect-only",
            "verification": "certificate",
            "resumption": "disabled",
            "key_exchange": "x25519",
            "cipher": "aes-128-gcm-sha256",
            "echo_verified": "true",
        }
        if client_impl == "netz":
            expected_result_fields["trust_cache"] = "enabled"
        elif client_impl == "quinn":
            expected_result_fields["trust_cache"] = "implementation-specific"
        for key, value in expected_result_fields.items():
            if result.get(key) != value:
                raise ValueError(f"run {outer_run}: {key} mismatch")
        if server.get("echo_verified") != "true" or server.get("peer_close") != "true":
            raise ValueError(f"run {outer_run}: incomplete server proof")

        measured: list[int] = []
        seen: set[int] = set()
        for row in matching_samples:
            expected_sample_fields = {
                "implementation": client_impl, "protocol": "quic-v1",
                "mode": "handshake", "role_pair": role_pair,
                "client_io": client_io, "server_io": server_io,
                "endpoint_role": "client", "timeout_ms": str(timeout_ms),
                "verified": "true",
            }
            if client_impl == "netz":
                expected_sample_fields["trust_cache"] = "enabled"
            elif client_impl == "quinn":
                expected_sample_fields["trust_cache"] = "implementation-specific"
            for key, value in expected_sample_fields.items():
                if row.get(key) != value:
                    raise ValueError(f"run {outer_run}: sample {key} mismatch")
            sample_number = integer(row, "sample", 1)
            if sample_number > iterations or sample_number in seen:
                raise ValueError(f"run {outer_run}: invalid sample number")
            seen.add(sample_number)
            measured.append(integer(row, "elapsed_ns", 1))
            if client_impl != "quic-go":
                for traffic_field in (
                    "connect_tx_datagrams", "connect_tx_bytes",
                    "connect_rx_datagrams", "connect_rx_bytes",
                ):
                    traffic_values[traffic_field].append(
                        integer(row, traffic_field, 1)
                    )
            if client_impl == "netz":
                phases = [
                    integer(row, "pre_trust_ns"),
                    integer(row, "trust_ns"),
                    integer(row, "post_trust_ns"),
                ]
                if sum(phases) != integer(row, "elapsed_ns", 1):
                    raise ValueError(f"run {outer_run}: phase sum mismatch")
                for key, value in zip(phase_values, phases):
                    phase_values[key].append(value)
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
    traffic_fields = ""
    if client_impl != "quic-go":
        traffic_medians = {
            key: sorted(values)[len(values) // 2]
            for key, values in traffic_values.items()
        }
        traffic_fields = (
            f"median_connect_tx_datagrams={traffic_medians['connect_tx_datagrams']} "
            f"median_connect_tx_bytes={traffic_medians['connect_tx_bytes']} "
            f"median_connect_rx_datagrams={traffic_medians['connect_rx_datagrams']} "
            f"median_connect_rx_bytes={traffic_medians['connect_rx_bytes']} "
        )
    phase_fields = ""
    if client_impl == "netz":
        phase_medians = {
            key: sorted(values)[len(values) // 2]
            for key, values in phase_values.items()
        }
        phase_fields = (
            f"median_pre_trust_ns={phase_medians['pre_trust_ns']} "
            f"median_trust_ns={phase_medians['trust_ns']} "
            f"median_post_trust_ns={phase_medians['post_trust_ns']} "
        )
    rate = iterations * 1_000_000_000 / total_ns
    print(
        f"protocol=quic-v1 mode=handshake role_pair={role_pair} samples={samples} "
        f"warmup={warmup} iterations={iterations} p50_ns={p50_ns} p99_ns={p99_ns} "
        f"client_io={client_io} server_io={server_io} "
        f"median_total_elapsed_ns={total_ns} "
        f"connects_per_second_from_timed_sum={rate:.1f} "
        f"{traffic_fields}"
        f"{phase_fields}"
        f"checksum={expected_checksum} complete=true"
    )


def io_name(implementation: str) -> str:
    return {
        "netz": "zio-std-io",
        "quic-go": "quic-go-netpoll",
        "quinn": "quinn-tokio-rustls",
    }[implementation]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--timeout-ms", type=int, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    args = parser.parse_args()
    verify(
        role_pair=args.role_pair, samples=args.samples, warmup=args.warmup,
        iterations=args.iterations, timeout_ms=args.timeout_ms,
        client_log=args.client_log, server_log=args.server_log,
    )


if __name__ == "__main__":
    main()

