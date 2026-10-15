#!/usr/bin/env python3
"""Validate and summarize the fixed-binary netz/Quinn handshake matrix."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import re


QUINN_REVISION = "d9c8c4c695fc64292d9b117844ea6924ca0d0815"
SHA256 = re.compile(r"[0-9a-f]{64}")
ROLE_PAIRS = (
    "netz-client+quinn-server",
    "quinn-client+quinn-server",
    "quinn-client+netz-server",
    "netz-client+netz-server",
)
IMPLEMENTATIONS = {
    "netz-client+quinn-server": ("netz", "quinn"),
    "quinn-client+quinn-server": ("quinn", "quinn"),
    "quinn-client+netz-server": ("quinn", "netz"),
    "netz-client+netz-server": ("netz", "netz"),
}


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


def expect_fields(row: dict[str, str], expected: dict[str, str], label: str) -> None:
    for key, value in expected.items():
        if row.get(key) != value:
            raise ValueError(f"invalid {label} {key}: {row}")


def expected_order(samples: int) -> list[tuple[int, str]]:
    if samples <= 0 or samples % 2 == 0:
        raise ValueError("samples must be a positive odd number")
    order: list[tuple[int, str]] = []
    even = (ROLE_PAIRS[1], ROLE_PAIRS[0], ROLE_PAIRS[3], ROLE_PAIRS[2])
    for sample in range(1, samples + 1):
        pairs = ROLE_PAIRS if sample % 2 else even
        order.extend((sample, role_pair) for role_pair in pairs)
    return order


def validate(
    log: Path, summaries_path: Path, samples: int, client_cpu: int,
    server_cpu: int, warmup: int, iterations: int, timeout_ms: int,
) -> list[str]:
    if client_cpu < 0 or server_cpu < 0 or client_cpu == server_cpu:
        raise ValueError("invalid CPU layout")
    if warmup < 0 or warmup > 4096 or iterations < 1 or iterations > 4096:
        raise ValueError("invalid iteration shape")
    if timeout_ms < 1 or timeout_ms > 600_000:
        raise ValueError("invalid timeout")

    environments = records(log, "environment")
    if len(environments) != 1:
        raise ValueError("expected one environment record")
    environment = environments[0]
    expected_environment = {
        "protocol": "quic-v1", "mode": "handshake", "peer": "quinn",
        "samples": str(samples), "schedule": "abba",
        "client_cpu": str(client_cpu), "server_cpu": str(server_cpu),
        "netz_build_mode": "ReleaseFast",
        "quinn_revision": QUINN_REVISION, "complete": "true",
        "server_identity": "shared-ca-signed-p256-leaf",
        "server_certificate_chain_entries": "1",
    }
    for key, value in expected_environment.items():
        if environment.get(key) != value:
            raise ValueError(f"invalid environment {key}: {environment}")
    netz_certificate_verify = environment.get("netz_certificate_verify")
    if netz_certificate_verify not in {"fresh-p256", "prepared-p256"}:
        raise ValueError(
            f"invalid environment netz_certificate_verify: {environment}"
        )
    for key in (
        "netz_binary_sha256", "quinn_binary_sha256", "quinn_lock_sha256",
        "server_certificate_sha256",
    ):
        if not SHA256.fullmatch(environment.get(key, "")):
            raise ValueError(f"invalid environment {key}: {environment}")
    for key in ("host", "arch", "kernel", "zig", "rustc"):
        if not environment.get(key):
            raise ValueError(f"missing environment {key}: {environment}")
    integer(environment, "server_certificate_der_bytes", 1)

    raw_records = [
        row for line in log.read_text(encoding="utf-8").splitlines()
        if (row := fields(line)).get("record") in {
            "run", "handshake-sample", "result", "server-complete",
        }
    ]
    runs = [row for row in raw_records if row["record"] == "run"]
    order = expected_order(samples)
    if len(runs) != len(order):
        raise ValueError(f"expected {len(order)} run markers, found {len(runs)}")
    for row, (sample, role_pair) in zip(runs, order):
        client, server = IMPLEMENTATIONS[role_pair]
        expected = {
            "protocol": "quic-v1", "mode": "handshake",
            "sample": str(sample), "role_pair": role_pair,
            "implementation": client, "fixed_server": server,
            "schedule": "abba", "client_cpu": str(client_cpu),
            "server_cpu": str(server_cpu),
        }
        for key, value in expected.items():
            if row.get(key) != value:
                raise ValueError(f"invalid run marker {key}: {row}")

    cursor = 0
    for sample, role_pair in order:
        client, server = IMPLEMENTATIONS[role_pair]
        expected_count = iterations + 3
        group = raw_records[cursor:cursor + expected_count]
        if len(group) != expected_count:
            raise ValueError(f"missing raw records for {sample}/{role_pair}")
        marker, *payload = group
        if marker.get("record") != "run" or marker.get("sample") != str(sample) or marker.get("role_pair") != role_pair:
            raise ValueError(f"raw run order mismatch: {marker}")
        samples_for_run = payload[:iterations]
        result, completion = payload[iterations:]
        common = {
            "protocol": "quic-v1", "mode": "handshake",
            "role_pair": role_pair, "run": str(sample),
            "client_io": io_name(client), "server_io": io_name(server),
            "timeout_ms": str(timeout_ms),
        }
        for sample_number, row in enumerate(samples_for_run, 1):
            expected_sample = {
                **common, "record": "handshake-sample",
                "implementation": client, "endpoint_role": "client",
                "sample": str(sample_number), "verified": "true",
                "trust_cache": "enabled" if client == "netz" else "implementation-specific",
            }
            if client == "netz":
                expected_sample["certificate_verify"] = netz_certificate_verify
            expect_fields(row, expected_sample, "handshake sample")
            integer(row, "elapsed_ns", 1)
            for traffic_field in (
                "connect_tx_datagrams", "connect_tx_bytes",
                "connect_rx_datagrams", "connect_rx_bytes",
            ):
                integer(row, traffic_field, 1)
        checksum = str((warmup + iterations) * (warmup + iterations - 1) // 2)
        result_common = {
            **common, "warmup": str(warmup),
            "iterations": str(iterations),
            "connections": str(warmup + iterations),
            "echo_bytes": str((warmup + iterations) * 32),
            "checksum": checksum, "echo_verified": "true",
            "complete": "true",
        }
        expected_result = {
            **result_common, "record": "result",
            "implementation": client, "endpoint_role": "client",
            "timing_scope": "client-connect-only",
            "verification": "certificate", "resumption": "disabled",
            "trust_cache": "enabled" if client == "netz" else "implementation-specific",
            "key_exchange": "x25519",
            "cipher": "aes-128-gcm-sha256",
        }
        if client == "netz":
            expected_result["certificate_verify"] = netz_certificate_verify
        expect_fields(result, expected_result, "result")
        expect_fields(completion, {
            **result_common, "record": "server-complete",
            "implementation": server, "endpoint_role": "server",
            "peer_close": "true",
        }, "server completion")
        cursor += expected_count
    if cursor != len(raw_records):
        raise ValueError("unexpected trailing raw records")

    summary_rows = [fields(line) for line in summaries_path.read_text(encoding="utf-8").splitlines()]
    if len(summary_rows) != len(ROLE_PAIRS):
        raise ValueError("expected one summary per role pair")
    by_pair: dict[str, dict[str, str]] = {}
    for row in summary_rows:
        role_pair = row.get("role_pair", "")
        if role_pair not in IMPLEMENTATIONS or role_pair in by_pair:
            raise ValueError(f"invalid or duplicate summary: {row}")
        client, server = IMPLEMENTATIONS[role_pair]
        expected = {
            "protocol": "quic-v1", "mode": "handshake",
            "samples": str(samples), "warmup": str(warmup),
            "iterations": str(iterations), "client_io": io_name(client),
            "server_io": io_name(server), "checksum": str((warmup + iterations) * (warmup + iterations - 1) // 2),
            "complete": "true",
        }
        if client == "netz":
            expected["certificate_verify"] = netz_certificate_verify
        for key, value in expected.items():
            if row.get(key) != value:
                raise ValueError(f"invalid summary {key}: {row}")
        integer(row, "p50_ns", 1)
        integer(row, "p99_ns", 1)
        integer(row, "median_total_elapsed_ns", 1)
        for traffic_field in (
            "median_connect_tx_datagrams", "median_connect_tx_bytes",
            "median_connect_rx_datagrams", "median_connect_rx_bytes",
        ):
            integer(row, traffic_field, 1)
        if client == "netz":
            for phase_field in (
                "median_pre_trust_ns", "median_trust_ns",
                "median_post_trust_ns",
            ):
                integer(row, phase_field)
        try:
            rate = float(row["connects_per_second_from_timed_sum"])
        except (KeyError, ValueError) as error:
            raise ValueError(f"invalid summary rate: {row}") from error
        if not math.isfinite(rate) or rate <= 0:
            raise ValueError(f"invalid summary rate: {row}")
        by_pair[role_pair] = row

    output = [" ".join(f"{key}={value}" for key, value in environment.items())]
    output.extend(" ".join(f"{key}={value}" for key, value in row.items()) for row in summary_rows)
    for fixed_server, netz_pair, quinn_pair in (
        ("quinn", "netz-client+quinn-server", "quinn-client+quinn-server"),
        ("netz", "netz-client+netz-server", "quinn-client+netz-server"),
    ):
        netz = integer(by_pair[netz_pair], "p50_ns", 1)
        quinn = integer(by_pair[quinn_pair], "p50_ns", 1)
        ratio = quinn / netz
        if not math.isfinite(ratio) or ratio <= 0:
            raise ValueError("invalid handshake comparison ratio")
        output.append(
            "record=comparison protocol=quic-v1 mode=handshake "
            f"fixed_server={fixed_server} samples={samples} schedule=abba "
            f"client_cpu={client_cpu} server_cpu={server_cpu} "
            f"p50_ns_netz={netz} p50_ns_quinn={quinn} "
            f"netz_speedup={ratio:.3f} benchmark_scope=same-security-policy complete=true"
        )
    return output


def io_name(implementation: str) -> str:
    return "zio-std-io" if implementation == "netz" else "quinn-tokio-rustls"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--summaries", required=True, type=Path)
    parser.add_argument("--samples", required=True, type=int)
    parser.add_argument("--client-cpu", required=True, type=int)
    parser.add_argument("--server-cpu", required=True, type=int)
    parser.add_argument("--warmup", required=True, type=int)
    parser.add_argument("--iterations", required=True, type=int)
    parser.add_argument("--timeout-ms", required=True, type=int)
    args = parser.parse_args()
    for line in validate(
        args.log, args.summaries, args.samples, args.client_cpu,
        args.server_cpu, args.warmup, args.iterations, args.timeout_ms,
    ):
        print(line)


if __name__ == "__main__":
    main()
