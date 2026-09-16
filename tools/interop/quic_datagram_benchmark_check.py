#!/usr/bin/env python3
"""Validate and summarize fixed-binary netz/Quinn raw DATAGRAM latency."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import re
import statistics


QUINN_REVISION = "d9c8c4c695fc64292d9b117844ea6924ca0d0815"
SHA256 = re.compile(r"[0-9a-f]{64}")
ROLE_PAIRS = {
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
        key, value = token.split("=", 1)
        if key in result:
            raise ValueError(f"duplicate field {key!r} in {line!r}")
        result[key] = value
    return result


def integer(record: dict[str, str], key: str, *, positive: bool = False) -> int:
    try:
        value = int(record[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {record}") from error
    if value < 0 or positive and value == 0:
        raise ValueError(f"invalid {key}: {record}")
    return value


def expected_order(samples: int) -> list[tuple[int, str]]:
    if samples <= 0 or samples % 2 == 0:
        raise ValueError("samples must be a positive odd number")
    order: list[tuple[int, str]] = []
    odd = (
        "netz-client+quinn-server",
        "quinn-client+quinn-server",
        "quinn-client+netz-server",
        "netz-client+netz-server",
    )
    even = (odd[1], odd[0], odd[3], odd[2])
    for sample in range(1, samples + 1):
        order.extend((sample, pair) for pair in (odd if sample % 2 else even))
    return order


def io_name(implementation: str) -> str:
    return "zio-std-io" if implementation == "netz" else "quinn-tokio-rustls"


def expected_checksum(rounds: int, payload_bytes: int) -> int:
    checksum = 0
    for sequence in range(rounds):
        payload = (
            b"NZDG"
            + sequence.to_bytes(8, "big")
            + bytes(
                (sequence * 17 + index * 131) & 0xFF
                for index in range(payload_bytes - 12)
            )
        )
        checksum = (checksum + sum(payload)) & ((1 << 64) - 1)
    return checksum


def validate_common(
    record: dict[str, str],
    role_pair: str,
    endpoint_role: str,
    implementation: str,
    warmup: int,
    iterations: int,
    payload_bytes: int,
    timeout_ms: int,
) -> None:
    client, server = ROLE_PAIRS[role_pair]
    expected = {
        "implementation": implementation,
        "protocol": "quic-datagram",
        "mode": "pingpong",
        "role_pair": role_pair,
        "endpoint_role": endpoint_role,
        "client_io": io_name(client),
        "server_io": io_name(server),
        "warmup": str(warmup),
        "iterations": str(iterations),
        "payload_bytes": str(payload_bytes),
        "timeout_ms": str(timeout_ms),
        "timing_scope": "post-handshake-single-outstanding-roundtrip",
        "complete": "true",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(
                f"{role_pair}/{endpoint_role} has {key}={record.get(key)!r}, "
                f"expected {value!r}"
            )


def validate_config(
    record: dict[str, str],
    role_pair: str,
    endpoint_role: str,
    implementation: str,
    warmup: int,
    iterations: int,
    payload_bytes: int,
    timeout_ms: int,
) -> None:
    validate_common(
        record, role_pair, endpoint_role, implementation, warmup, iterations,
        payload_bytes, timeout_ms,
    )
    expected = {
        "record": "config",
        "connection_scope": "fresh-per-sample",
        "benchmark_scope": "same-application-shape",
        "steady_state_mtu": "1200",
        "datagram_limit": "1171" if implementation == "netz" else "1162",
        "quic_version": "1",
        "cert_verify": "true",
        "pacing": "implementation-specific",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f"invalid config {key}: {record}")


def validate_result(
    record: dict[str, str],
    role_pair: str,
    implementation: str,
    warmup: int,
    iterations: int,
    payload_bytes: int,
    timeout_ms: int,
) -> int:
    validate_common(
        record, role_pair, "client", implementation, warmup, iterations,
        payload_bytes, timeout_ms,
    )
    expected = {
        "record": "result",
        "connection_scope": "fresh-per-sample",
        "benchmark_scope": "same-application-shape",
        "datagram_limit": "1171" if implementation == "netz" else "1162",
        "completion_exchange_verified": "true",
        "close_code": "59",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f"invalid result {key}: {record}")
    rounds = warmup + iterations
    if integer(record, "received_bytes") != rounds * payload_bytes:
        raise ValueError(f"invalid received byte count: {record}")
    if integer(record, "checksum") != expected_checksum(rounds, payload_bytes):
        raise ValueError(f"invalid checksum: {record}")
    values = [
        integer(record, key, positive=True)
        for key in ("min_ns", "p50_ns", "p90_ns", "p99_ns", "p999_ns", "max_ns")
    ]
    if values != sorted(values):
        raise ValueError(f"invalid latency ordering: {record}")
    mean = integer(record, "mean_ns", positive=True)
    if not values[0] <= mean <= values[-1]:
        raise ValueError(f"invalid latency mean: {record}")
    return integer(record, "p50_ns", positive=True)


def validate_server_complete(
    record: dict[str, str],
    role_pair: str,
    implementation: str,
    warmup: int,
    iterations: int,
    payload_bytes: int,
    timeout_ms: int,
) -> None:
    validate_common(
        record, role_pair, "server", implementation, warmup, iterations,
        payload_bytes, timeout_ms,
    )
    rounds = warmup + iterations
    expected = {
        "record": "server-complete",
        "received_bytes": str(rounds * payload_bytes),
        "checksum": str(expected_checksum(rounds, payload_bytes)),
        "completion_exchange_verified": "true",
        "close_code": "59",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f"invalid server completion {key}: {record}")


def summarize(
    path: Path,
    samples: int,
    client_cpu: int,
    server_cpu: int,
    warmup: int,
    iterations: int,
    payload_bytes: int,
    timeout_ms: int,
) -> list[str]:
    order = expected_order(samples)
    if (
        client_cpu < 0
        or server_cpu < 0
        or client_cpu == server_cpu
        or warmup < 0
        or iterations <= 0
        or not 12 <= payload_bytes <= 1024
        or timeout_ms <= 0
    ):
        raise ValueError("invalid benchmark configuration")
    parsed = [
        record
        for line in path.read_text(encoding="utf-8").splitlines()
        if (record := fields(line)).get("record")
        in ("environment", "run", "config", "result", "server-complete")
    ]
    environments = [x for x in parsed if x["record"] == "environment"]
    if len(environments) != 1:
        raise ValueError(f"expected one environment record, found {len(environments)}")
    environment = environments[0]
    expected_environment = {
        "protocol": "quic-datagram",
        "mode": "pingpong",
        "samples": str(samples),
        "schedule": "abba",
        "client_cpu": str(client_cpu),
        "server_cpu": str(server_cpu),
        "netz_build_mode": "ReleaseFast",
        "quinn_revision": QUINN_REVISION,
        "complete": "true",
    }
    for key, value in expected_environment.items():
        if environment.get(key) != value:
            raise ValueError(f"invalid environment {key}: {environment}")
    for key in (
        "netz_client_sha256",
        "netz_server_sha256",
        "quinn_binary_sha256",
        "quinn_lock_sha256",
    ):
        if not SHA256.fullmatch(environment.get(key, "")):
            raise ValueError(f"invalid environment {key}: {environment}")
    for key in ("host", "arch", "kernel", "zig", "rustc"):
        if not environment.get(key):
            raise ValueError(f"missing environment {key}: {environment}")

    records = [x for x in parsed if x["record"] != "environment"]
    if len(records) != len(order) * 5:
        raise ValueError(f"expected {len(order) * 5} run records, found {len(records)}")
    grouped: dict[str, dict[str, list[int]]] = {
        pair: {key: [] for key in ("p50_ns", "p99_ns", "p999_ns")}
        for pair in ROLE_PAIRS
    }
    for index, (sample, role_pair) in enumerate(order):
        marker, client_config, result, server_config, server_done = records[index * 5:index * 5 + 5]
        client, server = ROLE_PAIRS[role_pair]
        expected_marker = {
            "record": "run",
            "protocol": "quic-datagram",
            "mode": "pingpong",
            "sample": str(sample),
            "role_pair": role_pair,
            "implementation": client,
            "fixed_server": server,
            "schedule": "abba",
            "client_cpu": str(client_cpu),
            "server_cpu": str(server_cpu),
        }
        for key, value in expected_marker.items():
            if marker.get(key) != value:
                raise ValueError(f"invalid run marker {key}: {marker}")
        validate_config(
            client_config, role_pair, "client", client, warmup, iterations,
            payload_bytes, timeout_ms,
        )
        validate_result(
            result, role_pair, client, warmup, iterations, payload_bytes, timeout_ms,
        )
        for key in grouped[role_pair]:
            grouped[role_pair][key].append(integer(result, key, positive=True))
        validate_config(
            server_config, role_pair, "server", server, warmup, iterations,
            payload_bytes, timeout_ms,
        )
        validate_server_complete(
            server_done, role_pair, server, warmup, iterations, payload_bytes, timeout_ms,
        )

    output = [
        "record=environment protocol=quic-datagram mode=pingpong "
        f"samples={samples} schedule=abba client_cpu={client_cpu} server_cpu={server_cpu} "
        f"host={environment['host']} arch={environment['arch']} kernel={environment['kernel']} "
        f"zig={environment['zig']} rustc={environment['rustc']} netz_build_mode=ReleaseFast "
        f"quinn_revision={QUINN_REVISION} netz_client_sha256={environment['netz_client_sha256']} "
        f"netz_server_sha256={environment['netz_server_sha256']} "
        f"quinn_binary_sha256={environment['quinn_binary_sha256']} "
        f"quinn_lock_sha256={environment['quinn_lock_sha256']} complete=true"
    ]
    medians: dict[str, int] = {}
    for role_pair in ROLE_PAIRS:
        values = grouped[role_pair]["p50_ns"]
        if len(values) != samples:
            raise ValueError(f"{role_pair}: expected {samples} samples, found {len(values)}")
        median = int(statistics.median(values))
        medians[role_pair] = median
        client, server = ROLE_PAIRS[role_pair]
        output.append(
            "record=summary protocol=quic-datagram mode=pingpong "
            f"role_pair={role_pair} implementation={client} fixed_server={server} "
            f"samples={samples} schedule=abba client_cpu={client_cpu} server_cpu={server_cpu} "
            f"client_io={io_name(client)} server_io={io_name(server)} "
            f"median_p50_ns={median} min_p50_ns={min(values)} max_p50_ns={max(values)} "
            f"median_p99_ns={int(statistics.median(grouped[role_pair]['p99_ns']))} "
            f"median_p999_ns={int(statistics.median(grouped[role_pair]['p999_ns']))} "
            "benchmark_scope=same-application-shape complete=true"
        )
    for fixed_server, netz_pair, quinn_pair in (
        ("quinn", "netz-client+quinn-server", "quinn-client+quinn-server"),
        ("netz", "netz-client+netz-server", "quinn-client+netz-server"),
    ):
        ratio = medians[quinn_pair] / medians[netz_pair]
        if not math.isfinite(ratio) or ratio <= 0:
            raise ValueError("invalid DATAGRAM comparison ratio")
        output.append(
            "record=comparison protocol=quic-datagram mode=pingpong "
            f"fixed_server={fixed_server} samples={samples} schedule=abba "
            f"client_cpu={client_cpu} server_cpu={server_cpu} "
            f"median_p50_ns_netz={medians[netz_pair]} "
            f"median_p50_ns_quinn={medians[quinn_pair]} netz_speedup={ratio:.3f} "
            "benchmark_scope=same-application-shape complete=true"
        )
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--samples", required=True, type=int)
    parser.add_argument("--client-cpu", required=True, type=int)
    parser.add_argument("--server-cpu", required=True, type=int)
    parser.add_argument("--warmup", required=True, type=int)
    parser.add_argument("--iterations", required=True, type=int)
    parser.add_argument("--payload-bytes", required=True, type=int)
    parser.add_argument("--timeout-ms", required=True, type=int)
    args = parser.parse_args()
    for line in summarize(
        args.log, args.samples, args.client_cpu, args.server_cpu, args.warmup,
        args.iterations, args.payload_bytes, args.timeout_ms,
    ):
        print(line)


if __name__ == "__main__":
    main()
