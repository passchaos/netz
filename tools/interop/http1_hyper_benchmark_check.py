#!/usr/bin/env python3
"""Validate and summarize fixed-binary HTTP/1 netz/Hyper benchmarks."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import re
import statistics


HYPER_REVISION = "084473f728f9d07b3be5845475aa2f62ed9ff579"
SHA256 = re.compile(r"[0-9a-f]{64}")


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


def expected_order(samples: int) -> list[str]:
    if samples <= 0 or samples % 2 == 0:
        raise ValueError("samples must be a positive odd number")
    order: list[str] = []
    for sample in range(samples):
        order.extend(
            ("netz", "hyper") if sample % 2 == 0 else ("hyper", "netz")
        )
    return order


def endpoint_io(implementation: str, workload: str) -> tuple[str, str]:
    if implementation == "netz":
        return "zio-std-io", "zio-std-io"
    if workload == "pipeline":
        return "rust-std-sync", "hyper-tokio"
    return "hyper-tokio", "hyper-tokio"


def validate_common(
    record: dict[str, str], implementation: str, workload: str
) -> None:
    client_io, server_io = endpoint_io(implementation, workload)
    expected = {
        "implementation": implementation,
        "protocol": "http1",
        "transport": "tcp",
        "workload": workload,
        "benchmark_scope": "same-application-shape",
        "client_io": client_io,
        "server_io": server_io,
        "connection_scope": "persistent",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(
                f"{implementation}/{workload} has {key}={record.get(key)!r}, "
                f"expected {value!r}"
            )


def validate_environment(
    record: dict[str, str], workload: str, samples: int, cpu: int
) -> None:
    expected = {
        "record": "environment",
        "protocol": "http1",
        "workload": workload,
        "samples": str(samples),
        "schedule": "abba",
        "cpu": str(cpu),
        "netz_build_mode": "ReleaseFast",
        "hyper_revision": HYPER_REVISION,
        "complete": "true",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f"environment {key} mismatch: {record}")
    for key in (
        "netz_binary_sha256",
        "hyper_binary_sha256",
        "hyper_lock_sha256",
    ):
        if not SHA256.fullmatch(record.get(key, "")):
            raise ValueError(f"invalid {key}: {record}")
    for key in ("host", "arch", "kernel", "zig", "rustc"):
        if not record.get(key):
            raise ValueError(f"missing {key}: {record}")


def validate_pipeline(
    config: dict[str, str],
    result: dict[str, str],
    implementation: str,
    warmup: int,
    iterations: int,
) -> int:
    for record in (config, result):
        validate_common(record, implementation, "pipeline")
        expected = {
            "pipeline_depth": "16",
            "warmup": str(warmup),
            "iterations": str(iterations),
        }
        for key, value in expected.items():
            if record.get(key) != value:
                raise ValueError(f"pipeline {key} mismatch: {record}")
    expected_config = {
        "request_wire_bytes": "35",
        "response_wire_bytes": "89",
        "pipeline_flush": "true",
        "write_strategy": (
            "auto" if implementation == "netz" else "hyper-pipeline-flush"
        ),
    }
    for key, value in expected_config.items():
        if config.get(key) != value:
            raise ValueError(f"pipeline config {key} mismatch: {config}")
    requests = iterations * 16
    expected_result = {
        "requests": requests,
        "received_bytes": requests * 89,
        "server_requests": (warmup + iterations) * 16,
    }
    for key, value in expected_result.items():
        if integer(result, key) != value:
            raise ValueError(f"pipeline result {key} mismatch: {result}")
    elapsed = integer(result, "elapsed_ns", positive=True)
    if integer(result, "ns_per_request") != elapsed // requests:
        raise ValueError(f"pipeline ns_per_request mismatch: {result}")
    if integer(result, "requests_per_s") != requests * 1_000_000_000 // elapsed:
        raise ValueError(f"pipeline requests_per_s mismatch: {result}")
    if result.get("complete") != "true":
        raise ValueError(f"pipeline result incomplete: {result}")
    return integer(result, "ns_per_request", positive=True)


def validate_body(
    config: dict[str, str],
    result: dict[str, str],
    implementation: str,
    mode: str,
    body_bytes: int,
    chunk_bytes: int,
    warmup: int,
    iterations: int,
) -> int:
    for record in (config, result):
        validate_common(record, implementation, "streaming-body")
        expected = {
            "mode": mode,
            "body_bytes": str(body_bytes),
            "chunk_bytes": str(chunk_bytes),
            "warmup": str(warmup),
            "iterations": str(iterations),
        }
        for key, value in expected.items():
            if record.get(key) != value:
                raise ValueError(f"body {key} mismatch: {record}")
    wire_bytes = body_bytes * 2 * iterations
    if integer(result, "measured_body_bytes") != wire_bytes:
        raise ValueError(f"body byte count mismatch: {result}")
    if integer(result, "server_received_requests") != warmup + iterations:
        raise ValueError(f"body server completion mismatch: {result}")
    elapsed = integer(result, "elapsed_ns", positive=True)
    ns_per_roundtrip = elapsed // iterations
    if integer(result, "ns_per_roundtrip") != ns_per_roundtrip:
        raise ValueError(f"body ns_per_roundtrip mismatch: {result}")
    mib_per_s = wire_bytes * 1_000_000_000 // (elapsed * 1024 * 1024)
    if integer(result, "aggregate_MiB_s") != mib_per_s:
        raise ValueError(f"body aggregate_MiB_s mismatch: {result}")
    if result.get("complete") != "true":
        raise ValueError(f"body result incomplete: {result}")
    return ns_per_roundtrip


def summarize(
    path: Path,
    workload: str,
    samples: int,
    cpu: int,
    warmup: int,
    iterations: int,
    mode: str | None = None,
    body_bytes: int = 1024 * 1024,
    chunk_bytes: int = 16 * 1024,
) -> list[str]:
    order = expected_order(samples)
    if cpu < 0 or warmup < 0 or iterations <= 0:
        raise ValueError("invalid benchmark configuration")
    if workload == "streaming-body" and (
        mode not in ("fixed", "chunked")
        or body_bytes <= 0
        or chunk_bytes <= 0
        or body_bytes % chunk_bytes != 0
    ):
        raise ValueError("invalid body benchmark configuration")

    parsed = [
        record
        for line in path.read_text(encoding="utf-8").splitlines()
        if (record := fields(line)).get("record")
        in ("environment", "run", "config", "result")
    ]
    environments = [record for record in parsed if record["record"] == "environment"]
    if len(environments) != 1:
        raise ValueError(f"expected one environment record, found {len(environments)}")
    validate_environment(environments[0], workload, samples, cpu)
    runs = [record for record in parsed if record["record"] != "environment"]
    if len(runs) != samples * 6:
        raise ValueError(f"expected {samples * 6} run records, found {len(runs)}")

    values: dict[str, list[int]] = {"netz": [], "hyper": []}
    for index, implementation in enumerate(order):
        marker, config, result = runs[index * 3 : index * 3 + 3]
        expected_marker = {
            "record": "run",
            "protocol": "http1",
            "workload": workload,
            "sample": str(index // 2 + 1),
            "implementation": implementation,
            "schedule": "abba",
            "cpu": str(cpu),
        }
        for key, value in expected_marker.items():
            if marker.get(key) != value:
                raise ValueError(
                    f"run marker has {key}={marker.get(key)!r}, expected {value!r}"
                )
        if (
            config.get("record") != "config"
            or result.get("record") != "result"
        ):
            raise ValueError(
                f"run {index + 1} does not contain config then result"
            )
        if workload == "pipeline":
            value = validate_pipeline(
                config, result, implementation, warmup, iterations
            )
        elif workload == "streaming-body":
            assert mode is not None
            value = validate_body(
                config, result, implementation, mode, body_bytes, chunk_bytes,
                warmup, iterations,
            )
        else:
            raise ValueError("invalid HTTP/1 benchmark workload")
        values[implementation].append(value)

    suffix = (
        f" mode={mode} body_bytes={body_bytes} chunk_bytes={chunk_bytes}"
        if mode
        else ""
    )
    environment = environments[0]
    output = [
        "record=environment protocol=http1 "
        f"workload={workload} samples={samples} schedule=abba cpu={cpu} "
        f"host={environment['host']} arch={environment['arch']} "
        f"kernel={environment['kernel']} zig={environment['zig']} "
        f"rustc={environment['rustc']} netz_build_mode=ReleaseFast "
        f"hyper_revision={HYPER_REVISION} "
        f"netz_binary_sha256={environment['netz_binary_sha256']} "
        f"hyper_binary_sha256={environment['hyper_binary_sha256']} "
        f"hyper_lock_sha256={environment['hyper_lock_sha256']} "
        "complete=true"
    ]
    medians: dict[str, int] = {}
    for implementation in ("netz", "hyper"):
        sample_values = values[implementation]
        median = int(statistics.median(sample_values))
        medians[implementation] = median
        client_io, server_io = endpoint_io(implementation, workload)
        output.append(
            f"record=summary implementation={implementation} protocol=http1 "
            f"workload={workload}{suffix} samples={samples} schedule=abba cpu={cpu} "
            f"client_io={client_io} server_io={server_io} median_ns={median} "
            f"min_ns={min(sample_values)} max_ns={max(sample_values)} "
            "benchmark_scope=same-application-shape complete=true"
        )
    ratio = medians["hyper"] / medians["netz"]
    if not math.isfinite(ratio) or ratio <= 0:
        raise ValueError("invalid HTTP/1 comparison ratio")
    output.append(
        f"record=comparison protocol=http1 workload={workload}{suffix} "
        f"samples={samples} schedule=abba cpu={cpu} "
        f"median_ns_netz={medians['netz']} median_ns_hyper={medians['hyper']} "
        f"netz_speedup={ratio:.3f} benchmark_scope=same-application-shape "
        "complete=true"
    )
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument(
        "--workload",
        choices=("pipeline", "streaming-body"),
        required=True,
    )
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--mode", choices=("fixed", "chunked"))
    parser.add_argument("--body-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--chunk-bytes", type=int, default=16 * 1024)
    args = parser.parse_args()
    for line in summarize(
        args.log, args.workload, args.samples, args.cpu, args.warmup,
        args.iterations, args.mode, args.body_bytes, args.chunk_bytes,
    ):
        print(line)


if __name__ == "__main__":
    main()
