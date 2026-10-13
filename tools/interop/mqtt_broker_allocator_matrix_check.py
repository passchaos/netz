#!/usr/bin/env python3
"""Validate the fixed-shape netz MQTT broker allocator matrix."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import statistics
import sys
from typing import NamedTuple


sys.dont_write_bytecode = True
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_MATRIX_BYTES = 128 * 1024 * 1024


class Shape(NamedTuple):
    name: str
    publishers: int
    subscribers: int
    warmup: int
    messages: int
    payload_bytes: int
    window: int


SHAPES = (
    Shape("serial", 1, 1, 128, 512, 256, 1),
    Shape("publishers-32", 32, 1, 256, 4_096, 64, 4),
    Shape("fanout-32", 1, 32, 256, 2_048, 64, 4),
    Shape("balanced-32x32", 32, 32, 256, 3_200, 64, 4),
    Shape("large-payload", 4, 4, 128, 2_048, 4_096, 16),
)
IDENTITY_FILES = {
    "netz-broker",
    "mqtt-driver",
    "mqtt_broker_allocator_matrix.sh",
    "mqtt_broker_allocator_matrix_check.py",
}
RUN_FILES = {"server.log", "driver.log"}


def fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in result or not value:
            raise ValueError(f"duplicate or empty field {token!r}")
        result[key] = value
    return result


def one_record(path: Path, kind: str) -> dict[str, str]:
    records = [
        parsed
        for line in path.read_text(encoding="utf-8").splitlines()
        if (parsed := fields(line)).get("record") == kind
    ]
    if len(records) != 1:
        raise ValueError(f"expected one {kind} in {path}, found {len(records)}")
    return records[0]


def integer(record: dict[str, str], key: str, *, positive: bool = True) -> int:
    try:
        value = int(record[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {record}") from error
    if value < 0 or (positive and value == 0):
        raise ValueError(f"invalid {key}: {record}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def exact_names(path: Path, expected: set[str]) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"artifact path is not a real directory: {path}")
    actual = {entry.name for entry in path.iterdir()}
    if actual != expected:
        raise ValueError(
            f"invalid artifact set in {path}: expected {sorted(expected)}, "
            f"found {sorted(actual)}"
        )


def require_artifact(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or not (
        0 < path.stat().st_size <= MAX_ARTIFACT_BYTES
    ):
        raise ValueError(f"missing, empty, or invalid artifact: {path}")


def require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or invalid regular file: {path}")


def validate_driver(
    record: dict[str, str],
    shape: Shape,
    qos: int,
    session_expiry_seconds: int,
) -> None:
    queue_capacity = max(1_024, shape.warmup, shape.messages)
    expected = {
        "record": "result",
        "implementation": "netz",
        "protocol": "mqtt5",
        "transport": "tcp",
        "mode": f"qos{qos}-fanout",
        "role_pair": "netz-client+netz-server",
        "client_io": "zio-std-io",
        "server_io": "zio-std-io",
        "benchmark_scope": "same-client-workload",
        "timing_usable": "true",
        "client_tcp_nodelay": "true",
        "server_tcp_nodelay": "true",
        "connection_scope": "persistent",
        "publishers": str(shape.publishers),
        "subscribers": str(shape.subscribers),
        "overlapping_subscriptions": "1",
        "publisher_window": str(shape.window),
        "server_queue_capacity": str(queue_capacity),
        "session_expiry_seconds": str(session_expiry_seconds),
        "warmup": str(shape.warmup),
        "publishes": str(shape.messages),
        "deliveries": str(shape.messages * shape.subscribers),
        "payload_bytes": str(shape.payload_bytes),
        "complete": "true",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f"invalid driver {key}: {record}")
    numeric = {
        key: integer(record, key)
        for key in (
            "elapsed_ns", "publishes_per_s", "deliveries_per_s",
            "p50_ns", "p99_ns", "p999_ns", "client_alloc_count",
            "client_total_allocated_bytes", "client_peak_live_bytes",
            "checksum",
        )
    }
    if numeric["publishes_per_s"] != (
        shape.messages * 1_000_000_000 // numeric["elapsed_ns"]
    ):
        raise ValueError(f"driver publish rate does not match elapsed time: {record}")
    if numeric["deliveries_per_s"] != (
        shape.messages * shape.subscribers * 1_000_000_000
        // numeric["elapsed_ns"]
    ):
        raise ValueError(f"driver delivery rate does not match elapsed time: {record}")
    if not (numeric["p50_ns"] <= numeric["p99_ns"] <= numeric["p999_ns"]):
        raise ValueError(f"driver latency percentiles are unordered: {record}")
    payload_last = ((shape.payload_bytes - 1) * 17 + 3) & 0xFF
    expected_checksum = (
        (shape.warmup + shape.messages)
        * shape.subscribers
        * (3 + payload_last)
    ) & ((1 << 64) - 1)
    if numeric["checksum"] != expected_checksum:
        raise ValueError(f"driver checksum does not match workload: {record}")


def validate_allocator(
    record: dict[str, str],
    shape: Shape,
    qos: int,
    session_expiry_seconds: int,
) -> dict[str, int]:
    expected = {
        "record": "allocator",
        "implementation": "netz",
        "endpoint_role": "server",
        "protocol": "mqtt5",
        "transport": "tcp",
        "mode": f"qos{qos}-fanout",
        "timing_usable": "false",
        "allocator_scope": "broker-explicit",
        "connection_scope": "persistent",
        "client_tcp_nodelay": "true",
        "server_tcp_nodelay": "true",
        "session_expiry_seconds": str(session_expiry_seconds),
        "configured_connections": str(shape.publishers + shape.subscribers),
        "complete": "true",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f"invalid allocator {key}: {record}")
    bucket_keys = (
        "alloc_le_64", "alloc_le_256", "alloc_le_1024",
        "alloc_le_4096", "alloc_le_16384", "alloc_le_65536",
        "alloc_gt_65536",
    )
    values = {
        key: integer(record, key, positive=key in {
            "alloc_count", "free_count", "total_allocated_bytes",
            "total_freed_bytes", "peak_live_bytes",
        })
        for key in (
            "alloc_count", "free_count", "resize_count",
            "remap_count", "total_allocated_bytes",
            "total_freed_bytes", "live_bytes", "peak_live_bytes",
            *bucket_keys,
        )
    }
    if values["live_bytes"] != 0:
        raise ValueError(f"broker allocator leaked live bytes: {record}")
    if values["total_allocated_bytes"] != values["total_freed_bytes"]:
        raise ValueError(f"broker allocator byte accounting differs: {record}")
    if values["peak_live_bytes"] > values["total_allocated_bytes"]:
        raise ValueError(f"broker allocator peak exceeds cumulative bytes: {record}")
    if sum(values[key] for key in bucket_keys) != values["alloc_count"]:
        raise ValueError(f"broker allocator buckets do not sum to allocations: {record}")
    return values


def verify(
    root: Path,
    samples: int,
    client_cpu: int,
    server_cpu: int,
    qos: int = 1,
    session_expiry_seconds: int = 0,
) -> list[str]:
    if samples <= 0:
        raise ValueError("samples must be positive")
    if min(client_cpu, server_cpu) < 0 or client_cpu == server_cpu:
        raise ValueError("client/server CPUs must be distinct and non-negative")
    if qos not in (1, 2):
        raise ValueError("QoS must be 1 or 2")
    if not 0 <= session_expiry_seconds <= (1 << 32) - 1:
        raise ValueError("invalid Session Expiry Interval")
    total_bytes = sum(
        path.stat().st_size for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    if total_bytes > MAX_MATRIX_BYTES:
        raise ValueError(f"matrix artifacts exceed {MAX_MATRIX_BYTES} bytes")
    exact_names(
        root,
        {"environment.log", "identity", "summary.log"}
        | {shape.name for shape in SHAPES},
    )
    require_artifact(root / "environment.log")
    # The runner creates this file before invoking the checker and fills it
    # only after the first independent summary succeeds. It must already be a
    # real file, but emptiness at this stage is intentional.
    require_regular_file(root / "summary.log")
    identity = root / "identity"
    exact_names(identity, IDENTITY_FILES)
    for name in IDENTITY_FILES:
        require_artifact(identity / name)
    environment = one_record(root / "environment.log", "environment")
    expected_environment = {
        "protocol": "mqtt5",
        "transport": "tcp",
        "mode": f"qos{qos}-fanout-allocator-matrix",
        "benchmark_scope": "same-client-workload",
        "timing_usable": "false",
        "allocator_scope": "broker-explicit",
        "session_expiry_seconds": str(session_expiry_seconds),
        "shapes": str(len(SHAPES)),
        "samples": str(samples),
        "schedule": "sequential",
        "client_cpu": str(client_cpu),
        "server_cpu": str(server_cpu),
        "timeout_seconds": "60",
        "max_artifact_bytes": str(MAX_ARTIFACT_BYTES),
        "max_matrix_bytes": str(MAX_MATRIX_BYTES),
        "netz_build_mode": "ReleaseFast",
        "complete": "true",
    }
    for key, value in expected_environment.items():
        if environment.get(key) != value:
            raise ValueError(f"invalid environment {key}: {environment}")
    for key in ("host", "arch", "kernel", "zig"):
        if not environment.get(key):
            raise ValueError(f"missing environment {key}: {environment}")
    identity_hashes = {
        "netz_broker_sha256": "netz-broker",
        "driver_sha256": "mqtt-driver",
        "runner_sha256": "mqtt_broker_allocator_matrix.sh",
        "checker_sha256": "mqtt_broker_allocator_matrix_check.py",
    }
    for field, name in identity_hashes.items():
        if environment.get(field) != sha256(identity / name):
            raise ValueError(f"environment {field} does not match {name}")

    output = [
        "record=allocator-matrix-environment protocol=mqtt5 transport=tcp "
        f"mode=qos{qos}-fanout-allocator-matrix "
        f"session_expiry_seconds={session_expiry_seconds} "
        "benchmark_scope=same-client-workload timing_usable=false "
        "allocator_scope=broker-explicit connection_scope=persistent "
        "client_tcp_nodelay=true server_tcp_nodelay=true "
        f"shapes={len(SHAPES)} samples={samples} schedule=sequential "
        f"client_cpu={client_cpu} server_cpu={server_cpu} timeout_seconds=60 "
        f"max_artifact_bytes={MAX_ARTIFACT_BYTES} "
        f"max_matrix_bytes={MAX_MATRIX_BYTES} host={environment['host']} "
        f"arch={environment['arch']} kernel={environment['kernel']} "
        f"zig={environment['zig']} netz_build_mode=ReleaseFast "
        f"netz_broker_sha256={environment['netz_broker_sha256']} "
        f"driver_sha256={environment['driver_sha256']} "
        f"runner_sha256={environment['runner_sha256']} "
        f"checker_sha256={environment['checker_sha256']} complete=true"
    ]
    for shape in SHAPES:
        shape_root = root / shape.name
        exact_names(
            shape_root,
            {f"sample-{sample:02d}" for sample in range(1, samples + 1)},
        )
        values = {key: [] for key in (
            "alloc_count", "free_count", "resize_count",
            "remap_count", "total_allocated_bytes",
            "peak_live_bytes", "alloc_le_64", "alloc_le_256",
            "alloc_le_1024", "alloc_le_4096", "alloc_le_16384",
            "alloc_le_65536", "alloc_gt_65536",
        )}
        for sample in range(1, samples + 1):
            run = shape_root / f"sample-{sample:02d}"
            exact_names(run, RUN_FILES)
            for name in RUN_FILES:
                require_artifact(run / name)
            server_log = run / "server.log"
            if "netz MQTT 3.1/3.1.1/5 broker listening" not in server_log.read_text(
                encoding="utf-8"
            ):
                raise ValueError(f"missing broker ready marker: {run}")
            allocator = validate_allocator(
                one_record(server_log, "allocator"),
                shape,
                qos,
                session_expiry_seconds,
            )
            validate_driver(
                one_record(run / "driver.log", "result"),
                shape,
                qos,
                session_expiry_seconds,
            )
            for key in values:
                values[key].append(allocator[key])
        medians = {key: int(statistics.median(value)) for key, value in values.items()}
        output.append(
            "record=allocator-matrix-shape protocol=mqtt5 transport=tcp "
            f"mode=qos{qos}-fanout-allocator-matrix "
            f"session_expiry_seconds={session_expiry_seconds} "
            "benchmark_scope=same-client-workload timing_usable=false "
            "allocator_scope=broker-explicit "
            f"shape={shape.name} samples={samples} "
            f"publishers={shape.publishers} subscribers={shape.subscribers} "
            f"warmup={shape.warmup} publishes={shape.messages} "
            f"deliveries={shape.messages * shape.subscribers} "
            f"payload_bytes={shape.payload_bytes} publisher_window={shape.window} "
            f"median_alloc_count={medians['alloc_count']} "
            f"min_alloc_count={min(values['alloc_count'])} "
            f"max_alloc_count={max(values['alloc_count'])} "
            f"median_free_count={medians['free_count']} "
            f"median_resize_count={medians['resize_count']} "
            f"median_remap_count={medians['remap_count']} "
            f"median_total_allocated_bytes={medians['total_allocated_bytes']} "
            f"median_peak_live_bytes={medians['peak_live_bytes']} "
            f"allocs_per_publish={medians['alloc_count'] / shape.messages:.3f} "
            f"allocs_per_delivery={medians['alloc_count'] / (shape.messages * shape.subscribers):.3f} "
            f"allocated_bytes_per_publish={medians['total_allocated_bytes'] / shape.messages:.3f} "
            f"median_alloc_le_64={medians['alloc_le_64']} "
            f"median_alloc_le_256={medians['alloc_le_256']} "
            f"median_alloc_le_1024={medians['alloc_le_1024']} "
            f"median_alloc_le_4096={medians['alloc_le_4096']} "
            f"median_alloc_le_16384={medians['alloc_le_16384']} "
            f"median_alloc_le_65536={medians['alloc_le_65536']} "
            f"median_alloc_gt_65536={medians['alloc_gt_65536']} "
            "live_bytes=0 complete=true"
        )
    output.append(
        "record=allocator-matrix-complete protocol=mqtt5 transport=tcp "
        f"mode=qos{qos}-fanout-allocator-matrix "
        f"session_expiry_seconds={session_expiry_seconds} "
        "benchmark_scope=same-client-workload timing_usable=false "
        f"shapes={len(SHAPES)} samples_per_shape={samples} "
        f"broker_runs={len(SHAPES) * samples} complete=true"
    )
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list-shapes", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--samples", type=int, default=4)
    parser.add_argument("--qos", type=int, choices=(1, 2), default=1)
    parser.add_argument(
        "--session-expiry-seconds", type=int, default=0
    )
    parser.add_argument("--client-cpu", type=int)
    parser.add_argument("--server-cpu", type=int)
    args = parser.parse_args()
    if args.list_shapes:
        for shape in SHAPES:
            print("\t".join(map(str, shape)))
        return
    if args.root is None or args.client_cpu is None or args.server_cpu is None:
        parser.error("matrix verification arguments are required")
    for line in verify(
        args.root,
        args.samples,
        args.client_cpu,
        args.server_cpu,
        args.qos,
        args.session_expiry_seconds,
    ):
        print(line)


if __name__ == "__main__":
    main()
