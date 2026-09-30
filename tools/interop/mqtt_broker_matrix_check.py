#!/usr/bin/env python3
"""Validate the fixed-shape netz/Mosquitto MQTT benchmark matrix."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import math
from pathlib import Path
import re
import statistics
import sys
from typing import NamedTuple


sys.dont_write_bytecode = True
SINGLE_PATH = Path(__file__).with_name("mqtt_broker_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location(
    "mqtt_broker_benchmark_check_for_matrix", SINGLE_PATH
)
assert SPEC is not None and SPEC.loader is not None
SINGLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SINGLE)

SHA256 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
MOSQUITTO_REVISION = "5cd2546511596a269dbf53f85858c623b09ebdd6"
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
    "mosquitto",
    "compare_mqtt_mosquitto.sh",
    "mqtt_broker_matrix.sh",
    "mqtt_broker_benchmark_check.py",
    "mqtt_broker_benchmark_config.py",
    "mqtt_broker_matrix_check.py",
    "mosquitto_build.sh",
    "mosquitto-configure.log",
    "mosquitto-build.log",
    "mosquitto-head.txt",
    "mosquitto-source-state.txt",
}
RUN_FILES = {"runner.log", "artifacts"}
ARTIFACT_FILES = {
    "netz-server.log",
    "netz-result.txt",
    "netz-server.rss",
    "mosquitto.conf",
    "mosquitto-server.log",
    "mosquitto-result.txt",
    "mosquitto-server.rss",
}


def sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"identity artifact is not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def exact_names(path: Path, expected: set[str]) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"matrix artifact path is not a real directory: {path}")
    try:
        actual = {entry.name for entry in path.iterdir()}
    except OSError as error:
        raise ValueError(f"cannot inspect matrix artifact directory {path}") from error
    if actual != expected:
        raise ValueError(
            f"invalid artifact set in {path}: expected {sorted(expected)}, "
            f"found {sorted(actual)}"
        )


def require_nonempty_regular(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or not (
        0 < path.stat().st_size <= MAX_ARTIFACT_BYTES
    ):
        raise ValueError(f"missing, empty, or non-regular artifact: {path}")


def validate_mosquitto_config(path: Path, queue_capacity: int) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    expected = {
        "allow_anonymous true",
        "persistence false",
        "max_inflight_messages 64",
        f"max_queued_messages {queue_capacity}",
        "set_tcp_nodelay true",
        "log_dest stdout",
    }
    if not expected <= set(lines):
        raise ValueError(f"invalid Mosquitto benchmark config: {path}")
    listeners = [line for line in lines if line.startswith("listener ")]
    if len(listeners) != 1 or not re.fullmatch(
        r"listener [1-9][0-9]{0,4} 127\.0\.0\.1", listeners[0]
    ):
        raise ValueError(f"invalid Mosquitto listener config: {path}")
    port = int(listeners[0].split()[1])
    if port > 65_535:
        raise ValueError(f"invalid Mosquitto listener port: {path}")


def one_record(path: Path, kind: str) -> dict[str, str]:
    records = [
        parsed
        for line in path.read_text(encoding="utf-8").splitlines()
        if (parsed := SINGLE.fields(line)).get("record") == kind
    ]
    if len(records) != 1:
        raise ValueError(f"expected one {kind} record in {path}, found {len(records)}")
    return records[0]


def integer(record: dict[str, str], key: str) -> int:
    return SINGLE.positive(record, key)


def expected_order(sample: int) -> str:
    if sample <= 0:
        raise ValueError("sample must be positive")
    return ("netz-first", "mosquitto-first", "mosquitto-first", "netz-first")[(sample - 1) % 4]


def verify_environment(
    path: Path,
    samples: int,
    client_cpu: int,
    server_cpu: int,
    sampler_cpu: int,
    qos: int,
    session_expiry_seconds: int,
) -> dict[str, str]:
    record = one_record(path, "environment")
    expected = {
        "protocol": "mqtt5",
        "transport": "tcp",
        "mode": f"qos{qos}-fanout-matrix",
        "benchmark_scope": "same-client-workload",
        "timing_usable": "true",
        "client_tcp_nodelay": "true",
        "server_tcp_nodelay": "true",
        "session_expiry_seconds": str(session_expiry_seconds),
        "shapes": str(len(SHAPES)),
        "samples": str(samples),
        "schedule": "abba",
        "client_cpu": str(client_cpu),
        "server_cpu": str(server_cpu),
        "sampler_cpu": str(sampler_cpu),
        "rss_source": "proc-vmrss-sampled-2ms",
        "max_artifact_bytes": str(MAX_ARTIFACT_BYTES),
        "max_matrix_bytes": str(MAX_MATRIX_BYTES),
        "netz_build_mode": "ReleaseFast",
        "mosquitto_source_clean": "true",
        "complete": "true",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f"invalid matrix environment {key}: {record}")
    for key in ("host", "arch", "kernel", "zig"):
        if not record.get(key):
            raise ValueError(f"missing matrix environment {key}: {record}")
    if (not REVISION.fullmatch(record.get("mosquitto_revision", "")) or
            record["mosquitto_revision"] != MOSQUITTO_REVISION):
        raise ValueError(f"invalid Mosquitto revision: {record}")
    identity = path.parent / "identity"
    exact_names(identity, IDENTITY_FILES)
    for name in IDENTITY_FILES:
        require_nonempty_regular(identity / name)
    artifacts = {
        "netz_broker_sha256": identity / "netz-broker",
        "driver_sha256": identity / "mqtt-driver",
        "mosquitto_binary_sha256": identity / "mosquitto",
        "single_runner_sha256": identity / "compare_mqtt_mosquitto.sh",
        "matrix_runner_sha256": identity / "mqtt_broker_matrix.sh",
        "single_checker_sha256": identity / "mqtt_broker_benchmark_check.py",
        "config_helper_sha256": identity / "mqtt_broker_benchmark_config.py",
        "matrix_checker_sha256": identity / "mqtt_broker_matrix_check.py",
        "mosquitto_build_helper_sha256": identity / "mosquitto_build.sh",
        "mosquitto_configure_log_sha256": identity / "mosquitto-configure.log",
        "mosquitto_build_log_sha256": identity / "mosquitto-build.log",
        "mosquitto_source_state_sha256": identity / "mosquitto-source-state.txt",
    }
    for key, artifact in artifacts.items():
        value = record.get(key, "")
        if not SHA256.fullmatch(value) or value != sha256(artifact):
            raise ValueError(f"matrix environment {key} does not match {artifact}")
    revision = (identity / "mosquitto-head.txt").read_text(
        encoding="ascii"
    ).strip()
    if record["mosquitto_revision"] != revision:
        raise ValueError("matrix Mosquitto revision artifact differs")
    if (identity / "mosquitto-source-state.txt").read_text(
        encoding="ascii"
    ) != f"revision={revision} source_clean=true\n":
        raise ValueError("invalid Mosquitto source-state artifact")
    return record


def median(values: list[int]) -> int:
    return int(statistics.median(values))


def verify(
    root: Path,
    samples: int,
    client_cpu: int,
    server_cpu: int,
    sampler_cpu: int,
    qos: int = 1,
    session_expiry_seconds: int = 0,
) -> list[str]:
    if samples <= 0 or samples % 4 != 0:
        raise ValueError("matrix samples must be a positive multiple of four")
    if min(client_cpu, server_cpu, sampler_cpu) < 0 or len(
        {client_cpu, server_cpu, sampler_cpu}
    ) != 3:
        raise ValueError("matrix CPUs must be distinct non-negative values")
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
    environment = verify_environment(
        root / "environment.log", samples, client_cpu, server_cpu,
        sampler_cpu, qos, session_expiry_seconds,
    )
    output = [
        "record=matrix-environment protocol=mqtt5 transport=tcp "
        f"mode=qos{qos}-fanout-matrix benchmark_scope=same-client-workload "
        f"session_expiry_seconds={session_expiry_seconds} "
        f"timing_usable=true shapes={len(SHAPES)} samples={samples} "
        "client_tcp_nodelay=true server_tcp_nodelay=true "
        f"schedule=abba client_cpu={client_cpu} server_cpu={server_cpu} "
        f"sampler_cpu={sampler_cpu} rss_source=proc-vmrss-sampled-2ms "
        f"max_artifact_bytes={MAX_ARTIFACT_BYTES} max_matrix_bytes={MAX_MATRIX_BYTES} "
        f"host={environment['host']} arch={environment['arch']} "
        f"kernel={environment['kernel']} zig={environment['zig']} "
        f"mosquitto_revision={environment['mosquitto_revision']} "
        "mosquitto_source_clean=true "
        f"netz_broker_sha256={environment['netz_broker_sha256']} "
        f"driver_sha256={environment['driver_sha256']} "
        f"mosquitto_binary_sha256={environment['mosquitto_binary_sha256']} "
        f"single_runner_sha256={environment['single_runner_sha256']} "
        f"matrix_runner_sha256={environment['matrix_runner_sha256']} "
        f"single_checker_sha256={environment['single_checker_sha256']} "
        f"config_helper_sha256={environment['config_helper_sha256']} "
        f"matrix_checker_sha256={environment['matrix_checker_sha256']} "
        f"mosquitto_build_helper_sha256={environment['mosquitto_build_helper_sha256']} "
        f"mosquitto_configure_log_sha256={environment['mosquitto_configure_log_sha256']} "
        f"mosquitto_build_log_sha256={environment['mosquitto_build_log_sha256']} "
        f"mosquitto_source_state_sha256={environment['mosquitto_source_state_sha256']} "
        "complete=true"
    ]
    for shape in SHAPES:
        shape_root = root / shape.name
        exact_names(
            shape_root,
            {f"sample-{sample:02d}" for sample in range(1, samples + 1)},
        )
        values = {
            server: {key: [] for key in (
                "publishes_per_s", "p50_ns", "p99_ns", "p999_ns",
                "client_alloc_count", "client_total_allocated_bytes",
                "client_peak_live_bytes", "server_rss_kib",
            )}
            for server in ("netz", "mosquitto")
        }
        queue_capacity = max(1_024, shape.warmup, shape.messages)
        for sample in range(1, samples + 1):
            run = root / shape.name / f"sample-{sample:02d}"
            exact_names(run, RUN_FILES)
            exact_names(run / "artifacts", ARTIFACT_FILES)
            for artifact_name in ARTIFACT_FILES | {"runner.log"}:
                artifact = (
                    run / artifact_name
                    if artifact_name == "runner.log"
                    else run / "artifacts" / artifact_name
                )
                require_nonempty_regular(artifact)
            order = one_record(run / "runner.log", "run-order")
            expected_marker = {
                "protocol": "mqtt5",
                "transport": "tcp",
                "mode": f"qos{qos}-fanout",
                "benchmark_scope": "same-client-workload",
                "timing_usable": "true",
                "client_tcp_nodelay": "true",
                "server_tcp_nodelay": "true",
                "session_expiry_seconds": str(session_expiry_seconds),
                "broker_order": expected_order(sample),
                "client_cpu": str(client_cpu),
                "server_cpu": str(server_cpu),
                "sampler_cpu": str(sampler_cpu),
                "complete": "true",
            }
            for key, value in expected_marker.items():
                if order.get(key) != value:
                    raise ValueError(f"invalid {shape.name} sample {sample} {key}: {order}")
            artifacts = run / "artifacts"
            validate_mosquitto_config(
                artifacts / "mosquitto.conf", queue_capacity
            )
            if "netz MQTT 3.1.1/5 broker listening" not in (
                artifacts / "netz-server.log"
            ).read_text(encoding="utf-8"):
                raise ValueError(f"missing netz ready marker: {run}")
            if not re.search(
                r"mosquitto version .* running",
                (artifacts / "mosquitto-server.log").read_text(
                    encoding="utf-8"
                ),
            ):
                raise ValueError(f"missing Mosquitto ready marker: {run}")
            netz_log = artifacts / "netz-result.txt"
            mosquitto_log = artifacts / "mosquitto-result.txt"
            netz_rss = artifacts / "netz-server.rss"
            mosquitto_rss = artifacts / "mosquitto-server.rss"
            single_output = SINGLE.verify(
                netz_log, mosquitto_log, shape.publishers, shape.subscribers,
                shape.warmup, shape.messages, shape.payload_bytes, shape.window,
                netz_rss, mosquitto_rss, "proc-vmrss-sampled-2ms",
                queue_capacity, qos, session_expiry_seconds,
            )
            expected_verified = SINGLE.fields(single_output.splitlines()[-1])
            actual_verified = one_record(run / "runner.log", "verified")
            if actual_verified != expected_verified:
                raise ValueError(
                    f"single-run verification record differs for "
                    f"{shape.name} sample {sample}"
                )
            for server, path, rss_path in (
                ("netz", netz_log, netz_rss),
                ("mosquitto", mosquitto_log, mosquitto_rss),
            ):
                record = SINGLE.result(path)
                for key in values[server]:
                    if key == "server_rss_kib":
                        values[server][key].append(SINGLE.read_rss(rss_path))
                    else:
                        values[server][key].append(integer(record, key))
        netz_rate = median(values["netz"]["publishes_per_s"])
        mosquitto_rate = median(values["mosquitto"]["publishes_per_s"])
        netz_p99 = median(values["netz"]["p99_ns"])
        mosquitto_p99 = median(values["mosquitto"]["p99_ns"])
        netz_p50 = median(values["netz"]["p50_ns"])
        mosquitto_p50 = median(values["mosquitto"]["p50_ns"])
        netz_p999 = median(values["netz"]["p999_ns"])
        mosquitto_p999 = median(values["mosquitto"]["p999_ns"])
        netz_rss = median(values["netz"]["server_rss_kib"])
        mosquitto_rss = median(values["mosquitto"]["server_rss_kib"])
        ratios = (
            netz_rate / mosquitto_rate,
            mosquitto_p99 / netz_p99,
            mosquitto_rss / netz_rss,
        )
        if not all(math.isfinite(value) and value > 0 for value in ratios):
            raise ValueError(f"invalid matrix ratios for {shape.name}")
        output.append(
            "record=matrix-shape protocol=mqtt5 transport=tcp "
            f"mode=qos{qos}-fanout benchmark_scope=same-client-workload "
            f"timing_usable=true shape={shape.name} samples={samples} "
            "client_tcp_nodelay=true server_tcp_nodelay=true "
            f"publishers={shape.publishers} subscribers={shape.subscribers} "
            f"warmup={shape.warmup} publishes={shape.messages} "
            f"deliveries={shape.messages * shape.subscribers} "
            f"payload_bytes={shape.payload_bytes} publisher_window={shape.window} "
            f"server_queue_capacity={queue_capacity} "
            f"session_expiry_seconds={session_expiry_seconds} "
            f"netz_median_publishes_per_s={netz_rate} "
            f"netz_min_publishes_per_s={min(values['netz']['publishes_per_s'])} "
            f"netz_max_publishes_per_s={max(values['netz']['publishes_per_s'])} "
            f"mosquitto_median_publishes_per_s={mosquitto_rate} "
            f"mosquitto_min_publishes_per_s={min(values['mosquitto']['publishes_per_s'])} "
            f"mosquitto_max_publishes_per_s={max(values['mosquitto']['publishes_per_s'])} "
            f"netz_throughput_over_mosquitto={ratios[0]:.3f} "
            f"netz_median_p50_ns={netz_p50} mosquitto_median_p50_ns={mosquitto_p50} "
            f"netz_median_p99_ns={netz_p99} mosquitto_median_p99_ns={mosquitto_p99} "
            f"netz_min_p99_ns={min(values['netz']['p99_ns'])} "
            f"netz_max_p99_ns={max(values['netz']['p99_ns'])} "
            f"mosquitto_min_p99_ns={min(values['mosquitto']['p99_ns'])} "
            f"mosquitto_max_p99_ns={max(values['mosquitto']['p99_ns'])} "
            f"netz_median_p999_ns={netz_p999} mosquitto_median_p999_ns={mosquitto_p999} "
            f"mosquitto_over_netz_p99={ratios[1]:.3f} "
            f"netz_median_server_rss_kib={netz_rss} "
            f"netz_min_server_rss_kib={min(values['netz']['server_rss_kib'])} "
            f"netz_max_server_rss_kib={max(values['netz']['server_rss_kib'])} "
            f"mosquitto_median_server_rss_kib={mosquitto_rss} "
            f"mosquitto_min_server_rss_kib={min(values['mosquitto']['server_rss_kib'])} "
            f"mosquitto_max_server_rss_kib={max(values['mosquitto']['server_rss_kib'])} "
            f"mosquitto_over_netz_rss={ratios[2]:.3f} "
            f"netz_median_client_alloc_count={median(values['netz']['client_alloc_count'])} "
            f"mosquitto_median_client_alloc_count={median(values['mosquitto']['client_alloc_count'])} "
            f"netz_median_client_total_allocated_bytes={median(values['netz']['client_total_allocated_bytes'])} "
            f"mosquitto_median_client_total_allocated_bytes={median(values['mosquitto']['client_total_allocated_bytes'])} "
            f"netz_median_client_peak_live_bytes={median(values['netz']['client_peak_live_bytes'])} "
            f"mosquitto_median_client_peak_live_bytes={median(values['mosquitto']['client_peak_live_bytes'])} "
            "complete=true"
        )
    output.append(
        "record=matrix-complete protocol=mqtt5 transport=tcp "
        f"mode=qos{qos}-fanout-matrix benchmark_scope=same-client-workload "
        f"session_expiry_seconds={session_expiry_seconds} "
        f"timing_usable=true shapes={len(SHAPES)} samples_per_shape={samples} "
        f"paired_samples={len(SHAPES) * samples} "
        f"broker_runs={len(SHAPES) * samples * 2} complete=true"
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
    parser.add_argument("--sampler-cpu", type=int)
    args = parser.parse_args()
    if args.list_shapes:
        for shape in SHAPES:
            print("\t".join(map(str, shape)))
        return
    required = (args.root, args.client_cpu, args.server_cpu, args.sampler_cpu)
    if any(value is None for value in required):
        parser.error("matrix verification arguments are required")
    for line in verify(
        args.root, args.samples, args.client_cpu, args.server_cpu,
        args.sampler_cpu, args.qos, args.session_expiry_seconds,
    ):
        print(line)


if __name__ == "__main__":
    main()
