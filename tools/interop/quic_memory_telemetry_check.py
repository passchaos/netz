#!/usr/bin/env python3
"""Validate QUIC-family process memory telemetry and attach peak RSS."""

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
        if (
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key)
            or key in result
            or not value
        ):
            raise ValueError(f"duplicate or empty field {token!r}")
        result[key] = value
    return result


def load(path: Path, protocol: str, role_pair: str) -> dict[str, str]:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        record = fields(line)
        if (
            record.get("record") == "memory"
            and record.get("memory_scope")
            and record.get("protocol") == protocol
            and record.get("role_pair") == role_pair
        ):
            records.append(record)
    if len(records) != 1:
        raise SystemExit(f"expected one memory record in {path}, found {len(records)}")
    return records[0]


def integer(record: dict[str, str], key: str, positive: bool = False) -> int:
    try:
        value = int(record[key])
    except (KeyError, ValueError) as error:
        raise SystemExit(f"invalid {key}: {record}") from error
    if value < 0 or positive and value == 0:
        raise SystemExit(f"invalid {key}: {record}")
    return value


def rss(path: Path) -> int:
    try:
        value = int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError) as error:
        raise SystemExit(f"invalid peak RSS file {path}") from error
    if value <= 0:
        raise SystemExit(f"non-positive peak RSS in {path}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", default="quic-stream")
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--sender", choices=("client", "server"), required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--mode")
    parser.add_argument("--body-bytes", type=int)
    parser.add_argument("--warmup", type=int)
    parser.add_argument("--iterations", type=int)
    parser.add_argument("--quic-version", type=int)
    parser.add_argument(
        "--rss-source",
        choices=("gnu-time-maxrss", "busybox-time-maxrss"),
        default="gnu-time-maxrss",
    )
    parser.add_argument("--client-log", required=True, type=Path)
    parser.add_argument("--server-log", required=True, type=Path)
    parser.add_argument("--client-rss", required=True, type=Path)
    parser.add_argument("--server-rss", required=True, type=Path)
    args = parser.parse_args()

    expected = {
        "netz-client+quic-go-server": {"client": "netz", "server": "quic-go"},
        "quic-go-client+netz-server": {"client": "quic-go", "server": "netz"},
        "netz-client+netz-server": {"client": "netz", "server": "netz"},
    }.get(args.role_pair)
    if (
        expected is None
        or args.protocol not in ("quic-stream", "http3")
        or (
            args.role_pair == "netz-client+netz-server"
            and args.protocol != "quic-stream"
        )
        or args.streams not in (1, 4, 16)
        or args.quic_version not in (None, 1, 2)
    ):
        raise SystemExit("invalid memory comparison configuration")
    expected_io = (
        {
            role: (
                "zio-std-io"
                if implementation == "netz"
                else "quic-go-netpoll"
            )
            for role, implementation in expected.items()
        }
        if args.protocol == "quic-stream"
        else None
    )
    if args.protocol == "http3" and (
        args.mode not in ("upload", "download")
        or args.body_bytes is None
        or args.body_bytes <= 0
        or args.warmup is None
        or args.warmup <= 0
        or args.iterations is None
        or args.iterations <= 0
    ):
        raise SystemExit("invalid HTTP/3 memory comparison configuration")

    for role, log_path, rss_path in (
        ("client", args.client_log, args.client_rss),
        ("server", args.server_log, args.server_rss),
    ):
        record = load(log_path, args.protocol, args.role_pair)
        implementation = expected[role]
        if (
            record.get("implementation") != implementation
            or record.get("protocol") != args.protocol
            or record.get("endpoint_role") != role
            or record.get("sender_role") != args.sender
            or (
                expected_io is not None
                and (
                    record.get("client_io") != expected_io["client"]
                    or record.get("server_io") != expected_io["server"]
                )
            )
            or integer(record, "streams") != args.streams
            or record.get("memory_scope")
            != "benchmark-run-after-argument-parse"
            or record.get("complete") != "true"
        ):
            raise SystemExit(f"memory record mismatch in {log_path}: {record}")
        if args.protocol == "http3" and (
            record.get("mode") != args.mode
            or integer(record, "body_bytes") != args.body_bytes
            or integer(record, "warmup") != args.warmup
            or integer(record, "iterations") != args.iterations
            or (args.quic_version is not None and
                integer(record, "quic_version") != args.quic_version)
        ):
            raise SystemExit(f"HTTP/3 memory shape mismatch in {log_path}: {record}")
        required = (
            ("netz-explicit", ("alloc_count", "total_allocated_bytes", "peak_live_bytes"))
            if implementation == "netz"
            else ("go-runtime-heap", ("alloc_count", "total_allocated_bytes", "heap_sys_bytes_end"))
        )
        if record.get("allocator_scope") != required[0]:
            raise SystemExit(f"allocator scope mismatch in {log_path}: {record}")
        for key in required[1]:
            integer(record, key, positive=True)
        if implementation == "netz" and integer(record, "live_bytes") != 0:
            raise SystemExit(f"netz allocator retained live bytes in {log_path}: {record}")
        fields_out = " ".join(
            f"{key}={value}" for key, value in record.items()
            if key not in {
                "record", "implementation", "protocol", "mode", "role_pair",
                "endpoint_role", "sender_role", "streams",
                "body_bytes", "complete",
                "quic_version", "client_io", "server_io",
            }
        )
        shape = (
            f"mode={args.mode} body_bytes={args.body_bytes} "
            f"quic_version={args.quic_version} "
            if args.protocol == "http3"
            else ""
        )
        io_shape = (
            f"client_io={expected_io['client']} "
            f"server_io={expected_io['server']} "
            if expected_io is not None else ""
        )
        print(
            f"record=memory implementation={implementation} protocol={args.protocol} "
            f"role_pair={args.role_pair} endpoint_role={role} "
            f"sender_role={args.sender} streams={args.streams} "
            f"{io_shape}"
            f"{shape}rss_scope=whole-process rss_source={args.rss_source} "
            f"process_peak_rss_kib={rss(rss_path)} {fields_out} complete=true"
        )


if __name__ == "__main__":
    main()
