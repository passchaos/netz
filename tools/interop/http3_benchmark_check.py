#!/usr/bin/env python3
"""Validate exact HTTP/3 benchmark sample records."""

from __future__ import annotations

import argparse
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split() if "=" in token)


def checksum(size: int) -> int:
    periods, remainder = divmod(size, 256)
    return periods * sum(range(256)) + sum((offset * 131) & 0xFF for offset in range(remainder))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--mode", choices=("upload", "download"), required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--body-bytes", type=int, required=True)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    endpoint_impl = {
        "netz-client+quic-go-server": {"client": "netz", "server": "quic-go"},
        "quic-go-client+netz-server": {"client": "quic-go", "server": "netz"},
    }.get(args.role_pair)
    if endpoint_impl is None or args.iterations <= 0 or args.body_bytes <= 0:
        raise SystemExit("invalid benchmark validation configuration")
    sender_role = "client" if args.mode == "upload" else "server"
    expected_impl = endpoint_impl[sender_role]
    records = []
    for line in args.log.read_text(encoding="utf-8").splitlines():
        record = fields(line)
        if (
            record.get("protocol") == "http3"
            and record.get("role_pair") == args.role_pair
            and "sample" in record
        ):
            records.append(record)
    if len(records) != args.iterations:
        raise SystemExit(f"expected {args.iterations} samples in {args.log}, found {len(records)}")
    expected_checksum = checksum(args.body_bytes)
    for index, record in enumerate(records, 1):
        expected = {
            "implementation": expected_impl,
            "mode": args.mode,
            "sample": str(index),
            "streams": "1",
            "connection_scope": "fresh-per-sample",
            "benchmark_scope": "same-application-shape",
            "sent_bytes": str(args.body_bytes),
            "received_bytes": str(args.body_bytes),
            "checksum": str(expected_checksum),
            "status": "200",
            "complete": "true",
        }
        for key, value in expected.items():
            if record.get(key) != value:
                raise SystemExit(f"sample {index} has {key}={record.get(key)!r}, expected {value!r}")
        try:
            elapsed_ns = int(record["elapsed_ns"])
        except (KeyError, ValueError) as error:
            raise SystemExit(f"sample {index} has invalid elapsed_ns") from error
        if elapsed_ns <= 0:
            raise SystemExit(f"sample {index} has non-positive elapsed_ns")
    print(
        f"protocol=http3 role_pair={args.role_pair} mode={args.mode} "
        f"samples={args.iterations} body_bytes={args.body_bytes} "
        f"checksum={expected_checksum} complete=true"
    )


if __name__ == "__main__":
    main()
