#!/usr/bin/env python3
"""Validate matched contiguous-vs-slices native WebSocket benchmark records."""

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
            raise ValueError(f"invalid field name {key!r}")
        if key in result or not value:
            raise ValueError(f"duplicate or empty field {token!r}")
        result[key] = value
    return result


def results(path: Path, protocol: str, shape: str) -> list[dict[str, str]]:
    matches = []
    for line in path.read_text(encoding="utf-8").splitlines():
        row = fields(line)
        if (
            row.get("record") == "result"
            and row.get("protocol") == protocol
            and row.get("send_shape") == shape
        ):
            matches.append(row)
    return matches


def positive_int(row: dict[str, str], key: str) -> int:
    try:
        value = int(row[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {row}") from error
    if value <= 0:
        raise ValueError(f"non-positive {key}: {row}")
    return value


def verify(
    protocol: str,
    parts: int,
    warmup: int,
    iterations: int,
    payload_bytes: int,
    samples: int,
    contiguous_log: Path,
    slices_log: Path,
) -> None:
    transport = {
        "websocket-h1": "tcp",
        "websocket-h2": "h2c",
        "websocket-h3": "h3",
    }.get(protocol)
    if (
        transport is None
        or parts <= 1
        or parts > 64
        or warmup < 0
        or iterations <= 0
        or payload_bytes <= 0
        or samples <= 0
        or samples % 2 == 0
    ):
        raise ValueError("invalid WebSocket slice benchmark configuration")

    rows_by_shape = {
        "contiguous": results(contiguous_log, protocol, "contiguous"),
        "slices": results(slices_log, protocol, "slices"),
    }
    expected_checksum = iterations * (0 + (payload_bytes // 2) % 256 +
                                      (payload_bytes - 1) % 256)
    expected = {
        "implementation": "netz",
        "protocol": protocol,
        "transport": transport,
        "mode": "binary-echo",
        "role_pair": "netz-self",
        "client_io": "zio-std-io",
        "server_io": "zio-std-io",
        "connection_scope": "persistent",
        "benchmark_scope": "caller-copy-vs-direct-slices",
        "connections": "1",
        "warmup": str(warmup),
        "iterations": str(iterations),
        "payload_bytes": str(payload_bytes),
        "payload_schedule": "fixed",
        "parts": str(parts),
        "compression": "false",
        "logical_bytes": str(iterations * payload_bytes * 2),
        "checksum": str(expected_checksum),
        "complete": "true",
    }
    elapsed: dict[str, list[int]] = {}
    for shape, rows in rows_by_shape.items():
        if len(rows) != samples:
            raise ValueError(
                f"expected {samples} {protocol}/{shape} results, found {len(rows)}"
            )
        elapsed[shape] = []
        for sample, row in enumerate(rows, 1):
            for key, value in expected.items():
                if row.get(key) != value:
                    raise ValueError(
                        f"{protocol}/{shape} sample {sample}: "
                        f"{key}={row.get(key)!r}, expected {value!r}"
                    )
            elapsed[shape].append(positive_int(row, "elapsed_ns"))

    contiguous_ns = sorted(elapsed["contiguous"])[samples // 2]
    slices_ns = sorted(elapsed["slices"])[samples // 2]
    print(
        f"protocol={protocol} samples={samples} parts={parts} warmup={warmup} "
        f"iterations={iterations} payload_bytes={payload_bytes} "
        f"checksum={expected_checksum} contiguous_ns={contiguous_ns} "
        f"slices_ns={slices_ns} slices_over_contiguous={slices_ns / contiguous_ns:.3f} "
        "client_io=zio-std-io server_io=zio-std-io complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--protocol",
        choices=("websocket-h1", "websocket-h2", "websocket-h3"),
        required=True,
    )
    parser.add_argument("--parts", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--payload-bytes", type=int, required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--contiguous-log", type=Path, required=True)
    parser.add_argument("--slices-log", type=Path, required=True)
    args = parser.parse_args()
    verify(
        args.protocol,
        args.parts,
        args.warmup,
        args.iterations,
        args.payload_bytes,
        args.samples,
        args.contiguous_log,
        args.slices_log,
    )


if __name__ == "__main__":
    main()
