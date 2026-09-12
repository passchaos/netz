#!/usr/bin/env python3
"""Strictly validate HTTP/3 benchmark client and server records."""

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
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key) or key in result or not value:
            raise ValueError(f"duplicate or empty field {token!r}")
        result[key] = value
    return result


def stream_checksum(size: int, stream_index: int) -> int:
    return sum((offset * 131 + stream_index * 17) & 0xFF for offset in range(size))


def aggregate_checksum(size: int, streams: int) -> int:
    return sum(stream_checksum(size, index) for index in range(streams)) & ((1 << 64) - 1)


def records(path: Path, kind: str, role_pair: str) -> list[dict[str, str]]:
    found = []
    for line in path.read_text(encoding="utf-8").splitlines():
        item = fields(line)
        if (
            item.get("record") == kind
            and item.get("protocol") == "http3"
            and item.get("role_pair") == role_pair
        ):
            found.append(item)
    return found


def verify(
    *,
    role_pair: str,
    mode: str,
    iterations: int,
    streams: int,
    body_bytes: int,
    quic_version: int,
    client_log: Path,
    server_log: Path,
) -> None:
    endpoints = {
        "netz-client+quic-go-server": {"client": "netz", "server": "quic-go"},
        "quic-go-client+netz-server": {"client": "quic-go", "server": "netz"},
    }.get(role_pair)
    if endpoints is None or mode not in ("upload", "download"):
        raise ValueError("invalid role pair or mode")
    if (
        iterations <= 0
        or streams not in (1, 4, 16)
        or body_bytes <= 0
        or quic_version not in (1, 2)
    ):
        raise ValueError("invalid benchmark validation configuration")
    result_records = records(client_log, "result", role_pair)
    server_records = records(server_log, "server-complete", role_pair)
    if len(result_records) != iterations:
        raise ValueError(f"expected {iterations} result records, found {len(result_records)}")
    if len(server_records) != iterations:
        raise ValueError(f"expected {iterations} server records, found {len(server_records)}")
    total_bytes = body_bytes * streams
    checksum = aggregate_checksum(body_bytes, streams)
    for source, rows, endpoint_role in (
        ("client", result_records, "client"),
        ("server", server_records, "server"),
    ):
        for sample, record in enumerate(rows, 1):
            expected = {
                "implementation": (
                    endpoints["client" if mode == "upload" else "server"]
                    if source == "client"
                    else endpoints[endpoint_role]
                ),
                "mode": mode,
                "role_pair": role_pair,
                "sample": str(sample),
                "streams": str(streams),
                "body_bytes": str(body_bytes),
                "connection_scope": "fresh-per-sample",
                "body_deadline_scope": "sample",
                "sent_bytes": str(
                    total_bytes if source == "client" or mode == "download" else 0
                ),
                "received_bytes": str(
                    total_bytes if source == "client" or mode == "upload" else 0
                ),
                "checksum": str(checksum),
                "status": "200",
                "streams_finished": str(streams),
                "per_stream_verified": "true",
                "quic_version": str(quic_version),
                "complete": "true",
            }
            if source == "server":
                expected["endpoint_role"] = "server"
            for key, value in expected.items():
                if record.get(key) != value:
                    raise ValueError(
                        f"{source} sample {sample}: {key}={record.get(key)!r}, expected {value!r}"
                    )
            if source == "client":
                try:
                    elapsed_ns = int(record["elapsed_ns"])
                except (KeyError, ValueError) as error:
                    raise ValueError(f"sample {sample} has invalid elapsed_ns") from error
                if elapsed_ns <= 0:
                    raise ValueError(f"sample {sample} has non-positive elapsed_ns")
    print(
        f"protocol=http3 role_pair={role_pair} mode={mode} samples={iterations} "
        f"streams={streams} body_bytes={body_bytes} total_bytes={total_bytes} "
        f"checksum={checksum} per_stream_verified=true "
        f"quic_version={quic_version} complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--mode", choices=("upload", "download"), required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--streams", type=int, default=1)
    parser.add_argument("--body-bytes", type=int, required=True)
    parser.add_argument("--quic-version", type=int, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    args = parser.parse_args()
    verify(
        role_pair=args.role_pair, mode=args.mode, iterations=args.iterations,
        streams=args.streams, body_bytes=args.body_bytes,
        quic_version=args.quic_version,
        client_log=args.client_log, server_log=args.server_log,
    )


if __name__ == "__main__":
    main()
