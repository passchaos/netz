#!/usr/bin/env python3
"""Strictly validate fresh-connection raw QUIC benchmark records."""

from __future__ import annotations

import argparse
import math
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


def records(path: Path, kind: str, role_pair: str) -> list[dict[str, str]]:
    return [
        row
        for line in path.read_text(encoding="utf-8").splitlines()
        if (row := fields(line)).get("record") == kind
        and row.get("protocol") == "quic-stream"
        and row.get("role_pair") == role_pair
    ]


def endpoints(role_pair: str) -> dict[str, str]:
    result = {
        "netz-client+quic-go-server": {"client": "netz", "server": "quic-go"},
        "quic-go-client+netz-server": {"client": "quic-go", "server": "netz"},
        "netz-client+netz-server": {"client": "netz", "server": "netz"},
    }.get(role_pair)
    if result is None:
        raise ValueError("invalid role pair")
    return result


def endpoint_ios(role_pair: str) -> dict[str, str]:
    return {
        role: "zio-std-io" if implementation == "netz" else "quic-go-netpoll"
        for role, implementation in endpoints(role_pair).items()
    }


def stream_checksum(size: int, stream: int, round_index: int) -> int:
    blocks, remainder = divmod(size, 256)
    checksum = blocks * sum(range(256))
    value = (stream * 17 + round_index * 29) & 0xFF
    for _ in range(remainder):
        checksum += value
        value = (value + 131) & 0xFF
    return checksum


def aggregate_checksum(size: int, streams: int, round_index: int) -> int:
    return sum(
        stream_checksum(size, stream, round_index) for stream in range(streams)
    ) & ((1 << 64) - 1)


def require_fields(
    row: dict[str, str], expected: dict[str, str], label: str,
) -> None:
    for key, value in expected.items():
        if row.get(key) != value:
            raise ValueError(
                f"{label}: {key}={row.get(key)!r}, expected {value!r}"
            )


def positive_integer(row: dict[str, str], key: str, label: str) -> int:
    try:
        value = int(row[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"{label}: invalid {key}") from error
    if value <= 0:
        raise ValueError(f"{label}: non-positive {key}")
    return value


def verify(
    *, role_pair: str, sender: str, warmup: int, iterations: int, streams: int,
    bytes_per_stream: int, chunk_bytes: int, stream_window: int,
    timeout_ms: int,
    client_log: Path, server_log: Path,
) -> None:
    implementations = endpoints(role_pair)
    ios = endpoint_ios(role_pair)
    if (
        sender not in ("client", "server")
        or warmup < 0
        or warmup > 4096
        or iterations <= 0
        or iterations > 100_000
        or streams not in (1, 4)
        or bytes_per_stream <= 0
        or bytes_per_stream > 1024 * 1024 * 1024
        or chunk_bytes <= 0
        or chunk_bytes > 1024 * 1024
        or chunk_bytes > bytes_per_stream
        or stream_window <= 0
        or stream_window > 1024 * 1024 * 1024
        or timeout_ms <= 0
        or timeout_ms > 10 * 60 * 1000
    ):
        raise ValueError("invalid benchmark validation configuration")
    logs = {"client": client_log, "server": server_log}
    direction = "upload" if sender == "client" else "download"
    common = {
        "direction": direction,
        "role_pair": role_pair,
        "sender_role": sender,
        "client_io": ios["client"],
        "server_io": ios["server"],
        "connection_scope": "fresh-per-sample",
        "benchmark_scope": "same-application-shape",
    }
    for role, path in logs.items():
        configs = records(path, "config", role_pair)
        if len(configs) != 1:
            raise ValueError(f"{role}: expected one config record, found {len(configs)}")
        require_fields(
            configs[0],
            common | {
                "implementation": implementations[role],
                "endpoint_role": role,
                "warmup": str(warmup),
                "iterations": str(iterations),
                "streams": str(streams),
                "bytes_per_stream": str(bytes_per_stream),
                "application_chunk_requested": str(chunk_bytes),
                "application_chunk_effective": str(min(chunk_bytes, 1152)),
                "stream_window": str(stream_window),
                "connection_window": str(stream_window * 8),
                "timeout_ms": str(timeout_ms),
                "steady_state_mtu": "1280",
                "quic_version": "1",
                "cert_verify": "true",
                "netz_gso": "false",
                "netz_gro": "false",
                "quic_go_gso": "false",
                "quic_go_gro": "false",
                "cipher": "negotiated-unexposed",
                "pacing": "implementation-specific",
            },
            f"{role} config",
        )

    receiver = "server" if sender == "client" else "client"
    result_rows_by_role = {
        role: records(path, "result", role_pair) for role, path in logs.items()
    }
    receiver_rows_by_role = {
        role: records(path, "receiver-complete", role_pair)
        for role, path in logs.items()
    }
    sender_rows = result_rows_by_role[sender]
    receiver_rows = receiver_rows_by_role[receiver]
    if len(sender_rows) != iterations:
        raise ValueError(
            f"expected {iterations} result records, found {len(sender_rows)}"
        )
    if len(receiver_rows) != iterations:
        raise ValueError(
            f"expected {iterations} receiver records, found {len(receiver_rows)}"
        )
    if result_rows_by_role[receiver] or receiver_rows_by_role[sender]:
        raise ValueError("result or receiver record emitted by wrong endpoint")
    total = streams * bytes_per_stream
    for index, (result, completion) in enumerate(
        zip(sender_rows, receiver_rows, strict=True), 1,
    ):
        checksum = aggregate_checksum(
            bytes_per_stream, streams, warmup + index - 1,
        )
        result_expected = common | {
            "implementation": implementations[sender],
            "endpoint_role": sender,
            "sample": str(index),
            "streams": str(streams),
            "bytes_per_stream": str(bytes_per_stream),
            "sent_bytes": str(total),
            "received_bytes": str(total),
            "checksum": str(checksum),
            "completion_exchange_verified": "true",
            "complete": "true",
        }
        completion_expected = common | {
            "implementation": implementations[receiver],
            "endpoint_role": receiver,
            "sample": str(index),
            "streams": str(streams),
            "bytes_per_stream": str(bytes_per_stream),
            "received_bytes": str(total),
            "checksum": str(checksum),
            "completion_exchange_verified": "true",
            "complete": "true",
        }
        require_fields(result, result_expected, f"result sample {index}")
        require_fields(
            completion, completion_expected, f"receiver sample {index}",
        )
        positive_integer(result, "elapsed_ns", f"result sample {index}")
        try:
            throughput = float(result["logical_MiB_s"])
        except (KeyError, ValueError) as error:
            raise ValueError(f"result sample {index}: invalid throughput") from error
        if not math.isfinite(throughput) or throughput <= 0:
            raise ValueError(f"result sample {index}: non-positive throughput")
        expected_throughput = (
            total * 1_000_000_000 / positive_integer(
                result, "elapsed_ns", f"result sample {index}",
            ) / (1024 * 1024)
        )
        if abs(throughput - expected_throughput) > 0.00051:
            raise ValueError(f"result sample {index}: throughput mismatch")

    print(
        f"protocol=quic-stream role_pair={role_pair} direction={direction} "
        f"samples={iterations} streams={streams} bytes_per_stream={bytes_per_stream} "
        f"client_io={ios['client']} server_io={ios['server']} complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--sender", choices=("client", "server"), required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--bytes-per-stream", type=int, required=True)
    parser.add_argument("--chunk-bytes", type=int, required=True)
    parser.add_argument("--stream-window", type=int, required=True)
    parser.add_argument("--timeout-ms", type=int, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    verify(**vars(parser.parse_args()))


if __name__ == "__main__":
    main()
