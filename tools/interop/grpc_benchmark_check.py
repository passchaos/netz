#!/usr/bin/env python3
"""Validate a completed native shared gRPC benchmark before using its timing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    row: dict[str, str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in row or not value or "=" in value:
            raise ValueError(f"duplicate or malformed field: {token}")
        row[key] = value
    return row


def integer(row: dict[str, str], key: str, positive: bool = False) -> int:
    try:
        value = int(row[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}") from error
    if value < 0 or positive and value == 0:
        raise ValueError(f"invalid {key}")
    return value


def verify_windows(result: dict[str, str], peer: dict[str, str]) -> None:
    schema = result.get("schema", "1")
    if peer.get("schema", "1") != schema:
        raise ValueError("peer schema mismatch")
    keys = ("stream_window", "connection_window", "adaptive_window", "adaptive_window_max", "final_client_stream_window", "final_server_stream_window")
    if schema == "1":
        # Historical version-one binaries only exercised the fixed defaults.
        if any(key in row for row in (result, peer) for key in keys):
            raise ValueError("legacy schema has explicit window fields")
        return
    if schema != "2":
        raise ValueError("unsupported schema")
    for key in keys:
        if key not in result or peer.get(key) != result[key]:
            raise ValueError(f"peer {key} mismatch")
    stream = integer(result, "stream_window", True)
    connection = integer(result, "connection_window", True)
    maximum = integer(result, "adaptive_window_max")
    if stream > 16 * 1024 * 1024 or connection < 65535 or connection > 16 * 1024 * 1024 or maximum > 16 * 1024 * 1024:
        raise ValueError("invalid window limits")
    adaptive = result["adaptive_window"]
    if adaptive not in ("true", "false"):
        raise ValueError("invalid adaptive_window")
    if adaptive == "true" and maximum < max(stream, connection):
        raise ValueError("adaptive window cap too small")
    for key in ("final_client_stream_window", "final_server_stream_window"):
        final = integer(result, key, True)
        if adaptive == "true":
            if not stream <= final <= maximum:
                raise ValueError("adaptive window growth outside limits")
        elif final != stream:
            raise ValueError("unexpected fixed-window growth")


def verify(text: str) -> dict[str, str]:
    rows = [fields(line) for line in text.splitlines() if line.startswith("record=")]
    results = [row for row in rows if row.get("record") == "result"]
    completions = [row for row in rows if row.get("record") == "peer-completion"]
    if len(results) != 1 or len(completions) != 1:
        raise ValueError("expected one result and one peer completion")
    result, peer = results[0], completions[0]
    verify_windows(result, peer)
    expected = {
        "implementation": "netz", "protocol": "grpc", "transport": "h2c",
        "client_api": "shared", "client_io": "zio-std-io", "server_io": "zio-std-io",
        "connection_scope": "persistent", "connections": "1",
        "validation": "full-bytes", "protobuf_scope": "preencoded",
        "allocation_scope": "client+server+protocol",
    }
    for key, value in expected.items():
        if result.get(key) != value:
            raise ValueError(f"result {key} mismatch")
    mode = result.get("mode")
    if mode not in ("persistent", "calls"):
        raise ValueError("invalid mode")
    for key, value in {"implementation": "netz", "protocol": "grpc", "mode": mode}.items():
        if peer.get(key) != value:
            raise ValueError(f"peer {key} mismatch")
    warmup = integer(result, "warmup")
    iterations = integer(result, "iterations", True)
    payload = integer(result, "payload_bytes")
    if payload > 16 * 1024 * 1024 - 8:
        raise ValueError("payload exceeds message limit")
    protobuf = 0 if payload == 0 else payload + 1 + (payload.bit_length() + 6) // 7
    if integer(result, "protobuf_bytes") != protobuf or integer(peer, "protobuf_bytes") != protobuf:
        raise ValueError("protobuf_bytes mismatch")
    if integer(result, "logical_bytes") != iterations * payload * 2:
        raise ValueError("logical_bytes mismatch")
    for key in ("request_messages", "response_messages"):
        if integer(peer, key) != warmup + iterations:
            raise ValueError(f"peer {key} mismatch")
    if integer(peer, "terminal_calls") != (1 if mode == "persistent" else warmup + iterations):
        raise ValueError("peer terminal_calls mismatch")
    elapsed = integer(result, "elapsed_ns", True)
    if integer(result, "ns_per_roundtrip") != elapsed // iterations:
        raise ValueError("ns_per_roundtrip mismatch")
    if integer(result, "roundtrips_per_second") != iterations * 1_000_000_000 // elapsed:
        raise ValueError("roundtrips_per_second mismatch")
    quantiles = [integer(result, key, True) for key in ("p50_ns", "p95_ns", "p99_ns")]
    if quantiles != sorted(quantiles) or quantiles[-1] > elapsed:
        raise ValueError("invalid latency quantiles")
    stats = result.get("stats_enabled")
    if stats not in ("true", "false"):
        raise ValueError("invalid stats_enabled")
    memory = [integer(result, key) for key in ("alloc_count", "allocated_bytes", "freed_bytes", "live_bytes")]
    if stats == "false" and any(memory) or stats == "true" and memory[0] == 0:
        raise ValueError("allocation telemetry mismatch")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.log.read_text(encoding="utf-8")), sort_keys=True))


if __name__ == "__main__":
    main()
