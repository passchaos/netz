"""Validate completed QoS delivery before consuming its benchmark timing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    result = {}
    for item in line.split():
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key in result or not value or "=" in value:
            raise ValueError(f"duplicate or malformed field: {item}")
        result[key] = value
    return result


def integer(row: dict[str, str], key: str, *, positive: bool = False) -> int:
    try:
        value = int(row[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}") from error
    if value < 0 or positive and value == 0:
        raise ValueError(f"invalid {key}")
    return value


def verify(text: str, *, require_release_fast: bool = False) -> dict[str, str]:
    records = [fields(line) for line in text.splitlines() if line.startswith("record=")]
    results = [row for row in records if row.get("record") == "result"]
    peers = [row for row in records if row.get("record") == "peer-completion"]
    if len(results) != 1 or len(peers) != 1:
        raise ValueError("expected one result and one peer completion")
    result, peer = results[0], peers[0]
    for key, value in {
        "schema": "1", "implementation": "netz", "protocol": "mqtt",
        "transport": "tcp", "client_api": "reconnect-stage-flush-poll",
        "client_io": "zio-std-io", "server_io": "zio-std-io",
        "connections": "1", "window": "1", "validation": "full-bytes+terminal",
        "deadline": "single-awake-budget", "session_pending": "0",
        "stats_enabled": "false",
    }.items():
        if result.get(key) != value:
            raise ValueError(f"result {key} mismatch")
    if result.get("build_mode") not in {"Debug", "ReleaseSafe", "ReleaseSmall", "ReleaseFast"}:
        raise ValueError("invalid build mode")
    if require_release_fast and result["build_mode"] != "ReleaseFast":
        raise ValueError("timing evidence requires ReleaseFast")
    if result.get("mqtt_version") not in {"4", "5"} or result.get("qos") not in {"1", "2"}:
        raise ValueError("invalid MQTT/QoS profile")
    if result.get("topic_alias") not in {"true", "false"} or result["mqtt_version"] == "4" and result["topic_alias"] != "false":
        raise ValueError("invalid Topic Alias profile")
    for key in ("schema", "implementation", "protocol", "mqtt_version", "qos", "topic_alias"):
        if peer.get(key) != result[key]:
            raise ValueError(f"peer {key} mismatch")
    warmup = integer(result, "warmup")
    iterations = integer(result, "iterations", positive=True)
    payload = integer(result, "payload_bytes")
    if payload > 4 * 1024 * 1024 or integer(peer, "payload_bytes") != payload:
        raise ValueError("payload mismatch")
    if integer(result, "completed_deliveries") != iterations:
        raise ValueError("delivery completion mismatch")
    if integer(result, "logical_bytes") != iterations * payload:
        raise ValueError("logical byte count mismatch")
    for key in ("received_messages", "terminal_acks"):
        if integer(peer, key) != warmup + iterations:
            raise ValueError(f"peer {key} mismatch")
    expected_releases = warmup + iterations if result["qos"] == "2" else 0
    if integer(peer, "pubrels") != expected_releases or peer.get("disconnected") != "true":
        raise ValueError("peer terminal phase mismatch")
    elapsed = integer(result, "elapsed_ns", positive=True)
    if integer(result, "ns_per_delivery", positive=True) != elapsed // iterations:
        raise ValueError("delivery timing mismatch")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--require-release-fast", action="store_true")
    args = parser.parse_args()
    print(json.dumps(verify(args.log.read_text(), require_release_fast=args.require_release_fast), sort_keys=True))


if __name__ == "__main__":
    main()
