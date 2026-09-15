#!/usr/bin/env python3
"""Validate equal-driver MQTT broker benchmark result records."""

from __future__ import annotations

import argparse
from pathlib import Path


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


def result(path: Path) -> dict[str, str]:
    matches = [
        row
        for line in path.read_text(encoding="utf-8").splitlines()
        if (row := fields(line)).get("record") == "result"
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one result in {path}, found {len(matches)}")
    return matches[0]


def positive(record: dict[str, str], key: str) -> int:
    try:
        value = int(record[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {record}") from error
    if value <= 0:
        raise ValueError(f"non-positive {key}: {record}")
    return value


def validate(
    record: dict[str, str],
    server: str,
    server_io: str,
    publishers: int,
    subscribers: int,
    warmup: int,
    messages: int,
    payload_bytes: int,
    window: int,
) -> None:
    expected = {
        "record": "result",
        "implementation": "netz",
        "protocol": "mqtt5",
        "transport": "tcp",
        "mode": "qos1-fanout",
        "role_pair": f"netz-client+{server}-server",
        "client_io": "zio-std-io",
        "server_io": server_io,
        "connection_scope": "persistent",
        "publishers": str(publishers),
        "subscribers": str(subscribers),
        "overlapping_subscriptions": "1",
        "publisher_window": str(window),
        "session_expiry_seconds": "0",
        "warmup": str(warmup),
        "publishes": str(messages),
        "deliveries": str(messages * subscribers),
        "payload_bytes": str(payload_bytes),
        "complete": "true",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(
                f"{server} result has {key}={record.get(key)!r}, expected {value!r}"
            )
    elapsed = positive(record, "elapsed_ns")
    if positive(record, "publishes_per_s") != messages * 1_000_000_000 // elapsed:
        raise ValueError(f"invalid publishes_per_s: {record}")
    if positive(record, "deliveries_per_s") != messages * subscribers * 1_000_000_000 // elapsed:
        raise ValueError(f"invalid deliveries_per_s: {record}")
    p50 = positive(record, "p50_ns")
    p99 = positive(record, "p99_ns")
    p999 = positive(record, "p999_ns")
    if not p50 <= p99 <= p999:
        raise ValueError(f"invalid latency ordering: {record}")
    positive(record, "checksum")


def verify(
    netz_path: Path,
    mosquitto_path: Path,
    publishers: int,
    subscribers: int,
    warmup: int,
    messages: int,
    payload_bytes: int,
    window: int,
) -> str:
    if min(publishers, subscribers, messages, payload_bytes, window) <= 0 or warmup < 0:
        raise ValueError("invalid MQTT benchmark configuration")
    netz = result(netz_path)
    mosquitto = result(mosquitto_path)
    validate(
        netz, "netz", "zio-std-io", publishers, subscribers, warmup,
        messages, payload_bytes, window,
    )
    validate(
        mosquitto, "mosquitto", "mosquitto-event-loop", publishers,
        subscribers, warmup, messages, payload_bytes, window,
    )
    if netz["checksum"] != mosquitto["checksum"]:
        raise ValueError("broker checksums differ")
    payload_last = ((payload_bytes - 1) * 17 + 3) & 0xFF
    expected_checksum = (
        (warmup + messages) * subscribers * (3 + payload_last)
    ) & ((1 << 64) - 1)
    if positive(netz, "checksum") != expected_checksum:
        raise ValueError("broker checksum does not match the workload")
    return (
        "record=verified protocol=mqtt5 transport=tcp mode=qos1-fanout "
        f"publishers={publishers} subscribers={subscribers} warmup={warmup} "
        f"publishes={messages} deliveries={messages * subscribers} "
        f"payload_bytes={payload_bytes} publisher_window={window} "
        f"checksum={expected_checksum} client_io=zio-std-io "
        "server_io=zio-std-io+mosquitto-event-loop complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--netz-log", type=Path, required=True)
    parser.add_argument("--mosquitto-log", type=Path, required=True)
    parser.add_argument("--publishers", type=int, required=True)
    parser.add_argument("--subscribers", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--messages", type=int, required=True)
    parser.add_argument("--payload-bytes", type=int, required=True)
    parser.add_argument("--publisher-window", type=int, required=True)
    args = parser.parse_args()
    print(
        verify(
            args.netz_log, args.mosquitto_log, args.publishers,
            args.subscribers, args.warmup, args.messages, args.payload_bytes,
            args.publisher_window,
        )
    )


if __name__ == "__main__":
    main()
