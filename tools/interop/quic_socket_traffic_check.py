#!/usr/bin/env python3
"""Validate and combine raw QUIC per-endpoint UDP socket accounting."""

from __future__ import annotations

import argparse
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        if "=" in token:
            key, value = token.split("=", 1)
            result[key] = value
    return result


def load(path: Path, role_pair: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        record = fields(line)
        if (
            record.get("socket_boundary") == "userspace-udp-payload"
            and record.get("role_pair") == role_pair
        ):
            records.append(record)
    return records


def positive(record: dict[str, str], key: str) -> int:
    try:
        value = int(record[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {record}") from error
    if value <= 0:
        raise ValueError(f"non-positive {key}: {record}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--sender", choices=("client", "server"), required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("logs", nargs=2, type=Path)
    args = parser.parse_args()

    expected_impl = {
        "netz-client+quic-go-server": {"client": "netz", "server": "quic-go"},
        "quic-go-client+netz-server": {"client": "quic-go", "server": "netz"},
    }.get(args.role_pair)
    if expected_impl is None or args.iterations <= 0:
        raise SystemExit("invalid comparison configuration")

    by_sample: dict[int, dict[str, dict[str, str]]] = {}
    for path in args.logs:
        for record in load(path, args.role_pair):
            try:
                sample = int(record["sample"])
                streams = int(record["streams"])
                role = record["endpoint_role"]
            except (KeyError, ValueError) as error:
                raise SystemExit(f"malformed traffic record in {path}: {record}") from error
            if streams != args.streams or role not in ("client", "server"):
                raise SystemExit(f"unexpected traffic record in {path}: {record}")
            if record.get("implementation") != expected_impl[role]:
                raise SystemExit(f"implementation/role mismatch in {path}: {record}")
            if record.get("traffic_scope") != "connection" or record.get("complete") != "true":
                raise SystemExit(f"incomplete traffic record in {path}: {record}")
            if record.get("logical_udp_segments") != "true":
                raise SystemExit(f"ambiguous datagram accounting in {path}: {record}")
            sample_records = by_sample.setdefault(sample, {})
            if role in sample_records:
                raise SystemExit(f"duplicate sample={sample} role={role}")
            sample_records[role] = record

    expected_samples = set(range(1, args.iterations + 1))
    if set(by_sample) != expected_samples:
        raise SystemExit(
            f"traffic samples mismatch: expected={sorted(expected_samples)} "
            f"actual={sorted(by_sample)}"
        )

    for sample in sorted(by_sample):
        records = by_sample[sample]
        if set(records) != {"client", "server"}:
            raise SystemExit(f"missing endpoint traffic sample={sample}: {records}")
        client = records["client"]
        server = records["server"]
        client_tx_datagrams = positive(client, "udp_sent_datagrams")
        client_tx_bytes = positive(client, "udp_sent_payload_bytes")
        client_rx_datagrams = positive(client, "udp_received_datagrams")
        client_rx_bytes = positive(client, "udp_received_payload_bytes")
        server_tx_datagrams = positive(server, "udp_sent_datagrams")
        server_tx_bytes = positive(server, "udp_sent_payload_bytes")
        server_rx_datagrams = positive(server, "udp_received_datagrams")
        server_rx_bytes = positive(server, "udp_received_payload_bytes")
        c2s_datagram_delta = client_tx_datagrams - server_rx_datagrams
        c2s_byte_delta = client_tx_bytes - server_rx_bytes
        s2c_datagram_delta = server_tx_datagrams - client_rx_datagrams
        s2c_byte_delta = server_tx_bytes - client_rx_bytes
        if (
            c2s_datagram_delta < 0
            or c2s_byte_delta < 0
            or s2c_datagram_delta < 0
            or s2c_byte_delta < 0
        ):
            raise SystemExit(
                f"peer observed traffic not sent in sample={sample}: "
                f"c2s=({c2s_datagram_delta},{c2s_byte_delta}) "
                f"s2c=({s2c_datagram_delta},{s2c_byte_delta})"
            )
        print(
            "protocol=quic-stream "
            f"role_pair={args.role_pair} sender_role={args.sender} "
            f"sample={sample} streams={args.streams} "
            "traffic_scope=connection socket_boundary=userspace-udp-payload "
            f"client_udp_sent_datagrams={client_tx_datagrams} "
            f"client_udp_sent_payload_bytes={client_tx_bytes} "
            f"server_udp_sent_datagrams={server_tx_datagrams} "
            f"server_udp_sent_payload_bytes={server_tx_bytes} "
            f"total_udp_sent_datagrams={client_tx_datagrams + server_tx_datagrams} "
            f"total_udp_sent_payload_bytes={client_tx_bytes + server_tx_bytes} "
            f"client_to_server_observation_delta_datagrams={c2s_datagram_delta} "
            f"client_to_server_observation_delta_bytes={c2s_byte_delta} "
            f"server_to_client_observation_delta_datagrams={s2c_datagram_delta} "
            f"server_to_client_observation_delta_bytes={s2c_byte_delta} "
            "benchmark_scope=same-application-shape complete=true"
        )


if __name__ == "__main__":
    main()
