#!/usr/bin/env python3
"""Validate one HTTP/3 role pair's userspace UDP traffic accounting."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "http3_benchmark_check", ROOT / "http3_benchmark_check.py"
)
assert SPEC is not None and SPEC.loader is not None
BENCHMARK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCHMARK
SPEC.loader.exec_module(BENCHMARK)


def positive(record: dict[str, str], key: str) -> int:
    try:
        value = int(record[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {record}") from error
    if value <= 0:
        raise ValueError(f"non-positive {key}: {record}")
    return value


def nonnegative(record: dict[str, str], key: str) -> int:
    try:
        value = int(record[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {record}") from error
    if value < 0:
        raise ValueError(f"negative {key}: {record}")
    return value


def verify(
    *,
    role_pair: str,
    mode: str,
    warmup: int,
    iterations: int,
    streams: int,
    body_bytes: int,
    chunk_bytes: int,
    stream_window: int,
    quic_version: int,
    client_log: Path,
    server_log: Path,
    netz_max_pacing_rate_bytes_per_second: int = 0,
) -> None:
    endpoints = {
        "netz-client+quic-go-server": {"client": "netz", "server": "quic-go"},
        "quic-go-client+netz-server": {"client": "quic-go", "server": "netz"},
        "netz-client+netz-server": {"client": "netz", "server": "netz"},
    }.get(role_pair)
    if endpoints is None or mode not in ("upload", "download"):
        raise ValueError("invalid socket-traffic comparison configuration")
    if min(warmup, iterations, streams, body_bytes, chunk_bytes, stream_window) <= 0:
        raise ValueError("socket-traffic workload values must be positive")
    if quic_version not in (1, 2):
        raise ValueError("invalid QUIC version")
    if not 0 <= netz_max_pacing_rate_bytes_per_second <= (1 << 64) - 1:
        raise ValueError("invalid netz maximum pacing rate")

    endpoint_io = {
        role: "zio-std-io" if implementation == "netz" else "quic-go-netpoll"
        for role, implementation in endpoints.items()
    }
    records: dict[str, dict[str, str]] = {}
    paths_by_role: dict[str, Path] = {}
    for path in (client_log, server_log):
        rows = BENCHMARK.records(path, "socket-traffic", role_pair)
        if len(rows) != 1:
            raise ValueError(f"expected one socket-traffic record in {path}, found {len(rows)}")
        record = rows[0]
        role = record.get("endpoint_role")
        if role not in ("client", "server") or role in records:
            raise ValueError(f"invalid or duplicate endpoint role in {path}: {record}")
        records[role] = record
        paths_by_role[role] = path
    if set(records) != {"client", "server"}:
        raise ValueError("socket-traffic records do not cover both endpoints")

    sender_role = "client" if mode == "upload" else "server"
    expected_common = {
        "protocol": "http3",
        "mode": mode,
        "role_pair": role_pair,
        "sender_role": sender_role,
        "client_io": endpoint_io["client"],
        "server_io": endpoint_io["server"],
        "warmup": str(warmup),
        "iterations": str(iterations),
        "streams": str(streams),
        "body_bytes": str(body_bytes),
        "application_chunk_effective": str(min(chunk_bytes, 1152)),
        "stream_window": str(stream_window),
        "quic_version": str(quic_version),
        "netz_max_pacing_rate_bytes_per_second": str(
            netz_max_pacing_rate_bytes_per_second
        ),
        "traffic_scope": "all-rounds",
        "socket_boundary": "userspace-udp-payload",
        "benchmark_scope": "socket-traffic-same-application-shape",
        "logical_udp_segments": "true",
        "complete": "true",
    }
    values: dict[str, dict[str, int]] = {}
    for role, record in records.items():
        if record.get("implementation") != endpoints[role]:
            raise ValueError(f"implementation mismatch for {role}: {record}")
        for key, value in expected_common.items():
            if record.get(key) != value:
                raise ValueError(
                    f"{role} {key} mismatch: {record.get(key)!r}, expected {value!r}"
                )
        values[role] = {
            key: positive(record, key)
            for key in (
                "udp_sent_datagrams",
                "udp_sent_payload_bytes",
                "udp_received_datagrams",
                "udp_received_payload_bytes",
            )
        }

    transport_stats: dict[str, dict[str, int]] = {}
    for role, implementation in endpoints.items():
        if implementation != "netz":
            continue
        rows = BENCHMARK.records(paths_by_role[role], "transport-stats", role_pair)
        if len(rows) != 1:
            raise ValueError(
                f"expected one netz transport-stats record for {role}, found {len(rows)}"
            )
        record = rows[0]
        expected_transport = {
            "implementation": "netz",
            "protocol": "http3",
            "mode": mode,
            "role_pair": role_pair,
            "endpoint_role": role,
            "sender_role": sender_role,
            "client_io": endpoint_io["client"],
            "server_io": endpoint_io["server"],
            "warmup": str(warmup),
            "iterations": str(iterations),
            "streams": str(streams),
            "body_bytes": str(body_bytes),
            "netz_max_pacing_rate_bytes_per_second": str(
                netz_max_pacing_rate_bytes_per_second
            ),
            "traffic_scope": "all-rounds",
            "benchmark_scope": "socket-traffic-same-application-shape",
            "complete": "true",
        }
        for key, value in expected_transport.items():
            if record.get(key) != value:
                raise ValueError(f"netz {role} transport {key} mismatch: {record}")
        transport_stats[role] = {
            "packets_sent": positive(record, "packets_sent"),
            "packets_received": positive(record, "packets_received"),
            "packets_lost": nonnegative(record, "packets_lost"),
            "bytes_sent": positive(record, "bytes_sent"),
            "bytes_received": positive(record, "bytes_received"),
            "authentication_failures": nonnegative(record, "authentication_failures"),
            "local_key_updates": nonnegative(record, "local_key_updates"),
            "peer_key_updates": nonnegative(record, "peer_key_updates"),
        }
        if transport_stats[role]["packets_lost"] > transport_stats[role]["packets_sent"]:
            raise ValueError(f"netz {role} lost more packets than it sent")

    drop_stats: dict[str, int] | None = None
    for role, implementation in endpoints.items():
        if implementation != "quic-go":
            continue
        rows = BENCHMARK.records(paths_by_role[role], "packet-drop-stats", role_pair)
        if len(rows) != 1:
            raise ValueError(
                f"expected one quic-go packet-drop-stats record for {role}, found {len(rows)}"
            )
        record = rows[0]
        expected_drops = {
            "implementation": "quic-go",
            "protocol": "http3",
            "mode": mode,
            "role_pair": role_pair,
            "endpoint_role": role,
            "sender_role": sender_role,
            "client_io": endpoint_io["client"],
            "server_io": endpoint_io["server"],
            "warmup": str(warmup),
            "iterations": str(iterations),
            "streams": str(streams),
            "body_bytes": str(body_bytes),
            "netz_max_pacing_rate_bytes_per_second": str(
                netz_max_pacing_rate_bytes_per_second
            ),
            "traffic_scope": "all-rounds",
            "benchmark_scope": "socket-traffic-same-application-shape",
            "complete": "true",
        }
        for key, value in expected_drops.items():
            if record.get(key) != value:
                raise ValueError(f"quic-go {role} drop {key} mismatch: {record}")
        drop_stats = {
            key: nonnegative(record, key)
            for key in (
                "dropped_total",
                "dropped_dos_prevention",
                "dropped_duplicate",
                "dropped_payload_decrypt",
                "dropped_other",
            )
        }
        if drop_stats["dropped_total"] != sum(
            drop_stats[key]
            for key in (
                "dropped_dos_prevention",
                "dropped_duplicate",
                "dropped_payload_decrypt",
                "dropped_other",
            )
        ):
            raise ValueError("quic-go packet-drop categories do not sum to total")

    client = values["client"]
    server = values["server"]
    c2s_datagram_delta = client["udp_sent_datagrams"] - server["udp_received_datagrams"]
    c2s_byte_delta = client["udp_sent_payload_bytes"] - server["udp_received_payload_bytes"]
    s2c_datagram_delta = server["udp_sent_datagrams"] - client["udp_received_datagrams"]
    s2c_byte_delta = server["udp_sent_payload_bytes"] - client["udp_received_payload_bytes"]
    if min(c2s_datagram_delta, c2s_byte_delta, s2c_datagram_delta, s2c_byte_delta) < 0:
        raise ValueError("peer observed more traffic than its sender recorded")

    sender = values[sender_role]
    sender_impl = endpoints[sender_role]
    average_payload = sender["udp_sent_payload_bytes"] / sender["udp_sent_datagrams"]
    netz_role = (
        sender_role
        if endpoints[sender_role] == "netz"
        else next(role for role, implementation in endpoints.items() if implementation == "netz")
    )
    netz_transport = transport_stats[netz_role]
    loss_rate = netz_transport["packets_lost"] / netz_transport["packets_sent"]
    drops = drop_stats or {
        "dropped_total": 0,
        "dropped_dos_prevention": 0,
        "dropped_duplicate": 0,
        "dropped_payload_decrypt": 0,
        "dropped_other": 0,
    }
    print(
        " ".join(
            (
                "record=socket-traffic-comparison",
                "protocol=http3",
                f"mode={mode}",
                f"role_pair={role_pair}",
                f"sender_implementation={sender_impl}",
                f"sender_udp_datagrams={sender['udp_sent_datagrams']}",
                f"sender_udp_payload_bytes={sender['udp_sent_payload_bytes']}",
                f"sender_mean_udp_payload_bytes={average_payload:.3f}",
                f"netz_packets_sent={netz_transport['packets_sent']}",
                f"netz_packets_lost={netz_transport['packets_lost']}",
                f"netz_packet_loss_rate={loss_rate:.6f}",
                f"quic_go_dropped_total={drops['dropped_total']}",
                f"quic_go_dropped_dos_prevention={drops['dropped_dos_prevention']}",
                f"quic_go_dropped_duplicate={drops['dropped_duplicate']}",
                f"quic_go_dropped_payload_decrypt={drops['dropped_payload_decrypt']}",
                f"quic_go_dropped_other={drops['dropped_other']}",
                "netz_max_pacing_rate_bytes_per_second="
                f"{netz_max_pacing_rate_bytes_per_second}",
                f"client_to_server_observation_delta_datagrams={c2s_datagram_delta}",
                f"client_to_server_observation_delta_bytes={c2s_byte_delta}",
                f"server_to_client_observation_delta_datagrams={s2c_datagram_delta}",
                f"server_to_client_observation_delta_bytes={s2c_byte_delta}",
                "benchmark_scope=socket-traffic-same-application-shape",
                "timing_usable=false",
                "complete=true",
            )
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--mode", choices=("upload", "download"), required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--body-bytes", type=int, required=True)
    parser.add_argument("--chunk-bytes", type=int, required=True)
    parser.add_argument("--stream-window", type=int, required=True)
    parser.add_argument("--quic-version", type=int, required=True)
    parser.add_argument(
        "--netz-max-pacing-rate-bytes-per-second",
        type=int,
        default=0,
    )
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    args = parser.parse_args()
    verify(
        role_pair=args.role_pair,
        mode=args.mode,
        warmup=args.warmup,
        iterations=args.iterations,
        streams=args.streams,
        body_bytes=args.body_bytes,
        chunk_bytes=args.chunk_bytes,
        stream_window=args.stream_window,
        quic_version=args.quic_version,
        client_log=args.client_log,
        server_log=args.server_log,
        netz_max_pacing_rate_bytes_per_second=(
            args.netz_max_pacing_rate_bytes_per_second
        ),
    )


if __name__ == "__main__":
    main()
