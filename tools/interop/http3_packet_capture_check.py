#!/usr/bin/env python3
"""Strictly bind an HTTP/3 benchmark result to a Linux packet capture."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BENCHMARK = load_module("http3_benchmark_check", ROOT / "http3_benchmark_check.py")
CAPTURE = load_module("http3_packet_capture", ROOT / "http3_packet_capture.py")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def integer(record: dict[str, str], name: str, *, positive: bool = False) -> int:
    try:
        value = int(record[name])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid capture integer {name}") from error
    if value < 0 or (positive and value == 0):
        raise ValueError(f"invalid capture integer {name}")
    return value


def verify(args: argparse.Namespace) -> None:
    if min(args.client_cpu, args.server_cpu, args.capture_cpu) < 0:
        raise ValueError("CPU identifiers must be non-negative")
    if len({args.client_cpu, args.server_cpu, args.capture_cpu}) != 3:
        raise ValueError("client, server, and capture CPUs must be distinct")
    with contextlib.redirect_stdout(io.StringIO()):
        BENCHMARK.verify(
            role_pair=args.role_pair,
            mode=args.mode,
            iterations=args.iterations,
            streams=args.streams,
            body_bytes=args.body_bytes,
            quic_version=args.quic_version,
            warmup=args.warmup,
            chunk_bytes=args.chunk_bytes,
            stream_window=args.stream_window,
            timeout_ms=args.timeout_ms,
            client_log=args.client_log,
            server_log=args.server_log,
            netz_max_pacing_rate_bytes_per_second=(
                args.netz_max_pacing_rate_bytes_per_second
            ),
            capture=True,
        )
    rows = BENCHMARK.records(args.capture_log, "kernel-capture", args.role_pair)
    if len(rows) != 1:
        raise ValueError(f"expected one kernel-capture record, found {len(rows)}")
    record = rows[0]
    if args.pcap.stat().st_size > CAPTURE.PCAP_MAX_BYTES:
        raise ValueError("PCAP exceeds the artifact bound")
    parsed = CAPTURE.summarize_pcap(args.pcap, "127.0.0.1", args.server_port)
    expected = {
        "protocol": "http3",
        "mode": args.mode,
        "role_pair": args.role_pair,
        "capture_source": "linux-af-packet",
        "capture_boundary": "loopback-single-copy-ip",
        "packet_socket": "SOCK_DGRAM",
        "packet_copy_filter": "PACKET_HOST",
        "pcap_link_type": "raw-ipv4",
        "pcap_snaplen": str(CAPTURE.PCAP_SNAPLEN),
        "pcap_max_bytes": str(CAPTURE.PCAP_MAX_BYTES),
        "payload_retention": "prefix",
        "capture_scope": "complete-process-pair",
        "benchmark_scope": "capture-backed-same-application-shape",
        "timing_usable": "false",
        "interface": "lo",
        "address_family": "ipv4",
        "server_ip": "127.0.0.1",
        "server_port": str(args.server_port),
        "client_cpu": str(args.client_cpu),
        "server_cpu": str(args.server_cpu),
        "capture_cpu": str(args.capture_cpu),
        "warmup": str(args.warmup),
        "iterations": str(args.iterations),
        "streams": str(args.streams),
        "body_bytes": str(args.body_bytes),
        "chunk_bytes": str(args.chunk_bytes),
        "stream_window": str(args.stream_window),
        "timeout_ms": str(args.timeout_ms),
        "quic_version": str(args.quic_version),
        "udp_gso": "disabled-both",
        "netz_gro": "false",
        "quic_go_gro": "implementation-default",
        "ack_policy": "implementation-default",
        "pacing": "implementation-specific",
        "packetization": "implementation-specific",
        "cipher": "negotiated-unexposed",
        "quic_go_version": "0.59.0",
        "client_binary_sha256": sha256_file(args.client_binary),
        "server_binary_sha256": sha256_file(args.server_binary),
        "capture_tool_sha256": sha256_file(args.capture_tool),
        "quic_go_mod_sha256": sha256_file(args.quic_go_mod),
        "quic_go_sum_sha256": sha256_file(args.quic_go_sum),
        "socket_drops": "0",
        "pcap_bytes": str(args.pcap.stat().st_size),
        "pcap_sha256": sha256_file(args.pcap),
        "packet_size_sequence_sha256": parsed.packet_size_sequence_sha256,
        "client_to_server_size_sequence_sha256": (
            parsed.client_to_server_size_sequence_sha256
        ),
        "server_to_client_size_sequence_sha256": (
            parsed.server_to_client_size_sequence_sha256
        ),
        "complete": "true",
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(
                f"capture {key} mismatch: {record.get(key)!r}, expected {value!r}"
            )
    if "github.com/quic-go/quic-go v0.59.0" not in args.quic_go_mod.read_text(
        encoding="utf-8"
    ):
        raise ValueError("quic-go module version mismatch")
    fields = (
        "client_to_server_datagrams",
        "client_to_server_udp_payload_bytes",
        "client_to_server_ip_bytes",
        "server_to_client_datagrams",
        "server_to_client_udp_payload_bytes",
        "server_to_client_ip_bytes",
        "total_datagrams",
        "total_udp_payload_bytes",
        "total_ip_bytes",
    )
    values = {name: integer(record, name, positive=True) for name in fields}
    integer(record, "capture_receive_buffer_bytes", positive=True)
    packets_seen = integer(record, "socket_packets_seen", positive=True)
    if values["total_datagrams"] != (
        values["client_to_server_datagrams"]
        + values["server_to_client_datagrams"]
    ):
        raise ValueError("capture datagram total mismatch")
    if values["total_udp_payload_bytes"] != (
        values["client_to_server_udp_payload_bytes"]
        + values["server_to_client_udp_payload_bytes"]
    ):
        raise ValueError("capture UDP payload total mismatch")
    if values["total_ip_bytes"] != (
        values["client_to_server_ip_bytes"]
        + values["server_to_client_ip_bytes"]
    ):
        raise ValueError("capture IP byte total mismatch")
    if values["total_ip_bytes"] != (
        values["total_udp_payload_bytes"] + values["total_datagrams"] * 28
    ):
        raise ValueError("capture IPv4/UDP header arithmetic mismatch")
    if packets_seen < values["total_datagrams"]:
        raise ValueError("kernel packet count is below retained capture count")

    for name in fields:
        if getattr(parsed, name) != values[name]:
            raise ValueError(f"PCAP {name} does not match capture record")

    expected_body_bytes = (
        (args.warmup + args.iterations) * args.streams * args.body_bytes
    )
    sender_bytes = values[
        "client_to_server_udp_payload_bytes"
        if args.mode == "upload"
        else "server_to_client_udp_payload_bytes"
    ]
    if sender_bytes < expected_body_bytes:
        raise ValueError("captured sender bytes do not cover the benchmark bodies")

    print(
        f"record=kernel-capture-verified protocol=http3 mode={args.mode} "
        f"role_pair={args.role_pair} warmup={args.warmup} "
        f"iterations={args.iterations} streams={args.streams} "
        f"body_bytes={args.body_bytes} quic_version={args.quic_version} "
        f"total_datagrams={values['total_datagrams']} "
        f"total_udp_payload_bytes={values['total_udp_payload_bytes']} "
        f"total_ip_bytes={values['total_ip_bytes']} timing_usable=false "
        "complete=true"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--mode", choices=("upload", "download"), required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--body-bytes", type=int, required=True)
    parser.add_argument("--quic-version", type=int, choices=(1, 2), required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--chunk-bytes", type=int, required=True)
    parser.add_argument("--stream-window", type=int, required=True)
    parser.add_argument("--timeout-ms", type=int, required=True)
    parser.add_argument(
        "--netz-max-pacing-rate-bytes-per-second",
        type=int,
        default=0,
    )
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument("--client-cpu", type=int, required=True)
    parser.add_argument("--server-cpu", type=int, required=True)
    parser.add_argument("--capture-cpu", type=int, required=True)
    parser.add_argument("--client-binary", type=Path, required=True)
    parser.add_argument("--server-binary", type=Path, required=True)
    parser.add_argument("--quic-go-mod", type=Path, required=True)
    parser.add_argument("--quic-go-sum", type=Path, required=True)
    parser.add_argument("--capture-tool", type=Path, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    parser.add_argument("--capture-log", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    verify(parse_args())
