#!/usr/bin/env python3
"""Compare two independently captured HTTP/3 implementation pairings."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import re
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

PAIR_NETZ_CLIENT = "netz-client+quic-go-server"
PAIR_GO_CLIENT = "quic-go-client+netz-server"


def capture_record(path: Path, role_pair: str) -> dict[str, str]:
    rows = BENCHMARK.records(path, "kernel-capture", role_pair)
    if len(rows) != 1:
        raise ValueError(f"expected one {role_pair} capture record, found {len(rows)}")
    return rows[0]


def integer(record: dict[str, str], name: str) -> int:
    try:
        value = int(record[name])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid capture comparison integer {name}") from error
    if value <= 0:
        raise ValueError(f"non-positive capture comparison integer {name}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(args: argparse.Namespace) -> None:
    if (
        min(
            args.warmup,
            args.iterations,
            args.streams,
            args.body_bytes,
            args.chunk_bytes,
            args.stream_window,
            args.timeout_ms,
        )
        <= 0
        or args.warmup + args.iterations > 4096
        or args.streams not in (1, 4, 16)
        or args.chunk_bytes > args.body_bytes
    ):
        raise ValueError("invalid capture comparison workload")
    if min(args.client_cpu, args.server_cpu, args.capture_cpu) < 0:
        raise ValueError("CPU identifiers must be non-negative")
    if len({args.client_cpu, args.server_cpu, args.capture_cpu}) != 3:
        raise ValueError("client, server, and capture CPUs must be distinct")
    netz_client = capture_record(args.netz_client_capture, PAIR_NETZ_CLIENT)
    go_client = capture_record(args.quic_go_client_capture, PAIR_GO_CLIENT)
    expected = {
        "protocol": "http3",
        "mode": args.mode,
        "capture_source": "linux-af-packet",
        "capture_boundary": "loopback-single-copy-ip",
        "packet_socket": "SOCK_DGRAM",
        "packet_copy_filter": "PACKET_HOST",
        "pcap_link_type": "raw-ipv4",
        "pcap_snaplen": "128",
        "pcap_max_bytes": str(512 * 1024 * 1024),
        "payload_retention": "prefix",
        "capture_scope": "complete-process-pair",
        "benchmark_scope": "capture-backed-same-application-shape",
        "timing_usable": "false",
        "interface": "lo",
        "address_family": "ipv4",
        "server_ip": "127.0.0.1",
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
        "socket_drops": "0",
        "complete": "true",
    }
    for role_pair, record in (
        (PAIR_NETZ_CLIENT, netz_client),
        (PAIR_GO_CLIENT, go_client),
    ):
        for key, value in expected.items():
            if record.get(key) != value:
                raise ValueError(
                    f"{role_pair} {key} mismatch: {record.get(key)!r}, expected {value!r}"
                )
        for key in (
            "capture_tool_sha256",
            "client_binary_sha256",
            "server_binary_sha256",
            "pcap_sha256",
            "packet_size_sequence_sha256",
            "client_to_server_size_sequence_sha256",
            "server_to_client_size_sequence_sha256",
            "quic_go_mod_sha256",
            "quic_go_sum_sha256",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", record.get(key, "")):
                raise ValueError(f"{role_pair} has invalid {key}")
    if (
        netz_client.get("capture_tool_sha256")
        != go_client.get("capture_tool_sha256")
    ):
        raise ValueError("capture tool hashes differ")
    for key in ("quic_go_mod_sha256", "quic_go_sum_sha256"):
        if netz_client.get(key) != go_client.get(key):
            raise ValueError(f"{key} differs across endpoint roles")
    if (
        netz_client.get("server_binary_sha256")
        != go_client.get("client_binary_sha256")
    ):
        raise ValueError("quic-go binary hashes differ across endpoint roles")
    for role_pair, record, pcap in (
        (PAIR_NETZ_CLIENT, netz_client, args.netz_client_pcap),
        (PAIR_GO_CLIENT, go_client, args.quic_go_client_pcap),
    ):
        if record.get("pcap_sha256") != sha256_file(pcap):
            raise ValueError(f"{role_pair} PCAP hash mismatch")
    ports = [
        integer(netz_client, "server_port"),
        integer(go_client, "server_port"),
    ]
    if any(port > 65535 for port in ports):
        raise ValueError("capture server ports must be valid")
    receive_buffers = [
        integer(netz_client, "capture_receive_buffer_bytes"),
        integer(go_client, "capture_receive_buffer_bytes"),
    ]
    if receive_buffers[0] != receive_buffers[1]:
        raise ValueError("capture receive buffer sizes differ")

    metric_names = (
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
    netz_values = {name: integer(netz_client, name) for name in metric_names}
    go_values = {name: integer(go_client, name) for name in metric_names}
    for role_pair, record, values in (
        (PAIR_NETZ_CLIENT, netz_client, netz_values),
        (PAIR_GO_CLIENT, go_client, go_values),
    ):
        if values["total_datagrams"] != (
            values["client_to_server_datagrams"]
            + values["server_to_client_datagrams"]
        ):
            raise ValueError(f"{role_pair} datagram total mismatch")
        if values["total_udp_payload_bytes"] != (
            values["client_to_server_udp_payload_bytes"]
            + values["server_to_client_udp_payload_bytes"]
        ):
            raise ValueError(f"{role_pair} UDP payload total mismatch")
        if values["total_ip_bytes"] != (
            values["client_to_server_ip_bytes"]
            + values["server_to_client_ip_bytes"]
        ):
            raise ValueError(f"{role_pair} IP byte total mismatch")
        if values["total_ip_bytes"] != (
            values["total_udp_payload_bytes"] + values["total_datagrams"] * 28
        ):
            raise ValueError(f"{role_pair} IPv4/UDP header arithmetic mismatch")
        if integer(record, "socket_packets_seen") < values["total_datagrams"]:
            raise ValueError(f"{role_pair} kernel packet count mismatch")
    equal = all(netz_values[name] == go_values[name] for name in metric_names)
    sender_prefix = (
        "client_to_server" if args.mode == "upload" else "server_to_client"
    )
    receiver_prefix = (
        "server_to_client" if args.mode == "upload" else "client_to_server"
    )
    netz_sender_record = netz_client if args.mode == "upload" else go_client
    go_sender_record = go_client if args.mode == "upload" else netz_client
    netz_sender = {
        suffix: integer(netz_sender_record, f"{sender_prefix}_{suffix}")
        for suffix in ("datagrams", "udp_payload_bytes", "ip_bytes")
    }
    go_sender = {
        suffix: integer(go_sender_record, f"{sender_prefix}_{suffix}")
        for suffix in ("datagrams", "udp_payload_bytes", "ip_bytes")
    }
    netz_receiver = {
        suffix: integer(netz_sender_record, f"{receiver_prefix}_{suffix}")
        for suffix in ("datagrams", "udp_payload_bytes", "ip_bytes")
    }
    go_receiver = {
        suffix: integer(go_sender_record, f"{receiver_prefix}_{suffix}")
        for suffix in ("datagrams", "udp_payload_bytes", "ip_bytes")
    }
    sender_sequence_key = f"{sender_prefix}_size_sequence_sha256"
    receiver_sequence_key = f"{receiver_prefix}_size_sequence_sha256"
    sender_sequence_equal = (
        netz_sender_record.get(sender_sequence_key)
        == go_sender_record.get(sender_sequence_key)
    )
    peer_sequence_equal = (
        netz_sender_record.get(receiver_sequence_key)
        == go_sender_record.get(receiver_sequence_key)
    )
    print(
        " ".join(
            (
                "record=kernel-capture-comparison",
                "protocol=http3",
                f"mode={args.mode}",
                "benchmark_scope=capture-backed-same-application-shape",
                "capture_boundary=loopback-single-copy-ip",
                "packet_socket=SOCK_DGRAM",
                "packet_copy_filter=PACKET_HOST",
                f"warmup={args.warmup}",
                f"iterations={args.iterations}",
                f"streams={args.streams}",
                f"body_bytes={args.body_bytes}",
                f"chunk_bytes={args.chunk_bytes}",
                f"stream_window={args.stream_window}",
                f"timeout_ms={args.timeout_ms}",
                f"quic_version={args.quic_version}",
                f"capture_receive_buffer_bytes={receive_buffers[0]}",
                f"netz_client_pair_server_port={ports[0]}",
                f"quic_go_client_pair_server_port={ports[1]}",
                f"netz_client_binary_sha256={netz_client['client_binary_sha256']}",
                f"netz_server_binary_sha256={go_client['server_binary_sha256']}",
                f"quic_go_binary_sha256={netz_client['server_binary_sha256']}",
                f"quic_go_mod_sha256={netz_client['quic_go_mod_sha256']}",
                f"quic_go_sum_sha256={netz_client['quic_go_sum_sha256']}",
                f"capture_tool_sha256={netz_client['capture_tool_sha256']}",
                f"netz_client_pcap_sha256={netz_client['pcap_sha256']}",
                f"quic_go_client_pcap_sha256={go_client['pcap_sha256']}",
                f"netz_sender_datagrams={netz_sender['datagrams']}",
                f"netz_sender_udp_payload_bytes={netz_sender['udp_payload_bytes']}",
                f"netz_sender_ip_bytes={netz_sender['ip_bytes']}",
                f"netz_sender_pair_peer_datagrams={netz_receiver['datagrams']}",
                f"netz_sender_pair_peer_udp_payload_bytes={netz_receiver['udp_payload_bytes']}",
                f"netz_sender_pair_peer_ip_bytes={netz_receiver['ip_bytes']}",
                f"quic_go_sender_datagrams={go_sender['datagrams']}",
                f"quic_go_sender_udp_payload_bytes={go_sender['udp_payload_bytes']}",
                f"quic_go_sender_ip_bytes={go_sender['ip_bytes']}",
                f"quic_go_sender_pair_peer_datagrams={go_receiver['datagrams']}",
                f"quic_go_sender_pair_peer_udp_payload_bytes={go_receiver['udp_payload_bytes']}",
                f"quic_go_sender_pair_peer_ip_bytes={go_receiver['ip_bytes']}",
                f"captured_totals_equal={str(equal).lower()}",
                f"sender_packet_size_sequence_equal={str(sender_sequence_equal).lower()}",
                f"peer_packet_size_sequence_equal={str(peer_sequence_equal).lower()}",
                "timing_usable=false",
                "complete=true",
            )
        )
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("upload", "download"), required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--body-bytes", type=int, required=True)
    parser.add_argument("--chunk-bytes", type=int, required=True)
    parser.add_argument("--stream-window", type=int, required=True)
    parser.add_argument("--timeout-ms", type=int, required=True)
    parser.add_argument("--quic-version", type=int, choices=(1, 2), required=True)
    parser.add_argument("--client-cpu", type=int, required=True)
    parser.add_argument("--server-cpu", type=int, required=True)
    parser.add_argument("--capture-cpu", type=int, required=True)
    parser.add_argument("--netz-client-capture", type=Path, required=True)
    parser.add_argument("--quic-go-client-capture", type=Path, required=True)
    parser.add_argument("--netz-client-pcap", type=Path, required=True)
    parser.add_argument("--quic-go-client-pcap", type=Path, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    verify(parse_args())
