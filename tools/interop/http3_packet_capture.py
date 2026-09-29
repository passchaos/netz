#!/usr/bin/env python3
"""Capture and summarize one loopback HTTP/3 benchmark UDP flow.

The live path uses a Linux AF_PACKET/SOCK_DGRAM socket and retains only the
outgoing copy of packets involving the selected server port.  The resulting
classic-PCAP file uses DLT_RAW and a bounded snapshot length; IPv4 and UDP
length fields preserve complete on-interface byte accounting without retaining
the whole encrypted benchmark payload.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ETH_P_IP = 0x0800
PACKET_OUTGOING = 4
SOL_PACKET = 263
PACKET_STATISTICS = 6
PCAP_MAGIC = 0xA1B2C3D4
PCAP_LINKTYPE_RAW = 101
PCAP_SNAPLEN = 128
PCAP_MAX_BYTES = 512 * 1024 * 1024


class CaptureError(ValueError):
    pass


@dataclass(frozen=True)
class PacketSummary:
    direction: str
    udp_payload_bytes: int
    ip_bytes: int


@dataclass
class CaptureTotals:
    client_to_server_datagrams: int = 0
    client_to_server_udp_payload_bytes: int = 0
    client_to_server_ip_bytes: int = 0
    server_to_client_datagrams: int = 0
    server_to_client_udp_payload_bytes: int = 0
    server_to_client_ip_bytes: int = 0
    _all_sizes: object = field(default_factory=hashlib.sha256, repr=False)
    _client_sizes: object = field(default_factory=hashlib.sha256, repr=False)
    _server_sizes: object = field(default_factory=hashlib.sha256, repr=False)

    def add(self, packet: PacketSummary) -> None:
        prefix = packet.direction
        setattr(
            self,
            f"{prefix}_datagrams",
            getattr(self, f"{prefix}_datagrams") + 1,
        )
        setattr(
            self,
            f"{prefix}_udp_payload_bytes",
            getattr(self, f"{prefix}_udp_payload_bytes") + packet.udp_payload_bytes,
        )
        setattr(
            self,
            f"{prefix}_ip_bytes",
            getattr(self, f"{prefix}_ip_bytes") + packet.ip_bytes,
        )
        encoded = struct.pack("!II", packet.udp_payload_bytes, packet.ip_bytes)
        direction = b"C" if packet.direction == "client_to_server" else b"S"
        self._all_sizes.update(direction + encoded)
        directional_sizes = (
            self._client_sizes if direction == b"C" else self._server_sizes
        )
        directional_sizes.update(encoded)

    @property
    def total_datagrams(self) -> int:
        return self.client_to_server_datagrams + self.server_to_client_datagrams

    @property
    def total_udp_payload_bytes(self) -> int:
        return (
            self.client_to_server_udp_payload_bytes
            + self.server_to_client_udp_payload_bytes
        )

    @property
    def total_ip_bytes(self) -> int:
        return self.client_to_server_ip_bytes + self.server_to_client_ip_bytes

    @property
    def packet_size_sequence_sha256(self) -> str:
        return self._all_sizes.hexdigest()

    @property
    def client_to_server_size_sequence_sha256(self) -> str:
        return self._client_sizes.hexdigest()

    @property
    def server_to_client_size_sequence_sha256(self) -> str:
        return self._server_sizes.hexdigest()


def parse_ipv4_udp(
    packet: bytes,
    server_ip: str,
    server_port: int,
    *,
    original_length: int | None = None,
) -> PacketSummary | None:
    if len(packet) < 20:
        return None
    version = packet[0] >> 4
    header_bytes = (packet[0] & 0x0F) * 4
    if version != 4 or header_bytes < 20 or len(packet) < header_bytes:
        return None
    if packet[9] != socket.IPPROTO_UDP:
        return None
    fragment = struct.unpack_from("!H", packet, 6)[0]
    if fragment & 0x1FFF:
        return None
    if len(packet) < header_bytes + 8:
        return None
    source_port, destination_port, udp_bytes = struct.unpack_from(
        "!HHH", packet, header_bytes
    )
    client_to_server = destination_port == server_port
    server_to_client = source_port == server_port
    if not client_to_server and not server_to_client:
        return None
    if client_to_server and server_to_client:
        raise CaptureError("ambiguous server-port packet")
    if header_bytes != 20:
        raise CaptureError("invalid IPv4 header")
    ip_bytes = struct.unpack_from("!H", packet, 2)[0]
    if ip_bytes < header_bytes:
        raise CaptureError("invalid IPv4 total length")
    if original_length is None:
        original_length = len(packet)
    if ip_bytes != original_length:
        raise CaptureError("IPv4 length does not match captured original length")
    if ip_bytes < header_bytes + 8:
        raise CaptureError("invalid IPv4 total length")
    if fragment & 0x2000:
        raise CaptureError("fragmented UDP packet is not supported")
    source_ip = socket.inet_ntoa(packet[12:16])
    destination_ip = socket.inet_ntoa(packet[16:20])
    if udp_bytes < 8 or header_bytes + udp_bytes != ip_bytes:
        raise CaptureError("invalid UDP length")
    if source_ip != server_ip or destination_ip != server_ip:
        raise CaptureError("selected UDP flow left the expected loopback address")
    return PacketSummary(
        direction=("client_to_server" if client_to_server else "server_to_client"),
        udp_payload_bytes=udp_bytes - 8,
        ip_bytes=ip_bytes,
    )


class PcapWriter:
    def __init__(self, path: Path) -> None:
        self.file = path.open("wb")
        self.file.write(
            struct.pack(
                "<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, PCAP_SNAPLEN, PCAP_LINKTYPE_RAW
            )
        )
        self.bytes_written = 24

    def write(self, packet: bytes, original_length: int, timestamp_ns: int) -> None:
        retained = packet[:PCAP_SNAPLEN]
        record_bytes = 16 + len(retained)
        if self.bytes_written + record_bytes > PCAP_MAX_BYTES:
            raise CaptureError("PCAP exceeds the 512 MiB artifact bound")
        seconds, remainder = divmod(timestamp_ns, 1_000_000_000)
        self.file.write(
            struct.pack("<IIII", seconds, remainder // 1_000, len(retained), original_length)
        )
        self.file.write(retained)
        self.bytes_written += record_bytes

    def close(self) -> None:
        self.file.close()


def summarize_pcap(path: Path, server_ip: str, server_port: int) -> CaptureTotals:
    with path.open("rb") as source:
        header = source.read(24)
        if len(header) < 24:
            raise CaptureError("truncated PCAP header")
        magic, major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(
            "<IHHIIII", header
        )
        if (magic, major, minor, snaplen, linktype) != (
            PCAP_MAGIC,
            2,
            4,
            PCAP_SNAPLEN,
            PCAP_LINKTYPE_RAW,
        ):
            raise CaptureError("unsupported PCAP format")
        totals = CaptureTotals()
        while True:
            packet_header = source.read(16)
            if not packet_header:
                break
            if len(packet_header) < 16:
                raise CaptureError("truncated PCAP packet header")
            _seconds, micros, captured_length, original_length = struct.unpack(
                "<IIII", packet_header
            )
            if (
                micros >= 1_000_000
                or captured_length > snaplen
                or captured_length > original_length
            ):
                raise CaptureError("invalid PCAP packet metadata")
            packet = source.read(captured_length)
            if len(packet) != captured_length:
                raise CaptureError("truncated PCAP packet data")
            parsed = parse_ipv4_udp(
                packet, server_ip, server_port, original_length=original_length
            )
            if parsed is None:
                raise CaptureError("PCAP contains a packet outside the selected UDP flow")
            totals.add(parsed)
        return totals


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_packet_socket(interface: str) -> socket.socket:
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("Linux AF_PACKET capture is unavailable on this platform")
    capture: socket.socket | None = None
    try:
        capture = socket.socket(
            socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP)
        )
        capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
        # Python's AF_PACKET address tuple expects the protocol in network
        # byte order, matching sockaddr_ll.sll_protocol.
        capture.bind((interface, socket.htons(ETH_P_IP)))
    except PermissionError as error:
        if capture is not None:
            capture.close()
        raise RuntimeError(
            "Linux packet capture requires CAP_NET_RAW (AF_PACKET was denied)"
        ) from error
    except OSError as error:
        if capture is not None:
            capture.close()
        raise RuntimeError(f"cannot capture interface {interface!r}: {error}") from error
    capture.settimeout(0.1)
    return capture


def socket_statistics(capture: socket.socket) -> tuple[int, int]:
    raw = capture.getsockopt(SOL_PACKET, PACKET_STATISTICS, 12)
    if len(raw) < 8:
        raise RuntimeError("kernel returned truncated PACKET_STATISTICS")
    return struct.unpack_from("=II", raw)


def capture(args: argparse.Namespace) -> int:
    if os.sched_getaffinity(0) != {args.capture_cpu}:
        raise RuntimeError("capture process CPU affinity does not match capture_cpu")
    capture_tool_sha256 = sha256_file(Path(__file__).resolve())
    packet_socket = open_packet_socket(args.interface)
    try:
        writer = PcapWriter(args.output)
    except OSError:
        packet_socket.close()
        raise
    receive_buffer_bytes = packet_socket.getsockopt(
        socket.SOL_SOCKET, socket.SO_RCVBUF
    )
    stopping = False
    totals = CaptureTotals()

    def retain(packet: bytes, address: tuple[object, ...]) -> None:
        if len(address) < 3 or address[0] != args.interface:
            return
        if address[2] != PACKET_OUTGOING:
            return
        parsed = parse_ipv4_udp(packet, args.server_ip, args.server_port)
        if parsed is None:
            return
        totals.add(parsed)
        writer.write(packet, parsed.ip_bytes, time.time_ns())

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    print("CAPTURE_READY=1", flush=True)
    try:
        while True:
            try:
                packet, address = packet_socket.recvfrom(65535)
            except socket.timeout:
                if stopping:
                    break
                continue
            except InterruptedError:
                continue
            retain(packet, address)
            if stopping:
                break
        packet_socket.setblocking(False)
        while True:
            try:
                packet, address = packet_socket.recvfrom(65535)
            except BlockingIOError:
                break
            retain(packet, address)
        packets_seen, socket_drops = socket_statistics(packet_socket)
    finally:
        writer.close()
        packet_socket.close()
    if totals.total_datagrams == 0:
        raise RuntimeError("capture contains no matching UDP datagrams")
    if socket_drops != 0:
        raise RuntimeError(f"packet socket dropped {socket_drops} packets")
    pcap_bytes = args.output.stat().st_size
    print(
        " ".join(
            (
                "record=kernel-capture",
                "protocol=http3",
                f"mode={args.mode}",
                f"role_pair={args.role_pair}",
                "capture_source=linux-af-packet",
                "capture_boundary=loopback-egress-ip",
                "packet_socket=SOCK_DGRAM",
                "packet_copy_filter=PACKET_OUTGOING",
                "pcap_link_type=raw-ipv4",
                f"pcap_snaplen={PCAP_SNAPLEN}",
                f"pcap_max_bytes={PCAP_MAX_BYTES}",
                "payload_retention=prefix",
                "capture_scope=complete-process-pair",
                "benchmark_scope=capture-backed-same-application-shape",
                "timing_usable=false",
                f"interface={args.interface}",
                "address_family=ipv4",
                f"server_ip={args.server_ip}",
                f"server_port={args.server_port}",
                f"client_cpu={args.client_cpu}",
                f"server_cpu={args.server_cpu}",
                f"capture_cpu={args.capture_cpu}",
                f"capture_receive_buffer_bytes={receive_buffer_bytes}",
                f"warmup={args.warmup}",
                f"iterations={args.iterations}",
                f"streams={args.streams}",
                f"body_bytes={args.body_bytes}",
                f"chunk_bytes={args.chunk_bytes}",
                f"stream_window={args.stream_window}",
                f"timeout_ms={args.timeout_ms}",
                f"quic_version={args.quic_version}",
                "udp_gso=disabled-both",
                "netz_gro=false",
                "quic_go_gro=implementation-default",
                "ack_policy=implementation-default",
                "pacing=implementation-specific",
                "packetization=implementation-specific",
                "cipher=negotiated-unexposed",
                f"quic_go_version={args.quic_go_version}",
                f"client_binary_sha256={args.client_binary_sha256}",
                f"server_binary_sha256={args.server_binary_sha256}",
                f"capture_tool_sha256={capture_tool_sha256}",
                f"quic_go_mod_sha256={args.quic_go_mod_sha256}",
                f"quic_go_sum_sha256={args.quic_go_sum_sha256}",
                f"client_to_server_datagrams={totals.client_to_server_datagrams}",
                f"client_to_server_udp_payload_bytes={totals.client_to_server_udp_payload_bytes}",
                f"client_to_server_ip_bytes={totals.client_to_server_ip_bytes}",
                f"server_to_client_datagrams={totals.server_to_client_datagrams}",
                f"server_to_client_udp_payload_bytes={totals.server_to_client_udp_payload_bytes}",
                f"server_to_client_ip_bytes={totals.server_to_client_ip_bytes}",
                f"total_datagrams={totals.total_datagrams}",
                f"total_udp_payload_bytes={totals.total_udp_payload_bytes}",
                f"total_ip_bytes={totals.total_ip_bytes}",
                f"packet_size_sequence_sha256={totals.packet_size_sequence_sha256}",
                f"client_to_server_size_sequence_sha256={totals.client_to_server_size_sequence_sha256}",
                f"server_to_client_size_sequence_sha256={totals.server_to_client_size_sequence_sha256}",
                f"socket_packets_seen={packets_seen}",
                f"socket_drops={socket_drops}",
                f"pcap_bytes={pcap_bytes}",
                f"pcap_sha256={sha256_file(args.output)}",
                "complete=true",
            )
        ),
        flush=True,
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--interface", default="lo")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--server-ip", default="127.0.0.1")
    parser.add_argument("--server-port", type=int)
    parser.add_argument(
        "--role-pair",
        choices=("netz-client+quic-go-server", "quic-go-client+netz-server"),
    )
    parser.add_argument("--mode", choices=("upload", "download"))
    parser.add_argument("--client-cpu", type=int)
    parser.add_argument("--server-cpu", type=int)
    parser.add_argument("--capture-cpu", type=int)
    parser.add_argument("--warmup", type=int)
    parser.add_argument("--iterations", type=int)
    parser.add_argument("--streams", type=int)
    parser.add_argument("--body-bytes", type=int)
    parser.add_argument("--chunk-bytes", type=int)
    parser.add_argument("--stream-window", type=int)
    parser.add_argument("--timeout-ms", type=int)
    parser.add_argument("--quic-version", type=int, choices=(1, 2))
    parser.add_argument("--client-binary-sha256")
    parser.add_argument("--server-binary-sha256")
    parser.add_argument("--quic-go-mod-sha256")
    parser.add_argument("--quic-go-sum-sha256")
    parser.add_argument("--quic-go-version")
    args = parser.parse_args()
    if args.check:
        if any(
            value is not None
            for value in (
                args.output,
                args.server_port,
                args.role_pair,
                args.mode,
                args.client_cpu,
                args.server_cpu,
                args.capture_cpu,
                args.warmup,
                args.iterations,
                args.streams,
                args.body_bytes,
                args.chunk_bytes,
                args.stream_window,
                args.timeout_ms,
                args.quic_version,
                args.client_binary_sha256,
                args.server_binary_sha256,
                args.quic_go_mod_sha256,
                args.quic_go_sum_sha256,
                args.quic_go_version,
            )
        ):
            parser.error("--check accepts only --interface")
        return args
    required = (
        "output",
        "server_port",
        "role_pair",
        "mode",
        "client_cpu",
        "server_cpu",
        "capture_cpu",
        "warmup",
        "iterations",
        "streams",
        "body_bytes",
        "chunk_bytes",
        "stream_window",
        "timeout_ms",
        "quic_version",
    )
    if any(getattr(args, name) is None for name in required):
        parser.error("capture mode requires complete benchmark metadata")
    if not 0 < args.server_port <= 65535:
        parser.error("invalid server port")
    if args.server_ip != "127.0.0.1":
        parser.error("only the current IPv4 loopback benchmark is supported")
    if args.interface != "lo":
        parser.error("only the current loopback interface is supported")
    if min(
        args.warmup,
        args.iterations,
        args.streams,
        args.body_bytes,
        args.chunk_bytes,
        args.stream_window,
        args.timeout_ms,
    ) <= 0:
        parser.error("benchmark counters must be positive")
    if args.chunk_bytes > args.body_bytes:
        parser.error("application chunk exceeds body bytes")
    logical_body_bytes = (
        (args.warmup + args.iterations) * args.streams * args.body_bytes
    )
    if logical_body_bytes > 1024 * 1024 * 1024:
        parser.error("capture workload exceeds the 1 GiB logical-body bound")
    for name in (
        "client_binary_sha256",
        "server_binary_sha256",
        "quic_go_mod_sha256",
        "quic_go_sum_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", getattr(args, name) or ""):
            parser.error(f"invalid {name.replace('_', '-')}")
    if args.quic_go_version != "0.59.0":
        parser.error("unsupported quic-go version")
    if min(args.client_cpu, args.server_cpu, args.capture_cpu) < 0:
        parser.error("CPU identifiers must be non-negative")
    if len({args.client_cpu, args.server_cpu, args.capture_cpu}) != 3:
        parser.error("client, server, and capture CPUs must be distinct")
    return args


def main() -> int:
    args = parse_args()
    try:
        if args.check:
            packet_socket = open_packet_socket(args.interface)
            packet_socket.close()
            print(
                "capture_capability=available capture_source=linux-af-packet "
                f"interface={args.interface}"
            )
            return 0
        return capture(args)
    except (CaptureError, RuntimeError, OSError) as error:
        print(f"HTTP/3 packet capture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
