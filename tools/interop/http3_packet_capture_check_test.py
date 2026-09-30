#!/usr/bin/env python3

import argparse
import contextlib
import hashlib
import importlib.util
import io
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MODULE_PATH = ROOT / "http3_packet_capture_check.py"
SPEC = importlib.util.spec_from_file_location("http3_packet_capture_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ipv4_udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    udp_length = 8 + len(payload)
    total_length = 20 + udp_length
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_length, 1, 0x4000, 64, socket.IPPROTO_UDP, 0,
            socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"),
        )
        + struct.pack("!HHHH", source_port, destination_port, udp_length, 0)
        + payload
    )


class Http3PacketCaptureCheckTests(unittest.TestCase):
    def fixture(self, directory: str) -> argparse.Namespace:
        root = Path(directory)
        client_log = root / "client.log"
        server_log = root / "server.log"
        capture_log = root / "capture.log"
        pcap = root / "capture.pcap"
        client_binary = root / "client"
        server_binary = root / "server"
        go_mod = root / "go.mod"
        go_sum = root / "go.sum"
        client_binary.write_bytes(b"netz client")
        server_binary.write_bytes(b"quic-go server")
        go_mod.write_text(
            "module fixture\nrequire github.com/quic-go/quic-go v0.59.0\n",
            encoding="utf-8",
        )
        go_sum.write_text("fixture sum\n", encoding="utf-8")
        common = (
            "protocol=http3 mode=upload role_pair=netz-client+quic-go-server "
            "sender_role=client client_io=zio-std-io server_io=quic-go-netpoll "
            "connection_scope=fresh-per-sample body_deadline_scope=sample "
            "timing_usable=false "
            "sample=1 streams=1 body_bytes=4 checksum=274 status=200 "
            "streams_finished=1 per_stream_verified=true quic_version=1 complete=true"
        )
        config = (
            "record=config protocol=http3 mode=upload "
            "role_pair=netz-client+quic-go-server sender_role=client "
            "client_io=zio-std-io server_io=quic-go-netpoll "
            "connection_scope=fresh-per-sample "
            "benchmark_scope=capture-backed-same-application-shape "
            "timing_usable=false body_deadline_scope=sample "
            "warmup=1 iterations=1 streams=1 body_bytes=4 "
            "application_chunk_requested=4 application_chunk_effective=4 "
            "stream_window=1024 connection_window=8192 timeout_ms=30000 "
            "steady_state_mtu=1280 quic_version=1 cipher=negotiated-unexposed "
            "cert_verify=true pacing=true gso=false"
        )
        client_log.write_text(
            f"implementation=netz endpoint_role=client gro=false {config}\n"
            "record=result implementation=netz result_owner=client "
            "endpoint_role=client benchmark_scope=capture-backed-same-application-shape "
            f"{common} elapsed_ns=1000 logical_MiB_s=3.815 "
            "sent_bytes=4 received_bytes=4\n",
            encoding="utf-8",
        )
        server_log.write_text(
            f"implementation=quic-go endpoint_role=server gro=implementation-default {config}\n"
            "record=server-complete implementation=quic-go endpoint_role=server "
            f"benchmark_scope=capture-backed-same-application-shape {common} "
            "sent_bytes=0 received_bytes=4\n",
            encoding="utf-8",
        )
        packets = (
            ipv4_udp(40000, 4433, b"abcdefghij"),
            ipv4_udp(4433, 40000, b"reply"),
        )
        writer = CHECK.CAPTURE.PcapWriter(pcap)
        for index, packet in enumerate(packets):
            writer.write(packet, len(packet), index + 1)
        writer.close()
        totals = CHECK.CAPTURE.summarize_pcap(pcap, "127.0.0.1", 4433)
        capture_log.write_text(
            " ".join(
                (
                    "record=kernel-capture",
                    "protocol=http3",
                    "mode=upload",
                    "role_pair=netz-client+quic-go-server",
                    "capture_source=linux-af-packet",
                    "capture_boundary=loopback-single-copy-ip",
                    "packet_socket=SOCK_DGRAM",
                    "packet_copy_filter=PACKET_HOST",
                    "pcap_link_type=raw-ipv4",
                    f"pcap_snaplen={CHECK.CAPTURE.PCAP_SNAPLEN}",
                    f"pcap_max_bytes={CHECK.CAPTURE.PCAP_MAX_BYTES}",
                    "payload_retention=prefix",
                    "capture_scope=complete-process-pair",
                    "benchmark_scope=capture-backed-same-application-shape",
                    "timing_usable=false",
                    "interface=lo",
                    "address_family=ipv4",
                    "server_ip=127.0.0.1",
                    "server_port=4433",
                    "client_cpu=0",
                    "server_cpu=1",
                    "capture_cpu=2",
                    "capture_receive_buffer_bytes=425984",
                    "warmup=1",
                    "iterations=1",
                    "streams=1",
                    "body_bytes=4",
                    "chunk_bytes=4",
                    "stream_window=1024",
                    "timeout_ms=30000",
                    "quic_version=1",
                    "udp_gso=disabled-both",
                    "netz_gro=false",
                    "quic_go_gro=implementation-default",
                    "ack_policy=implementation-default",
                    "pacing=implementation-specific",
                    "packetization=implementation-specific",
                    "cipher=negotiated-unexposed",
                    "quic_go_version=0.59.0",
                    f"client_binary_sha256={sha256(client_binary)}",
                    f"server_binary_sha256={sha256(server_binary)}",
                    f"capture_tool_sha256={sha256(ROOT / 'http3_packet_capture.py')}",
                    f"quic_go_mod_sha256={sha256(go_mod)}",
                    f"quic_go_sum_sha256={sha256(go_sum)}",
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
                    "socket_packets_seen=2",
                    "socket_drops=0",
                    f"pcap_bytes={pcap.stat().st_size}",
                    f"pcap_sha256={sha256(pcap)}",
                    "complete=true",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        return argparse.Namespace(
            role_pair="netz-client+quic-go-server",
            mode="upload",
            iterations=1,
            streams=1,
            body_bytes=4,
            chunk_bytes=4,
            stream_window=1024,
            timeout_ms=30000,
            quic_version=1,
            warmup=1,
            server_port=4433,
            client_cpu=0,
            server_cpu=1,
            capture_cpu=2,
            client_binary=client_binary,
            server_binary=server_binary,
            quic_go_mod=go_mod,
            quic_go_sum=go_sum,
            capture_tool=ROOT / "http3_packet_capture.py",
            client_log=client_log,
            server_log=server_log,
            capture_log=capture_log,
            pcap=pcap,
        )

    def test_complete_capture_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stdout(io.StringIO()):
                CHECK.verify(self.fixture(directory))

    def test_tampered_pcap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.pcap.write_bytes(args.pcap.read_bytes() + b"x")
            with self.assertRaisesRegex(
                ValueError, "truncated PCAP|pcap_bytes|pcap_sha256"
            ):
                CHECK.verify(args)

    def test_capture_arithmetic_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.capture_log.write_text(
                args.capture_log.read_text().replace(
                    "total_datagrams=2", "total_datagrams=3"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "datagram total"):
                CHECK.verify(args)

    def test_packet_size_sequence_hash_is_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.capture_log.write_text(
                args.capture_log.read_text().replace(
                    " packet_size_sequence_sha256=",
                    " packet_size_sequence_sha256=0",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "packet_size_sequence_sha256"):
                CHECK.verify(args)

    def test_binary_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.client_binary.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "client_binary_sha256"):
                CHECK.verify(args)

    def test_cpu_overlap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.capture_cpu = 1
            with self.assertRaisesRegex(ValueError, "CPUs must be distinct"):
                CHECK.verify(args)

    def test_negative_cpu_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.capture_cpu = -1
            with self.assertRaisesRegex(ValueError, "non-negative"):
                CHECK.verify(args)

    def test_missing_server_completion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.server_log.write_text(
                "\n".join(
                    line
                    for line in args.server_log.read_text().splitlines()
                    if "record=server-complete" not in line
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "expected 1 server"):
                CHECK.verify(args)

    def test_capture_timing_cannot_be_marked_usable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            for path in (args.client_log, args.server_log, args.capture_log):
                path.write_text(
                    path.read_text().replace(
                        "timing_usable=false", "timing_usable=true"
                    ),
                    encoding="utf-8",
                )
            with self.assertRaisesRegex(ValueError, "timing_usable"):
                CHECK.verify(args)


if __name__ == "__main__":
    unittest.main()
