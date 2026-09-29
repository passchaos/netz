#!/usr/bin/env python3

import argparse
import contextlib
import hashlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("http3_packet_capture_compare.py")
SPEC = importlib.util.spec_from_file_location("http3_packet_capture_compare", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
COMPARE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMPARE
SPEC.loader.exec_module(COMPARE)


class Http3PacketCaptureCompareTests(unittest.TestCase):
    def fixture(self, directory: str) -> argparse.Namespace:
        root = Path(directory)
        first = root / "netz-client.log"
        second = root / "quic-go-client.log"
        first_pcap = root / "netz-client.pcap"
        second_pcap = root / "quic-go-client.pcap"
        first_pcap.write_bytes(b"first pcap")
        second_pcap.write_bytes(b"second pcap")
        common = (
            "record=kernel-capture protocol=http3 mode=upload "
            "capture_source=linux-af-packet "
            "capture_boundary=loopback-egress-ip "
            "packet_copy_filter=PACKET_OUTGOING "
            "packet_socket=SOCK_DGRAM pcap_link_type=raw-ipv4 pcap_snaplen=128 "
            "pcap_max_bytes=536870912 "
            "payload_retention=prefix "
            "capture_scope=complete-process-pair "
            "benchmark_scope=capture-backed-same-application-shape "
            "timing_usable=false "
            "interface=lo address_family=ipv4 server_ip=127.0.0.1 "
            "client_cpu=0 server_cpu=1 "
            "capture_cpu=2 warmup=1 iterations=1 streams=1 body_bytes=4 "
            "chunk_bytes=4 stream_window=1024 timeout_ms=30000 "
            "capture_receive_buffer_bytes=425984 "
            "quic_version=1 udp_gso=disabled-both netz_gro=false "
            "quic_go_gro=implementation-default ack_policy=implementation-default "
            "pacing=implementation-specific packetization=implementation-specific "
            "cipher=negotiated-unexposed "
            "quic_go_version=0.59.0 "
            "socket_drops=0 "
            "capture_tool_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
            "packet_size_sequence_sha256=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee "
            "client_to_server_size_sequence_sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff "
            "server_to_client_size_sequence_sha256=1111111111111111111111111111111111111111111111111111111111111111 "
            "quic_go_mod_sha256=2222222222222222222222222222222222222222222222222222222222222222 "
            "quic_go_sum_sha256=3333333333333333333333333333333333333333333333333333333333333333 "
            "client_to_server_datagrams=3 "
            "client_to_server_udp_payload_bytes=30 client_to_server_ip_bytes=114 "
            "server_to_client_datagrams=2 "
            "server_to_client_udp_payload_bytes=20 server_to_client_ip_bytes=76 "
            "total_datagrams=5 total_udp_payload_bytes=50 total_ip_bytes=190 "
            "socket_packets_seen=5 "
            "complete=true"
        )
        netz_hash = "b" * 64
        go_hash = "c" * 64
        first.write_text(
            f"role_pair=netz-client+quic-go-server server_port=4433 {common} "
            f"pcap_sha256={hashlib.sha256(first_pcap.read_bytes()).hexdigest()} "
            f"client_binary_sha256={netz_hash} server_binary_sha256={go_hash}\n"
        )
        second.write_text(
            f"role_pair=quic-go-client+netz-server server_port=4434 {common} "
            f"pcap_sha256={hashlib.sha256(second_pcap.read_bytes()).hexdigest()} "
            f"client_binary_sha256={go_hash} server_binary_sha256={netz_hash}\n"
        )
        return argparse.Namespace(
            mode="upload", warmup=1, iterations=1, streams=1, body_bytes=4,
            chunk_bytes=4, stream_window=1024, timeout_ms=30000,
            quic_version=1, client_cpu=0, server_cpu=1, capture_cpu=2,
            netz_client_capture=first, quic_go_client_capture=second,
            netz_client_pcap=first_pcap, quic_go_client_pcap=second_pcap,
        )

    def output(self, args: argparse.Namespace) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            COMPARE.verify(args)
        return buffer.getvalue()

    def test_equal_capture_shapes_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = self.output(self.fixture(directory))
            self.assertIn("captured_totals_equal=true", output)
            self.assertIn("sender_packet_size_sequence_equal=true", output)
            self.assertIn("timing_usable=false", output)

    def test_different_capture_shapes_are_reported_without_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.quic_go_client_capture.write_text(
                args.quic_go_client_capture.read_text()
                .replace("client_to_server_udp_payload_bytes=30", "client_to_server_udp_payload_bytes=31")
                .replace("total_udp_payload_bytes=50", "total_udp_payload_bytes=51")
                .replace("client_to_server_ip_bytes=114", "client_to_server_ip_bytes=115")
                .replace("total_ip_bytes=190", "total_ip_bytes=191")
            )
            self.assertIn("captured_totals_equal=false", self.output(args))

    def test_equal_totals_can_have_different_packetization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.quic_go_client_capture.write_text(
                args.quic_go_client_capture.read_text().replace(
                    "client_to_server_size_sequence_sha256=" + "f" * 64,
                    "client_to_server_size_sequence_sha256=" + "2" * 64,
                )
            )
            output = self.output(args)
            self.assertIn("captured_totals_equal=true", output)
            self.assertIn("sender_packet_size_sequence_equal=false", output)

    def test_cross_role_binary_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.netz_client_capture.write_text(
                args.netz_client_capture.read_text().replace(
                    "server_binary_sha256=" + "c" * 64,
                    "server_binary_sha256=" + "e" * 64,
                )
            )
            with self.assertRaisesRegex(ValueError, "quic-go binary hashes"):
                COMPARE.verify(args)

    def test_tampered_pcap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.netz_client_pcap.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "PCAP hash"):
                COMPARE.verify(args)

    def test_workload_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.quic_go_client_capture.write_text(
                args.quic_go_client_capture.read_text().replace(
                    "body_bytes=4", "body_bytes=5"
                )
            )
            with self.assertRaisesRegex(ValueError, "body_bytes mismatch"):
                COMPARE.verify(args)

    def test_cpu_overlap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.capture_cpu = 1
            with self.assertRaisesRegex(ValueError, "CPUs must be distinct"):
                COMPARE.verify(args)

    def test_invalid_workload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args.chunk_bytes = 5
            with self.assertRaisesRegex(ValueError, "invalid capture comparison workload"):
                COMPARE.verify(args)


if __name__ == "__main__":
    unittest.main()
