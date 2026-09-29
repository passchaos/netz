#!/usr/bin/env python3

import importlib.util
import argparse
import contextlib
import io
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("http3_packet_capture.py")
SPEC = importlib.util.spec_from_file_location("http3_packet_capture", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CAPTURE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CAPTURE
SPEC.loader.exec_module(CAPTURE)


def ipv4_udp(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
) -> bytes:
    udp_length = 8 + len(payload)
    total_length = 20 + udp_length
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 7, 0x4000, 64, socket.IPPROTO_UDP, 0,
        socket.inet_aton(source), socket.inet_aton(destination),
    )
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0)
    return ip + udp + payload


class Http3PacketCaptureTests(unittest.TestCase):
    def test_permission_denial_is_fail_closed(self) -> None:
        with mock.patch.object(
            CAPTURE.socket, "socket", side_effect=PermissionError(1, "denied")
        ):
            with self.assertRaisesRegex(RuntimeError, "CAP_NET_RAW"):
                CAPTURE.open_packet_socket("lo")

    def test_capture_rejects_wrong_cpu_affinity(self) -> None:
        args = argparse.Namespace(capture_cpu=2)
        with mock.patch.object(CAPTURE.os, "sched_getaffinity", return_value={0}):
            with self.assertRaisesRegex(RuntimeError, "CPU affinity"):
                CAPTURE.capture(args)

    def test_capture_loop_writes_and_summarizes_outgoing_packet(self) -> None:
        packet = ipv4_udp("127.0.0.1", "127.0.0.1", 40000, 4433, b"data")

        class FakeSocket:
            calls = 0

            def settimeout(self, _timeout: float) -> None:
                pass

            def setblocking(self, _blocking: bool) -> None:
                pass

            def recvfrom(self, _size: int):
                self.calls += 1
                if self.calls == 1:
                    return packet, ("lo", CAPTURE.ETH_P_IP, 0)
                if self.calls == 2:
                    return packet, ("lo", CAPTURE.ETH_P_IP, CAPTURE.PACKET_OUTGOING)
                raise BlockingIOError()

            def getsockopt(self, level: int, option: int, _size: int | None = None):
                if level == socket.SOL_SOCKET and option == socket.SO_RCVBUF:
                    return 425984
                if level == CAPTURE.SOL_PACKET and option == CAPTURE.PACKET_STATISTICS:
                    return struct.pack("=II", 2, 0)
                raise AssertionError((level, option))

            def close(self) -> None:
                pass

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "capture.pcap")
            args = argparse.Namespace(
                interface="lo", output=output, server_ip="127.0.0.1",
                server_port=4433, role_pair="netz-client+quic-go-server",
                mode="upload", client_cpu=0, server_cpu=1, capture_cpu=2,
                warmup=1, iterations=1, streams=1, body_bytes=4, chunk_bytes=4,
                stream_window=1024, timeout_ms=30000, quic_version=1,
                client_binary_sha256="a" * 64, server_binary_sha256="b" * 64,
                quic_go_mod_sha256="c" * 64, quic_go_sum_sha256="d" * 64,
                quic_go_version="0.59.0",
            )
            fake = FakeSocket()

            def install_handler(_signal: int, handler):
                handler(0, None)

            stdout = io.StringIO()
            with (
                mock.patch.object(
                    CAPTURE, "open_packet_socket", return_value=fake
                ),
                mock.patch.object(
                    CAPTURE.signal, "signal", side_effect=install_handler
                ),
                mock.patch.object(CAPTURE.os, "sched_getaffinity", return_value={2}),
                contextlib.redirect_stdout(stdout),
            ):
                self.assertEqual(CAPTURE.capture(args), 0)
            self.assertIn("record=kernel-capture", stdout.getvalue())
            self.assertIn("socket_drops=0", stdout.getvalue())
            totals = CAPTURE.summarize_pcap(output, "127.0.0.1", 4433)
            self.assertEqual(totals.client_to_server_datagrams, 1)
            self.assertEqual(totals.client_to_server_udp_payload_bytes, 4)

    def test_capture_stop_during_receive_drains_without_waiting_for_timeout(self) -> None:
        packet = ipv4_udp("127.0.0.1", "127.0.0.1", 40000, 4433, b"data")
        installed_handler = None

        class FakeSocket:
            calls = 0

            def settimeout(self, _timeout: float) -> None:
                pass

            def setblocking(self, _blocking: bool) -> None:
                pass

            def recvfrom(self, _size: int):
                self.calls += 1
                if self.calls == 1:
                    assert installed_handler is not None
                    installed_handler(0, None)
                    return packet, ("lo", CAPTURE.ETH_P_IP, CAPTURE.PACKET_OUTGOING)
                raise BlockingIOError()

            def getsockopt(self, level: int, option: int, _size: int | None = None):
                if level == socket.SOL_SOCKET and option == socket.SO_RCVBUF:
                    return 425984
                if level == CAPTURE.SOL_PACKET and option == CAPTURE.PACKET_STATISTICS:
                    return struct.pack("=II", 1, 0)
                raise AssertionError((level, option))

            def close(self) -> None:
                pass

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "capture.pcap")
            args = argparse.Namespace(
                interface="lo", output=output, server_ip="127.0.0.1",
                server_port=4433, role_pair="netz-client+quic-go-server",
                mode="upload", client_cpu=0, server_cpu=1, capture_cpu=2,
                warmup=1, iterations=1, streams=1, body_bytes=4, chunk_bytes=4,
                stream_window=1024, timeout_ms=30000, quic_version=1,
                client_binary_sha256="a" * 64, server_binary_sha256="b" * 64,
                quic_go_mod_sha256="c" * 64, quic_go_sum_sha256="d" * 64,
                quic_go_version="0.59.0",
            )

            def install_handler(_signal: int, handler):
                nonlocal installed_handler
                installed_handler = handler

            with (
                mock.patch.object(
                    CAPTURE, "open_packet_socket", return_value=FakeSocket()
                ),
                mock.patch.object(
                    CAPTURE.signal, "signal", side_effect=install_handler
                ),
                mock.patch.object(CAPTURE.os, "sched_getaffinity", return_value={2}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(CAPTURE.capture(args), 0)
            totals = CAPTURE.summarize_pcap(output, "127.0.0.1", 4433)
            self.assertEqual(totals.total_datagrams, 1)

    def test_parses_both_directions_and_ignores_other_ports(self) -> None:
        sent = ipv4_udp("127.0.0.1", "127.0.0.1", 40000, 4433, b"request")
        received = ipv4_udp("127.0.0.1", "127.0.0.1", 4433, 40000, b"response")
        other = ipv4_udp("127.0.0.1", "127.0.0.1", 40001, 4434, b"other")
        self.assertEqual(
            CAPTURE.parse_ipv4_udp(sent, "127.0.0.1", 4433),
            CAPTURE.PacketSummary("client_to_server", 7, len(sent)),
        )
        self.assertEqual(
            CAPTURE.parse_ipv4_udp(received, "127.0.0.1", 4433),
            CAPTURE.PacketSummary("server_to_client", 8, len(received)),
        )
        self.assertIsNone(CAPTURE.parse_ipv4_udp(other, "127.0.0.1", 4433))

    def test_rejects_truncated_fragmented_and_inconsistent_packets(self) -> None:
        packet = bytearray(ipv4_udp("127.0.0.1", "127.0.0.1", 40000, 4433, b"x"))
        self.assertIsNone(
            CAPTURE.parse_ipv4_udp(
                bytes(packet[:24]),
                "127.0.0.1",
                4433,
                original_length=len(packet),
            )
        )
        fragmented = bytearray(packet)
        struct.pack_into("!H", fragmented, 6, 0x2000)
        with self.assertRaisesRegex(CAPTURE.CaptureError, "fragmented"):
            CAPTURE.parse_ipv4_udp(bytes(fragmented), "127.0.0.1", 4433)
        with self.assertRaisesRegex(CAPTURE.CaptureError, "original length"):
            CAPTURE.parse_ipv4_udp(
                bytes(packet), "127.0.0.1", 4433, original_length=len(packet) + 1
            )
        other_loopback = ipv4_udp(
            "127.0.0.2", "127.0.0.1", 40000, 4433, b"x"
        )
        with self.assertRaisesRegex(CAPTURE.CaptureError, "loopback address"):
            CAPTURE.parse_ipv4_udp(other_loopback, "127.0.0.1", 4433)

    def test_bounded_pcap_round_trip_preserves_original_lengths(self) -> None:
        client = ipv4_udp(
            "127.0.0.1", "127.0.0.1", 40000, 4433, bytes(range(256)) * 8
        )
        server = ipv4_udp("127.0.0.1", "127.0.0.1", 4433, 40000, b"ack")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "capture.pcap")
            writer = CAPTURE.PcapWriter(path)
            writer.write(client, len(client), 1_500_000_000)
            writer.write(server, len(server), 2_000_000_000)
            writer.close()
            totals = CAPTURE.summarize_pcap(path, "127.0.0.1", 4433)
            self.assertEqual(totals.client_to_server_datagrams, 1)
            self.assertEqual(totals.client_to_server_udp_payload_bytes, 2048)
            self.assertEqual(totals.client_to_server_ip_bytes, len(client))
            self.assertEqual(totals.server_to_client_datagrams, 1)
            self.assertEqual(totals.server_to_client_udp_payload_bytes, 3)
            self.assertEqual(totals.server_to_client_ip_bytes, len(server))
            self.assertLess(path.stat().st_size, len(client))

    def test_pcap_rejects_packets_outside_selected_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "capture.pcap")
            packet = ipv4_udp("127.0.0.1", "127.0.0.1", 40000, 4434, b"x")
            writer = CAPTURE.PcapWriter(path)
            writer.write(packet, len(packet), 1)
            writer.close()
            with self.assertRaisesRegex(CAPTURE.CaptureError, "outside"):
                CAPTURE.summarize_pcap(path, "127.0.0.1", 4433)

    def test_pcap_rejects_truncated_packet_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "capture.pcap")
            packet = ipv4_udp("127.0.0.1", "127.0.0.1", 40000, 4433, b"x")
            writer = CAPTURE.PcapWriter(path)
            writer.write(packet, len(packet), 1)
            writer.close()
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaisesRegex(CAPTURE.CaptureError, "truncated PCAP packet data"):
                CAPTURE.summarize_pcap(path, "127.0.0.1", 4433)

    def test_pcap_writer_enforces_artifact_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "capture.pcap")
            writer = CAPTURE.PcapWriter(path)
            writer.bytes_written = CAPTURE.PCAP_MAX_BYTES
            with self.assertRaisesRegex(CAPTURE.CaptureError, "artifact bound"):
                writer.write(b"x", 1, 1)
            writer.close()


if __name__ == "__main__":
    unittest.main()
