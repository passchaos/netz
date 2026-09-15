#!/usr/bin/env python3

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parent
SOCKET_CHECK = ROOT / "quic_socket_traffic_check.py"
MEMORY_CHECK = ROOT / "quic_memory_telemetry_check.py"


class RawQuicAuxiliaryCheckTest(unittest.TestCase):
    def run_check(self, script: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(script), *args],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_socket_records_require_zio_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = Path(directory, "client.log")
            server = Path(directory, "server.log")
            common = (
                "record=socket-traffic protocol=quic-stream "
                "role_pair=netz-client+netz-server sender_role=client "
                "client_io=zio-std-io server_io=zio-std-io sample=1 streams=1 "
                "traffic_scope=connection socket_boundary=userspace-udp-payload "
                "logical_udp_segments=true complete=true "
            )
            client.write_text(
                f"implementation=netz endpoint_role=client {common}"
                "udp_sent_datagrams=2 udp_sent_payload_bytes=20 "
                "udp_received_datagrams=1 udp_received_payload_bytes=10\n",
                encoding="utf-8",
            )
            server.write_text(
                f"implementation=netz endpoint_role=server {common}"
                "udp_sent_datagrams=1 udp_sent_payload_bytes=10 "
                "udp_received_datagrams=2 udp_received_payload_bytes=20\n",
                encoding="utf-8",
            )
            args = (
                "--role-pair=netz-client+netz-server", "--sender=client",
                "--streams=1", "--iterations=1", str(client), str(server),
            )
            accepted = self.run_check(SOCKET_CHECK, *args)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            client.write_text(
                client.read_text().replace("client_io=zio-std-io", "client_io=threaded"),
                encoding="utf-8",
            )
            rejected = self.run_check(SOCKET_CHECK, *args)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("runtime/role mismatch", rejected.stderr)
            client.write_text(
                client.read_text().replace("sample=1", "sample=1 sample=1"),
                encoding="utf-8",
            )
            duplicate = self.run_check(SOCKET_CHECK, *args)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertIn("duplicate", duplicate.stderr)

    def test_memory_records_require_zio_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = Path(directory, "client.log")
            server = Path(directory, "server.log")
            client_rss = Path(directory, "client.rss")
            server_rss = Path(directory, "server.rss")
            common = (
                "record=memory implementation=netz protocol=quic-stream "
                "role_pair=netz-client+netz-server sender_role=server "
                "client_io=zio-std-io server_io=zio-std-io streams=1 "
                "memory_scope=benchmark-run-after-argument-parse "
                "allocator_scope=netz-explicit alloc_count=1 free_count=1 "
                "resize_count=0 remap_count=0 total_allocated_bytes=64 "
                "live_bytes=0 peak_live_bytes=64 complete=true\n"
            )
            client.write_text(
                common.replace("sender_role=server", "endpoint_role=client sender_role=server"),
                encoding="utf-8",
            )
            server.write_text(
                common.replace("sender_role=server", "endpoint_role=server sender_role=server"),
                encoding="utf-8",
            )
            client_rss.write_text("100\n", encoding="ascii")
            server_rss.write_text("101\n", encoding="ascii")
            args = (
                "--role-pair=netz-client+netz-server", "--sender=server",
                "--streams=1", "--rss-source=busybox-time-maxrss",
                f"--client-log={client}",
                f"--server-log={server}", f"--client-rss={client_rss}",
                f"--server-rss={server_rss}",
            )
            accepted = self.run_check(MEMORY_CHECK, *args)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout.count("record=memory"), 2)
            self.assertIn("rss_source=busybox-time-maxrss", accepted.stdout)
            server.write_text(
                server.read_text().replace("server_io=zio-std-io", "server_io=threaded"),
                encoding="utf-8",
            )
            rejected = self.run_check(MEMORY_CHECK, *args)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("memory record mismatch", rejected.stderr)

    def test_http3_memory_schema_remains_backend_neutral(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = Path(directory, "client.log")
            server = Path(directory, "server.log")
            client_rss = Path(directory, "client.rss")
            server_rss = Path(directory, "server.rss")
            common = (
                "record=memory protocol=http3 mode=upload "
                "role_pair=netz-client+quic-go-server sender_role=client "
                "client_io=zio-std-io server_io=quic-go-netpoll "
                "streams=1 body_bytes=1024 warmup=1 iterations=1 quic_version=1 "
                "memory_scope=benchmark-run-after-argument-parse complete=true "
            )
            client.write_text(
                f"implementation=netz endpoint_role=client {common}"
                "allocator_scope=netz-explicit alloc_count=1 free_count=1 "
                "total_allocated_bytes=64 live_bytes=0 peak_live_bytes=64\n",
                encoding="utf-8",
            )
            server.write_text(
                f"implementation=quic-go endpoint_role=server {common}"
                "allocator_scope=go-runtime-heap alloc_count=1 free_count=0 "
                "total_allocated_bytes=64 heap_alloc_bytes_end=64 "
                "heap_sys_bytes_end=128 runtime_sys_bytes_end=256 gc_cycles=0\n",
                encoding="utf-8",
            )
            client_rss.write_text("100\n", encoding="ascii")
            server_rss.write_text("101\n", encoding="ascii")
            accepted = self.run_check(
                MEMORY_CHECK, "--protocol=http3",
                "--role-pair=netz-client+quic-go-server", "--sender=client",
                "--streams=1", "--mode=upload", "--body-bytes=1024",
                "--warmup=1", "--iterations=1", "--quic-version=1",
                f"--client-log={client}", f"--server-log={server}",
                f"--client-rss={client_rss}", f"--server-rss={server_rss}",
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn("client_io=zio-std-io", accepted.stdout)


if __name__ == "__main__":
    unittest.main()
