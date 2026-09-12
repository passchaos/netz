#!/usr/bin/env python3
"""Positive and negative schema tests for WebTransport benchmark output."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


CHECKER = Path(__file__).with_name("webtransport_benchmark_check.py")


class BenchmarkCheckTest(unittest.TestCase):
    role_pair = "netz-client+wtransport-server"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.client_log = self.directory / "client.log"
        self.server_log = self.directory / "server.log"
        self.client_rss = self.directory / "client.rss"
        self.server_rss = self.directory / "server.rss"
        self.client_rss.write_text("4096\n", encoding="ascii")
        self.server_rss.write_text("8192\n", encoding="ascii")

    @staticmethod
    def shape(implementation: str, endpoint_role: str) -> str:
        return (
            f"implementation={implementation} protocol=webtransport transport=h3 "
            "mode=stream-upload direction=upload "
            "role_pair=netz-client+wtransport-server "
            f"endpoint_role={endpoint_role} connection_scope=persistent "
            "warmup=1 iterations=2 streams=2 bytes_per_stream=256 "
            "payload_bytes=32 chunk_bytes=64 stream_window=1024 "
            "timeout_ms=100 netz_ack_every=2 netz_max_ack_delay_us=25000"
        )

    def result(self, sample: int, *, checksum: int = 65_280) -> str:
        return (
            f"record=result {self.shape('netz', 'client')} "
            "benchmark_scope=same-application-shape "
            f"sample={sample} elapsed_ns=1000 logical_MiB_s=488.281 "
            f"sent_bytes=512 received_bytes=512 streams_finished=2 "
            f"checksum={checksum} complete=true"
        )

    def server_complete(self) -> str:
        return (
            f"record=server-complete {self.shape('wtransport', 'server')} "
            "sent_bytes=1024 received_bytes=1024 checksum=130560 "
            "server_complete=true"
        )

    def traffic(
        self,
        implementation: str,
        endpoint_role: str,
        *,
        sent_datagrams: int,
        sent_bytes: int,
        received_datagrams: int,
        received_bytes: int,
    ) -> str:
        source = (
            "netz-socket-counters"
            if implementation == "netz"
            else "quinn-connection-stats"
        )
        return (
            f"record=traffic {self.shape(implementation, endpoint_role)} "
            "traffic_scope=connection socket_boundary=userspace-udp-payload "
            f"traffic_source={source} "
            f"udp_sent_datagrams={sent_datagrams} "
            f"udp_sent_payload_bytes={sent_bytes} "
            f"udp_received_datagrams={received_datagrams} "
            f"udp_received_payload_bytes={received_bytes} "
            "logical_udp_segments=true complete=true"
        )

    def memory(
        self,
        implementation: str,
        endpoint_role: str,
        *,
        live_bytes: int = 0,
    ) -> str:
        if implementation == "netz":
            scope = "benchmark-run-after-argument-parse"
            allocator = "netz-explicit"
            live = f"live_bytes={live_bytes}"
        else:
            scope = "process-start-through-runtime-teardown"
            allocator = "rust-system-requested"
            live = f"live_bytes_end={live_bytes}"
        return (
            f"record=memory {self.shape(implementation, endpoint_role)} "
            f"memory_scope={scope} allocator_scope={allocator} "
            f"alloc_count=10 free_count=10 realloc_count=1 "
            f"total_allocated_bytes=1000 total_freed_bytes=1000 {live} "
            "peak_live_bytes=512 complete=true"
        )

    def write_logs(
        self,
        *,
        traffic: bool = False,
        memory: bool = False,
        client_extra: tuple[str, ...] = (),
        server_extra: tuple[str, ...] = (),
    ) -> None:
        client = [self.result(1), self.result(2)]
        server = [self.server_complete()]
        if traffic:
            client.append(
                self.traffic(
                    "netz", "client", sent_datagrams=100, sent_bytes=10_000,
                    received_datagrams=89, received_bytes=8_900,
                )
            )
            server.append(
                self.traffic(
                    "wtransport", "server", sent_datagrams=90, sent_bytes=9_000,
                    received_datagrams=99, received_bytes=9_900,
                )
            )
        if memory:
            client.append(self.memory("netz", "client"))
            server.append(self.memory("wtransport", "server", live_bytes=2))
        client.extend(client_extra)
        server.extend(server_extra)
        self.client_log.write_text("\n".join(client) + "\n", encoding="utf-8")
        self.server_log.write_text("\n".join(server) + "\n", encoding="utf-8")

    def command(self, *extra: str) -> list[str]:
        return [
            "python3", str(CHECKER),
            f"--role-pair={self.role_pair}",
            "--mode=stream-upload",
            "--warmup=1",
            "--iterations=2",
            "--streams=2",
            "--bytes-per-stream=256",
            "--payload-bytes=32",
            "--chunk-bytes=64",
            "--stream-window=1024",
            "--timeout-ms=100",
            "--netz-ack-every=2",
            "--netz-max-ack-delay-us=25000",
            f"--client-log={self.client_log}",
            f"--server-log={self.server_log}",
            *extra,
        ]

    def run_check(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(*extra),
            check=False,
            text=True,
            capture_output=True,
        )

    def assert_rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(result.stderr, "rejection must explain the schema error")

    def test_accepts_base_traffic_and_memory_schemas(self) -> None:
        self.write_logs(traffic=True, memory=True)
        result = self.run_check(
            "--require-traffic",
            f"--client-rss={self.client_rss}",
            f"--server-rss={self.server_rss}",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("record=traffic-summary", result.stdout)
        self.assertEqual(result.stdout.count("record=memory"), 2)

    def test_rejects_duplicate_result(self) -> None:
        self.write_logs(client_extra=(self.result(2),))
        self.assert_rejected(self.run_check())

    def test_rejects_bad_checksum(self) -> None:
        self.write_logs()
        text = self.client_log.read_text(encoding="utf-8")
        self.client_log.write_text(
            text.replace("checksum=65280", "checksum=65281", 1),
            encoding="utf-8",
        )
        self.assert_rejected(self.run_check())

    def test_rejects_traffic_seen_but_not_sent(self) -> None:
        self.write_logs(traffic=True)
        text = self.server_log.read_text(encoding="utf-8")
        self.server_log.write_text(
            text.replace("udp_received_datagrams=99", "udp_received_datagrams=101"),
            encoding="utf-8",
        )
        self.assert_rejected(self.run_check("--require-traffic"))

    def test_rejects_missing_or_leaking_memory_record(self) -> None:
        self.write_logs(memory=True)
        self.client_log.write_text(
            self.client_log.read_text(encoding="utf-8").replace(
                "live_bytes=0", "live_bytes=1"
            ),
            encoding="utf-8",
        )
        self.assert_rejected(
            self.run_check(
                f"--client-rss={self.client_rss}",
                f"--server-rss={self.server_rss}",
            )
        )

        self.write_logs()
        self.assert_rejected(
            self.run_check(
                f"--client-rss={self.client_rss}",
                f"--server-rss={self.server_rss}",
            )
        )

    def test_rejects_ack_shape_mismatch(self) -> None:
        self.write_logs()
        result = subprocess.run(
            [
                argument.replace("--netz-ack-every=2", "--netz-ack-every=1")
                for argument in self.command()
            ],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assert_rejected(result)


if __name__ == "__main__":
    unittest.main()
