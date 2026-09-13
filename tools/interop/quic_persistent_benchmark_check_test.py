#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("quic_persistent_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("quic_persistent_check", MODULE)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class PersistentBenchmarkCheckTest(unittest.TestCase):
    def write_pair(self, directory: str, *, checksum: int | None = None):
        expected = sum(CHECK.transfer_checksum(256, 4, index) for index in range(4))
        value = expected if checksum is None else checksum
        common = (
            "protocol=quic-stream mode=aggregate direction=upload "
            "role_pair=quic-go-client+netz-server run=1 connections=4 streams=4 "
            "connection_scope=parallel-independent-endpoints "
            "endpoint_topology=one-udp-socket-per-connection "
            "benchmark_scope=same-application-shape bytes_per_stream=256 "
            f"transferred_bytes=4096 checksum={value} sender_role=client "
            "cert_verify=true quic_version=1 gso=false gro=false "
            "completion_exchange_verified=true complete=true"
        )
        client = Path(directory, "client.log")
        server = Path(directory, "server.log")
        client.write_text(
            f"record=result implementation=quic-go result_owner=client {common} "
            "timing_scope=stream-setup-through-verified-completion "
            "elapsed_ns=1000 logical_MiB_s=3906.25\n", encoding="utf-8",
        )
        server.write_text(
            f"record=server-complete implementation=netz endpoint_role=server {common} "
            "warmup=0 iterations=1 payload_bytes=1024 connections_complete=4\n",
            encoding="utf-8",
        )
        return client, server

    def verify(self, client: Path, server: Path) -> None:
        CHECK.verify(
            mode="aggregate", role_pair="quic-go-client+netz-server", run=1,
            connections=4, warmup=0, iterations=1, streams=4,
            bytes_per_stream=256, payload_bytes=1024, sender="client",
            client_log=client, server_log=server,
        )

    def test_accepts_complete_aggregate_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.verify(*self.write_pair(directory))

    def test_rejects_checksum_or_missing_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory, checksum=1)
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.verify(client, server)
            client, server = self.write_pair(directory)
            server.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "one result"):
                self.verify(client, server)

    def test_rejects_duplicate_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text().replace("connections=4", "connections=4 connections=4"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                self.verify(client, server)

    def test_accepts_echo_and_rejects_bad_latency_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checksum = CHECK.echo_checksum(3, 64)
            common = (
                "protocol=quic-stream mode=echo direction=roundtrip "
                "role_pair=netz-client+quic-go-server run=2 "
                "connection_scope=persistent endpoint_topology=independent-udp "
                "benchmark_scope=same-application-shape warmup=1 iterations=2 "
                "connections=1 streams=1 payload_bytes=64 total_bytes=192 "
                f"checksum={checksum} sender_role=client cert_verify=true "
                "quic_version=1 gso=false gro=false completion_exchange_verified=true "
                "complete=true"
            )
            client = Path(directory, "client.log")
            server = Path(directory, "server.log")
            client.write_text(
                f"record=result implementation=netz result_owner=client {common} "
                "measured_bytes=128 total_elapsed_ns=30 mean_ns=15 "
                "min_ns=10 p50_ns=15 p90_ns=20 p99_ns=20 p999_ns=20 max_ns=20\n",
                encoding="utf-8",
            )
            server.write_text(
                f"record=server-complete implementation=quic-go endpoint_role=server {common} "
                "connections_complete=1\n", encoding="utf-8",
            )
            kwargs = dict(
                mode="echo", role_pair="netz-client+quic-go-server", run=2,
                connections=1, warmup=1, iterations=2, streams=1,
                bytes_per_stream=256, payload_bytes=64, sender="client",
                client_log=client, server_log=server,
            )
            CHECK.verify(**kwargs)
            client.write_text(
                client.read_text().replace("p90_ns=20", "p90_ns=9"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "latency ordering"):
                CHECK.verify(**kwargs)

    def test_accepts_shared_server_and_rejects_topology_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            for path in (client, server):
                path.write_text(
                    path.read_text().replace(
                        "role_pair=quic-go-client+netz-server",
                        "role_pair=netz-client+netz-server",
                    ).replace(
                        "implementation=quic-go",
                        "implementation=netz",
                    ).replace(
                        "connection_scope=parallel-independent-endpoints "
                        "endpoint_topology=one-udp-socket-per-connection",
                        "connection_scope=parallel-shared-server-endpoint "
                        "endpoint_topology=shared-server-udp "
                        "server_receive_batch=32 server_receive_calls=4 "
                        "server_receive_events=7 server_receive_max_events=3 "
                        "server_received_datagrams=8 "
                        "server_receive_max_datagrams=4 "
                        "server_connected_events=4 server_packet_events=3 "
                        "server_timer_events=0 "
                        "server_socket_sent_datagrams=4 "
                        "server_socket_sent_bytes=4096 "
                        "server_socket_received_datagrams=8 "
                        "server_socket_received_bytes=8192",
                    ),
                    encoding="utf-8",
                )
            CHECK.verify(
                mode="aggregate", role_pair="netz-client+netz-server",
                run=1, connections=4, warmup=0, iterations=1, streams=4,
                bytes_per_stream=256, payload_bytes=1024, sender="client",
                server_topology="shared", client_log=client, server_log=server,
            )
            server.write_text(
                server.read_text().replace(
                    "server_receive_events=7",
                    "server_receive_events=8",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "event count"):
                CHECK.verify(
                    mode="aggregate", role_pair="netz-client+netz-server",
                    run=1, connections=4, warmup=0, iterations=1, streams=4,
                    bytes_per_stream=256, payload_bytes=1024, sender="client",
                    server_topology="shared", client_log=client,
                    server_log=server,
                )
            server.write_text(
                server.read_text().replace(
                    "server_receive_events=8",
                    "server_receive_events=7",
                ),
                encoding="utf-8",
            )
            server.write_text(
                server.read_text().replace(
                    "server_receive_max_datagrams=4",
                    "server_receive_max_datagrams=40",
                ),
                encoding="utf-8",
            )
            CHECK.verify(
                mode="aggregate", role_pair="netz-client+netz-server",
                run=1, connections=4, warmup=0, iterations=1, streams=4,
                bytes_per_stream=256, payload_bytes=1024, sender="client",
                server_topology="shared", client_log=client, server_log=server,
            )
            for path in (client, server):
                path.write_text(
                    path.read_text().replace(
                        "server_receive_batch=32",
                        "server_receive_batch=31",
                    ),
                    encoding="utf-8",
                )
            with self.assertRaisesRegex(ValueError, "server_receive_batch"):
                CHECK.verify(
                    mode="aggregate", role_pair="netz-client+netz-server",
                    run=1, connections=4, warmup=0, iterations=1, streams=4,
                    bytes_per_stream=256, payload_bytes=1024, sender="client",
                    server_topology="shared", shared_receive_batch=32,
                    client_log=client, server_log=server,
                )
            for path in (client, server):
                path.write_text(
                    path.read_text().replace(
                        "server_receive_batch=31",
                        "server_receive_batch=32",
                    ),
                    encoding="utf-8",
                )
            with self.assertRaisesRegex(
                ValueError,
                "connection_scope mismatch|endpoint_topology mismatch",
            ):
                CHECK.verify(
                    mode="aggregate",
                    role_pair="netz-client+netz-server",
                    run=1,
                    connections=4,
                    warmup=0,
                    iterations=1,
                    streams=4,
                    bytes_per_stream=256,
                    payload_bytes=1024,
                    sender="client",
                    server_topology="independent",
                    client_log=client,
                    server_log=server,
                )


if __name__ == "__main__":
    unittest.main()
