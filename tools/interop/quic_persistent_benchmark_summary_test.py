#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("quic_persistent_benchmark_summary.py")
SPEC = importlib.util.spec_from_file_location("quic_persistent_summary", MODULE)
assert SPEC is not None and SPEC.loader is not None
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class PersistentBenchmarkSummaryTest(unittest.TestCase):
    def test_echo_summary_requires_every_role_pair_and_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "results.log")
            lines = []
            values = {
                "netz-client+quic-go-server": (10, 12, 11),
                "quic-go-client+quic-go-server": (20, 22, 21),
                "quic-go-client+netz-server": (18, 19, 20),
                "netz-client+netz-server": (9, 8, 10),
            }
            for pair, samples in values.items():
                for run, value in enumerate(samples, 1):
                    lines.append(
                        "record=result protocol=quic-stream mode=echo "
                        f"role_pair={pair} sender_role=client result_owner=client "
                        f"implementation={'netz' if pair.startswith('netz-client') else 'quic-go'} "
                        f"client_io={'zio-std-io' if pair.startswith('netz-client') else 'quic-go-netpoll'} "
                        f"server_io={'zio-std-io' if pair.endswith('netz-server') else 'quic-go-netpoll'} "
                        f"run={run} warmup=1 iterations=2 connections=1 streams=1 "
                        f"payload_bytes=64 p50_ns={value} p99_ns={value + 10} "
                        f"p999_ns={value + 20} benchmark_scope=same-application-shape "
                        "completion_exchange_verified=true complete=true"
                    )
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            output = SUMMARY.summarize(path, "echo", 3)
            self.assertEqual(len(output), 6)
            self.assertIn("netz_speedup=1.909", output[-2])
            path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "expected 3"):
                SUMMARY.summarize(path, "echo", 3)

    def test_aggregate_summary_preserves_mib_units(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "results.log")
            lines = []
            values = {
                ("netz-client+quic-go-server", "client"): 150.0,
                ("netz-client+quic-go-server", "server"): 90.0,
                ("quic-go-client+quic-go-server", "client"): 100.0,
                ("quic-go-client+quic-go-server", "server"): 100.0,
                ("quic-go-client+netz-server", "client"): 80.0,
                ("quic-go-client+netz-server", "server"): 140.0,
                ("netz-client+netz-server", "client"): 120.0,
                ("netz-client+netz-server", "server"): 110.0,
            }
            for (pair, sender), value in values.items():
                lines.append(
                    "record=result protocol=quic-stream mode=aggregate "
                    f"role_pair={pair} sender_role={sender} result_owner=client "
                    f"implementation={'netz' if (sender == 'client' and pair.startswith('netz-client')) or (sender == 'server' and pair.endswith('netz-server')) else 'quic-go'} "
                    f"client_io={'zio-std-io' if pair.startswith('netz-client') else 'quic-go-netpoll'} "
                    f"server_io={'zio-std-io' if pair.endswith('netz-server') else 'quic-go-netpoll'} "
                    "run=1 connections=4 streams=1 bytes_per_stream=1024 "
                    "timing_scope=stream-setup-through-verified-completion "
                    "endpoint_topology=one-udp-socket-per-connection "
                    f"elapsed_ns=1000 logical_MiB_s={value:.3f} "
                    "benchmark_scope=same-application-shape "
                    "completion_exchange_verified=true complete=true"
                )
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            output = SUMMARY.summarize(path, "aggregate", 1)
            self.assertEqual(len(output), 12)
            self.assertIn("median_logical_MiB_s_netz=150.000", output[-4])
            self.assertIn("netz_speedup=1.500", output[-4])

    def test_shared_summary_separates_endpoint_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "results.log")
            lines = []
            for pair, value in (("netz-client+netz-server", 120.0),):
                for sender in ("client", "server"):
                    for run in range(1, 4):
                        lines.append(
                            "record=result protocol=quic-stream mode=aggregate "
                            f"direction={'upload' if sender == 'client' else 'download'} "
                            f"role_pair={pair} sender_role={sender} result_owner=client "
                            f"implementation={'netz' if pair.startswith('netz-client') else 'quic-go'} "
                            "client_io=zio-std-io server_io=zio-std-io "
                            f"run={run} connections=4 streams=1 bytes_per_stream=1024 "
                            "timing_scope=stream-setup-through-verified-completion "
                            f"elapsed_ns=1000 logical_MiB_s={value:.3f} "
                            "connection_scope=parallel-shared-server-endpoint "
                            "endpoint_topology=shared-server-udp "
                            "server_receive_batch=32 server_ack_every=2 "
                            "server_ack_delay_us=25000 "
                            "benchmark_scope=same-application-shape "
                            "completion_exchange_verified=true complete=true"
                        )
            lines.append(lines[0].replace(
                "endpoint_topology=shared-server-udp",
                "endpoint_topology=one-udp-socket-per-connection",
            ))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            output = SUMMARY.summarize(path, "aggregate", 3, "shared", 32)
            self.assertEqual(len(output), 2)
            self.assertIn("median_logical_MiB_s=120.000", output[0])
            self.assertIn("sender_role=client", output[0])
            self.assertIn("sender_role=server", output[1])
            self.assertIn("server_receive_batch=32", output[0])
            self.assertIn("server_ack_every=2", output[0])
            self.assertIn("server_ack_delay_us=25000", output[0])
            path.write_text(
                path.read_text().replace(
                    "server_ack_every=2", "server_ack_every=1", 1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "mixed|policy mismatch"):
                SUMMARY.summarize(path, "aggregate", 3, "shared", 32, 1, 0)
            path.write_text(
                path.read_text().replace(
                    "server_ack_every=1", "server_ack_every=2", 1,
                ),
                encoding="utf-8",
            )
            path.write_text(
                path.read_text().replace(
                    "server_receive_batch=32",
                    "server_receive_batch=31",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "mixed|batch mismatch"):
                SUMMARY.summarize(path, "aggregate", 3, "shared", 32)

    def test_netz_only_independent_summary_needs_no_go_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "results.log")
            lines = []
            for sender, values in (
                ("client", (90.0, 100.0, 95.0)),
                ("server", (80.0, 85.0, 82.0)),
            ):
                for run, value in enumerate(values, 1):
                    lines.append(
                        "record=result implementation=netz protocol=quic-stream "
                        "mode=aggregate role_pair=netz-client+netz-server "
                        "client_io=zio-std-io server_io=zio-std-io "
                        f"sender_role={sender} result_owner=client run={run} "
                        "connections=4 streams=1 bytes_per_stream=1024 "
                        "timing_scope=stream-setup-through-verified-completion "
                        "endpoint_topology=one-udp-socket-per-connection "
                        f"elapsed_ns=1000 logical_MiB_s={value:.3f} "
                        "benchmark_scope=same-application-shape "
                        "completion_exchange_verified=true complete=true"
                    )
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            output = SUMMARY.summarize(
                path, "aggregate", 3, netz_only=True,
            )
            self.assertEqual(len(output), 2)
            self.assertIn("median_logical_MiB_s=95.000", output[0])
            self.assertIn("median_logical_MiB_s=82.000", output[1])

    def test_rejects_mixed_or_legacy_io_backend_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "results.log")
            lines = []
            for sender in ("client", "server"):
                lines.append(
                    "record=result implementation=netz protocol=quic-stream "
                    "mode=aggregate role_pair=netz-client+netz-server "
                    f"sender_role={sender} result_owner=client run=1 "
                    "client_io=zio-std-io server_io=zio-std-io "
                    "connections=4 streams=1 bytes_per_stream=1024 "
                    "timing_scope=stream-setup-through-verified-completion "
                    "endpoint_topology=one-udp-socket-per-connection "
                    "elapsed_ns=1000 logical_MiB_s=100.000 "
                    "benchmark_scope=same-application-shape "
                    "completion_exchange_verified=true complete=true"
                )
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            output = SUMMARY.summarize(
                path, "aggregate", 1, netz_only=True,
            )
            self.assertIn("client_io=zio-std-io", output[0])
            path.write_text(
                path.read_text().replace(" client_io=zio-std-io", "", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "identity or proof"):
                SUMMARY.summarize(path, "aggregate", 1, netz_only=True)

    def test_topology_comparison_requires_both_verified_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "results.log")
            lines = []
            values = {
                ("independent", "client"): (80.0, 100.0, 90.0),
                ("independent", "server"): (100.0, 120.0, 110.0),
                ("shared", "client"): (72.0, 90.0, 81.0),
                ("shared", "server"): (75.0, 99.0, 88.0),
            }
            for (topology, sender), samples in values.items():
                shared = topology == "shared"
                for run, value in enumerate(samples, 1):
                    lines.append(
                        "record=result implementation=netz protocol=quic-stream "
                        "mode=aggregate role_pair=netz-client+netz-server "
                        f"sender_role={sender} result_owner=client run={run} "
                        "client_io=zio-std-io server_io=zio-std-io "
                        "connections=4 streams=1 bytes_per_stream=1024 "
                        "timing_scope=stream-setup-through-verified-completion "
                        f"endpoint_topology={'shared-server-udp' if shared else 'one-udp-socket-per-connection'} "
                        + (
                            "server_receive_batch=32 server_ack_every=2 "
                            "server_ack_delay_us=25000 "
                            if shared else ""
                        )
                        + f"elapsed_ns=1000 logical_MiB_s={value:.3f} "
                        "benchmark_scope=same-application-shape "
                        "completion_exchange_verified=true complete=true"
                    )
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            output = SUMMARY.compare_topologies(path, 3, 32, 2, 25000)
            self.assertEqual(len(output), 6)
            self.assertIn("sender_role=client", output[-2])
            self.assertIn("shared_over_independent=0.900", output[-2])
            self.assertIn("sender_role=server", output[-1])
            self.assertIn("shared_over_independent=0.800", output[-1])
            self.assertIn("server_ack_every=2", output[-1])

            path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "expected 3"):
                SUMMARY.compare_topologies(path, 3, 32, 2, 25000)
            with self.assertRaisesRegex(ValueError, "identical ACK policy"):
                SUMMARY.compare_topologies(path, 3, 32, 4, 25000)


if __name__ == "__main__":
    unittest.main()
