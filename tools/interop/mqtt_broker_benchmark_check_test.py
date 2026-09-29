#!/usr/bin/env python3

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

MODULE = Path(__file__).with_name("mqtt_broker_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("mqtt_broker_benchmark_check", MODULE)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class MqttBrokerBenchmarkCheckTest(unittest.TestCase):
    def record(self, server: str, server_io: str) -> str:
        elapsed = 1_000_000
        return (
            "record=result implementation=netz protocol=mqtt5 transport=tcp "
            f"mode=qos1-fanout role_pair=netz-client+{server}-server "
            f"client_io=zio-std-io server_io={server_io} "
            "benchmark_scope=same-client-workload timing_usable=true "
            "client_tcp_nodelay=true server_tcp_nodelay=true "
            "connection_scope=persistent publishers=2 subscribers=2 "
            "overlapping_subscriptions=1 publisher_window=8 "
            "server_queue_capacity=1024 "
            "session_expiry_seconds=0 warmup=10 publishes=100 deliveries=200 "
            f"payload_bytes=256 elapsed_ns={elapsed} publishes_per_s=100000 "
            "deliveries_per_s=200000 p50_ns=10 p99_ns=20 p999_ns=30 "
            "client_alloc_count=100 client_total_allocated_bytes=10000 "
            "client_peak_live_bytes=5000 "
            "checksum=53900 complete=true\n"
        )

    def verify(self, netz: Path, mosquitto: Path) -> str:
        return CHECK.verify(netz, mosquitto, 2, 2, 10, 100, 256, 8)

    def test_accepts_complete_pair(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "zio-std-io"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop")
            )
            output = self.verify(netz, mosquitto)
            self.assertIn("client_io=zio-std-io", output)

    def test_accepts_broker_rss_pair(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "zio-std-io"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop")
            )
            netz_rss = Path(directory, "netz.rss")
            mosquitto_rss = Path(directory, "mosquitto.rss")
            netz_rss.write_text("4096\n", encoding="ascii")
            mosquitto_rss.write_text("2048\n", encoding="ascii")
            output = CHECK.verify(
                netz, mosquitto, 2, 2, 10, 100, 256, 8,
                netz_rss, mosquitto_rss, "proc-vmrss-sampled-2ms",
            )
            self.assertIn("record=memory implementation=netz", output)
            self.assertIn("process_peak_rss_kib=4096", output)
            self.assertIn("server_io=zio-std-io", output)
            self.assertIn("role_pair=netz-client+netz-server", output)
            self.assertIn(
                "record=memory implementation=mosquitto", output
            )

    def test_rejects_incomplete_broker_rss_pair(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "zio-std-io"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop")
            )
            rss = Path(directory, "netz.rss")
            rss.write_text("4096\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "both broker RSS"):
                CHECK.verify(
                    netz, mosquitto, 2, 2, 10, 100, 256, 8,
                    netz_server_rss=rss,
                )

    def test_rejects_nonpositive_broker_rss(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "zio-std-io"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop")
            )
            netz_rss = Path(directory, "netz.rss")
            mosquitto_rss = Path(directory, "mosquitto.rss")
            netz_rss.write_text("0\n", encoding="ascii")
            mosquitto_rss.write_text("2048\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "non-positive"):
                CHECK.verify(
                    netz, mosquitto, 2, 2, 10, 100, 256, 8,
                    netz_rss, mosquitto_rss,
                )

    def test_rejects_unknown_rss_source(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "zio-std-io"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop")
            )
            netz_rss = Path(directory, "netz.rss")
            mosquitto_rss = Path(directory, "mosquitto.rss")
            netz_rss.write_text("4096\n", encoding="ascii")
            mosquitto_rss.write_text("2048\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "unsupported RSS"):
                CHECK.verify(
                    netz, mosquitto, 2, 2, 10, 100, 256, 8,
                    netz_rss, mosquitto_rss, "untrusted source",
                )

    def test_rejects_wrong_backend(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "threaded"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop")
            )
            with self.assertRaisesRegex(ValueError, "server_io"):
                self.verify(netz, mosquitto)

    def test_rejects_unusable_timing_scope(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(
                self.record("netz", "zio-std-io").replace(
                    "timing_usable=true", "timing_usable=false"
                )
            )
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop")
            )
            with self.assertRaisesRegex(ValueError, "timing_usable"):
                self.verify(netz, mosquitto)

    def test_rejects_mismatched_tcp_nodelay(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "zio-std-io"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop").replace(
                    "server_tcp_nodelay=true",
                    "server_tcp_nodelay=false",
                )
            )
            with self.assertRaisesRegex(ValueError, "server_tcp_nodelay"):
                self.verify(netz, mosquitto)

    def test_rejects_wrong_delivery_count(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "zio-std-io"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop").replace(
                    "deliveries=200", "deliveries=199", 1
                )
            )
            with self.assertRaisesRegex(ValueError, "deliveries"):
                self.verify(netz, mosquitto)

    def test_rejects_mismatched_server_queue_capacity(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "zio-std-io"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop").replace(
                    "server_queue_capacity=1024",
                    "server_queue_capacity=2048",
                )
            )
            with self.assertRaisesRegex(ValueError, "server_queue_capacity"):
                self.verify(netz, mosquitto)

    def test_rejects_bad_derived_rate(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(
                self.record("netz", "zio-std-io").replace(
                    "publishes_per_s=100000", "publishes_per_s=1"
                )
            )
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop")
            )
            with self.assertRaisesRegex(ValueError, "publishes_per_s"):
                self.verify(netz, mosquitto)

    def test_rejects_invalid_allocation_telemetry(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(
                self.record("netz", "zio-std-io").replace(
                    "client_peak_live_bytes=5000",
                    "client_peak_live_bytes=10001",
                )
            )
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop")
            )
            with self.assertRaisesRegex(ValueError, "allocation telemetry"):
                self.verify(netz, mosquitto)

    def test_rejects_checksum_mismatch(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(self.record("netz", "zio-std-io"))
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop").replace(
                    "checksum=53900", "checksum=53901"
                )
            )
            with self.assertRaisesRegex(ValueError, "checksums differ"):
                self.verify(netz, mosquitto)

    def test_rejects_identically_wrong_checksums(self) -> None:
        with TemporaryDirectory() as directory:
            netz = Path(directory, "netz.log")
            mosquitto = Path(directory, "mosquitto.log")
            netz.write_text(
                self.record("netz", "zio-std-io").replace(
                    "checksum=53900", "checksum=1"
                )
            )
            mosquitto.write_text(
                self.record("mosquitto", "mosquitto-event-loop").replace(
                    "checksum=53900", "checksum=1"
                )
            )
            with self.assertRaisesRegex(ValueError, "match the workload"):
                self.verify(netz, mosquitto)


if __name__ == "__main__":
    unittest.main()
