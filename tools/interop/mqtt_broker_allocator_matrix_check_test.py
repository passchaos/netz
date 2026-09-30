#!/usr/bin/env python3

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


MODULE = Path(__file__).with_name("mqtt_broker_allocator_matrix_check.py")
SPEC = importlib.util.spec_from_file_location(
    "mqtt_broker_allocator_matrix_check", MODULE
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class MqttBrokerAllocatorMatrixCheckTest(unittest.TestCase):
    def make_matrix(
        self,
        root: Path,
        qos: int = 1,
        session_expiry_seconds: int = 0,
    ) -> None:
        identity = root / "identity"
        identity.mkdir(parents=True)
        for name in CHECK.IDENTITY_FILES:
            (identity / name).write_bytes(f"artifact:{name}\n".encode())
        hashes = {
            "netz_broker_sha256": CHECK.sha256(identity / "netz-broker"),
            "driver_sha256": CHECK.sha256(identity / "mqtt-driver"),
            "runner_sha256": CHECK.sha256(
                identity / "mqtt_broker_allocator_matrix.sh"
            ),
            "checker_sha256": CHECK.sha256(
                identity / "mqtt_broker_allocator_matrix_check.py"
            ),
        }
        (root / "environment.log").write_text(
            "record=environment protocol=mqtt5 transport=tcp "
            f"mode=qos{qos}-fanout-allocator-matrix "
            "benchmark_scope=same-client-workload timing_usable=false "
            "allocator_scope=broker-explicit connection_scope=persistent "
            "client_tcp_nodelay=true server_tcp_nodelay=true "
            f"session_expiry_seconds={session_expiry_seconds} "
            "shapes=5 samples=2 "
            "schedule=sequential client_cpu=0 server_cpu=1 "
            "timeout_seconds=60 "
            "max_artifact_bytes=33554432 max_matrix_bytes=134217728 "
            "host=test arch=aarch64 kernel=test zig=0.16.0 "
            "netz_build_mode=ReleaseFast "
            + " ".join(f"{key}={value}" for key, value in hashes.items())
            + " complete=true\n",
            encoding="utf-8",
        )
        (root / "summary.log").write_text("pending\n", encoding="utf-8")
        for shape in CHECK.SHAPES:
            queue = max(1_024, shape.warmup, shape.messages)
            for sample in range(1, 3):
                run = root / shape.name / f"sample-{sample:02d}"
                run.mkdir(parents=True)
                alloc_count = shape.messages + sample
                allocated = shape.messages * shape.payload_bytes + sample
                (run / "server.log").write_text(
                    "netz MQTT 3.1.1/5 broker listening server_io=zio-std-io\n"
                    "record=allocator implementation=netz endpoint_role=server "
                    f"protocol=mqtt5 transport=tcp mode=qos{qos}-fanout "
                    "timing_usable=false allocator_scope=broker-explicit "
                    "connection_scope=persistent client_tcp_nodelay=true "
                    "server_tcp_nodelay=true "
                    f"session_expiry_seconds={session_expiry_seconds} "
                    f"configured_connections={shape.publishers + shape.subscribers} "
                    f"alloc_count={alloc_count} free_count={alloc_count} "
                    "resize_count=1 remap_count=2 "
                    f"total_allocated_bytes={allocated} "
                    f"total_freed_bytes={allocated} live_bytes=0 "
                    f"peak_live_bytes={allocated // 2} "
                    f"alloc_le_64={alloc_count} alloc_le_256=0 "
                    "alloc_le_1024=0 alloc_le_4096=0 alloc_le_16384=0 "
                    "alloc_le_65536=0 alloc_gt_65536=0 complete=true\n",
                    encoding="utf-8",
                )
                (run / "driver.log").write_text(
                    "record=result implementation=netz protocol=mqtt5 "
                    f"transport=tcp mode=qos{qos}-fanout "
                    "role_pair=netz-client+netz-server client_io=zio-std-io "
                    "server_io=zio-std-io benchmark_scope=same-client-workload "
                    "timing_usable=true client_tcp_nodelay=true "
                    "server_tcp_nodelay=true connection_scope=persistent "
                    f"publishers={shape.publishers} subscribers={shape.subscribers} "
                    f"overlapping_subscriptions=1 publisher_window={shape.window} "
                    f"server_queue_capacity={queue} "
                    f"session_expiry_seconds={session_expiry_seconds} "
                    f"warmup={shape.warmup} publishes={shape.messages} "
                    f"deliveries={shape.messages * shape.subscribers} "
                    f"payload_bytes={shape.payload_bytes} "
                    f"elapsed_ns={shape.messages * 1_000_000_000} "
                    f"publishes_per_s=1 deliveries_per_s={shape.subscribers} "
                    "p50_ns=1 p99_ns=2 "
                    "p999_ns=3 client_alloc_count=1 "
                    "client_total_allocated_bytes=1 client_peak_live_bytes=1 "
                    f"checksum={((shape.warmup + shape.messages) * shape.subscribers * (3 + (((shape.payload_bytes - 1) * 17 + 3) & 0xFF))) & ((1 << 64) - 1)} "
                    "complete=true\n",
                    encoding="utf-8",
                )

    def test_accepts_complete_matrix(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            output = CHECK.verify(root, 2, 0, 1)
            self.assertEqual(len(output), len(CHECK.SHAPES) + 2)
            self.assertIn("broker_runs=10", output[-1])
            self.assertIn("shape=balanced-32x32", output[-3])

    def test_accepts_complete_qos2_matrix(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root, qos=2)
            output = CHECK.verify(root, 2, 0, 1, qos=2)
            self.assertIn("mode=qos2-fanout-allocator-matrix", output[0])
            self.assertIn("mode=qos2-fanout-allocator-matrix", output[1])

    def test_accepts_qos2_persistent_session_matrix(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root, qos=2, session_expiry_seconds=3600)
            output = CHECK.verify(
                root,
                2,
                0,
                1,
                qos=2,
                session_expiry_seconds=3600,
            )
            self.assertIn("mode=qos2-fanout-allocator-matrix", output[0])
            self.assertIn("session_expiry_seconds=3600", output[0])

    def test_rejects_live_bytes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            path = root / "serial" / "sample-01" / "server.log"
            path.write_text(path.read_text().replace("live_bytes=0", "live_bytes=1"))
            with self.assertRaisesRegex(ValueError, "leaked live bytes"):
                CHECK.verify(root, 2, 0, 1)

    def test_rejects_allocator_byte_mismatch(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            path = root / "serial" / "sample-01" / "server.log"
            path.write_text(
                path.read_text().replace("total_freed_bytes=131073", "total_freed_bytes=1")
            )
            with self.assertRaisesRegex(ValueError, "byte accounting differs"):
                CHECK.verify(root, 2, 0, 1)

    def test_rejects_tampered_broker(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            (root / "identity" / "netz-broker").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ValueError, "does not match"):
                CHECK.verify(root, 2, 0, 1)

    def test_rejects_bad_checksum(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            path = root / "fanout-32" / "sample-01" / "driver.log"
            text = path.read_text()
            checksum = text.split("checksum=", 1)[1].split()[0]
            path.write_text(text.replace(f"checksum={checksum}", "checksum=1"))
            with self.assertRaisesRegex(ValueError, "checksum"):
                CHECK.verify(root, 2, 0, 1)

    def test_rejects_bucket_mismatch(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            path = root / "serial" / "sample-01" / "server.log"
            path.write_text(path.read_text().replace("alloc_le_64=513", "alloc_le_64=1"))
            with self.assertRaisesRegex(ValueError, "buckets"):
                CHECK.verify(root, 2, 0, 1)


if __name__ == "__main__":
    unittest.main()
