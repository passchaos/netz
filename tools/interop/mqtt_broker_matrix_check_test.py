#!/usr/bin/env python3

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


MODULE = Path(__file__).with_name("mqtt_broker_matrix_check.py")
SPEC = importlib.util.spec_from_file_location("mqtt_broker_matrix_check", MODULE)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class MqttBrokerMatrixCheckTest(unittest.TestCase):
    def make_matrix(
        self,
        root: Path,
        qos: int = 1,
        session_expiry_seconds: int = 0,
    ) -> None:
        identity = root / "identity"
        identity.mkdir(parents=True)
        for name in CHECK.IDENTITY_FILES - {"mosquitto-head.txt"}:
            (identity / name).write_bytes(f"artifact:{name}\n".encode())
        revision = CHECK.MOSQUITTO_REVISION
        (identity / "mosquitto-head.txt").write_text(
            revision + "\n", encoding="ascii"
        )
        (identity / "mosquitto-source-state.txt").write_text(
            f"revision={revision} source_clean=true\n", encoding="ascii"
        )
        hashes = {
            "netz_broker_sha256": CHECK.sha256(identity / "netz-broker"),
            "driver_sha256": CHECK.sha256(identity / "mqtt-driver"),
            "mosquitto_binary_sha256": CHECK.sha256(identity / "mosquitto"),
            "single_runner_sha256": CHECK.sha256(identity / "compare_mqtt_mosquitto.sh"),
            "matrix_runner_sha256": CHECK.sha256(identity / "mqtt_broker_matrix.sh"),
            "single_checker_sha256": CHECK.sha256(identity / "mqtt_broker_benchmark_check.py"),
            "config_helper_sha256": CHECK.sha256(identity / "mqtt_broker_benchmark_config.py"),
            "matrix_checker_sha256": CHECK.sha256(identity / "mqtt_broker_matrix_check.py"),
            "mosquitto_build_helper_sha256": CHECK.sha256(identity / "mosquitto_build.sh"),
            "mosquitto_configure_log_sha256": CHECK.sha256(identity / "mosquitto-configure.log"),
            "mosquitto_build_log_sha256": CHECK.sha256(identity / "mosquitto-build.log"),
            "mosquitto_source_state_sha256": CHECK.sha256(identity / "mosquitto-source-state.txt"),
        }
        (root / "environment.log").write_text(
            "record=environment protocol=mqtt5 transport=tcp "
            f"mode=qos{qos}-fanout-matrix benchmark_scope=same-client-workload "
            "timing_usable=true client_tcp_nodelay=true "
            "server_tcp_nodelay=true "
            f"session_expiry_seconds={session_expiry_seconds} "
            "shapes=5 samples=4 schedule=abba "
            "client_cpu=0 server_cpu=1 sampler_cpu=2 "
            "rss_source=proc-vmrss-sampled-2ms max_artifact_bytes=33554432 "
            "max_matrix_bytes=134217728 host=test arch=aarch64 "
            "kernel=test zig=0.16.0 netz_build_mode=ReleaseFast "
            f"mosquitto_revision={revision} mosquitto_source_clean=true "
            + " ".join(f"{key}={value}" for key, value in hashes.items())
            + " complete=true\n",
            encoding="utf-8",
        )
        (root / "summary.log").write_text("pending\n", encoding="utf-8")
        for shape in CHECK.SHAPES:
            queue = max(1_024, shape.warmup, shape.messages)
            checksum = (
                (shape.warmup + shape.messages)
                * shape.subscribers
                * (3 + ((shape.payload_bytes - 1) * 17 + 3 & 0xFF))
            ) & ((1 << 64) - 1)
            for sample in range(1, 5):
                run = root / shape.name / f"sample-{sample:02d}"
                artifacts = run / "artifacts"
                artifacts.mkdir(parents=True)
                (run / "runner.log").write_text(
                    "record=run-order protocol=mqtt5 transport=tcp "
                    f"mode=qos{qos}-fanout benchmark_scope=same-client-workload "
                    "timing_usable=true client_tcp_nodelay=true "
                    "server_tcp_nodelay=true "
                    f"session_expiry_seconds={session_expiry_seconds} "
                    f"broker_order={CHECK.expected_order(sample)} "
                    "client_cpu=0 server_cpu=1 sampler_cpu=2 complete=true\n"
                    "record=verified protocol=mqtt5 transport=tcp "
                    f"mode=qos{qos}-fanout benchmark_scope=same-client-workload "
                    "timing_usable=true client_tcp_nodelay=true "
                    "server_tcp_nodelay=true "
                    f"publishers={shape.publishers} "
                    f"subscribers={shape.subscribers} warmup={shape.warmup} "
                    f"publishes={shape.messages} "
                    f"deliveries={shape.messages * shape.subscribers} "
                    f"payload_bytes={shape.payload_bytes} "
                    f"publisher_window={shape.window} "
                    f"server_queue_capacity={queue} "
                    f"session_expiry_seconds={session_expiry_seconds} "
                    f"checksum={checksum} "
                    "client_io=zio-std-io "
                    "server_io=zio-std-io+mosquitto-event-loop complete=true\n",
                    encoding="utf-8",
                )
                for server, server_io, rate, rss in (
                    ("netz", "zio-std-io", 200_000 + sample, 6_000 + sample),
                    ("mosquitto", "mosquitto-event-loop", 100_000 + sample, 4_000 + sample),
                ):
                    elapsed = shape.messages * 1_000_000_000 // rate
                    actual_rate = shape.messages * 1_000_000_000 // elapsed
                    deliveries_rate = (
                        shape.messages * shape.subscribers * 1_000_000_000
                        // elapsed
                    )
                    (artifacts / f"{server}-result.txt").write_text(
                        "record=result implementation=netz protocol=mqtt5 "
                        f"transport=tcp mode=qos{qos}-fanout "
                        f"role_pair=netz-client+{server}-server client_io=zio-std-io "
                        f"server_io={server_io} benchmark_scope=same-client-workload "
                        "timing_usable=true client_tcp_nodelay=true "
                        "server_tcp_nodelay=true connection_scope=persistent "
                        f"publishers={shape.publishers} subscribers={shape.subscribers} "
                        "overlapping_subscriptions=1 "
                        f"publisher_window={shape.window} server_queue_capacity={queue} "
                        f"session_expiry_seconds={session_expiry_seconds} "
                        f"warmup={shape.warmup} "
                        f"publishes={shape.messages} "
                        f"deliveries={shape.messages * shape.subscribers} "
                        f"payload_bytes={shape.payload_bytes} elapsed_ns={elapsed} "
                        f"publishes_per_s={actual_rate} deliveries_per_s={deliveries_rate} "
                        "p50_ns=100 p99_ns=200 p999_ns=300 "
                        "client_alloc_count=10 client_total_allocated_bytes=1000 "
                        f"client_peak_live_bytes=500 checksum={checksum} complete=true\n",
                        encoding="utf-8",
                    )
                    (artifacts / f"{server}-server.rss").write_text(
                        f"{rss}\n", encoding="ascii"
                    )
                (artifacts / "netz-server.log").write_text(
                    "netz MQTT 3.1/3.1.1/5 broker listening server_io=zio-std-io\n",
                    encoding="utf-8",
                )
                (artifacts / "mosquitto-server.log").write_text(
                    "mosquitto version 2.1.0 running\n", encoding="utf-8"
                )
                (artifacts / "mosquitto.conf").write_text(
                    "listener 1883 127.0.0.1\nallow_anonymous true\n"
                    "persistence false\nmax_inflight_messages 64\n"
                    f"max_queued_messages {queue}\nset_tcp_nodelay true\n"
                    "log_dest stdout\n",
                    encoding="utf-8",
                )

    def verify(
        self,
        root: Path,
        qos: int = 1,
        session_expiry_seconds: int = 0,
    ) -> list[str]:
        return CHECK.verify(
            root,
            4,
            0,
            1,
            2,
            qos,
            session_expiry_seconds,
        )

    def test_accepts_complete_matrix(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            output = self.verify(root)
            self.assertEqual(len(output), len(CHECK.SHAPES) + 2)
            self.assertIn("broker_runs=40", output[-1])
            self.assertIn("shape=balanced-32x32", output[-3])
            self.assertIn("netz_min_publishes_per_s=200001", output[1])

    def test_accepts_complete_qos2_matrix(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root, qos=2)
            output = self.verify(root, qos=2)
            self.assertIn("mode=qos2-fanout-matrix", output[0])
            self.assertIn("mode=qos2-fanout", output[1])

    def test_accepts_persistent_session_matrix(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root, qos=2, session_expiry_seconds=3600)
            output = self.verify(
                root,
                qos=2,
                session_expiry_seconds=3600,
            )
            self.assertIn("session_expiry_seconds=3600", output[0])
            self.assertIn("session_expiry_seconds=3600", output[1])

    def test_rejects_missing_shape(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            (root / CHECK.SHAPES[0].name).rename(root / "missing")
            with self.assertRaisesRegex(ValueError, "invalid artifact set"):
                self.verify(root)

    def test_rejects_wrong_abba_order(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            marker = root / CHECK.SHAPES[0].name / "sample-02" / "runner.log"
            marker.write_text(
                marker.read_text().replace("mosquitto-first", "netz-first")
            )
            with self.assertRaisesRegex(ValueError, "broker_order"):
                self.verify(root)

    def test_rejects_tampered_binary(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            (root / "identity" / "mqtt-driver").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ValueError, "driver_sha256"):
                self.verify(root)

    def test_rejects_false_source_state(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            (root / "identity" / "mosquitto-source-state.txt").write_text(
                f"revision={CHECK.MOSQUITTO_REVISION} source_clean=false\n",
                encoding="ascii",
            )
            environment = root / "environment.log"
            old_hash = CHECK.sha256(root / "identity" / "mosquitto-source-state.txt")
            environment.write_text(
                environment.read_text().replace(
                    environment.read_text().split(
                        "mosquitto_source_state_sha256=", 1
                    )[1].split()[0],
                    old_hash,
                    1,
                )
            )
            with self.assertRaisesRegex(ValueError, "source-state"):
                self.verify(root)

    def test_rejects_symlinked_artifact_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            sample = root / CHECK.SHAPES[0].name / "sample-01"
            artifacts = sample / "artifacts"
            moved = root / "moved-artifacts"
            artifacts.rename(moved)
            artifacts.symlink_to(moved, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "real directory|artifact set"):
                self.verify(root)

    def test_rejects_oversized_artifact(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            path = root / "identity" / "mqtt-driver"
            with path.open("r+b") as artifact:
                artifact.truncate(CHECK.MAX_ARTIFACT_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "missing, empty, or non-regular"):
                self.verify(root)

    def test_rejects_bad_single_run_checksum(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            path = root / CHECK.SHAPES[0].name / "sample-01" / "artifacts" / "netz-result.txt"
            path.write_text(path.read_text().replace(" checksum=", " checksum=1 # original=", 1))
            with self.assertRaisesRegex(ValueError, "checksums differ|workload"):
                self.verify(root)

    def test_rejects_extra_artifact(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            path = root / CHECK.SHAPES[0].name / "sample-01" / "artifacts" / "extra"
            path.write_text("unexpected\n")
            with self.assertRaisesRegex(ValueError, "invalid artifact set"):
                self.verify(root)

    def test_rejects_false_runner_verification_record(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_matrix(root)
            path = root / CHECK.SHAPES[0].name / "sample-01" / "runner.log"
            path.write_text(path.read_text().replace("checksum=", "checksum=1 original=", 1))
            with self.assertRaisesRegex(ValueError, "verification record differs"):
                self.verify(root)


if __name__ == "__main__":
    unittest.main()
