#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).with_name("http1_hyper_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("http1_hyper_benchmark_check", MODULE)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class Http1HyperBenchmarkCheckTests(unittest.TestCase):
    def make_log(
        self, directory: str, *, workload: str = "pipeline", samples: int = 3
    ) -> Path:
        path = Path(directory, "results.log")
        lines = [
            f"record=environment protocol=http1 workload={workload} samples={samples} "
            "schedule=abba cpu=0 host=test-host arch=test-arch "
            "kernel=test-kernel zig=0.16.0 rustc=1.98.0 "
            "netz_build_mode=ReleaseFast "
            f"hyper_revision={CHECK.HYPER_REVISION} "
            f"netz_binary_sha256={'a' * 64} hyper_binary_sha256={'b' * 64} "
            f"hyper_lock_sha256={'c' * 64} "
            "complete=true"
        ]
        for index, implementation in enumerate(CHECK.expected_order(samples)):
            lines.append(
                f"record=run protocol=http1 workload={workload} "
                f"sample={index // 2 + 1} implementation={implementation} "
                "schedule=abba cpu=0"
            )
            client_io, server_io = CHECK.endpoint_io(implementation, workload)
            base = (
                f"implementation={implementation} protocol=http1 transport=tcp "
                f"workload={workload} benchmark_scope=same-application-shape "
                f"client_io={client_io} server_io={server_io} "
                "connection_scope=persistent "
            )
            elapsed = 32000 if implementation == "netz" else 35200
            if workload == "pipeline":
                config = (
                    "pipeline_depth=16 warmup=1 iterations=2 "
                    "request_wire_bytes=35 response_wire_bytes=89 "
                    "pipeline_flush=true write_strategy="
                    + (
                        "auto"
                        if implementation == "netz"
                        else "hyper-pipeline-flush"
                    )
                )
                result = (
                    f"pipeline_depth=16 warmup=1 iterations=2 requests=32 "
                    f"received_bytes=2848 server_requests=48 elapsed_ns={elapsed} "
                    f"ns_per_request={elapsed // 32} "
                    f"requests_per_s={32 * 1_000_000_000 // elapsed} complete=true"
                )
            else:
                config = (
                    "mode=fixed body_bytes=1024 chunk_bytes=256 "
                    "warmup=1 iterations=2"
                )
                result = (
                    "mode=fixed body_bytes=1024 chunk_bytes=256 warmup=1 iterations=2 "
                    f"measured_body_bytes=4096 server_received_requests=3 "
                    f"elapsed_ns={elapsed} ns_per_roundtrip={elapsed // 2} "
                    f"aggregate_MiB_s={4096 * 1_000_000_000 // (elapsed * 1024 * 1024)} "
                    "complete=true"
                )
            lines.extend(
                (f"record=config {base}{config}", f"record=result {base}{result}")
            )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_pipeline_summary_validates_shape_and_runtimes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = CHECK.summarize(
                self.make_log(directory), "pipeline", 3, 0, 1, 2
            )
            self.assertEqual(len(output), 4)
            self.assertIn("record=environment", output[0])
            self.assertIn("client_io=zio-std-io server_io=zio-std-io", output[1])
            self.assertIn(
                "client_io=rust-std-sync server_io=hyper-tokio", output[2]
            )
            self.assertIn("netz_speedup=1.100", output[3])

    def test_body_summary_validates_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = CHECK.summarize(
                self.make_log(directory, workload="streaming-body"),
                "streaming-body",
                3,
                0,
                1,
                2,
                "fixed",
                1024,
                256,
            )
            self.assertIn("mode=fixed body_bytes=1024 chunk_bytes=256", output[1])

    def test_even_sample_count_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "positive odd"):
                CHECK.summarize(self.make_log(directory), "pipeline", 2, 0, 1, 2)

    def test_wrong_backend_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_log(directory)
            path.write_text(
                path.read_text().replace(
                    "client_io=zio-std-io", "client_io=threaded", 1
                )
            )
            with self.assertRaisesRegex(ValueError, "client_io"):
                CHECK.summarize(path, "pipeline", 3, 0, 1, 2)

    def test_non_abba_order_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_log(directory)
            path.write_text(
                path.read_text().replace(
                    "sample=1 implementation=netz",
                    "sample=1 implementation=hyper",
                    1,
                )
            )
            with self.assertRaisesRegex(ValueError, "expected 'netz'"):
                CHECK.summarize(path, "pipeline", 3, 0, 1, 2)

    def test_missing_lock_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_log(directory)
            path.write_text(
                path.read_text().replace(f"hyper_lock_sha256={'c' * 64} ", "")
            )
            with self.assertRaisesRegex(ValueError, "hyper_lock_sha256"):
                CHECK.summarize(path, "pipeline", 3, 0, 1, 2)

    def test_incomplete_or_bad_arithmetic_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_log(directory)
            path.write_text(
                path.read_text().replace(
                    "received_bytes=2848", "received_bytes=1", 1
                )
            )
            with self.assertRaisesRegex(ValueError, "received_bytes"):
                CHECK.summarize(path, "pipeline", 3, 0, 1, 2)

    def test_duplicate_field_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate field"):
            CHECK.fields("record=result complete=true complete=true")


if __name__ == "__main__":
    unittest.main()
