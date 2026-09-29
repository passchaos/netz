#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("http2_cancel_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("http2_cancel_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def environment(implementation: str) -> str:
    return (
        f"record=environment implementation={implementation} samples=1 schedule=alternating "
        "warmup=1 iterations=2 stream_window=8192 connection_window=65535 "
        "offered_bytes=131072 canceled_bytes=8192 sibling_bytes=16384 "
        "client_cpu=0 server_cpu=1 host=test arch=test kernel=test zig=0.16.0 "
        "rustc=1.90.0 netz_build_mode=ReleaseFast "
        "hyper_revision=084473f728f9d07b3be5845475aa2f62ed9ff579 "
        f"netz_binary_sha256={'a' * 64} hyper_client_binary_sha256={'b' * 64} "
        f"hyper_server_binary_sha256={'c' * 64} hyper_lock_sha256={'d' * 64} "
        "complete=true\n"
    )


def client_log(implementation: str, *, completed: int = 2, elapsed: int = 100) -> str:
    client_io = "zio-std-io" if implementation == "netz" else "hyper-tokio"
    allocator_scope = "netz-explicit" if implementation == "netz" else "rust-system-requested"
    memory_tail = "resize_count=0 remap_count=0" if implementation == "netz" else "realloc_count=0"
    order = 1 if implementation == "netz" else 2
    return (
        environment(implementation)
        + f"record=run sample=1 implementation={implementation} order={order} complete=true\n"
        + f"record=result implementation={implementation} protocol=http2 transport=h2c "
        f"mode=cancellation-race server_implementation=hyper client_io={client_io} "
        "server_io=hyper-tokio connection_scope=persistent benchmark_scope=same-server-behavior "
        f"warmup=1 iterations=2 stream_window=8192 connection_window=65535 "
        f"offered_bytes=131072 canceled_bytes=8192 sibling_bytes=16384 completed_batches={completed} "
        f"reuse_requests=1 cancellation_observation=server-body-drop-gated-sibling "
        f"sibling_concurrent=true "
        f"elapsed_ns={elapsed} ns_per_batch={elapsed // 2} "
        f"batches_per_s={2_000_000_000 // elapsed} checksum=49152 complete=true\n"
        + f"record=memory implementation={implementation} protocol=http2 transport=h2c "
        f"mode=cancellation-race server_implementation=hyper client_io={client_io} "
        f"server_io=hyper-tokio memory_scope=client-process-through-reuse "
        f"allocator_scope={allocator_scope} alloc_count=10 free_count=5 {memory_tail} "
        "total_allocated_bytes=200 total_freed_bytes=80 live_bytes=120 "
        "peak_live_bytes=160 complete=true\n"
        + f"record=rss sample=1 implementation={implementation} process_scope=client "
        "rss_scope=whole-process-lifetime rss_source=gnu-time-maxrss "
        "process_peak_rss_kib=1000 complete=true\n"
    )


def server_log(*, resets: int = 3) -> str:
    return (
        "record=server-complete implementation=hyper protocol=http2 transport=h2c "
        "mode=cancellation-race server_io=hyper-tokio stream_window=8192 "
        "connection_window=65535 offered_bytes=131072 canceled_bytes=8192 "
        f"sibling_bytes=16384 batches=3 cancellations_observed={resets} "
        "siblings_completed=3 reuse_requests=1 complete=true\n"
    )


class VerifyTests(unittest.TestCase):
    def run_case(self, netz: str, hyper: str, netz_server: str, hyper_server: str) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = [root / name for name in ("netz", "hyper", "netz-server", "hyper-server")]
            for path, value in zip(paths, (netz, hyper, netz_server, hyper_server)):
                path.write_text(value, encoding="utf-8")
            CHECK.verify_pair(paths[0], paths[2], paths[1], paths[3], 1, 1, 2)

    def test_accepts_complete_pair(self) -> None:
        self.run_case(client_log("netz"), client_log("hyper"), server_log(), server_log())

    def test_rejects_missing_server_reset(self) -> None:
        with self.assertRaisesRegex(ValueError, "cancellations_observed mismatch"):
            self.run_case(client_log("netz"), client_log("hyper"), server_log(resets=2), server_log())

    def test_rejects_incomplete_client_batch(self) -> None:
        with self.assertRaisesRegex(ValueError, "completed_batches mismatch"):
            self.run_case(client_log("netz", completed=1), client_log("hyper"), server_log(), server_log())

    def test_rejects_wrong_timing_arithmetic(self) -> None:
        bad = client_log("netz").replace("ns_per_batch=50", "ns_per_batch=51")
        with self.assertRaisesRegex(ValueError, "ns_per_batch mismatch"):
            self.run_case(bad, client_log("hyper"), server_log(), server_log())

    def test_rejects_mismatched_binary_identity(self) -> None:
        hyper = client_log("hyper").replace(
            f"netz_binary_sha256={'a' * 64}",
            f"netz_binary_sha256={'e' * 64}",
        )
        with self.assertRaisesRegex(ValueError, "netz_binary_sha256 differs"):
            self.run_case(client_log("netz"), hyper, server_log(), server_log())

    def test_rejects_shared_client_server_cpu(self) -> None:
        netz = client_log("netz").replace("server_cpu=1", "server_cpu=0")
        with self.assertRaisesRegex(ValueError, "CPUs overlap"):
            self.run_case(netz, client_log("hyper"), server_log(), server_log())


if __name__ == "__main__":
    unittest.main()
