#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("websocket_mostly_idle_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("mostly_idle_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def record(implementation: str, kind: str, *, live: int = 100, peak: int = 120) -> str:
    role = "netz-self" if implementation == "netz" else "websocket-zig-self"
    server_io = "zio-std-io" if implementation == "netz" else "websocket-zig-worker"
    common = (
        f"implementation={implementation} protocol=websocket-h1 transport=tcp "
        f"role_pair={role} client_io=zio-std-io server_io={server_io} "
        "benchmark_scope=mostly-idle-buffer-retention connections=4 "
        "active_connections=2 idle_connections=2 warmup=1 iterations=2 "
        "payload_bytes=4096 payload_schedule=fixed send_shape=contiguous parts=1 "
        "compression=false tcp_nodelay=true "
        "checksum=610 complete=true"
    )
    if kind == "environment":
        return (
            f"record=environment implementation={implementation} samples=1 "
            "schedule=alternating connections=4 active_connections=2 "
            "idle_connections=2 warmup=1 iterations=2 payload_bytes=4096 "
            "payload_schedule=fixed memory_stage=connections-live-after-workload "
            "rss_scope=whole-process-lifetime host=test arch=test kernel=test zig=0.16.0 "
            "netz_build_mode=ReleaseFast "
            "reference_revision=efa879736bd438bea8b86a91f220ba408de57273 "
            f"netz_binary_sha256={'a' * 64} reference_binary_sha256={'b' * 64} "
            "complete=true\n"
        )
    if kind == "run":
        order = 1 if implementation == "netz" else 2
        return (
            f"record=run sample=1 implementation={implementation} "
            f"order={order} complete=true\n"
        )
    if kind == "rss":
        return (
            f"record=rss sample=1 implementation={implementation} "
            "process_scope=client+server rss_scope=whole-process-lifetime "
            "rss_source=gnu-time-maxrss "
            "process_peak_rss_kib=1000 complete=true\n"
        )
    if kind == "result":
        return f"record=result {common} connection_scope=persistent logical_bytes=32768 elapsed_ns=10\n"
    return (
        f"record=memory {common} process_scope=client+server "
        "memory_stage=connections-live-after-workload "
        "allocator_scope=explicit-library-and-harness alloc_count=4 free_count=2 "
        f"resize_count=0 remap_count=0 total_allocated_bytes={live + 20} "
        f"total_freed_bytes=20 live_bytes={live} peak_live_bytes={peak}\n"
    )


class VerifyTests(unittest.TestCase):
    @staticmethod
    def complete_log(implementation: str, *, live: int = 100, peak: int = 120) -> str:
        return (
            record(implementation, "environment")
            + record(implementation, "run")
            + record(implementation, "result")
            + record(implementation, "memory", live=live, peak=peak)
            + record(implementation, "rss")
        )

    def run_case(self, netz: str, reference: str) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            netz_path = root / "netz.log"
            reference_path = root / "reference.log"
            netz_path.write_text(netz, encoding="utf-8")
            reference_path.write_text(reference, encoding="utf-8")
            CHECK.verify(netz_path, reference_path, 1, 4, 2, 1, 2)

    def test_accepts_complete_matched_pair(self) -> None:
        self.run_case(
            self.complete_log("netz"),
            self.complete_log("websocket-zig", live=200, peak=220),
        )

    def test_rejects_wrong_active_count(self) -> None:
        netz = self.complete_log("netz")
        reference = self.complete_log("websocket-zig").replace(
            "active_connections=2", "active_connections=1", 1
        )
        with self.assertRaisesRegex(ValueError, "active_connections"):
            self.run_case(netz, reference)

    def test_rejects_post_close_memory_stage(self) -> None:
        netz = self.complete_log("netz")
        reference = self.complete_log("websocket-zig").replace(
            "connections-live-after-workload", "after-close", 1
        )
        with self.assertRaisesRegex(ValueError, "memory_stage"):
            self.run_case(netz, reference)

    def test_rejects_inconsistent_memory_totals(self) -> None:
        netz = self.complete_log("netz").replace(
            "total_freed_bytes=20", "total_freed_bytes=19"
        )
        reference = self.complete_log("websocket-zig")
        with self.assertRaisesRegex(ValueError, "inconsistent memory totals"):
            self.run_case(netz, reference)

    def test_rejects_mismatched_binary_identity(self) -> None:
        netz = self.complete_log("netz")
        reference = self.complete_log("websocket-zig").replace(
            f"netz_binary_sha256={'a' * 64}",
            f"netz_binary_sha256={'c' * 64}",
        )
        with self.assertRaisesRegex(ValueError, "netz_binary_sha256 differs"):
            self.run_case(netz, reference)


if __name__ == "__main__":
    unittest.main()
