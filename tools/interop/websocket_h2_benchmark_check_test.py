#!/usr/bin/env python3

import importlib.util
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name(
    "websocket_h2_benchmark_check.py"
)
SPEC = importlib.util.spec_from_file_location(
    "websocket_h2_benchmark_check", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class WebSocketH2BenchmarkCheckTests(unittest.TestCase):
    def write_pair(
        self,
        directory: str,
        *,
        role_pair: str = "netz-client+hyper-server",
        checksum: int | None = None,
        with_memory: bool = False,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        implementations = (
            {"client": "netz", "server": "hyper"}
            if role_pair == "netz-client+hyper-server"
            else {"client": "hyper", "server": "netz"}
        )
        endpoint_io = {
            role: "zio-std-io" if implementation == "netz" else "hyper-tokio"
            for role, implementation in implementations.items()
        }
        value = (
            CHECK.expected_checksum(1, 2, 16)
            if checksum is None
            else checksum
        )
        base = (
            "protocol=websocket-h2 transport=h2c mode=binary-echo "
            f"role_pair={role_pair} client_io={endpoint_io['client']} "
            f"server_io={endpoint_io['server']} connection_scope=persistent "
            "warmup=1 iterations=2 payload_bytes=16 timeout_ms=30000"
        )
        config_tail = (
            "benchmark_scope=same-application-shape stream_window=1048576 "
            "connection_window=8388608 max_frame_size=16384 "
            "tcp_nodelay=true compression=false"
        )
        client_lines = [
            f"record=config implementation={implementations['client']} "
            f"endpoint_role=client {base} {config_tail}",
            f"record=result implementation={implementations['client']} "
            f"endpoint_role=client {base} benchmark_scope=same-application-shape "
            "elapsed_ns=2000 ns_per_roundtrip=1000.000 "
            "roundtrips_per_s=1000000.000 logical_MiB_s=30.518 "
            f"sent_bytes=32 received_bytes=32 checksum={value} complete=true",
        ]
        server_lines = [
            f"record=config implementation={implementations['server']} "
            f"endpoint_role=server {base} {config_tail}",
            f"record=server-complete implementation={implementations['server']} "
            f"endpoint_role=server {base} benchmark_scope=same-application-shape "
            f"sent_bytes=32 received_bytes=32 "
            f"checksum={value} server_complete=true",
        ]
        if with_memory:
            for role, lines in (("client", client_lines), ("server", server_lines)):
                implementation = implementations[role]
                if implementation == "netz":
                    detail = (
                        "memory_scope=benchmark-run-after-argument-parse "
                        "allocator_scope=netz-explicit alloc_count=1 free_count=1 "
                        "resize_count=0 remap_count=0 total_allocated_bytes=64 "
                        "live_bytes=0 peak_live_bytes=64"
                    )
                else:
                    detail = (
                        "memory_scope=process-start-through-runtime-teardown "
                        "allocator_scope=rust-system-requested alloc_count=1 free_count=0 "
                        "realloc_count=0 total_allocated_bytes=64 "
                        "total_freed_bytes=0 live_bytes_end=64 peak_live_bytes=64"
                    )
                lines.append(
                    f"record=memory implementation={implementation} "
                    f"endpoint_role={role} {base} {detail} complete=true"
                )
        client = pathlib.Path(directory, "client.log")
        server = pathlib.Path(directory, "server.log")
        client.write_text("\n".join(client_lines) + "\n", encoding="utf-8")
        server.write_text("\n".join(server_lines) + "\n", encoding="utf-8")
        return client, server

    def verify_pair(
        self,
        client: pathlib.Path,
        server: pathlib.Path,
        *,
        role_pair: str = "netz-client+hyper-server",
        rss: bool = False,
    ) -> None:
        kwargs = {}
        if rss:
            client_rss = client.with_suffix(".rss")
            server_rss = server.with_suffix(".rss")
            client_rss.write_text("1024\n", encoding="ascii")
            server_rss.write_text("2048\n", encoding="ascii")
            kwargs = {
                "client_rss": client_rss,
                "server_rss": server_rss,
                "rss_source": "busybox-time-maxrss",
            }
        CHECK.verify(
            role_pair=role_pair,
            warmup=1,
            iterations=2,
            payload_bytes=16,
            timeout_ms=30000,
            client_log=client,
            server_log=server,
            **kwargs,
        )

    def test_complete_both_role_pairs_are_accepted(self) -> None:
        for role_pair in (
            "netz-client+hyper-server",
            "hyper-client+netz-server",
        ):
            with (
                self.subTest(role_pair=role_pair),
                tempfile.TemporaryDirectory() as directory,
            ):
                self.verify_pair(
                    *self.write_pair(directory, role_pair=role_pair),
                    role_pair=role_pair,
                )

    def test_memory_records_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.verify_pair(
                *self.write_pair(directory, with_memory=True),
                rss=True,
            )

    def test_wrong_backend_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text(encoding="utf-8").replace(
                    "client_io=zio-std-io", "client_io=threaded"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "client_io"):
                self.verify_pair(client, server)

    def test_missing_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                "\n".join(
                    line
                    for line in client.read_text(encoding="utf-8").splitlines()
                    if "record=config" not in line
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "client config"):
                self.verify_pair(client, server)

    def test_wrong_timeout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            server.write_text(
                server.read_text(encoding="utf-8").replace(
                    "timeout_ms=30000", "timeout_ms=1", 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "timeout_ms"):
                self.verify_pair(client, server)

    def test_throughput_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text(encoding="utf-8").replace(
                    "logical_MiB_s=30.518", "logical_MiB_s=1"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "logical_MiB_s"):
                self.verify_pair(client, server)

    def test_checksum_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory, checksum=1)
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.verify_pair(client, server)

    def test_duplicate_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, _ = self.write_pair(directory)
            client.write_text(
                client.read_text(encoding="utf-8").replace(
                    "payload_bytes=16",
                    "payload_bytes=16 payload_bytes=16",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                CHECK.records(client, "config", "netz-client+hyper-server")


if __name__ == "__main__":
    unittest.main()
