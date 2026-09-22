#!/usr/bin/env python3

import importlib.util
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("websocket_h3_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("websocket_h3_benchmark_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class WebSocketH3BenchmarkCheckTests(unittest.TestCase):
    def write_pair(
        self, directory: str, *,
        role_pair: str = "netz-client+quic-go-server",
        checksum: int | None = None, with_memory: bool = False,
        quic_version: int = 1,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        implementations = (
            {"client": "netz", "server": "quic-go"}
            if role_pair == "netz-client+quic-go-server"
            else {"client": "quic-go", "server": "netz"}
        )
        endpoint_io = {
            role: "zio-std-io" if implementation == "netz" else "quic-go-netpoll"
            for role, implementation in implementations.items()
        }
        value = CHECK.expected_checksum(1, 2, 16) if checksum is None else checksum
        base = (
            "protocol=websocket-h3 transport=h3 mode=binary-echo "
            f"role_pair={role_pair} client_io={endpoint_io['client']} "
            f"server_io={endpoint_io['server']} connection_scope=persistent "
            f"warmup=1 iterations=2 payload_bytes=16 timeout_ms=30000 "
            f"quic_version={quic_version}"
        )
        config_tail = (
            "benchmark_scope=same-application-shape stream_window=1048576 "
            "connection_window=8388608 steady_state_mtu=1280 "
            "cipher=negotiated-unexposed cert_verify=true compression=false "
            "netz_gso=false netz_gro=false quic_go_gso=implementation-default "
            "quic_go_gro=implementation-default pacing=implementation-specific"
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
            f"sent_bytes=32 received_bytes=32 checksum={value} server_complete=true",
        ]
        if with_memory:
            for role, lines in (("client", client_lines), ("server", server_lines)):
                implementation = implementations[role]
                if implementation == "netz":
                    detail = (
                        "allocator_scope=netz-explicit alloc_count=1 free_count=1 "
                        "resize_count=0 remap_count=0 total_allocated_bytes=64 "
                        "live_bytes=0 peak_live_bytes=64"
                    )
                else:
                    detail = (
                        "allocator_scope=go-runtime-heap alloc_count=1 free_count=0 "
                        "total_allocated_bytes=64 heap_alloc_bytes_end=64 "
                        "heap_sys_bytes_end=4096 runtime_sys_bytes_end=8192 gc_cycles=0"
                    )
                lines.append(
                    f"record=memory implementation={implementation} endpoint_role={role} "
                    f"{base} memory_scope=benchmark-run-after-argument-parse "
                    f"{detail} complete=true"
                )
        client = pathlib.Path(directory, "client.log")
        server = pathlib.Path(directory, "server.log")
        client.write_text("\n".join(client_lines) + "\n")
        server.write_text("\n".join(server_lines) + "\n")
        return client, server

    def verify_pair(
        self, client: pathlib.Path, server: pathlib.Path, *,
        role_pair: str = "netz-client+quic-go-server",
        rss: bool = False, quic_version: int = 1,
    ) -> None:
        kwargs = {}
        if rss:
            client_rss = client.with_suffix(".rss")
            server_rss = server.with_suffix(".rss")
            client_rss.write_text("1024\n")
            server_rss.write_text("2048\n")
            kwargs = {
                "client_rss": client_rss, "server_rss": server_rss,
                "rss_source": "busybox-time-maxrss",
            }
        CHECK.verify(
            role_pair=role_pair, warmup=1, iterations=2, payload_bytes=16,
            timeout_ms=30000, quic_version=quic_version,
            client_log=client, server_log=server, **kwargs,
        )

    def test_complete_both_role_pairs_are_accepted(self) -> None:
        for role_pair in (
            "netz-client+quic-go-server",
            "quic-go-client+netz-server",
        ):
            with self.subTest(role_pair=role_pair), tempfile.TemporaryDirectory() as directory:
                self.verify_pair(*self.write_pair(directory, role_pair=role_pair), role_pair=role_pair)

    def test_memory_records_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.verify_pair(*self.write_pair(directory, with_memory=True), rss=True)

    def test_quic_v2_is_accepted_and_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory, quic_version=2)
            self.verify_pair(client, server, quic_version=2)
            server.write_text(server.read_text().replace("quic_version=2", "quic_version=1"))
            with self.assertRaisesRegex(ValueError, "quic_version"):
                self.verify_pair(client, server, quic_version=2)

    def test_wrong_backend_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(client.read_text().replace("client_io=zio-std-io", "client_io=threaded"))
            with self.assertRaisesRegex(ValueError, "client_io"):
                self.verify_pair(client, server)

    def test_missing_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text("\n".join(line for line in client.read_text().splitlines() if "record=config" not in line) + "\n")
            with self.assertRaisesRegex(ValueError, "client config"):
                self.verify_pair(client, server)

    def test_wrong_timeout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            server.write_text(server.read_text().replace("timeout_ms=30000", "timeout_ms=1", 1))
            with self.assertRaisesRegex(ValueError, "timeout_ms"):
                self.verify_pair(client, server)

    def test_throughput_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(client.read_text().replace("logical_MiB_s=30.518", "logical_MiB_s=1"))
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
            client.write_text(client.read_text().replace("payload_bytes=16", "payload_bytes=16 payload_bytes=16", 1))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                CHECK.records(client, "config", "netz-client+quic-go-server")


if __name__ == "__main__":
    unittest.main()
