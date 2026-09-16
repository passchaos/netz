#!/usr/bin/env python3

from pathlib import Path
import importlib.util
import tempfile
import unittest


CHECKER = Path(__file__).with_name("quic_datagram_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("quic_datagram_benchmark_check", CHECKER)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class DatagramBenchmarkCheckTests(unittest.TestCase):
    def record(self, kind: str, role_pair: str, endpoint_role: str, implementation: str) -> str:
        client, server = CHECK.ROLE_PAIRS[role_pair]
        common = (
            f"record={kind} implementation={implementation} protocol=quic-datagram "
            f"mode=pingpong role_pair={role_pair} endpoint_role={endpoint_role} "
            f"client_io={CHECK.io_name(client)} server_io={CHECK.io_name(server)} "
            "timing_scope=post-handshake-single-outstanding-roundtrip "
            "warmup=1 iterations=3 payload_bytes=32 timeout_ms=30000 complete=true"
        )
        total = 4 * 32
        checksum = CHECK.expected_checksum(4, 32)
        if kind == "config":
            limit = 1171 if implementation == "netz" else 1162
            return (
                common + " connection_scope=fresh-per-sample "
                "benchmark_scope=same-application-shape steady_state_mtu=1200 "
                f"datagram_limit={limit} quic_version=1 cert_verify=true "
                "pacing=implementation-specific"
            )
        if kind == "result":
            limit = 1171 if implementation == "netz" else 1162
            return (
                common + " connection_scope=fresh-per-sample "
                "benchmark_scope=same-application-shape "
                f"datagram_limit={limit} p50_ns=20 p90_ns=30 p99_ns=40 "
                f"p999_ns=50 mean_ns=25 min_ns=10 max_ns=60 received_bytes={total} "
                f"checksum={checksum} completion_exchange_verified=true close_code=59"
            )
        return (
            common + f" received_bytes={total} checksum={checksum} "
            "completion_exchange_verified=true close_code=59"
        )

    def valid_log(self) -> str:
        sha = "a" * 64
        lines = [
            "record=environment protocol=quic-datagram mode=pingpong samples=1 "
            "schedule=abba client_cpu=0 server_cpu=1 host=test arch=x86_64 kernel=test "
            f"zig=0.16.0 rustc=1.98.0 netz_build_mode=ReleaseFast "
            f"quinn_revision={CHECK.QUINN_REVISION} netz_client_sha256={sha} "
            f"netz_server_sha256={sha} quinn_binary_sha256={sha} "
            f"quinn_lock_sha256={sha} complete=true"
        ]
        for sample, role_pair in CHECK.expected_order(1):
            client, server = CHECK.ROLE_PAIRS[role_pair]
            lines.append(
                "record=run protocol=quic-datagram mode=pingpong "
                f"sample={sample} role_pair={role_pair} implementation={client} "
                f"fixed_server={server} schedule=abba client_cpu=0 server_cpu=1"
            )
            lines.append(self.record("config", role_pair, "client", client))
            lines.append(self.record("result", role_pair, "client", client))
            lines.append(self.record("config", role_pair, "server", server))
            lines.append(self.record("server-complete", role_pair, "server", server))
        return "\n".join(lines) + "\n"

    def summarize(self, text: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.log"
            path.write_text(text, encoding="utf-8")
            return CHECK.summarize(path, 1, 0, 1, 1, 3, 32, 30000)

    def test_valid_matrix(self) -> None:
        output = self.summarize(self.valid_log())
        self.assertEqual(len(output), 7)
        self.assertIn("fixed_server=quinn", output[-2])
        self.assertIn("netz_speedup=1.000", output[-1])

    def test_wrong_order_is_rejected(self) -> None:
        text = self.valid_log().replace(
            "role_pair=netz-client+quinn-server implementation=netz",
            "role_pair=quinn-client+quinn-server implementation=quinn",
            1,
        )
        with self.assertRaisesRegex(ValueError, "run marker"):
            self.summarize(text)

    def test_bad_checksum_is_rejected(self) -> None:
        text = self.valid_log().replace(
            f"checksum={CHECK.expected_checksum(4, 32)}",
            "checksum=1",
            1,
        )
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.summarize(text)

    def test_even_sample_count_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive odd"):
            CHECK.expected_order(2)


if __name__ == "__main__":
    unittest.main()
