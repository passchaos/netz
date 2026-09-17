from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import handshake_benchmark_check as check


class QuinnHandshakeMatrixCheckTest(unittest.TestCase):
    def write_case(self, directory: str, *, samples: int = 1):
        root = Path(directory)
        log = root / "results.log"
        summaries = root / "summaries.log"
        env = (
            "record=environment protocol=quic-v1 mode=handshake peer=quinn "
            f"samples={samples} schedule=abba client_cpu=0 server_cpu=1 "
            "host=test arch=aarch64 kernel=test zig=test rustc=test "
            "netz_build_mode=ReleaseFast "
            f"quinn_revision={check.QUINN_REVISION} "
            f"netz_binary_sha256={'a' * 64} quinn_binary_sha256={'b' * 64} "
            f"quinn_lock_sha256={'c' * 64} "
            "server_identity=shared-ca-signed-p256-leaf "
            "server_certificate_chain_entries=1 server_certificate_der_bytes=450 "
            f"server_certificate_sha256={'d' * 64} complete=true"
        )
        run_lines = []
        for sample, pair in check.expected_order(samples):
            client, server = check.IMPLEMENTATIONS[pair]
            run_lines.append(
                "record=run protocol=quic-v1 mode=handshake "
                f"sample={sample} role_pair={pair} implementation={client} "
                f"fixed_server={server} schedule=abba client_cpu=0 server_cpu=1"
            )
            for sample_number in range(1, 4):
                run_lines.append(
                    "record=handshake-sample protocol=quic-v1 mode=handshake "
                    f"role_pair={pair} run={sample} implementation={client} "
                    "endpoint_role=client "
                    f"client_io={check.io_name(client)} server_io={check.io_name(server)} "
                    f"timeout_ms=10000 sample={sample_number} elapsed_ns={100 + sample_number} "
                    "connect_tx_datagrams=2 connect_tx_bytes=1300 "
                    "connect_rx_datagrams=1 connect_rx_bytes=1200 "
                    + ("pre_trust_ns=40 trust_ns=30 post_trust_ns=" + str(30 + sample_number) + " " if client == "netz" else "")
                    + ("trust_cache=enabled " if client == "netz" else "trust_cache=implementation-specific ")
                    + "verified=true"
                )
            run_lines.append(
                "record=result protocol=quic-v1 mode=handshake "
                f"role_pair={pair} run={sample} implementation={client} "
                "endpoint_role=client timing_scope=client-connect-only "
                f"client_io={check.io_name(client)} server_io={check.io_name(server)} "
                "timeout_ms=10000 verification=certificate resumption=disabled "
                + ("trust_cache=enabled " if client == "netz" else "trust_cache=implementation-specific ")
                + "key_exchange=x25519 "
                "cipher=aes-128-gcm-sha256 warmup=2 iterations=3 connections=5 "
                "echo_bytes=160 checksum=10 total_elapsed_ns=306 p50_ns=102 p99_ns=103 "
                "echo_verified=true complete=true"
            )
            run_lines.append(
                "record=server-complete protocol=quic-v1 mode=handshake "
                f"role_pair={pair} run={sample} implementation={server} "
                "endpoint_role=server "
                f"client_io={check.io_name(client)} server_io={check.io_name(server)} "
                "timeout_ms=10000 warmup=2 iterations=3 connections=5 "
                "echo_bytes=160 checksum=10 echo_verified=true peer_close=true complete=true"
            )
        log.write_text("\n".join([env, *run_lines]) + "\n", encoding="utf-8")
        summary_lines = []
        for index, pair in enumerate(check.ROLE_PAIRS):
            client, server = check.IMPLEMENTATIONS[pair]
            phase_fields = (
                "median_pre_trust_ns=40 median_trust_ns=30 "
                "median_post_trust_ns=32 "
                if client == "netz" else ""
            )
            summary_lines.append(
                "protocol=quic-v1 mode=handshake "
                f"role_pair={pair} samples={samples} warmup=2 iterations=3 "
                f"p50_ns={100 + index} p99_ns={200 + index} "
                f"client_io={check.io_name(client)} server_io={check.io_name(server)} "
                "median_total_elapsed_ns=303 connects_per_second_from_timed_sum=9900990.1 "
                "median_connect_tx_datagrams=2 median_connect_tx_bytes=1300 "
                "median_connect_rx_datagrams=1 median_connect_rx_bytes=1200 "
                + phase_fields + "checksum=10 complete=true"
            )
        summaries.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
        return log, summaries

    def test_accepts_strict_matrix(self) -> None:
        with TemporaryDirectory() as directory:
            log, summaries = self.write_case(directory, samples=3)
            output = check.validate(log, summaries, 3, 0, 1, 2, 3, 10000)
            self.assertEqual(len(output), 7)
            self.assertIn("fixed_server=quinn", output[-2])
            self.assertIn("fixed_server=netz", output[-1])

    def test_rejects_wrong_schedule(self) -> None:
        with TemporaryDirectory() as directory:
            log, summaries = self.write_case(directory, samples=3)
            text = log.read_text(encoding="utf-8")
            log.write_text(text.replace("sample=2 role_pair=netz-client+netz-server", "sample=2 role_pair=netz-client+quinn-server", 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "run marker"):
                check.validate(log, summaries, 3, 0, 1, 2, 3, 10000)

    def test_rejects_bad_hash_and_backend(self) -> None:
        with TemporaryDirectory() as directory:
            log, summaries = self.write_case(directory)
            log.write_text(log.read_text().replace("a" * 64, "short"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sha256"):
                check.validate(log, summaries, 1, 0, 1, 2, 3, 10000)

    def test_rejects_missing_raw_sample(self) -> None:
        with TemporaryDirectory() as directory:
            log, summaries = self.write_case(directory)
            lines = log.read_text(encoding="utf-8").splitlines()
            removed = False
            kept = []
            for line in lines:
                if not removed and line.startswith("record=handshake-sample"):
                    removed = True
                    continue
                kept.append(line)
            log.write_text("\n".join(kept) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "raw run order|missing raw records|handshake sample",
            ):
                check.validate(log, summaries, 1, 0, 1, 2, 3, 10000)
            log, summaries = self.write_case(directory)
            summaries.write_text(summaries.read_text().replace("quinn-tokio-rustls", "wrong", 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "client_io|server_io"):
                check.validate(log, summaries, 1, 0, 1, 2, 3, 10000)


if __name__ == "__main__":
    unittest.main()
