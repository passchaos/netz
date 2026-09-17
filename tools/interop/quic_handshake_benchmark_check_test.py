from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import quic_handshake_benchmark_check as check


class QuicHandshakeBenchmarkCheckTest(unittest.TestCase):
    def write_case(
        self, directory: str, *, role_pair: str = "netz-client+quic-go-server",
        samples: int = 1, iterations: int = 3,
    ):
        root = Path(directory)
        client = root / "client.log"
        server = root / "server.log"
        sample_lines = []
        result_lines = []
        server_lines = []
        total_connections = 2 + iterations
        checksum = total_connections * (total_connections - 1) // 2
        client_impl, server_impl = {
            "netz-client+quic-go-server": ("netz", "quic-go"),
            "quic-go-client+quic-go-server": ("quic-go", "quic-go"),
            "quic-go-client+netz-server": ("quic-go", "netz"),
            "netz-client+quinn-server": ("netz", "quinn"),
            "quinn-client+quinn-server": ("quinn", "quinn"),
            "quinn-client+netz-server": ("quinn", "netz"),
            "netz-client+netz-server": ("netz", "netz"),
        }[role_pair]
        for run in range(1, samples + 1):
            elapsed = [100 + run + sample for sample in range(iterations)]
            for sample, value in enumerate(elapsed, 1):
                sample_lines.append(
                    f"record=handshake-sample implementation={client_impl} protocol=quic-v1 "
                    f"mode=handshake role_pair={role_pair} endpoint_role=client run={run} "
                    f"client_io={check.io_name(client_impl)} "
                    f"server_io={check.io_name(server_impl)} "
                    f"sample={sample} timeout_ms=10000 elapsed_ns={value} verified=true"
                )
            ordered = sorted(elapsed)
            result_lines.append(
                f"record=result implementation={client_impl} protocol=quic-v1 mode=handshake "
                f"role_pair={role_pair} endpoint_role=client run={run} "
                f"client_io={check.io_name(client_impl)} "
                f"server_io={check.io_name(server_impl)} "
                "timeout_ms=10000 "
                "timing_scope=client-connect-only verification=certificate resumption=disabled "
                "key_exchange=x25519 cipher=aes-128-gcm-sha256 warmup=2 "
                f"iterations={iterations} connections={total_connections} "
                f"echo_bytes={total_connections * 32} checksum={checksum} "
                f"total_elapsed_ns={sum(elapsed)} p50_ns={ordered[iterations // 2]} "
                f"p99_ns={ordered[min(iterations - 1, iterations * 99 // 100)]} "
                "echo_verified=true complete=true"
            )
            server_lines.append(
                f"record=server-complete implementation={server_impl} protocol=quic-v1 "
                f"mode=handshake role_pair={role_pair} endpoint_role=server run={run} "
                f"client_io={check.io_name(client_impl)} "
                f"server_io={check.io_name(server_impl)} "
                "timeout_ms=10000 "
                f"warmup=2 iterations={iterations} connections={total_connections} "
                f"echo_bytes={total_connections * 32} checksum={checksum} "
                "echo_verified=true peer_close=true complete=true"
            )
        client.write_text("\n".join(sample_lines + result_lines) + "\n", encoding="utf-8")
        server.write_text("\n".join(server_lines) + "\n", encoding="utf-8")
        return client, server

    def test_accepts_recomputed_samples(self) -> None:
        for role_pair in (
            "netz-client+quic-go-server",
            "quic-go-client+quic-go-server",
            "quic-go-client+netz-server",
            "netz-client+netz-server",
            "netz-client+quinn-server",
            "quinn-client+quinn-server",
            "quinn-client+netz-server",
        ):
            with self.subTest(role_pair=role_pair), TemporaryDirectory() as directory:
                client, server = self.write_case(
                    directory, role_pair=role_pair, samples=3
                )
                check.verify(
                    role_pair=role_pair, samples=3, warmup=2,
                    iterations=3, timeout_ms=10000, client_log=client, server_log=server,
                )

    def test_rejects_bad_total(self) -> None:
        with TemporaryDirectory() as directory:
            client, server = self.write_case(directory)
            client.write_text(
                client.read_text().replace("total_elapsed_ns=306", "total_elapsed_ns=307")
            )
            with self.assertRaises(ValueError):
                check.verify(
                    role_pair="netz-client+quic-go-server", samples=1, warmup=2,
                    iterations=3, timeout_ms=10000, client_log=client, server_log=server,
                )

    def test_rejects_missing_server_completion(self) -> None:
        with TemporaryDirectory() as directory:
            client, server = self.write_case(directory)
            server.write_text("")
            with self.assertRaises(ValueError):
                check.verify(
                    role_pair="netz-client+quic-go-server", samples=1, warmup=2,
                    iterations=3, timeout_ms=10000, client_log=client, server_log=server,
                )

    def test_rejects_even_sample_count(self) -> None:
        with TemporaryDirectory() as directory:
            client, server = self.write_case(directory, samples=2)
            with self.assertRaises(ValueError):
                check.verify(
                    role_pair="netz-client+quic-go-server", samples=2, warmup=2,
                    iterations=3, timeout_ms=10000, client_log=client, server_log=server,
                )

    def test_rejects_wrong_backend(self) -> None:
        with TemporaryDirectory() as directory:
            client, server = self.write_case(directory)
            client.write_text(
                client.read_text().replace(
                    "client_io=zio-std-io", "client_io=threaded",
                )
            )
            with self.assertRaisesRegex(ValueError, "client_io"):
                check.verify(
                    role_pair="netz-client+quic-go-server", samples=1, warmup=2,
                    iterations=3, timeout_ms=10000, client_log=client, server_log=server,
                )

    def test_rejects_wrong_endpoint_role_and_timeout(self) -> None:
        with TemporaryDirectory() as directory:
            client, server = self.write_case(directory)
            server.write_text(
                server.read_text().replace(
                    "endpoint_role=server", "endpoint_role=client",
                )
            )
            with self.assertRaisesRegex(ValueError, "endpoint role"):
                check.verify(
                    role_pair="netz-client+quic-go-server", samples=1, warmup=2,
                    iterations=3, timeout_ms=10000, client_log=client, server_log=server,
                )
            client, server = self.write_case(directory)
            client.write_text(
                client.read_text().replace("timeout_ms=10000", "timeout_ms=9999", 1)
            )
            with self.assertRaisesRegex(ValueError, "timeout_ms"):
                check.verify(
                    role_pair="netz-client+quic-go-server", samples=1, warmup=2,
                    iterations=3, timeout_ms=10000, client_log=client, server_log=server,
                )


if __name__ == "__main__":
    unittest.main()

