#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("quic_quic_go_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("quic_quic_go_benchmark_check", MODULE)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class RawQuicBenchmarkCheckTest(unittest.TestCase):
    def write_pair(
        self, directory: str, *, sender: str = "server", checksum: int | None = None,
    ) -> tuple[Path, Path]:
        role_pair = "quic-go-client+netz-server"
        direction = "upload" if sender == "client" else "download"
        expected_checksum = CHECK.aggregate_checksum(1024, 4, 2)
        checksum = expected_checksum if checksum is None else checksum
        common = (
            f"protocol=quic-stream direction={direction} role_pair={role_pair} "
            f"sender_role={sender} client_io=quic-go-netpoll server_io=zio-std-io "
            "connection_scope=fresh-per-sample benchmark_scope=same-application-shape "
        )
        config_shape = (
            "warmup=2 iterations=1 streams=4 bytes_per_stream=1024 "
            "application_chunk_requested=512 application_chunk_effective=512 "
            "stream_window=1048576 connection_window=8388608 steady_state_mtu=1280 "
            "timeout_ms=30000 "
            "quic_version=1 cert_verify=true netz_gso=false netz_gro=false "
            "quic_go_gso=false quic_go_gro=false "
            "cipher=negotiated-unexposed pacing=implementation-specific"
        )
        client = Path(directory, "client.log")
        server = Path(directory, "server.log")
        client_lines = [
            f"record=config implementation=quic-go endpoint_role=client {common}{config_shape}"
        ]
        server_lines = [
            f"record=config implementation=netz endpoint_role=server {common}{config_shape}"
        ]
        result = (
            f"record=result implementation=netz endpoint_role=server {common}"
            f"sample=1 elapsed_ns=1000 logical_MiB_s=3906.250 streams=4 "
            f"bytes_per_stream=1024 sent_bytes=4096 received_bytes=4096 "
            f"checksum={checksum} completion_exchange_verified=true complete=true"
        )
        completion = (
            f"record=receiver-complete implementation=quic-go endpoint_role=client "
            f"{common}sample=1 streams=4 bytes_per_stream=1024 "
            f"received_bytes=4096 checksum={checksum} "
            "completion_exchange_verified=true complete=true"
        )
        if sender == "server":
            server_lines.append(result)
            client_lines.append(completion)
        else:
            client_lines.append(result.replace(
                "implementation=netz endpoint_role=server",
                "implementation=quic-go endpoint_role=client",
            ))
            server_lines.append(completion.replace(
                "implementation=quic-go endpoint_role=client",
                "implementation=netz endpoint_role=server",
            ))
        client.write_text("\n".join(client_lines) + "\n", encoding="utf-8")
        server.write_text("\n".join(server_lines) + "\n", encoding="utf-8")
        return client, server

    def verify(
        self, client: Path, server: Path, sender: str = "server",
        role_pair: str = "quic-go-client+netz-server",
    ) -> None:
        CHECK.verify(
            role_pair=role_pair, sender=sender, warmup=2,
            iterations=1, streams=4, bytes_per_stream=1024, chunk_bytes=512,
            stream_window=1048576, timeout_ms=30000, client_log=client,
            server_log=server,
        )

    def test_checksum_formula_handles_full_cycles_and_rounds(self) -> None:
        expected = sum(
            (offset * 131 + stream * 17 + 2 * 29) & 0xFF
            for stream in range(4) for offset in range(1024)
        )
        self.assertEqual(CHECK.aggregate_checksum(1024, 4, 2), expected)

    def test_accepts_bidirectional_verified_records(self) -> None:
        for sender in ("client", "server"):
            with self.subTest(sender=sender), tempfile.TemporaryDirectory() as directory:
                self.verify(*self.write_pair(directory, sender=sender), sender=sender)

    def test_accepts_netz_only_runtime_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            for path in (client, server):
                path.write_text(
                    path.read_text().replace(
                        "quic-go-client+netz-server",
                        "netz-client+netz-server",
                    ).replace(
                        "client_io=quic-go-netpoll",
                        "client_io=zio-std-io",
                    ),
                    encoding="utf-8",
                )
            client.write_text(
                client.read_text().replace("implementation=quic-go", "implementation=netz"),
                encoding="utf-8",
            )
            self.verify(client, server, role_pair="netz-client+netz-server")

    def test_rejects_bad_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.verify(*self.write_pair(directory, checksum=1))

    def test_rejects_missing_receiver_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                "\n".join(
                    line for line in client.read_text().splitlines()
                    if "record=receiver-complete" not in line
                ) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "expected 1 receiver"):
                self.verify(client, server)

    def test_rejects_wrong_or_missing_backend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            server.write_text(
                server.read_text().replace("server_io=zio-std-io", "server_io=threaded"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "server_io"):
                self.verify(client, server)
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text().replace(" client_io=quic-go-netpoll", "", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "client_io"):
                self.verify(client, server)

    def test_rejects_duplicate_field(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text().replace("sample=1", "sample=1 sample=1"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                self.verify(client, server)

    def test_rejects_non_finite_throughput(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            server.write_text(
                server.read_text().replace("logical_MiB_s=3906.250", "logical_MiB_s=nan"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "non-positive throughput"):
                self.verify(client, server)


if __name__ == "__main__":
    unittest.main()
