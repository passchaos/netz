#!/usr/bin/env python3

import importlib.util
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("http3_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("http3_benchmark_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class Http3BenchmarkCheckTests(unittest.TestCase):
    def write_pair(self, directory: str, *, checksum: int | None = None):
        value = CHECK.aggregate_checksum(1024, 4) if checksum is None else checksum
        common = (
            "protocol=http3 mode=download role_pair=quic-go-client+netz-server "
            "sender_role=server client_io=quic-go-netpoll server_io=zio-std-io "
            "connection_scope=fresh-per-sample body_deadline_scope=sample "
            "sample=1 streams=4 body_bytes=1024 "
            f"checksum={value} status=200 streams_finished=4 "
            "per_stream_verified=true quic_version=2 complete=true"
        )
        client = pathlib.Path(directory, "client.log")
        server = pathlib.Path(directory, "server.log")
        config_shape = (
            "record=config protocol=http3 mode=download "
            "role_pair=quic-go-client+netz-server sender_role=server "
            "client_io=quic-go-netpoll server_io=zio-std-io "
            "connection_scope=fresh-per-sample "
            "benchmark_scope=same-application-shape body_deadline_scope=sample "
            "warmup=1 iterations=1 streams=4 body_bytes=1024 "
            "application_chunk_requested=512 application_chunk_effective=512 "
            "stream_window=1048576 connection_window=8388608 timeout_ms=30000 "
            "steady_state_mtu=1280 quic_version=2 cipher=negotiated-unexposed "
            "cert_verify=true pacing=true"
        )
        client.write_text(
            f"implementation=quic-go endpoint_role=client gso=implementation-default "
            f"gro=implementation-default {config_shape}\n"
            "record=result implementation=netz result_owner=client endpoint_role=client "
            "benchmark_scope=same-application-shape "
            f"{common} elapsed_ns=1000 logical_MiB_s=3906.250 "
            "sent_bytes=4096 received_bytes=4096\n"
        )
        server.write_text(
            f"implementation=netz endpoint_role=server gso=false gro=false {config_shape}\n"
            f"record=server-complete implementation=netz endpoint_role=server {common} "
            "benchmark_scope=same-application-shape sent_bytes=4096 received_bytes=0\n"
        )
        return client, server

    def verify_pair(self, client: pathlib.Path, server: pathlib.Path) -> None:
        CHECK.verify(
            role_pair="quic-go-client+netz-server",
            mode="download",
            iterations=1,
            streams=4,
            body_bytes=1024,
            quic_version=2,
            warmup=1,
            chunk_bytes=512,
            stream_window=1048576,
            timeout_ms=30000,
            client_log=client,
            server_log=server,
        )

    def test_index_aware_checksum(self) -> None:
        self.assertEqual(CHECK.aggregate_checksum(1024, 4), 522240)
        self.assertNotEqual(
            CHECK.stream_checksum(1000, 0),
            CHECK.stream_checksum(1000, 1),
        )

    def test_complete_pair_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.verify_pair(*self.write_pair(directory))

    def test_checksum_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = self.write_pair(directory, checksum=1)
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.verify_pair(*files)

    def test_missing_server_completion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            server.write_text(
                "\n".join(
                    line for line in server.read_text().splitlines()
                    if "record=server-complete" not in line
                ) + "\n"
            )
            with self.assertRaisesRegex(ValueError, "expected 1 server"):
                self.verify_pair(client, server)

    def test_duplicate_result_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            result = next(
                line for line in client.read_text().splitlines()
                if "record=result" in line
            )
            client.write_text(client.read_text() + result + "\n")
            with self.assertRaisesRegex(ValueError, "expected 1 result"):
                self.verify_pair(client, server)

    def test_missing_per_stream_proof_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text().replace("per_stream_verified=true", "per_stream_verified=false")
            )
            with self.assertRaisesRegex(ValueError, "per_stream_verified"):
                self.verify_pair(client, server)

    def test_wrong_quic_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text().replace("quic_version=2", "quic_version=1")
            )
            with self.assertRaisesRegex(ValueError, "quic_version"):
                self.verify_pair(client, server)

    def test_wrong_backend_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            server.write_text(
                server.read_text().replace(
                    "server_io=zio-std-io", "server_io=threaded",
                )
            )
            with self.assertRaisesRegex(ValueError, "server_io"):
                self.verify_pair(client, server)

    def test_accepts_netz_only_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            for path in (client, server):
                path.write_text(
                    path.read_text().replace(
                        "quic-go-client+netz-server", "netz-client+netz-server",
                    ).replace(
                        "client_io=quic-go-netpoll", "client_io=zio-std-io",
                    ).replace(
                        "implementation=quic-go", "implementation=netz",
                    ).replace(
                        "gso=implementation-default", "gso=false",
                    ).replace(
                        "gro=implementation-default", "gro=false",
                    )
                )
            CHECK.verify(
                role_pair="netz-client+netz-server", mode="download",
                iterations=1, streams=4, body_bytes=1024, quic_version=2,
                warmup=1, chunk_bytes=512, stream_window=1048576,
                timeout_ms=30000, client_log=client, server_log=server,
            )

    def test_duplicate_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, _ = self.write_pair(directory)
            client.write_text(client.read_text().replace("streams=4", "streams=4 streams=4"))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                CHECK.records(client, "result", "quic-go-client+netz-server")


if __name__ == "__main__":
    unittest.main()
