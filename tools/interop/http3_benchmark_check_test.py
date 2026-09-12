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
            "connection_scope=fresh-per-sample body_deadline_scope=sample "
            "sample=1 streams=4 body_bytes=1024 "
            f"checksum={value} status=200 streams_finished=4 "
            "per_stream_verified=true quic_version=2 complete=true"
        )
        client = pathlib.Path(directory, "client.log")
        server = pathlib.Path(directory, "server.log")
        client.write_text(
            "record=result implementation=netz benchmark_scope=same-application-shape "
            f"{common} elapsed_ns=123 sent_bytes=4096 received_bytes=4096\n"
        )
        server.write_text(
            f"record=server-complete implementation=netz endpoint_role=server {common} "
            "sent_bytes=4096 received_bytes=0\n"
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
            server.write_text("")
            with self.assertRaisesRegex(ValueError, "expected 1 server"):
                self.verify_pair(client, server)

    def test_duplicate_result_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(client.read_text() * 2)
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

    def test_duplicate_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, _ = self.write_pair(directory)
            client.write_text(client.read_text().replace("streams=4", "streams=4 streams=4"))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                CHECK.records(client, "result", "quic-go-client+netz-server")


if __name__ == "__main__":
    unittest.main()
