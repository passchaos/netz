#!/usr/bin/env python3

import importlib.util
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("webtransport_churn_check.py")
SPEC = importlib.util.spec_from_file_location("webtransport_churn_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ChurnCheckTests(unittest.TestCase):
    def write_pair(self, directory: str, *, checksum: int = 33_945_600):
        fields = (
            "fault=loss fault_scope=netz-client-outbound streams=32 fin=16 "
            f"reset=16 bytes=266240 checksum={checksum} "
            "reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 sibling=true"
        )
        client = pathlib.Path(directory, "client.log")
        server = pathlib.Path(directory, "server.log")
        client.write_text(
            f"netz client churn passed: {fields} considered=314 dropped=12 "
            "held=0 reordered=0 peer-close=true\n"
        )
        server.write_text(f"wtransport server churn passed: {fields}\n")
        return client, server

    def test_expected_32_stream_shape(self) -> None:
        self.assertEqual(
            CHECK.expected(32, 16_384, 256, 2),
            {
                "streams": 32,
                "fin": 16,
                "reset": 16,
                "bytes": 266_240,
                "checksum": 33_945_600,
                "reset_mask": 0xAAAA_AAAA,
                "reset_code_sum": 262_400,
            },
        )

    def test_expected_64_stream_shape(self) -> None:
        result = CHECK.expected(64, 16_384, 256, 2)
        self.assertEqual(result["bytes"], 532_480)
        self.assertEqual(result["checksum"], 67_891_200)
        self.assertEqual(result["reset_mask"], 0xAAAA_AAAA_AAAA_AAAA)
        self.assertEqual(result["reset_code_sum"], 525_312)

    def test_record_retains_hyphenated_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "client.log")
            path.write_text(
                "netz client churn passed: peer-close=true fault_scope=netz-client-outbound\n"
            )
            result = CHECK.record(path, "netz client churn passed:")
            self.assertEqual(result["peer-close"], "true")

    def test_record_rejects_duplicate_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "client.log")
            line = "netz client churn passed: peer-close=true\n"
            path.write_text(line + line)
            with self.assertRaisesRegex(ValueError, "expected one"):
                CHECK.record(path, "netz client churn passed:")

    def test_complete_pair_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            CHECK.verify(
                sender="netz",
                fault="loss",
                streams=32,
                bytes_per_stream=16_384,
                reset_after_bytes=256,
                reset_every=2,
                client_log=client,
                server_log=server,
            )

    def test_checksum_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory, checksum=1)
            with self.assertRaisesRegex(ValueError, "checksum"):
                CHECK.verify(
                    sender="netz",
                    fault="loss",
                    streams=32,
                    bytes_per_stream=16_384,
                    reset_after_bytes=256,
                    reset_every=2,
                    client_log=client,
                    server_log=server,
                )

    def test_inactive_fault_counter_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(client.read_text().replace("held=0", "held=1"))
            with self.assertRaisesRegex(ValueError, "inactive fault counter"):
                CHECK.verify(
                    sender="netz",
                    fault="loss",
                    streams=32,
                    bytes_per_stream=16_384,
                    reset_after_bytes=256,
                    reset_every=2,
                    client_log=client,
                    server_log=server,
                )

    def test_reverse_pair_requires_matching_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text()
                .replace("netz client", "wtransport client")
                .replace("netz-client-outbound", "wtransport-client-outbound")
                .replace("considered=314 dropped=12", "considered=2 dropped=2")
                .replace(
                    "peer-close=true",
                    "reset_dropped=1 reset_held=0 reset_reordered=0 "
                    "fin_dropped=1 fin_held=0 fin_reordered=0 peer-close=true",
                )
            )
            server.write_text(
                server.read_text()
                .replace("wtransport server", "netz server")
                .replace("netz-client-outbound", "wtransport-client-outbound")
            )
            proxy = pathlib.Path(directory, "proxy.log")
            proxy.write_text(
                "udp fault proxy passed: fault=loss "
                "fault_direction=client "
                "fault_scope=wtransport-client-outbound considered=2 "
                "dropped=2 held=0 reordered=0\n"
            )
            CHECK.verify(
                sender="wtransport",
                fault="loss",
                streams=32,
                bytes_per_stream=16_384,
                reset_after_bytes=256,
                reset_every=2,
                client_log=client,
                server_log=server,
                proxy_log=proxy,
            )

    def test_reverse_pair_rejects_a_phase_without_faults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text()
                .replace("netz client", "wtransport client")
                .replace("netz-client-outbound", "wtransport-client-outbound")
                .replace("considered=314 dropped=12", "considered=2 dropped=2")
                .replace(
                    "peer-close=true",
                    "reset_dropped=1 reset_held=0 reset_reordered=0 "
                    "fin_dropped=0 fin_held=0 fin_reordered=0 peer-close=true",
                )
            )
            server.write_text(
                server.read_text()
                .replace("wtransport server", "netz server")
                .replace("netz-client-outbound", "wtransport-client-outbound")
            )
            proxy = pathlib.Path(directory, "proxy.log")
            proxy.write_text(
                "udp fault proxy passed: fault=loss "
                "fault_direction=client "
                "fault_scope=wtransport-client-outbound considered=2 "
                "dropped=2 held=0 reordered=0\n"
            )
            with self.assertRaisesRegex(ValueError, "fin phase"):
                CHECK.verify(
                    sender="wtransport",
                    fault="loss",
                    streams=32,
                    bytes_per_stream=16_384,
                    reset_after_bytes=256,
                    reset_every=2,
                    client_log=client,
                    server_log=server,
                    proxy_log=proxy,
                )

    def test_reverse_pair_rejects_wrong_proxy_direction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            client.write_text(
                client.read_text()
                .replace("netz client", "wtransport client")
                .replace("netz-client-outbound", "wtransport-client-outbound")
                .replace("considered=314 dropped=12", "considered=2 dropped=2")
                .replace(
                    "peer-close=true",
                    "reset_dropped=1 reset_held=0 reset_reordered=0 "
                    "fin_dropped=1 fin_held=0 fin_reordered=0 peer-close=true",
                )
            )
            server.write_text(
                server.read_text()
                .replace("wtransport server", "netz server")
                .replace("netz-client-outbound", "wtransport-client-outbound")
            )
            proxy = pathlib.Path(directory, "proxy.log")
            proxy.write_text(
                "udp fault proxy passed: fault=loss fault_direction=server "
                "fault_scope=wtransport-client-outbound considered=2 "
                "dropped=2 held=0 reordered=0\n"
            )
            with self.assertRaisesRegex(ValueError, "proxy fault metadata"):
                CHECK.verify(
                    sender="wtransport",
                    fault="loss",
                    streams=32,
                    bytes_per_stream=16_384,
                    reset_after_bytes=256,
                    reset_every=2,
                    client_log=client,
                    server_log=server,
                    proxy_log=proxy,
                )

    def test_record_rejects_duplicate_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "client.log")
            path.write_text("netz client churn passed: streams=32 streams=64\n")
            with self.assertRaisesRegex(ValueError, "duplicate field"):
                CHECK.record(path, "netz client churn passed:")


if __name__ == "__main__":
    unittest.main()
