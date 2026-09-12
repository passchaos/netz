#!/usr/bin/env python3

import importlib.util
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("quic_quic_go_churn_check.py")
SPEC = importlib.util.spec_from_file_location("quic_quic_go_churn_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class RawQuicChurnCheckTests(unittest.TestCase):
    def write_case(
        self,
        directory: str,
        *,
        role_pair: str = "quic-go-client+netz-server",
        sender: str = "client",
        fault: str = "loss",
        checksum: int = 33_945_600,
        reset_faults: int = 1,
        fin_faults: int = 1,
    ):
        client_impl, server_impl = {
            "netz-client+quic-go-server": ("netz", "quic-go"),
            "quic-go-client+netz-server": ("quic-go", "netz"),
        }[role_pair]
        scope = f"{client_impl}-client" if sender == "client" else f"{server_impl}-server"
        receiver = server_impl if sender == "client" else client_impl
        common = (
            f"role_pair={role_pair} sender={sender} fault={fault} "
            f"fault_scope={scope}-outbound streams=32 fin=16 reset=16 "
            f"bytes=266240 checksum={checksum} reset_mask=0x00000000aaaaaaaa "
            "reset_code_sum=262400 sibling=true"
        )
        if fault == "loss":
            counters = "considered=2 dropped=2 held=0 reordered=0"
        else:
            counters = "considered=4 dropped=0 held=2 reordered=2"
        client = pathlib.Path(directory, "client.log")
        server = pathlib.Path(directory, "server.log")
        proxy = pathlib.Path(directory, "proxy.log")
        client.write_text(
            f"raw QUIC churn client passed: implementation={client_impl} {common} "
            f"{counters} reset_faults={reset_faults} fin_faults={fin_faults} "
            f"reset_final_size_verified={'true' if client_impl == receiver == 'netz' else 'false'} "
            "peer-close=true\n"
        )
        server.write_text(
            f"raw QUIC churn server passed: implementation={server_impl} {common} "
            f"reset_final_size_verified={'true' if server_impl == receiver == 'netz' else 'false'}\n"
        )
        proxy.write_text(
            f"udp fault proxy passed: fault={fault} fault_direction={sender} "
            f"fault_scope={scope}-outbound {counters}\n"
        )
        return client, server, proxy

    def verify_case(self, client, server, proxy, **kwargs):
        CHECK.verify(
            role_pair=kwargs.get("role_pair", "quic-go-client+netz-server"),
            sender=kwargs.get("sender", "client"),
            fault=kwargs.get("fault", "loss"),
            streams=32,
            bytes_per_stream=16_384,
            reset_after_bytes=256,
            reset_every=2,
            client_log=client,
            server_log=server,
            proxy_log=proxy,
        )

    def test_expected_shapes(self) -> None:
        small = CHECK.expected(32, 16_384, 256, 2)
        large = CHECK.expected(64, 16_384, 256, 2)
        self.assertEqual(small["bytes"], 266_240)
        self.assertEqual(small["checksum"], 33_945_600)
        self.assertEqual(small["reset_mask"], 0xAAAA_AAAA)
        self.assertEqual(large["bytes"], 532_480)
        self.assertEqual(large["checksum"], 67_891_200)
        self.assertEqual(large["reset_mask"], 0xAAAA_AAAA_AAAA_AAAA)

    def test_netz_receiver_loss_case_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = self.write_case(directory)
            self.verify_case(*files)

    def test_go_receiver_reorder_case_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kwargs = {
                "role_pair": "netz-client+quic-go-server",
                "sender": "client",
                "fault": "reorder",
            }
            files = self.write_case(directory, **kwargs)
            self.verify_case(*files, **kwargs)

    def test_checksum_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = self.write_case(directory, checksum=1)
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.verify_case(*files)

    def test_missing_phase_fault_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            files = self.write_case(directory, fin_faults=0)
            with self.assertRaisesRegex(ValueError, "both phases"):
                self.verify_case(*files)

    def test_proxy_counter_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server, proxy = self.write_case(directory)
            proxy.write_text(proxy.read_text().replace("dropped=2", "dropped=3"))
            with self.assertRaisesRegex(ValueError, "proxy/client dropped"):
                self.verify_case(client, server, proxy)

    def test_unexpected_considered_count_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server, proxy = self.write_case(directory)
            client.write_text(client.read_text().replace("considered=2 dropped=2", "considered=3 dropped=3"))
            proxy.write_text(proxy.read_text().replace("considered=2 dropped=2", "considered=3 dropped=3"))
            with self.assertRaisesRegex(ValueError, "unexpected considered"):
                self.verify_case(client, server, proxy)

    def test_false_go_final_size_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server, proxy = self.write_case(directory)
            client.write_text(
                client.read_text().replace(
                    "reset_final_size_verified=false",
                    "reset_final_size_verified=true",
                )
            )
            with self.assertRaisesRegex(ValueError, "final-size evidence"):
                self.verify_case(client, server, proxy)

    def test_duplicate_result_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server, proxy = self.write_case(directory)
            client.write_text(client.read_text() * 2)
            with self.assertRaisesRegex(ValueError, "expected one"):
                self.verify_case(client, server, proxy)


if __name__ == "__main__":
    unittest.main()
