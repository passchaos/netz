#!/usr/bin/env python3

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mqtt_broker_config_bridge
import mqtt_broker_config
from mqtt_broker_config_include import connack_policy
from mqtt_scenarios import subscription_lifecycle
from mqtt_scenarios.will_delay_test import QuietDeadlineOracleTest
from mqtt_broker_config import wait_process_line


class IncludeConnackOracleTest(unittest.TestCase):
    def test_decodes_properties_at_their_wire_boundaries(self) -> None:
        self.assertEqual(
            connack_policy(bytes.fromhex("20 0e 00 00 0b 12 00 01 24 24 01 22 00 05 29 01")),
            {0x12: "$", 0x24: 1, 0x22: 5, 0x29: 1},
        )

    def test_rejects_duplicate_or_truncated_policy(self) -> None:
        for packet in ("20 07 00 00 04 24 01 24 00", "20 05 00 00 02 22 00"):
            with self.subTest(packet=packet), self.assertRaises(AssertionError):
                connack_policy(bytes.fromhex(packet))


class WaitProcessLineTest(unittest.TestCase):
    def test_drains_text_wrapper_lines_before_waiting_on_descriptor(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import sys, time; "
                    "sys.stdout.write('first\\nsecond\\n'); "
                    "sys.stdout.flush(); time.sleep(1)"
                ),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_process_line(process, "first", "first line", timeout=0.5)
            wait_process_line(process, "second", "buffered line", timeout=0.1)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            assert process.stdout is not None
            process.stdout.close()


class RestartConnectTest(unittest.TestCase):
    def test_retries_transport_reset_after_process_restart(self) -> None:
        connected = mock.sentinel.connected
        with (
            mock.patch.object(
                mqtt_broker_config_bridge,
                "_connect_client",
                side_effect=[ConnectionResetError(), connected],
            ) as connect,
            mock.patch.object(
                mqtt_broker_config_bridge.time,
                "sleep",
            ) as sleep,
        ):
            actual = mqtt_broker_config_bridge._connect_client_after_restart(
                1883,
                "observer",
            )
        self.assertIs(actual, connected)
        self.assertEqual(connect.call_count, 2)
        sleep.assert_called_once_with(0.02)

    def test_does_not_retry_mqtt_refusal(self) -> None:
        with (
            mock.patch.object(
                mqtt_broker_config_bridge,
                "_connect_client",
                side_effect=AssertionError("CONNACK refused"),
            ) as connect,
            mock.patch.object(
                mqtt_broker_config_bridge.time,
                "sleep",
            ) as sleep,
        ):
            with self.assertRaisesRegex(AssertionError, "CONNACK refused"):
                mqtt_broker_config_bridge._connect_client_after_restart(
                    1883,
                    "observer",
                )
        connect.assert_called_once_with(1883, "observer")
        sleep.assert_not_called()


class CrlServerFixtureTest(unittest.TestCase):
    def test_creates_complete_identity_for_focused_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ca = directory / "generated-ca.crt"
            ca_key = directory / "generated-ca.key"
            with (
                mock.patch.object(
                    mqtt_broker_config,
                    "create_ca",
                    return_value=(ca, ca_key),
                ) as create_ca,
                mock.patch.object(
                    mqtt_broker_config,
                    "create_signed_certificate",
                ) as create_certificate,
            ):
                mqtt_broker_config.ensure_signed_crl_server_identity(
                    directory,
                )
            create_ca.assert_called_once_with(
                directory,
                "server-ca",
                "Server Root",
            )
            create_certificate.assert_called_once_with(
                directory,
                "mtls-server",
                "localhost",
                ca,
                ca_key,
                101,
                "serverAuth",
                "DNS:localhost",
            )

    def test_reuses_complete_identity_and_rejects_partial_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            paths = tuple(
                directory / name
                for name in (
                    "server-ca.crt",
                    "server-ca.key",
                    "mtls-server.crt",
                    "mtls-server.key",
                )
            )
            for path in paths:
                path.touch()
            with (
                mock.patch.object(mqtt_broker_config, "create_ca") as create_ca,
                mock.patch.object(
                    mqtt_broker_config,
                    "create_signed_certificate",
                ) as create_certificate,
            ):
                mqtt_broker_config.ensure_signed_crl_server_identity(
                    directory,
                )
            create_ca.assert_not_called()
            create_certificate.assert_not_called()

            paths[-1].unlink()
            with self.assertRaisesRegex(
                AssertionError,
                "incomplete shared CRL server identity fixture",
            ):
                mqtt_broker_config.ensure_signed_crl_server_identity(
                    directory,
                )


class SubscriptionLifecycleOracleTest(unittest.TestCase):
    # Independent MQTT 5 wire image: topic=subpub/local, Packet Identifier=42,
    # Subscription Identifier=53, payload=message.
    delivery = bytes.fromhex("000c7375627075622f6c6f63616c002a020b356d657373616765")

    def test_accepts_exact_initial_delivery(self) -> None:
        self.assertEqual(subscription_lifecycle._delivery(
            0x32, self.delivery, 5, "subpub/local", b"message", 53,
        ), 42)

    def test_rejects_wrong_flags_identifier_and_payload(self) -> None:
        invalid = (
            (0x3A, self.delivery),
            (0x30, self.delivery),
            (0x32, self.delivery[:14] + b"\x00\x00" + self.delivery[16:]),
            (0x32, self.delivery[:18] + b"\x36" + self.delivery[19:]),
            (0x32, self.delivery[:-1] + b"x"),
            (0x32, b"\xff\xff"),
        )
        for first, body in invalid:
            with self.subTest(first=first, body=body.hex()), self.assertRaises(AssertionError):
                subscription_lifecycle._delivery(first, body, 5, "subpub/local", b"message", 53)

    def test_no_matching_ack_does_not_hide_errors_or_wrong_packet_id(self) -> None:
        subscription_lifecycle._puback(0x40, bytes.fromhex("012c10"), 300, 5, matched=False)
        for body, matched in (("012c87", False), ("012d10", False), ("012c10", True)):
            with self.subTest(body=body, matched=matched), self.assertRaises(AssertionError):
                subscription_lifecycle._puback(0x40, bytes.fromhex(body), 300, 5, matched=matched)


if __name__ == "__main__":
    unittest.main()
