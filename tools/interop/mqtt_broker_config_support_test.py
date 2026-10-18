#!/usr/bin/env python3

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mqtt_broker_config_bridge
import mqtt_broker_config
from mqtt_broker_config import wait_process_line


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


if __name__ == "__main__":
    unittest.main()
