#!/usr/bin/env python3

import subprocess
import sys
import unittest
from unittest import mock

import mqtt_broker_config_bridge
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


if __name__ == "__main__":
    unittest.main()
