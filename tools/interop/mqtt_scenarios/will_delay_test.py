import socket
import time
import unittest

from mqtt_scenarios.will_delay import quiet_until


class QuietDeadlineOracleTest(unittest.TestCase):
    def test_rejects_a_byte_arriving_before_the_deadline(self) -> None:
        receiver, sender = socket.socketpair()
        with receiver, sender:
            sender.sendall(b"\x30")
            with self.assertRaisesRegex(AssertionError, "unexpected MQTT byte"):
                quiet_until(receiver, time.monotonic() + 0.05, "early Will")

    def test_closed_observer_cannot_prove_no_will(self) -> None:
        receiver, sender = socket.socketpair()
        with receiver:
            sender.close()
            with self.assertRaisesRegex(AssertionError, "observer closed"):
                quiet_until(receiver, time.monotonic() + 0.05, "lost observer")

    def test_quiet_interval_restores_the_original_socket_budget(self) -> None:
        receiver, sender = socket.socketpair()
        with receiver, sender:
            receiver.settimeout(2.0)
            started = time.monotonic()
            quiet_until(receiver, started + 0.02, "live observer")
            self.assertGreaterEqual(time.monotonic() - started, 0.02)
            self.assertEqual(receiver.gettimeout(), 2.0)
            sender.sendall(b"\xd0")
            self.assertEqual(receiver.recv(1), b"\xd0")


if __name__ == "__main__":
    unittest.main()
