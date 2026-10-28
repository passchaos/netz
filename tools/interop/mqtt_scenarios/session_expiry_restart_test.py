from __future__ import annotations

import socket
import unittest

from mqtt_commit_log_support import ack_packet, publish_packet
from mqtt_scenarios import session_expiry_restart as scenario


class SessionExpiryOracleTests(unittest.TestCase):
    def test_source_matrix_preserves_all_five_upstream_variants(self) -> None:
        upstream = [case for case in scenario.CASES if case.source is not None]
        self.assertEqual(
            [(case.resubscribe, case.sibling_count, case.retain_count, case.qos) for case in upstream],
            [(False, 0, 0, 1), (True, 0, 0, 1), (False, 20, 0, 1), (True, 20, 0, 1), (False, 0, 30, 1)],
        )
        self.assertEqual(scenario.COUNT, 100)
        self.assertEqual(len(scenario.CASES) - len(upstream), 1)

    def test_delivery_rejects_duplicate_flags_payload_and_topic_changes(self) -> None:
        case = scenario.CASES[0]
        topic = scenario.TOPIC
        valid = publish_packet(topic, scenario.payload(42), 17)
        first, body = valid[0], valid[2:]
        self.assertEqual(scenario.delivery(first, body, case, 42), 17)
        for wrong_first in (first | 0x08, first | 1, 0x34, 0x30):
            with self.subTest(first=wrong_first), self.assertRaises(AssertionError):
                scenario.delivery(wrong_first, body, case, 42)
        for wrong_body in (body[:-1] + b"x", body.replace(topic.encode(), b"X" * len(topic)), body[:-1]):
            with self.subTest(body=wrong_body), self.assertRaises(AssertionError):
                scenario.delivery(first, wrong_body, case, 42)
        offset = 2 + len(topic)
        with self.assertRaisesRegex(AssertionError, "zero"):
            scenario.delivery(first, body[:offset] + b"\x00\x00" + body[offset + 2:], case, 42)

    def test_qos2_consumer_accepts_interleaved_publish_and_pubrel(self) -> None:
        case = scenario.CASES[-1]
        left, right = socket.socketpair()
        with left, right:
            left.settimeout(1)
            right.settimeout(1)
            right.sendall(
                publish_packet(scenario.TOPIC, scenario.payload(0), 17, qos=2)
                + publish_packet(scenario.TOPIC, scenario.payload(1), 18, qos=2)
                + ack_packet(0x62, 17) + ack_packet(0x62, 18)
                + b"\xd0\x00"
            )
            scenario.consume(left, case, range(2))
            expected = ack_packet(0x50, 17) + ack_packet(0x50, 18) + ack_packet(0x70, 17) + ack_packet(0x70, 18) + b"\xc0\x00"
            actual = bytearray()
            while len(actual) < len(expected):
                actual.extend(right.recv(len(expected) - len(actual)))
            self.assertEqual(bytes(actual), expected)

    def test_quiet_barrier_rejects_late_publication_and_eof(self) -> None:
        for extra in (publish_packet(scenario.TOPIC, b"unexpected", 1), b""):
            left, right = socket.socketpair()
            with left, right:
                left.settimeout(1)
                right.sendall(extra)
                right.shutdown(socket.SHUT_WR)
                with self.subTest(extra=extra), self.assertRaises(AssertionError):
                    scenario.consume(left, scenario.CASES[0], range(0))

    def test_qos2_consumer_rejects_unknown_pubrel(self) -> None:
        left, right = socket.socketpair()
        with left, right:
            left.settimeout(1)
            right.sendall(ack_packet(0x62, 19))
            with self.assertRaisesRegex(AssertionError, "unknown PUBREL"):
                scenario.consume(left, scenario.CASES[-1], range(1))


if __name__ == "__main__":
    unittest.main()
