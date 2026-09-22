#!/usr/bin/env python3
"""Unit tests for outbound-bridge MQTT wire helpers."""

import socket
import unittest

import mqtt_outbound_bridge_support as support
from mqtt_outbound_bridge_harness import Case


class WireHelpersTests(unittest.TestCase):
    def test_case_protocol_labels_are_cli_stable(self) -> None:
        case = Case("case", 4, 5, 2, False)
        self.assertEqual(case.source_label, "v311")
        self.assertEqual(case.target_label, "v5")

    def test_read_packet_reassembles_fragmented_input(self) -> None:
        left, right = socket.socketpair()
        try:
            right.sendall(bytes.fromhex("30 05 0001 61 6263"))
            self.assertEqual(
                support.read_packet(left),
                bytes.fromhex("30 05 0001 61 6263"),
            )
        finally:
            left.close()
            right.close()

    def test_assert_publish_parses_mqtt5_packet_identifier_and_properties(
        self,
    ) -> None:
        packet = bytes.fromhex(
            "34 1f 0013 72656d6f74652f73656e736f72732f726f6f6d "
            "002a 00 7061796c6f6164"
        )
        self.assertEqual(
            support.assert_publish(
                packet, 5, qos=2, retain=False, payload=b"payload"
            ),
            42,
        )
        local_packet = bytes.fromhex(
            "34 1e 0012 6c6f63616c2f73656e736f72732f726f6f6d "
            "002a 00 7061796c6f6164"
        )
        self.assertEqual(
            support.assert_publish_on_topic(
                local_packet, 5, topic="local/sensors/room", qos=2,
                retain=False, payload=b"payload",
            ),
            42,
        )

    def test_assert_publish_rejects_wrong_application_message(self) -> None:
        packet = bytes.fromhex("30 07 0001 61 64617461")
        with self.assertRaisesRegex(AssertionError, "remapped topic"):
            support.assert_publish(
                packet, 4, qos=0, retain=False, payload=b"data"
            )

    def test_remaining_length_rejects_fifth_digit(self) -> None:
        with self.assertRaisesRegex(AssertionError, "Remaining Length"):
            support.decode_remaining_length(bytes.fromhex("30 80808080"))

    def test_ack_parser_observes_negative_pubrec_reason(self) -> None:
        support.assert_ack(bytes.fromhex("50 04 002a 97 00"), 5, 42, 0x97)
        with self.assertRaisesRegex(AssertionError, "ACK mismatch"):
            support.assert_ack(
                bytes.fromhex("50 04 002a 97 00"), 5, 42, 0x87
            )


if __name__ == "__main__":
    unittest.main()
