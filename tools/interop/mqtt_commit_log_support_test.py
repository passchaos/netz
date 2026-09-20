#!/usr/bin/env python3
"""Unit tests for MQTT commit-log wire helpers."""

import unittest

import mqtt_commit_log_support as support


class WireHelpersTests(unittest.TestCase):
    def test_connect_encodes_both_supported_protocol_versions(self) -> None:
        self.assertEqual(
            support.connect_packet(
                "c", clean_start=False, protocol=4, session_expiry=60
            ),
            bytes.fromhex("10 0d 00 04 4d515454 04 00 003c 0001 63"),
        )
        self.assertEqual(
            support.connect_packet(
                "c", clean_start=False, protocol=5, session_expiry=60
            ),
            bytes.fromhex(
                "10 13 00 04 4d515454 05 00 003c 05 11 0000003c 0001 63"
            ),
        )

    def test_subscription_and_publish_have_version_specific_properties(self) -> None:
        self.assertEqual(
            support.subscribe_packet(7, "a", qos=1, protocol=4),
            bytes.fromhex("82 06 0007 0001 61 01"),
        )
        self.assertEqual(
            support.subscribe_packet(7, "a", qos=1, protocol=5),
            bytes.fromhex("82 09 0007 02 0b35 0001 61 01"),
        )
        self.assertEqual(
            support.publish_packet(
                "a", b"b", 9, dup=True, protocol=4
            ),
            bytes.fromhex("3a 06 0001 61 0009 62"),
        )
        self.assertEqual(
            support.publish_packet(
                "a", b"b", 9, dup=True, protocol=5
            ),
            bytes.fromhex("3a 07 0001 61 0009 00 62"),
        )
        self.assertEqual(
            support.qos0_publish_packet(
                "a", b"b", retain=True, protocol=4
            ),
            bytes.fromhex("31 04 0001 61 62"),
        )

    def test_will_payload_has_version_specific_property_prefix(self) -> None:
        self.assertEqual(
            support.connect_packet(
                "c", clean_start=True, protocol=4, session_expiry=0,
                will_topic="w", will_payload=b"p", will_qos=1,
            ),
            bytes.fromhex(
                "10 13 0004 4d515454 04 0e 003c 0001 63 0001 77 0001 70"
            ),
        )
        with self.assertRaisesRegex(ValueError, "Will Delay"):
            support.connect_packet(
                "c", clean_start=True, protocol=4,
                will_topic="w", will_delay=1,
            )

    def test_invalid_protocol_or_qos_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "protocol"):
            support.connect_packet("c", clean_start=True, protocol=3)
        with self.assertRaisesRegex(ValueError, "QoS"):
            support.publish_packet("a", b"b", 1, qos=0)
        with self.assertRaisesRegex(ValueError, "Message Expiry"):
            support.publish_packet(
                "a", b"b", 1, protocol=4, expiry_seconds=1
            )


if __name__ == "__main__":
    unittest.main()
