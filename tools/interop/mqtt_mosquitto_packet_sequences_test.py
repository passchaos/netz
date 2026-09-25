#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import mqtt_mosquitto_packet_sequences as sequences


class PacketDslTests(unittest.TestCase):
    def test_parses_every_upstream_token_kind(self) -> None:
        self.assertEqual(
            sequences.parse_message(
                "i1 H258 k3 m4 s2 'ab cd' v128 r127 0A0B"
            ),
            bytes.fromhex(
                "01 0102 0003 0004 0002 6162206364 8001 7f 0a0b"
            ),
        )

    def test_rejects_an_incomplete_quoted_string(self) -> None:
        with self.assertRaisesRegex(ValueError, "incomplete string"):
            sequences.parse_message("'unterminated value")


class SequenceLoadingTests(unittest.TestCase):
    def write_source(self, root: Path, groups: list[dict]) -> dict[str, str]:
        source = json.dumps(groups).encode()
        (root / "TEST.json").write_bytes(source)
        return {"TEST.json": hashlib.sha256(source).hexdigest()}

    def test_inherits_group_defaults_and_applies_test_overrides(self) -> None:
        groups = [{
            "group": "portable",
            "ver": 5,
            "connect": False,
            "expect_disconnect": True,
            "tests": [
                {"name": "inherited", "msgs": [
                    {"type": "send", "payload": "C0 r0"}
                ]},
                {
                    "name": "overridden",
                    "ver": 4,
                    "connect": True,
                    "expect_disconnect": False,
                    "msgs": [{"type": "recv", "payload": "D0 00"}],
                },
            ],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            loaded = sequences.load_sequences(root, selected)

        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0]["protocol"], 5)
        self.assertFalse(loaded[0]["connect"])
        self.assertTrue(loaded[0]["expect_disconnect"])
        self.assertEqual(loaded[1]["protocol"], 4)
        self.assertTrue(loaded[1]["connect"])
        self.assertFalse(loaded[1]["expect_disconnect"])

    def test_rejects_nonportable_actions(self) -> None:
        groups = [{
            "group": "not-portable",
            "tests": [{
                "name": "helper",
                "msgs": [{"type": "subscribe"}],
            }],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            with self.assertRaisesRegex(ValueError, "not a portable raw sequence"):
                sequences.load_sequences(root, selected)

    def test_accepts_external_publish_action(self) -> None:
        groups = [{
            "group": "portable-helper",
            "tests": [{
                "name": "publish",
                "msgs": [{
                    "type": "external_publish",
                    "topic": "p",
                    "qos": 2,
                    "payload": "message",
                    "retain": True,
                }],
            }],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            loaded = sequences.load_sequences(root, selected)

        self.assertEqual(loaded[0]["actions"], groups[0]["tests"][0]["msgs"])

    def test_rejects_source_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "TEST.json").write_text("[]")
            with self.assertRaisesRegex(ValueError, "source hash mismatch"):
                sequences.load_sequences(root, {"TEST.json": "0" * 64})

    def test_rejects_packet_generator_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "mqtt_packets.py"
            source.write_text("changed")
            with self.assertRaisesRegex(ValueError, "source hash mismatch"):
                sequences.verify_source_hash(source, "0" * 64)

    def test_default_manifest_is_complete_and_pinned(self) -> None:
        self.assertEqual(
            set(sequences.SEQUENCE_FILES),
            {
                "AUTH.json",
                "DISCONNECT.json",
                "FLOW.json",
                "FORBIDDEN.json",
                "OTHER.json",
                "PINGREQ.json",
                "PINGRESP.json",
                "PUBACK.json",
                "PUBCOMP.json",
                "PUBREC.json",
                "PUBREL.json",
                "REGRESSION.json",
                "SUBACK.json",
                "SUBSCRIBE.json",
                "UNSUBACK.json",
                "UNSUBSCRIBE.json",
            },
        )
        self.assertEqual(
            sequences.SEQUENCE_FILES["AUTH.json"],
            "e9591dd6236144f9d913d9cf2a167e2ed0aacc45f9e8ec1adb6a96031958b1a4",
        )
        self.assertEqual(
            sequences.SEQUENCE_FILES["DISCONNECT.json"],
            "7572c864a8aea807ab8122a28fa6721292ee367b19e6cbb2a6e76ccb2d21f3bd",
        )
        self.assertEqual(
            sequences.SEQUENCE_FILES["PUBREL.json"],
            "5edf48213e6a9c85254b6255618fa5c67b47bfe59bf84b3b09307b8691cea225",
        )
        self.assertEqual(
            sequences.SEQUENCE_SUBSET_FILES,
            {
                "CONNECT.json":
                    "22dc51ebccb0d9938bb1e5111988ab02a061671dec15beab8aa4410e948158ac",
                "CONNACK.json":
                    "307445b4773e219f4377b880e19678791ee70379f85a43c729b45af548fb9108",
                "PUBLISH.json":
                    "a3b6a5d5b2cd44b70550ce17a03ff5607cc76e4f165ae1f1f6deb68eb7013f86",
            },
        )
        self.assertEqual(
            set(sequences.SEQUENCE_EXCLUSIONS),
            set(sequences.SEQUENCE_SUBSET_FILES),
        )
        self.assertEqual(sequences.EXPECTED_COMPLETE_SEQUENCE_COUNT, 1212)
        self.assertEqual(
            sequences.EXPECTED_SUBSET_SEQUENCE_COUNTS,
            {
                "CONNECT.json": 299,
                "CONNACK.json": 145,
                "PUBLISH.json": 158,
            },
        )
        self.assertEqual(sequences.EXPECTED_SUBSET_SEQUENCE_COUNT, 602)
        self.assertEqual(sequences.EXPECTED_SEQUENCE_COUNT, 1814)
        self.assertEqual(sequences.EXPECTED_EXPECTATION_OVERRIDE_COUNT, 259)
        self.assertEqual(
            sequences.EXPECTED_CONNECT_REFUSAL_DIAGNOSTIC_COUNT, 12,
        )
        self.assertEqual(
            set(sequences.CONNECT_REFUSAL_DIAGNOSTICS),
            {
                ("CONNECT.json", "v3.1.1 CONNECT",
                 "10 incorrect command flags"),
                ("CONNECT.json", "v3.1.1 CONNECT",
                 "10 missing keepalive"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 Will flag 1 Will Qos 3 [MQTT-3.1.2-14]"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 [MQTT-3.1.2-17]"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 Username with 0x0000"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 Username with 0xD800"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 Username with 0x0001"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 Username with 0x001F"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 Username with 0x007F"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 Username with 0x009F"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 Username with 0xFFFF"),
                ("CONNECT.json", "v5.0   CONNECT",
                 "10 [MQTT-3.1.2-19]"),
            },
        )
        self.assertEqual(
            set(sequences.CONNECT_REFUSAL_DIAGNOSTICS.values()),
            {bytes.fromhex("20 03 00 81 00")},
        )
        self.assertEqual(
            set(sequences.SEQUENCE_EXCLUSIONS["CONNECT.json"]),
            {
                ("v3.1   CONNECT", test)
                for test in (
                    "10 ok ",
                    "14 ok ",
                    "10 proto ver 2",
                    "10 proto ver 4",
                    "10 proto ver 6",
                    "10 empty client ID",
                    "10 ok",
                    "10 remaining length 5 bytes",
                )
            },
        )
        self.assertEqual(
            sequences.SEQUENCE_EXCLUSIONS["CONNACK.json"],
            {("v3.1.1 CONNACK", "issue 2163 v3"):
                "unsupported_mqtt_3_1"},
        )
        self.assertEqual(
            set(sequences.SEQUENCE_EXCLUSIONS["PUBLISH.json"]),
            {
                ("v3.1.1 PUBLISH", "34 QoS 2 Dup flow*3"),
                ("v5.0   PUBLISH", "34 QoS 2 Dup flow*3"),
            },
        )
        self.assertEqual(
            {
                reason: sum(
                    value == reason
                    for exclusions in sequences.SEQUENCE_EXCLUSIONS.values()
                    for value in exclusions.values()
                )
                for reason in sequences.EXCLUSION_REASONS
            },
            {
                "unsupported_mqtt_3_1": 9,
                "mosquitto_qos2_reuse_limit": 2,
            },
        )
        expected_override_counts = {
            "AUTH.json": 5,
            "CONNECT.json": 87,
            "CONNACK.json": 5,
            "DISCONNECT.json": 27,
            "PUBACK.json": 24,
            "PUBREC.json": 24,
            "PUBREL.json": 28,
            "PUBCOMP.json": 24,
            "PUBLISH.json": 22,
            "SUBSCRIBE.json": 9,
            "UNSUBSCRIBE.json": 4,
        }
        self.assertEqual(
            {
                filename: len(overrides)
                for filename, overrides in
                    sequences.EXPECTATION_OVERRIDES.items()
            },
            expected_override_counts,
        )
        for filename, packet, prefix in (
            ("PUBACK.json", "PUBACK", "40"),
            ("PUBREC.json", "PUBREC", "50"),
            ("PUBCOMP.json", "PUBCOMP", "70"),
        ):
            self.assertEqual(
                set(sequences.EXPECTATION_OVERRIDES[filename]),
                {
                    (
                        f"v5.0   {packet} DISALLOWED PROPERTIES",
                        f"{prefix} with {case}",
                        1,
                    )
                    for case in sequences.ACK_DISALLOWED_PROPERTY_CASES
                },
            )
        self.assertEqual(
            set(sequences.EXPECTATION_OVERRIDES["AUTH.json"]),
            {
                ("v5.0   AUTH", "F0 long", 1),
                ("v5.0   AUTH", "F1", 1),
                ("v5.0   AUTH", "F2", 1),
                ("v5.0   AUTH", "F4", 1),
                ("v5.0   AUTH", "F8", 1),
            },
        )
        self.assertEqual(
            set(sequences.EXPECTATION_OVERRIDES["CONNECT.json"]),
            {
                *((group, test, occurrence, 1)
                  for group, test, occurrence in sequences.CONNECT_SUCCESS_CASES),
                *(("v5.0   CONNECT DISALLOWED PROPERTIES", test, 0, 1)
                  for test in sequences.CONNECT_DISALLOWED_PROPERTY_CASES),
                *(("v5.0   WILL DISALLOWED PROPERTIES", test, 0, 1)
                  for test in sequences.WILL_DISALLOWED_PROPERTY_CASES),
                ("v5.0   CONNECT", "10 Client ID with 0x0000", 0, 1),
                ("v5.0   CONNECT", "10 Client ID with U+D800", 0, 1),
                ("v5.0   CONNECT", "10 Client ID with U+0001", 0, 1),
                ("v5.0   CONNECT", "10 Client ID with U+001F", 0, 1),
                ("v5.0   CONNECT", "10 Client ID with U+007F", 0, 1),
                ("v5.0   CONNECT", "10 Client ID with U+009F", 0, 1),
                ("v5.0   CONNECT", "10 Client ID with U+FFFF", 0, 1),
            },
        )
        self.assertEqual(
            set(sequences.EXPECTATION_OVERRIDES["CONNACK.json"]),
            {
                ("v5.0   CONNACK", "21", 1),
                ("v5.0   CONNACK", "22", 1),
                ("v5.0   CONNACK", "24", 1),
                ("v5.0   CONNACK", "28", 1),
                ("v5.0   CONNACK", "issue 2163 v5", 1),
            },
        )
        self.assertEqual(
            set(sequences.EXPECTATION_OVERRIDES["PUBREL.json"]),
            {
                (
                    "v5.0   PUBREL DISALLOWED PROPERTIES",
                    f"62 with {case}",
                    1,
                )
                for case in sequences.ACK_DISALLOWED_PROPERTY_CASES
            } | {
                ("v5.0   PUBREL", f"{header} unsolicited", 1)
                for header in ("63", "64", "66", "6A")
            },
        )
        self.assertEqual(
            set(sequences.EXPECTATION_OVERRIDES["PUBLISH.json"]),
            {
                ("v5.0   PUBLISH DISALLOWED PROPERTIES", case, 1)
                for case in sequences.PUBLISH_DISALLOWED_PROPERTY_CASES
            } | {
                (
                    "v5.0   PUBLISH ALLOWED PROPERTIES",
                    "maximum packet size",
                    1,
                ),
                ("v5.0   PUBLISH", "30 topic 0", 1),
                (
                    "v5.0   PUBLISH",
                    "30 topic with + [MQTT-3.3.2-2]",
                    1,
                ),
                (
                    "v5.0   PUBLISH",
                    "30 topic with # [MQTT-3.3.2-2]",
                    1,
                ),
            },
        )
        self.assertEqual(
            set(sequences.EXPECTATION_OVERRIDES["SUBSCRIBE.json"]),
            {
                (
                    "v5.0   SUBSCRIBE",
                    "82 QoS 3 [MQTT-3-8.3-2] (no topic or qos)",
                    1,
                ),
                (
                    "v5.0   SUBSCRIBE",
                    "82 QoS 3 [MQTT-3-8.3-4]",
                    1,
                ),
                (
                    "v5.0   SUBSCRIBE",
                    "82 QoS 0 retain handling=3 0x30 [MQTT-3-8.3-4]",
                    1,
                ),
                ("v5.0   SUBSCRIBE", "82 short 3", 1),
                ("v5.0   SUBSCRIBE", "82 single topic len 0", 1),
                ("v5.0   SUBSCRIBE", "82 multiple topic 1 len 0", 1),
                ("v5.0   SUBSCRIBE", "82 multiple topic 2 len 0", 1),
                ("v5.0   SUBSCRIBE", "82 multiple topic 1,2 len 0", 1),
                ("v5.0   SUBSCRIBE", "82 mid 0", 1),
            },
        )
        self.assertEqual(
            set(
                sequences.EXPECTATION_OVERRIDES[
                    "UNSUBSCRIBE.json"
                ]
            ),
            {
                ("v5.0   UNSUBSCRIBE", "A2 multiple zero 1st", 1),
                ("v5.0   UNSUBSCRIBE", "A2 multiple zero 2nd", 1),
                (
                    "v5.0   UNSUBSCRIBE",
                    "A2 short 3 [MQTT-3.10.3-2]",
                    1,
                ),
                ("v5.0   UNSUBSCRIBE", "A2 zero mid", 1),
            },
        )
        self.assertEqual(
            set(sequences.EXPECTATION_OVERRIDES["DISCONNECT.json"]),
            {
                (
                    "v5.0   DISCONNECT DISALLOWED PROPERTIES",
                    f"E0 with {case}",
                    1,
                )
                for case in sequences.DISCONNECT_DISALLOWED_PROPERTY_CASES
            } | {
                (
                    "v5.0   DISCONNECT",
                    "E0 non-zero session expiry",
                    1,
                ),
                *{
                    (
                        "v5.0   DISCONNECT",
                        f"{header} [MQTT-3.14.1-1]",
                        1,
                    )
                    for header in ("E1", "E2", "E4", "E8")
                },
            },
        )
        self.assertEqual(
            sequences.EXPECTATION_OVERRIDES["PUBLISH.json"][
                (
                    "v5.0   PUBLISH ALLOWED PROPERTIES",
                    "maximum packet size",
                    1,
                )
            ],
            (
                "20 r14 00000b 22 H10 27 H30 84 80 21 00 14",
                "20 r14 00000B 21 H20 27 L2000000 22 H10",
                "equivalent_connack_property_order",
            ),
        )
        self.assertEqual(
            sequences.EXPECTATION_OVERRIDES["DISCONNECT.json"][
                (
                    "v5.0   DISCONNECT",
                    "E0 non-zero session expiry",
                    1,
                )
            ],
            (
                "20 r14 00000B 22 H10 27 L2000000 21 H20",
                "20 r14 00000B 21 H20 27 L2000000 22 H10",
                "equivalent_connack_property_order",
            ),
        )
        override_reasons = [
            override[2]
            for overrides in
                sequences.EXPECTATION_OVERRIDES.values()
            for override in overrides.values()
        ]
        self.assertEqual(
            {
                reason: override_reasons.count(reason)
                for reason in sequences.EXPECTATION_OVERRIDE_REASONS
            },
            {
                "mqtt5_property_context_malformed": 186,
                "mqtt5_invalid_utf8_malformed": 7,
                "mqtt5_publish_protocol_error": 3,
                "mqtt5_subscribe_protocol_error": 9,
                "mqtt5_unsubscribe_protocol_error": 4,
                "mqtt5_fixed_header_flags_malformed": 17,
                "mqtt5_truncated_variable_header_malformed": 1,
                "equivalent_connack_property_order": 32,
            },
        )
        for filename, overrides in (
            sequences.EXPECTATION_OVERRIDES.items()
        ):
            for identity, (source, expected, reason) in overrides.items():
                self.assertEqual(identity[-1], 1, filename)
                self.assertIn(reason, sequences.EXPECTATION_OVERRIDE_REASONS)
                if reason in {
                    "mqtt5_property_context_malformed",
                    "mqtt5_fixed_header_flags_malformed",
                    "mqtt5_truncated_variable_header_malformed",
                }:
                    source_bytes = sequences.parse_message(source)
                    expected_bytes = sequences.parse_message(expected)
                    if filename == "CONNECT.json":
                        self.assertEqual(
                            (source_bytes[3], expected_bytes[3]),
                            (0x82, 0x81),
                        )
                    else:
                        self.assertEqual(
                            (source, expected),
                            ("E0 r1 82", "E0 r1 81"),
                        )
                elif reason == "mqtt5_invalid_utf8_malformed":
                    self.assertEqual(
                        (source, expected),
                        ("20 r3 00 85 00", "20 r3 00 81 00"),
                    )
                elif reason != "equivalent_connack_property_order":
                    self.assertEqual((source, expected),
                                     ("E0 r1 81", "E0 r1 82"))
        self.assertEqual(
            sequences.PACKET_SEQUENCE_BROKER_ARGS,
            (
                "--max-outgoing-inflight=20",
                "--max-packet-size=2000000",
                "--topic-alias-maximum=10",
                "--strict-utf8",
            ),
        )
        self.assertEqual(len(sequences.MQTT_PACKETS_SHA256), 64)
        int(sequences.MQTT_PACKETS_SHA256, 16)
        for digest in sequences.SEQUENCE_FILES.values():
            self.assertEqual(len(digest), 64)
            int(digest, 16)
        for digest in sequences.SEQUENCE_SUBSET_FILES.values():
            self.assertEqual(len(digest), 64)
            int(digest, 16)

    def test_rejects_missing_named_subset_exclusion(self) -> None:
        groups = [{
            "group": "portable",
            "tests": [{"name": "present", "msgs": []}],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            with self.assertRaisesRegex(ValueError, "exclusions not found"):
                sequences.load_sequences(
                    root,
                    selected,
                    {"TEST.json": {
                        ("portable", "missing"):
                            "unsupported_mqtt_3_1",
                    }},
                )

    def test_rejects_unknown_subset_exclusion_reason(self) -> None:
        groups = [{
            "group": "portable",
            "tests": [{"name": "excluded", "msgs": []}],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            with self.assertRaisesRegex(ValueError, "unknown exclusion reason"):
                sequences.load_sequences(
                    root,
                    selected,
                    {"TEST.json": {
                        ("portable", "excluded"): "undocumented",
                    }},
                )

    def test_applies_exact_standard_expectation_override(self) -> None:
        groups = [{
            "group": "portable",
            "tests": [{
                "name": "reason",
                "msgs": [
                    {"type": "send", "payload": "C0 r0"},
                    {"type": "recv", "payload": "E0 r1 82"},
                ],
            }],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            loaded = sequences.load_sequences(
                root,
                selected,
                expectation_overrides={"TEST.json": {
                    ("portable", "reason", 1): (
                        "E0 r1 82",
                        "E0 r1 81",
                        "mqtt5_property_context_malformed",
                    ),
                }},
            )
        self.assertEqual(loaded[0]["actions"][1]["payload"], "E0 r1 81")
        self.assertEqual(
            groups[0]["tests"][0]["msgs"][1]["payload"],
            "E0 r1 82",
        )

    def test_rejects_standard_expectation_source_drift(self) -> None:
        groups = [{
            "group": "portable",
            "tests": [{
                "name": "reason",
                "msgs": [{"type": "recv", "payload": "E0 r1 81"}],
            }],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            with self.assertRaisesRegex(ValueError, "override source drift"):
                sequences.load_sequences(
                    root,
                    selected,
                    expectation_overrides={"TEST.json": {
                        ("portable", "reason", 0): (
                            "E0 r1 82",
                            "E0 r1 81",
                            "mqtt5_property_context_malformed",
                        ),
                    }},
                )

    def test_disambiguates_duplicate_names_by_source_payload(self) -> None:
        groups = [{
            "group": "portable",
            "tests": [
                {"name": "duplicate", "msgs": [
                    {"type": "send", "payload": "C0 r0"},
                    {"type": "recv", "payload": "D0 r0"},
                ]},
                {"name": "duplicate", "msgs": [
                    {"type": "send", "payload": "C0 r0"},
                    {"type": "recv", "payload": "E0 r1 82"},
                ]},
            ],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            loaded = sequences.load_sequences(
                root,
                selected,
                expectation_overrides={"TEST.json": {
                    ("portable", "duplicate", 0, 1): (
                        "D0 r0", "D0 r0",
                        "equivalent_connack_property_order",
                    ),
                }},
            )
        self.assertEqual(loaded[0]["actions"][1]["payload"], "D0 r0")
        self.assertEqual(loaded[1]["actions"][1]["payload"], "E0 r1 82")

    def test_rejects_missing_or_unknown_standard_override(self) -> None:
        groups = [{
            "group": "portable",
            "tests": [{
                "name": "reason",
                "msgs": [{"type": "recv", "payload": "E0 r1 82"}],
            }],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            with self.assertRaisesRegex(ValueError, "overrides not found"):
                sequences.load_sequences(
                    root,
                    selected,
                    expectation_overrides={"TEST.json": {
                        ("portable", "missing", 0): (
                            "E0 r1 82",
                            "E0 r1 81",
                            "mqtt5_property_context_malformed",
                        ),
                    }},
                )
            with self.assertRaisesRegex(ValueError, "unknown override reason"):
                sequences.load_sequences(
                    root,
                    selected,
                    expectation_overrides={"TEST.json": {
                        ("portable", "reason", 0): (
                            "E0 r1 82", "E0 r1 81", "undocumented",
                        ),
                    }},
                )


class ExternalPublishTests(unittest.TestCase):
    class FakeSocket:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def sendall(self, packet: bytes) -> None:
            self.sent.append(packet)

    class FakeBroker:
        def __init__(self) -> None:
            self.socket = ExternalPublishTests.FakeSocket()

        def connect(self):
            return self.socket

    class FakePackets:
        @staticmethod
        def gen_publish(**kwargs) -> bytes:
            return repr(sorted(kwargs.items())).encode()

        @staticmethod
        def gen_puback(*, mid: int) -> bytes:
            return bytes((0x40, mid))

        @staticmethod
        def gen_pubrec(*, mid: int) -> bytes:
            return bytes((0x50, mid))

        @staticmethod
        def gen_pubrel(*, mid: int) -> bytes:
            return bytes((0x62, mid))

        @staticmethod
        def gen_pubcomp(*, mid: int) -> bytes:
            return bytes((0x70, mid))

    def test_qos2_helper_runs_complete_v311_handshake(self) -> None:
        broker = self.FakeBroker()
        action = {
            "topic": "p",
            "payload": "message",
            "qos": 2,
            "retain": True,
        }
        with (
            mock.patch.object(sequences, "connect_client") as connect,
            mock.patch.object(sequences, "expect_sequence_packet") as expect,
        ):
            sequences.external_publish(
                broker, action, self.FakePackets, "helper"
            )

        connect.assert_called_once_with(
            broker.socket, self.FakePackets, "helper", 4
        )
        self.assertIn(b"('mid', 1)", broker.socket.sent[0])
        self.assertIn(b"('qos', 2)", broker.socket.sent[0])
        self.assertIn(b"('retain', True)", broker.socket.sent[0])
        self.assertEqual(broker.socket.sent[1], bytes((0x62, 1)))
        self.assertEqual(
            [call.args[1] for call in expect.call_args_list],
            [bytes((0x50, 1)), bytes((0x70, 1))],
        )

    def test_rejects_invalid_helper_qos_before_connect(self) -> None:
        broker = self.FakeBroker()
        with self.assertRaisesRegex(ValueError, "invalid helper QoS"):
            sequences.external_publish(
                broker,
                {"topic": "p", "payload": "v", "qos": 3},
                self.FakePackets,
                "helper",
            )


if __name__ == "__main__":
    unittest.main()
