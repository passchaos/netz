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
                "FLOW.json",
                "FORBIDDEN.json",
                "PINGREQ.json",
                "PINGRESP.json",
                "PUBACK.json",
                "PUBCOMP.json",
                "PUBREC.json",
                "REGRESSION.json",
                "SUBACK.json",
                "UNSUBACK.json",
            },
        )
        self.assertEqual(sequences.EXPECTED_SEQUENCE_COUNT, 663)
        self.assertEqual(len(sequences.MQTT_PACKETS_SHA256), 64)
        int(sequences.MQTT_PACKETS_SHA256, 16)
        for digest in sequences.SEQUENCE_FILES.values():
            self.assertEqual(len(digest), 64)
            int(digest, 16)


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
