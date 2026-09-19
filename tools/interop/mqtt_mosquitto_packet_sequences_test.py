#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

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
                "msgs": [{"type": "external_publish"}],
            }],
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = self.write_source(root, groups)
            with self.assertRaisesRegex(ValueError, "not a portable raw sequence"):
                sequences.load_sequences(root, selected)

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
                "FORBIDDEN.json",
                "PINGREQ.json",
                "PINGRESP.json",
                "PUBACK.json",
                "PUBCOMP.json",
                "PUBREC.json",
                "SUBACK.json",
                "UNSUBACK.json",
            },
        )
        self.assertEqual(sequences.EXPECTED_SEQUENCE_COUNT, 628)
        self.assertEqual(len(sequences.MQTT_PACKETS_SHA256), 64)
        int(sequences.MQTT_PACKETS_SHA256, 16)
        for digest in sequences.SEQUENCE_FILES.values():
            self.assertEqual(len(digest), 64)
            int(digest, 16)


if __name__ == "__main__":
    unittest.main()
