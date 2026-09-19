#!/usr/bin/env python3
"""Unit tests for fail-closed Mosquitto vector source identities."""

from pathlib import Path
import tempfile
import unittest

import persistent_subscriptions
import source_lock
import subscription_flip_flop


class SourceLockTests(unittest.TestCase):
    def test_accepts_exact_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.py"
            path.write_bytes(b"locked source\n")
            source_lock.verify_source_hash(
                path,
                "8454df03c6142b8211ad66c10bf448fc022ba86eb99962f5bc14f65cb26725d8",
            )

    def test_rejects_changed_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.py"
            path.write_bytes(b"changed source\n")
            with self.assertRaisesRegex(RuntimeError, "unexpected SHA-256"):
                source_lock.verify_source_hash(path, "0" * 64)

    def test_manifest_has_exact_sources_and_scenario_counts(self) -> None:
        self.assertEqual(
            source_lock.MOSQUITTO_SOURCE_SHA256,
            {
                "broker/02-subpub-recover-subscriptions.py":
                    "2f6289be6000de501a7329b635ea1659f81abb06fbf6f597144a160371e8a271",
                "broker/02-subscribe-persistence-flipflop.py":
                    "a505ba09fbeea473296914d9bc7704c88ef99e2db0a5c952c220ab7104b8dffe",
            },
        )
        self.assertEqual(persistent_subscriptions.SCENARIO_COUNT, 2)
        self.assertEqual(subscription_flip_flop.SCENARIO_COUNT, 2)


if __name__ == "__main__":
    unittest.main()
