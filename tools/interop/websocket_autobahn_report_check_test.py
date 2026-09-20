#!/usr/bin/env python3
"""Tests for strict Autobahn report validation."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE = Path(__file__).with_name("websocket_autobahn_report_check.py")
SPEC = importlib.util.spec_from_file_location(
    "websocket_autobahn_report_check", MODULE
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class AutobahnReportCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write(self, value: object) -> None:
        (self.directory / "index.json").write_text(
            json.dumps(value), encoding="utf-8"
        )

    def test_accepts_complete_report_and_documented_statuses(self) -> None:
        cases = {
            str(index): {"behavior": "OK", "behaviorClose": "OK"}
            for index in range(1, 518)
        }
        cases["7.1.6"] = {
            "behavior": "INFORMATIONAL",
            "behaviorClose": "INFORMATIONAL",
        }
        cases.pop("517")
        self.write({"netz": cases})
        behavior, close, non_ok = CHECK.validate(
            self.directory, expected_agent="netz", expected_count=517
        )
        self.assertEqual(517, sum(behavior.values()))
        self.assertEqual(1, behavior["INFORMATIONAL"])
        self.assertEqual(1, close["INFORMATIONAL"])
        self.assertEqual([("7.1.6", "INFORMATIONAL", "INFORMATIONAL")], non_ok)

    def test_rejects_incomplete_full_report(self) -> None:
        self.write({"netz": {"1.1.1": {"behavior": "OK", "behaviorClose": "OK"}}})
        with self.assertRaisesRegex(CHECK.ReportError, "contained 1 cases, expected 517"):
            CHECK.validate(self.directory, expected_agent="netz", expected_count=517)

    def test_filtered_report_must_still_be_nonempty(self) -> None:
        self.write({"netz": {}})
        with self.assertRaisesRegex(CHECK.ReportError, "no case results"):
            CHECK.validate(self.directory, expected_agent="netz", expected_count=None)

    def test_rejects_wrong_or_extra_agent(self) -> None:
        valid = {"1.1.1": {"behavior": "OK", "behaviorClose": "OK"}}
        self.write({"other": valid})
        with self.assertRaisesRegex(CHECK.ReportError, "expected.*netz"):
            CHECK.validate(self.directory, expected_agent="netz", expected_count=None)
        self.write({"netz": valid, "other": valid})
        with self.assertRaisesRegex(CHECK.ReportError, "expected.*netz"):
            CHECK.validate(self.directory, expected_agent="netz", expected_count=None)

    def test_rejects_missing_and_failed_statuses(self) -> None:
        self.write({"netz": {"1.1.1": {"behavior": "OK"}}})
        with self.assertRaisesRegex(CHECK.ReportError, "missing behavior status"):
            CHECK.validate(self.directory, expected_agent="netz", expected_count=None)
        self.write({"netz": {"1.1.1": {"behavior": "FAILED", "behaviorClose": "OK"}}})
        with self.assertRaisesRegex(CHECK.ReportError, "rejected status"):
            CHECK.validate(self.directory, expected_agent="netz", expected_count=None)

    def test_rejects_duplicate_case_keys(self) -> None:
        (self.directory / "index.json").write_text(
            '{"netz":{"1.1.1":{"behavior":"OK","behaviorClose":"OK"},'
            '"1.1.1":{"behavior":"OK","behaviorClose":"OK"}}}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CHECK.ReportError, "duplicate JSON key"):
            CHECK.validate(self.directory, expected_agent="netz", expected_count=None)

    def test_prefers_uncompressed_canonical_index(self) -> None:
        self.write({"netz": {"1.1.1": {"behavior": "OK", "behaviorClose": "OK"}}})
        (self.directory / "index.json.gz").write_bytes(b"not gzip")
        behavior, _, _ = CHECK.validate(
            self.directory, expected_agent="netz", expected_count=None
        )
        self.assertEqual(1, behavior["OK"])


if __name__ == "__main__":
    unittest.main()
