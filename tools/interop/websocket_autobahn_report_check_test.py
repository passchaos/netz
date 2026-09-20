#!/usr/bin/env python3
"""Tests for strict Autobahn report validation."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE = Path(__file__).with_name("websocket_autobahn_report_check.py")
MANIFEST = Path(__file__).with_name("websocket_autobahn_cases_25_10_1.json")
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
        self.expected_cases = CHECK.load_case_manifest(MANIFEST)

    def write(self, value: object) -> None:
        (self.directory / "index.json").write_text(
            json.dumps(value), encoding="utf-8"
        )

    def test_accepts_complete_report_and_documented_statuses(self) -> None:
        cases = {
            case_id: {"behavior": "OK", "behaviorClose": "OK"}
            for case_id in self.expected_cases
        }
        cases["7.1.6"] = {
            "behavior": "INFORMATIONAL",
            "behaviorClose": "INFORMATIONAL",
        }
        self.write({"netz": cases})
        behavior, close, non_ok = CHECK.validate(
            self.directory,
            expected_agent="netz",
            expected_count=517,
            expected_cases=self.expected_cases,
        )
        self.assertEqual(517, sum(behavior.values()))
        self.assertEqual(1, behavior["INFORMATIONAL"])
        self.assertEqual(1, close["INFORMATIONAL"])
        self.assertEqual([("7.1.6", "INFORMATIONAL", "INFORMATIONAL")], non_ok)

    def test_manifest_is_the_pinned_25_10_1_case_set(self) -> None:
        self.assertEqual(517, len(self.expected_cases))
        self.assertIn("1.1.1", self.expected_cases)
        self.assertIn("6.22.34", self.expected_cases)
        self.assertIn("13.7.18", self.expected_cases)

    def test_rejects_manifest_with_a_stale_count_or_digest(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        local_manifest = self.directory / "case-manifest.json"
        manifest["case_count"] = 516
        local_manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(CHECK.ReportError, "expands to 517 cases"):
            CHECK.load_case_manifest(local_manifest)

        manifest["case_count"] = 517
        manifest["case_ids_sha256"] = "0" * 64
        local_manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(CHECK.ReportError, "digest does not match"):
            CHECK.load_case_manifest(local_manifest)

    def test_rejects_same_count_with_missing_and_unknown_case(self) -> None:
        cases = {
            case_id: {"behavior": "OK", "behaviorClose": "OK"}
            for case_id in self.expected_cases
        }
        cases.pop("6.22.34")
        cases["99.99.99"] = {"behavior": "OK", "behaviorClose": "OK"}
        self.write({"netz": cases})
        with self.assertRaisesRegex(
            CHECK.ReportError, r"case set mismatch.*6\.22\.34.*99\.99\.99"
        ):
            CHECK.validate(
                self.directory,
                expected_agent="netz",
                expected_count=517,
                expected_cases=self.expected_cases,
            )

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
