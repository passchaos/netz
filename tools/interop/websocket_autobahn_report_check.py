#!/usr/bin/env python3
"""Validate a complete or explicitly filtered Autobahn client report."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
from collections import Counter
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any


ACCEPTED_BEHAVIORS = {"OK", "NON-STRICT", "INFORMATIONAL"}
ACCEPTED_CLOSE_BEHAVIORS = {"OK", "INFORMATIONAL"}


class ReportError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                return json.load(stream, object_pairs_hook=unique_object)
        with path.open(encoding="utf-8") as stream:
            return json.load(stream, object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportError(f"invalid JSON document {path}") from error


def report_path(directory: Path) -> Path:
    preferred = directory / "index.json"
    if preferred.is_file():
        return preferred
    candidates = sorted(directory.glob("index.json*"))
    if not candidates:
        raise ReportError("Autobahn did not produce an index report")
    if len(candidates) != 1:
        names = ", ".join(path.name for path in candidates)
        raise ReportError(f"ambiguous Autobahn index reports: {names}")
    return candidates[0]


def load_report(directory: Path) -> dict[str, Any]:
    path = report_path(directory)
    value = load_json(path)
    if not isinstance(value, dict):
        raise ReportError("Autobahn index report must be an object")
    return value


ExpectedStatus = tuple[str, str]
ExpectedCases = Mapping[str, ExpectedStatus]


def load_case_manifest(path: Path) -> dict[str, ExpectedStatus]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise ReportError("Autobahn case manifest must be an object")
    required = {
        "version",
        "source_revision",
        "image_digest",
        "case_count",
        "case_ids_sha256",
        "expected_non_ok",
        "case_groups",
    }
    if set(value) != required:
        raise ReportError("Autobahn case manifest has unexpected fields")
    if not isinstance(value["version"], str) or not value["version"]:
        raise ReportError("Autobahn case manifest has an invalid version")
    if not isinstance(value["source_revision"], str) or not re.fullmatch(
        r"[0-9a-f]{40}", value["source_revision"]
    ):
        raise ReportError("Autobahn case manifest has an invalid source revision")
    if not isinstance(value["image_digest"], str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", value["image_digest"]
    ):
        raise ReportError("Autobahn case manifest has an invalid image digest")
    count = value["case_count"]
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise ReportError("Autobahn case manifest has an invalid case count")
    digest = value["case_ids_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ReportError("Autobahn case manifest has an invalid case ID digest")
    groups = value["case_groups"]
    if not isinstance(groups, dict) or not groups:
        raise ReportError("Autobahn case manifest has no case groups")

    case_ids: set[str] = set()
    for prefix, group_count in groups.items():
        if not isinstance(prefix, str) or not re.fullmatch(
            r"[1-9][0-9]*(?:\.[1-9][0-9]*)*", prefix
        ):
            raise ReportError(f"Autobahn case manifest has invalid group {prefix!r}")
        if (
            isinstance(group_count, bool)
            or not isinstance(group_count, int)
            or group_count <= 0
        ):
            raise ReportError(
                f"Autobahn case manifest group {prefix!r} has an invalid count"
            )
        for index in range(1, group_count + 1):
            case_id = f"{prefix}.{index}"
            if case_id in case_ids:
                raise ReportError(
                    f"Autobahn case manifest repeats case ID {case_id!r}"
                )
            case_ids.add(case_id)

    if len(case_ids) != count:
        raise ReportError(
            f"Autobahn case manifest expands to {len(case_ids)} cases, expected {count}"
        )
    canonical = "".join(f"{case_id}\n" for case_id in sorted(case_ids)).encode()
    if hashlib.sha256(canonical).hexdigest() != digest:
        raise ReportError("Autobahn case manifest case ID digest does not match")

    expected_non_ok = value["expected_non_ok"]
    if not isinstance(expected_non_ok, dict):
        raise ReportError("Autobahn case manifest has invalid expected statuses")
    expected = {case_id: ("OK", "OK") for case_id in case_ids}
    for case_id, statuses in expected_non_ok.items():
        if case_id not in case_ids:
            raise ReportError(
                f"Autobahn case manifest has status for unknown case {case_id!r}"
            )
        if not isinstance(statuses, dict) or set(statuses) != {
            "behavior",
            "behaviorClose",
        }:
            raise ReportError(
                f"Autobahn case manifest has invalid status for {case_id}"
            )
        behavior = statuses["behavior"]
        close_behavior = statuses["behaviorClose"]
        if (
            not isinstance(behavior, str)
            or not isinstance(close_behavior, str)
            or behavior not in ACCEPTED_BEHAVIORS
            or close_behavior not in ACCEPTED_CLOSE_BEHAVIORS
            or (behavior == "OK" and close_behavior == "OK")
        ):
            raise ReportError(
                f"Autobahn case manifest has invalid status for {case_id}"
            )
        expected[case_id] = (behavior, close_behavior)
    return expected


def format_case_ids(case_ids: Collection[str]) -> str:
    ordered = sorted(case_ids)
    shown = ", ".join(ordered[:10])
    if len(ordered) > 10:
        shown += f", ... ({len(ordered)} total)"
    return shown


def validate(
    reports: Path,
    *,
    expected_agent: str,
    expected_count: int | None,
    expected_cases: Collection[str] | ExpectedCases | None = None,
) -> tuple[Counter[str], Counter[str], list[tuple[str, str, str]]]:
    data = load_report(reports)
    if set(data) != {expected_agent}:
        raise ReportError(
            f"Autobahn agents {sorted(data)!r}, expected [{expected_agent!r}]"
        )
    cases = data[expected_agent]
    if not isinstance(cases, dict):
        raise ReportError(f"Autobahn agent {expected_agent!r} cases must be an object")
    total = len(cases)
    if total == 0:
        raise ReportError("Autobahn report contained no case results")
    if expected_count is not None and total != expected_count:
        raise ReportError(
            f"Autobahn report contained {total} cases, expected {expected_count}"
        )
    if expected_cases is not None:
        actual = set(cases)
        expected = set(expected_cases)
        missing = expected - actual if expected_count is not None else set()
        unexpected = actual - expected
        if missing or unexpected:
            details = []
            if missing:
                details.append(f"missing=[{format_case_ids(missing)}]")
            if unexpected:
                details.append(f"unexpected=[{format_case_ids(unexpected)}]")
            raise ReportError(f"Autobahn case set mismatch: {'; '.join(details)}")

    behavior_counts: Counter[str] = Counter()
    close_counts: Counter[str] = Counter()
    non_ok: list[tuple[str, str, str]] = []
    rejected: list[tuple[str, str, str]] = []
    unexpected_statuses: list[tuple[str, str, str, str, str]] = []
    for case_id, result in cases.items():
        if not isinstance(case_id, str) or not case_id:
            raise ReportError("Autobahn report contains an invalid case identifier")
        if not isinstance(result, dict):
            raise ReportError(f"Autobahn case {case_id} result must be an object")
        behavior = result.get("behavior")
        close_behavior = result.get("behaviorClose")
        if not isinstance(behavior, str) or not isinstance(close_behavior, str):
            raise ReportError(f"Autobahn case {case_id} is missing behavior status")
        behavior_counts[behavior] += 1
        close_counts[close_behavior] += 1
        item = (case_id, behavior, close_behavior)
        if behavior != "OK" or close_behavior != "OK":
            non_ok.append(item)
        if (
            behavior not in ACCEPTED_BEHAVIORS
            or close_behavior not in ACCEPTED_CLOSE_BEHAVIORS
        ):
            rejected.append(item)
        if isinstance(expected_cases, Mapping):
            expected_behavior, expected_close = expected_cases[case_id]
            if (behavior, close_behavior) != (
                expected_behavior,
                expected_close,
            ):
                unexpected_statuses.append(
                    (
                        case_id,
                        behavior,
                        close_behavior,
                        expected_behavior,
                        expected_close,
                    )
                )

    if rejected:
        details = "; ".join(
            f"{case_id} behavior={behavior} close={close_behavior}"
            for case_id, behavior, close_behavior in rejected
        )
        raise ReportError(f"Autobahn rejected status: {details}")
    if unexpected_statuses:
        details = "; ".join(
            f"{case_id} behavior={behavior} close={close_behavior} "
            f"expected behavior={expected_behavior} close={expected_close}"
            for case_id, behavior, close_behavior, expected_behavior, expected_close
            in unexpected_statuses
        )
        raise ReportError(f"Autobahn unexpected status: {details}")
    return behavior_counts, close_counts, non_ok


def format_counts(counts: Counter[str]) -> str:
    return ", ".join(f"{status}={counts[status]}" for status in sorted(counts))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", type=Path)
    parser.add_argument("--expected-agent", default="netz")
    parser.add_argument("--expected-count", type=int)
    parser.add_argument("--expected-cases", type=Path)
    args = parser.parse_args()
    if args.expected_count is not None and args.expected_count <= 0:
        raise SystemExit("expected case count must be positive")
    try:
        expected_cases = (
            load_case_manifest(args.expected_cases)
            if args.expected_cases is not None
            else None
        )
        behavior_counts, close_counts, non_ok = validate(
            args.reports,
            expected_agent=args.expected_agent,
            expected_count=args.expected_count,
            expected_cases=expected_cases,
        )
    except ReportError as error:
        raise SystemExit(str(error)) from error

    total = sum(behavior_counts.values())
    print(f"Autobahn WebSocket cases completed: {total}")
    print(f"Autobahn behavior counts: {format_counts(behavior_counts)}")
    print(f"Autobahn close-behavior counts: {format_counts(close_counts)}")
    for case_id, behavior, close_behavior in non_ok:
        print(
            f"Autobahn non-OK: {args.expected_agent} {case_id} "
            f"behavior={behavior} close={close_behavior}"
        )


if __name__ == "__main__":
    main()
