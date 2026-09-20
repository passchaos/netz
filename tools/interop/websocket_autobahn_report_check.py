#!/usr/bin/env python3
"""Validate a complete or explicitly filtered Autobahn client report."""

from __future__ import annotations

import argparse
import gzip
import json
from collections import Counter
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
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                value = json.load(stream, object_pairs_hook=unique_object)
        else:
            with path.open(encoding="utf-8") as stream:
                value = json.load(stream, object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportError(f"invalid Autobahn index report {path}") from error
    if not isinstance(value, dict):
        raise ReportError("Autobahn index report must be an object")
    return value


def validate(
    reports: Path,
    *,
    expected_agent: str,
    expected_count: int | None,
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

    behavior_counts: Counter[str] = Counter()
    close_counts: Counter[str] = Counter()
    non_ok: list[tuple[str, str, str]] = []
    rejected: list[tuple[str, str, str]] = []
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

    if rejected:
        details = "; ".join(
            f"{case_id} behavior={behavior} close={close_behavior}"
            for case_id, behavior, close_behavior in rejected
        )
        raise ReportError(f"Autobahn rejected status: {details}")
    return behavior_counts, close_counts, non_ok


def format_counts(counts: Counter[str]) -> str:
    return ", ".join(f"{status}={counts[status]}" for status in sorted(counts))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", type=Path)
    parser.add_argument("--expected-agent", default="netz")
    parser.add_argument("--expected-count", type=int)
    args = parser.parse_args()
    if args.expected_count is not None and args.expected_count <= 0:
        raise SystemExit("expected case count must be positive")
    try:
        behavior_counts, close_counts, non_ok = validate(
            args.reports,
            expected_agent=args.expected_agent,
            expected_count=args.expected_count,
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
