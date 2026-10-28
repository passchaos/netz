#!/usr/bin/env python3
"""Fixed-binary AB/BA checks for the MQTT Session metadata benchmark."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(output: str) -> list[dict[str, str]]:
    rows = []
    for line in output.splitlines():
        if not line.startswith("record=result "):
            raise ValueError(f"unexpected benchmark line: {line}")
        fields = {}
        for token in line.split():
            key, value = token.split("=", 1)
            if key in fields or not value:
                raise ValueError(f"duplicate or empty benchmark field: {token}")
            fields[key] = value
        expected = {
            "benchmark": "mqtt-shared-properties", "io": "zio-std-io",
            "sessions": "64", "messages": "256", "deliveries": "16384",
            "teardown_live_bytes": "0", "complete": "true",
        }
        if any(fields.get(key) != value for key, value in expected.items()):
            raise ValueError(f"incomplete or changed workload: {fields}")
        if fields.get("metadata") not in ("false", "true") or fields.get("shared") not in ("false", "true"):
            raise ValueError(f"unknown benchmark mode: {fields}")
        if int(fields["checksum"]) != (12730368 if fields["metadata"] == "true" else 1605632):
            raise ValueError("benchmark content checksum changed")
        for key in ("elapsed_ns", "allocations", "live_bytes", "logical_bytes"):
            if int(fields[key]) <= 0:
                raise ValueError(f"invalid benchmark {key}")
        rows.append(fields)
    keys = {(row["metadata"], row["shared"], row["sample"]) for row in rows}
    expected_keys = {(metadata, shared, str(sample)) for metadata in ("false", "true") for shared in ("false", "true") for sample in range(7)}
    if len(rows) != 28 or keys != expected_keys:
        raise ValueError("missing or duplicate internal samples")
    return rows


def summarize(rows: list[dict[str, str]]) -> dict:
    summary = {}
    for metadata in ("false", "true"):
        for shared in ("false", "true"):
            group = [row for row in rows if row["metadata"] == metadata and row["shared"] == shared]
            for key in ("allocations", "live_bytes", "logical_bytes", "checksum"):
                if len({row[key] for row in group}) != 1:
                    raise ValueError(f"unstable benchmark accounting: {key}")
            summary[f"metadata={metadata},shared={shared}"] = {
                key: statistics.median(int(row[key]) for row in group)
                for key in ("elapsed_ns", "allocations", "live_bytes", "logical_bytes", "checksum")
            }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pairs", type=int, default=4)
    args = parser.parse_args()
    if args.pairs < 1:
        parser.error("--pairs must be positive")
    args.output.mkdir(parents=True, exist_ok=False)
    cpu = min(os.sched_getaffinity(0))
    binaries = {name: path.resolve(strict=True) for name, path in (("baseline", args.baseline), ("candidate", args.candidate))}
    hashes = {name: sha256(path) for name, path in binaries.items()}
    if hashes["baseline"] == hashes["candidate"]:
        raise ValueError("A/B binaries must be distinct")
    runs = []
    for pair in range(args.pairs):
        for name in (("baseline", "candidate") if pair % 2 == 0 else ("candidate", "baseline")):
            completed = subprocess.run(["taskset", "-c", str(cpu), str(binaries[name])], capture_output=True, text=True, timeout=60, check=True)
            output = completed.stdout + completed.stderr
            rows = records(output)
            path = args.output / f"pair-{pair}-{name}.log"
            path.write_text(output)
            runs.append({"pair": pair, "implementation": name, "binary_sha256": hashes[name], "log_sha256": sha256(path), "summary": summarize(rows), "records": rows})
    ratios = {}
    for shape in runs[0]["summary"]:
        paired = []
        for pair in range(args.pairs):
            baseline = next(run for run in runs if run["pair"] == pair and run["implementation"] == "baseline")["summary"][shape]
            candidate = next(run for run in runs if run["pair"] == pair and run["implementation"] == "candidate")["summary"][shape]
            if baseline["logical_bytes"] != candidate["logical_bytes"] or baseline["checksum"] != candidate["checksum"]:
                raise ValueError("A/B logical ownership or content changed")
            paired.append({key: candidate[key] / baseline[key] for key in ("elapsed_ns", "allocations", "live_bytes")})
        ratios[shape] = {"pairs": paired, "median_ratio": {key: statistics.median(pair[key] for pair in paired) for key in paired[0]}}
    if any(sha256(path) != hashes[name] for name, path in binaries.items()):
        raise ValueError("benchmark binary changed during the capture")
    result = {"cpu": cpu, "schedule": "AB/BA", "internal_samples": 7, "binaries": hashes, "runs": runs, "ratios": ratios}
    (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(ratios, indent=2))


if __name__ == "__main__":
    main()
