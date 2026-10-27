#!/usr/bin/env python3
"""Alternate native shared gRPC and official grpc-cpp TCP ping-pong workloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile

from grpc_benchmark_check import verify

PAYLOADS = (0, 512, 4096, 262144)
MODES = ("persistent", "calls")
GRPC_REVISION = "03d65cc67c450ccbb58a8a45627c4da83a886ccd"


def command(args: list[str], log: Path, timeout: int) -> None:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"benchmark failed with {result.returncode}; see {log}")


def cpp_results(path: Path) -> dict[tuple[str, int], float]:
    result: dict[tuple[str, int], float] = {}
    entries = json.loads(path.read_text(encoding="utf-8"))["benchmarks"]
    for mode in MODES:
        for payload in PAYLOADS:
            name = f"BM_StreamingPingPong{'Msgs' if mode == 'persistent' else ''}<TCP, NoOpMutator, NoOpMutator>/{payload}" + ("/1" if mode == "calls" else "")
            matches = [entry for entry in entries if entry.get("name") == name]
            if len(matches) != 1:
                raise ValueError(f"expected one grpc-cpp result: {name}")
            entry = matches[0]
            if entry.get("error_occurred") or entry.get("iterations", 0) <= 0:
                raise ValueError(f"incomplete grpc-cpp benchmark: {name}")
            scale = {"ns": 1, "us": 1000, "ms": 1_000_000, "s": 1_000_000_000}[entry["time_unit"]]
            wall_ns = entry["real_time"] * scale
            if not math.isfinite(wall_ns) or wall_ns <= 0:
                raise ValueError(f"invalid grpc-cpp wall time: {name}")
            result[mode, payload] = wall_ns
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("netz", type=Path)
    parser.add_argument("--netz-build-mode", required=True, choices=("ReleaseFast",))
    parser.add_argument("--grpc-root", type=Path, default=Path.home() / "Work/grpc")
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.samples < 3 or args.iterations <= 0 or args.warmup < 0 or args.cpu not in os.sched_getaffinity(0):
        parser.error("use at least three samples, positive iterations, nonnegative warmup, and an allowed CPU")
    netz = args.netz.resolve()
    grpc_root = args.grpc_root.resolve()
    cpp = grpc_root / "bazel-bin/test/cpp/microbenchmarks/bm_fullstack_streaming_ping_pong"
    revision = subprocess.check_output(["git", "-C", str(grpc_root), "rev-parse", "HEAD"], text=True).strip()
    if revision != GRPC_REVISION:
        parser.error(f"grpc-cpp must use {GRPC_REVISION}")
    if not netz.is_file() or not cpp.is_file():
        parser.error("build both benchmark executables first")
    output = args.output
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="netz-grpc-benchmark-"))
    else:
        output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    context = {
        "cpu": args.cpu, "samples": args.samples, "schedule": "alternating",
        "netz_build_mode": args.netz_build_mode,
        "netz_revision": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
        "netz_dirty": bool(subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True)),
        "grpc_revision": revision, "arch": os.uname().machine,
        "netz_sha256": hashlib.sha256(netz.read_bytes()).hexdigest(),
        "grpc_cpp_sha256": hashlib.sha256(cpp.read_bytes()).hexdigest(),
        "cpp_time_basis": "real_time", "netz_validation": "full-bytes",
        "netz_protobuf_scope": "preencoded", "grpc_cpp_protobuf_scope": "serialize+parse",
    }
    (output / "context.json").write_text(json.dumps(context, indent=2) + "\n")
    # The official TCP fixture reserves ports through this reusable helper.
    # Send inherited output to a file because the helper detaches its server.
    with (output / "port-server-start.log").open("w") as port_log:
        subprocess.run([sys.executable, str(grpc_root / "tools/run_tests/start_port_server.py")], cwd=grpc_root, stdout=port_log, stderr=subprocess.STDOUT, timeout=30, check=True)
    native: dict[tuple[str, int], list[int]] = {(mode, size): [] for mode in MODES for size in PAYLOADS}
    reference: dict[tuple[str, int], list[float]] = {key: [] for key in native}
    for sample in range(1, args.samples + 1):
        for implementation in (("netz", "grpc-cpp") if sample % 2 else ("grpc-cpp", "netz")):
            if implementation == "netz":
                for mode, payload in native:
                    log = output / f"netz-{sample}-{mode}-{payload}.log"
                    command(["taskset", "-c", str(args.cpu), str(netz), f"--mode={mode}", f"--payload={payload}", f"--warmup={args.warmup}", f"--iterations={args.iterations}"], log, 60)
                    row = verify(log.read_text(encoding="utf-8"))
                    if row["mode"] != mode or int(row["payload_bytes"]) != payload or int(row["warmup"]) != args.warmup or int(row["iterations"]) != args.iterations or row["stats_enabled"] != "false" or row.get("stream_window", "65535") != "65535" or row.get("connection_window", "65535") != "65535" or row.get("adaptive_window", "false") != "false":
                        raise ValueError(f"native workload mismatch: {log}")
                    native[mode, payload].append(int(row["ns_per_roundtrip"]))
            else:
                data = output / f"grpc-cpp-{sample}.json"
                command(["taskset", "-c", str(args.cpu), str(cpp), "--benchmark_filter=^BM_StreamingPingPong(Msgs)?<TCP, NoOpMutator, NoOpMutator>/(0|512|4096|262144)(/1)?$", "--benchmark_min_time=0.2s", "--benchmark_repetitions=1", f"--benchmark_out={data}", "--benchmark_out_format=json"], output / f"grpc-cpp-{sample}.log", 120)
                for key, value in cpp_results(data).items():
                    reference[key].append(value)
        print(f"completed sample={sample} output={output}", flush=True)
    results = []
    for mode, payload in native:
        netz_ns = statistics.median(native[mode, payload])
        cpp_ns = statistics.median(reference[mode, payload])
        results.append({"mode": mode, "payload_bytes": payload, "netz_median_ns": netz_ns, "grpc_cpp_median_ns": cpp_ns, "netz_over_grpc_cpp": netz_ns / cpp_ns, "netz_samples_ns": native[mode, payload], "grpc_cpp_samples_ns": reference[mode, payload]})
    report = {"context": context, "results": results}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
