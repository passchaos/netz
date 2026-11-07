#!/usr/bin/env python3
"""Run prebuilt production Managed SotW/delta federation against official ADS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

DIRECTORY = Path(__file__).resolve().parent
REPO = DIRECTORY.parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    files = list((REPO / "src/grpc").rglob("*.zig"))
    files += [REPO / name for name in ("build.zig", "build.zig.zon")]
    files += [DIRECTORY / name for name in ("client.zig", "schema.js", "peer.js", "run.py", "README.md")]
    files += [DIRECTORY.parent / "grpc_locality" / name for name in ("package.json", "package-lock.json")]
    return {str(file.relative_to(REPO)): digest(file) for file in sorted(files)}


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--node", default="node")
    parser.add_argument("--mode", choices=("sotw", "delta", "both"), default="both")
    parser.add_argument("--output", type=Path, default=Path("/tmp/netz-grpc-federation/report.json"))
    args = parser.parse_args()
    native = args.native.resolve()
    node = Path(shutil.which(args.node) or args.node).resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    case_root = output.parent / (output.stem + "-cases")
    if case_root.exists():
        raise RuntimeError(f"Existing evidence directory {case_root}; choose a fresh output path")
    case_root.mkdir()
    report = {"status": "failed", "gate": "production-managed-real-wire-federation", "results": [], "failures": []}
    try:
        if not native.is_file() or not os.access(native, os.X_OK):
            raise RuntimeError("Prebuilt native client is missing or not executable")
        if not (DIRECTORY.parent / "grpc_locality/node_modules/@grpc/grpc-js-xds").is_dir():
            raise RuntimeError("Prepare existing grpc_locality Node dependencies before running")
        report["source_sha256"] = sources()
        report["executable_sha256"] = {"native": digest(native), "node": digest(node)}
        report["executables"] = {"native": str(native), "node": str(node)}
        modes = ("sotw", "delta") if args.mode == "both" else (args.mode,)
        for mode in modes:
            directory = case_root / mode
            directory.mkdir()
            try:
                result = subprocess.run([str(node), str(DIRECTORY / "peer.js"), str(native), mode, str(directory)],
                                        text=True, capture_output=True, timeout=55)
                (directory / "peer.stdout").write_text(result.stdout)
                (directory / "peer.stderr").write_text(result.stderr)
                wire_path = directory / "wire.json"
                wire = json.loads(wire_path.read_text()) if wire_path.exists() else {
                    "status": "failed", "failure": "peer did not produce a wire report"}
                if result.returncode or wire.get("status") != "passed":
                    raise RuntimeError(wire.get("failure") or result.stderr[-3000:] or f"peer exited {result.returncode}")
                for field in ("managed_resource_routing", "source_features_isolated", "foreign_cache_preserved",
                              "pending_route_retained", "held_completion_retained_b", "automatic_lrs"):
                    if wire["native"].get(field) is not True:
                        raise RuntimeError(f"native omitted required behavior: {field}")
                report["results"].append({"mode": mode, "status": "passed", "artifact": str(wire_path),
                                          "bootstrap_sha256": digest(directory / "bootstrap.json"), **wire})
                print(f"PASS {mode}: production subscriptions, scoped caches, pending handoff, held completion, LRS", file=sys.stderr, flush=True)
            except subprocess.TimeoutExpired as error:
                for name, value in (("peer.stdout", error.stdout), ("peer.stderr", error.stderr)):
                    value = value or b""
                    (directory / name).write_bytes(value.encode() if isinstance(value, str) else value)
                report["failures"].append({"mode": mode, "failure": "peer process exceeded 55s", "directory": str(directory)})
            except Exception as error:
                report["failures"].append({"mode": mode, "failure": str(error), "directory": str(directory)})
            write(output, report)
        if sources() != report["source_sha256"]:
            raise RuntimeError("Native or fixture sources changed during verification")
        if digest(native) != report["executable_sha256"]["native"]:
            raise RuntimeError("Native executable changed during verification")
        if not report["failures"]:
            report["status"] = "passed"
    except Exception as error:
        report["failures"].append({"mode": "harness", "failure": str(error)})
    write(output, report)
    print(json.dumps({"status": report["status"], "passed_modes": [value["mode"] for value in report["results"]],
                      "report": str(output), "failures": report["failures"]}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
