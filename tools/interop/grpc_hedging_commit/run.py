#!/usr/bin/env python3
"""Independent HTTP/2 wire gate for A6 commitment and call-wide replay."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(repo, directory):
    sources = [
        "build.zig", "src/runtime.zig", "src/grpc/mod.zig", "src/grpc/call.zig",
        "src/grpc/call/retry.zig", "src/grpc/channel.zig", "src/grpc/channel/shared.zig",
        "src/grpc/channel/shared/state.zig", "src/grpc/channel/shared/job.zig",
        "src/grpc/channel/shared/worker.zig", "src/grpc/channel/shared/hedging.zig",
        "src/grpc/channel/shared/hedging/control.zig", "src/grpc/channel/shared/hedging/stats.zig",
        "src/http2/runtime.zig",
    ]
    sources += [str(path.relative_to(repo)) for path in sorted(directory.iterdir())
                if path.name in {"peer.js", "client.zig", "run.py", "README.md"}]
    return {name: digest(repo / name) for name in sources}


def main():
    if not __debug__:
        raise RuntimeError("This gate requires Python assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", type=Path, help="compiled native client executable")
    parser.add_argument("--output", type=Path, help="write the verified JSON report")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    repo = directory.parents[2]
    client = args.client.resolve(strict=True)
    before = source_hashes(repo, directory)
    executable_before = digest(client)
    result = subprocess.run(["node", str(directory / "peer.js"), str(client)],
                            capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    assert report["status"] == "passed"
    assert report["oracle"] == "node:http2"
    assert report["runtime"] == "zio"
    assert len(report["cases"]) == 6
    assert [case["backend_counts"] for case in report["cases"]] == [
        {"A": 1, "B": 1}, {"A": 1, "B": 0}, {"A": 1, "B": 0},
        {"A": 1, "B": 1}, {"A": 1, "B": 1}, {"A": 2, "B": 1},
    ]
    after = source_hashes(repo, directory)
    if before != after or executable_before != digest(client):
        raise RuntimeError("Interop sources or native executable changed during the gate")
    report["source_sha256"] = before
    report["client_sha256"] = executable_before
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
