#!/usr/bin/env python3
"""Official grpc-js Channelz client against the native netz admin server."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    if not __debug__:
        raise RuntimeError("This gate requires Python assertions")
    parser = argparse.ArgumentParser()
    parser.add_argument("server", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    modules = directory.parent / "grpc_locality"
    if not (modules / "node_modules/@grpc/grpc-js").exists():
        subprocess.run(
            ["npm", "ci", "--prefix", str(modules), "--ignore-scripts", "--no-audit", "--no-fund"],
            check=True,
            timeout=60,
        )
    result = subprocess.run(
        ["node", str(directory / "client.js"), str(args.server.resolve())],
        text=True,
        capture_output=True,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    assert report["status"] == "passed"
    repo = directory.parents[2]
    files = [
        "build.zig",
        "src/grpc/mod.zig",
        "src/grpc/channelz.zig",
        "src/grpc/channelz_tests.zig",
        "src/grpc/runtime.zig",
        "tools/interop/grpc_channelz/server.zig",
        "tools/interop/grpc_channelz/client.js",
        "tools/interop/grpc_channelz/run.py",
    ]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report["source_sha256"] = {name: digest(repo / name) for name in files}
    report["schema_sha256"] = digest(
        modules / "node_modules/@grpc/grpc-js/proto/channelz.proto"
    )
    report["server_sha256"] = digest(args.server)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
