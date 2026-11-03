#!/usr/bin/env python3
"""Load Reporting Service wire compatibility against official Envoy schemas."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    if not __debug__:
        raise RuntimeError("This gate requires Python assertions")
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    deps = directory.parent / "grpc_locality"
    if not (deps / "node_modules/@grpc/grpc-js-xds").exists():
        subprocess.run(["npm", "ci", "--prefix", str(deps), "--ignore-scripts", "--no-audit", "--no-fund"], check=True, timeout=120)
    result = subprocess.run(["node", str(directory / "peer.js"), str(args.client.resolve())], capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    assert report["status"] == "passed"
    for contract in ("initial_subscription", "report_counters", "send_all", "endpoint_granularity"):
        assert report[contract] is True
    repo = directory.parents[2]
    files = ["src/grpc/xds/lrs.zig", "src/grpc/xds/lrs/codec.zig", "src/grpc/xds/lrs/client.zig"]
    files += ["tools/interop/grpc_lrs/" + name for name in ("client.zig", "peer.js", "run.py")]
    files += ["tools/interop/grpc_locality/" + name for name in ("package.json", "package-lock.json")]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report["source_sha256"] = {file: digest(repo / file) for file in files}
    proto_root = deps / "node_modules/@grpc/grpc-js-xds/deps/envoy-api"
    report["reference_proto_sha256"] = {file: digest(proto_root / file) for file in ("envoy/service/load_stats/v3/lrs.proto", "envoy/config/endpoint/v3/load_report.proto")}
    report["client_sha256"] = digest(args.client)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
