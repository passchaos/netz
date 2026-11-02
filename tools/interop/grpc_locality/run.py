#!/usr/bin/env python3
"""xDS locality config oracle and official gRPC network interoperability."""
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
    if not (directory / "node_modules/@grpc/grpc-js-xds").exists():
        subprocess.run(["npm", "ci", "--prefix", str(directory), "--ignore-scripts", "--no-audit", "--no-fund"], check=True, timeout=60)
    result = subprocess.run(["node", str(directory / "peer.js"), str(args.client.resolve())], text=True, capture_output=True, timeout=70)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    assert report["status"] == "passed"
    repo = directory.parents[2]
    files = ["build.zig", "src/grpc/mod.zig", "src/grpc/service_config.zig", "src/grpc/service_config/locality.zig",
             "src/grpc/channel.zig", "src/grpc/channel/locality.zig", "src/grpc/channel/locality_tests.zig",
             "src/grpc/channel/locality_runtime_tests.zig", "src/grpc/channel/ring_hash.zig", "src/grpc/channel/weighted_target.zig",
             "src/grpc/channel/shared/init.zig", "src/grpc/channel/shared/weighted_target.zig",
             "src/grpc/channel/shared/source.zig", "src/grpc/channel/shared/update/prepare.zig", "src/grpc/channel/shared/update/publish.zig"]
    files += ["tools/interop/grpc_locality/" + name for name in ("client.zig", "peer.js", "run.py", "package.json", "package-lock.json")]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report["source_sha256"] = {name: digest(repo / name) for name in files}
    report["reference_sha256"] = {name: digest(directory / "node_modules/@grpc/grpc-js-xds/build/src" / name)
                                 for name in ("load-balancer-xds-wrr-locality.js", "load-balancer-weighted-target.js")}
    report["client_sha256"] = digest(args.client)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
