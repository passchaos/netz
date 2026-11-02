#!/usr/bin/env python3
"""Independent v3 ADS protobuf and bidirectional gRPC interoperability."""
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
        subprocess.run(["npm", "ci", "--prefix", str(deps), "--ignore-scripts", "--no-audit", "--no-fund"], check=True, timeout=60)
    result = subprocess.run(["node", str(directory / "peer.js"), str(args.client.resolve())], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    assert report["status"] == "passed"
    repo = directory.parents[2]
    files = ["build.zig", "src/grpc/mod.zig", "src/grpc/channel/shared.zig", "src/grpc/channel/shared/stream/open.zig", "src/grpc/channel/shared/stream/owner.zig"]
    files += [str(path.relative_to(repo)) for path in sorted((repo / "src/grpc/xds").rglob("*.zig"))]
    files += ["tools/interop/grpc_ads/" + name for name in ("client.zig", "peer.js", "run.py")]
    files += ["tools/interop/grpc_locality/" + name for name in ("package.json", "package-lock.json")]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report["source_sha256"] = {file: digest(repo / file) for file in files}
    proto_root = deps / "node_modules/@grpc/grpc-js-xds/deps/envoy-api"
    report["reference_proto_sha256"] = {file: digest(proto_root / file) for file in ("envoy/service/discovery/v3/ads.proto", "envoy/service/discovery/v3/discovery.proto", "envoy/config/core/v3/base.proto")}
    report["client_sha256"] = digest(args.client)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
