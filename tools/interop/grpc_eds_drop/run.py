#!/usr/bin/env python3
"""Independent official EDS/cluster-impl drop rules and native RPC admission."""
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
    result = subprocess.run(["node", str(directory / "peer.js"), str(args.client.resolve())], capture_output=True, text=True, timeout=70)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    assert report["status"] == "passed"
    repo = directory.parents[2]
    files = ["build.zig", "src/grpc/mod.zig", "src/grpc/call.zig", "src/grpc/call/retry.zig", "src/grpc/channel.zig", "src/grpc/channel/drop_policy.zig", "src/grpc/channel/drop_runtime_tests.zig", "src/grpc/channel/shared.zig", "src/grpc/channel/shared/state.zig", "src/grpc/channel/shared/job.zig", "src/grpc/channel/shared/drop_admission.zig", "src/grpc/channel/shared/init.zig", "src/grpc/channel/shared/hedging.zig", "src/grpc/channel/shared/update.zig", "src/grpc/channel/shared/update/prepare.zig", "src/grpc/channel/shared/update/publish.zig", "src/grpc/xds/eds/decode.zig", "src/grpc/xds/eds/target.zig", "src/grpc/xds/eds/tests.zig", "src/grpc/channel/shared/weighted_target/outlier_tests.zig"]
    files += ["tools/interop/grpc_eds_drop/" + name for name in ("client.zig", "peer.js", "run.py")]
    files += ["tools/interop/grpc_locality/" + name for name in ("package.json", "package-lock.json")]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report["source_sha256"] = {file: digest(repo / file) for file in files}
    report["official_cluster_impl_sha256"] = digest(deps / "node_modules/@grpc/grpc-js-xds/build/src/load-balancer-xds-cluster-impl.js")
    report["client_sha256"] = digest(args.client)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
