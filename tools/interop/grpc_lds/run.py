#!/usr/bin/env python3
"""Official LDS/HCM and listener-driven RDS publication."""
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
    result = subprocess.run(["node", str(directory / "peer.js"), str(args.client.resolve())], capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    assert report["status"] == "passed"
    repo = directory.parents[2]
    files = ["src/grpc/fault.zig", "src/grpc/channel.zig", "src/grpc/channel/tree_query.zig", "src/grpc/channel/shared/layout.zig", "build.zig", "src/grpc/channel/ring_hash.zig", "src/grpc/channel/shared/source.zig", "src/grpc/channel/shared/state.zig", "src/grpc/channel/shared/target_lifetime.zig", "src/grpc/channel/shared/update.zig", "src/grpc/channel/shared/update/prepare.zig", "src/grpc/channel/shared/update/publish.zig", "src/grpc/channel/shared/weighted_target.zig", "src/grpc/channel/shared/cluster_dispatch.zig", "src/grpc/channel/shared/weighted_target/selection_tests.zig"]
    files += [str(path.relative_to(repo)) for path in sorted((repo / "src/grpc/xds").rglob("*.zig")) if "runtime" not in path.relative_to(repo).parts and path.name != "prepared_batch.zig"]
    files += ["src/grpc/channel/" + name for name in ("call_selector.zig", "shared/config_storage.zig", "shared/config_generation.zig", "shared/selector.zig", "shared/stream/open.zig", "shared/init.zig")]
    files += ["tools/interop/grpc_lds/" + name for name in ("client.zig", "peer.js", "run.py")]
    files += ["tools/interop/grpc_locality/" + name for name in ("package.json", "package-lock.json")]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report["source_sha256"] = {file: digest(repo / file) for file in files}
    proto_root = deps / "node_modules/@grpc/grpc-js-xds/deps/envoy-api"
    report["reference_proto_sha256"] = {file: digest(proto_root / file) for file in ("envoy/config/listener/v3/listener.proto", "envoy/config/listener/v3/api_listener.proto", "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto", "envoy/config/core/v3/config_source.proto", "envoy/config/core/v3/protocol.proto", "envoy/config/route/v3/route.proto", "envoy/config/route/v3/route_components.proto", "envoy/type/matcher/v3/string.proto", "envoy/type/matcher/v3/regex.proto")}
    report["client_sha256"] = digest(args.client)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
