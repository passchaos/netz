#!/usr/bin/env python3
"""Official-schema automatic LRS provenance with real application traffic."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(repo, directory):
    sources = {
        "build.zig", "src/runtime.zig", "src/grpc/mod.zig", "src/grpc/runtime.zig",
        "src/grpc/channel.zig", "src/grpc/call.zig", "src/grpc/service_config.zig",
        "src/grpc/orca.zig", "src/grpc/protobuf.zig", "src/http2/runtime.zig",
    }
    # Bound the inventory to the discovery, routing, call and runtime owners,
    # including nested helpers and adjacent provenance regression fixtures.
    for tree in ("src/grpc/xds", "src/grpc/channel", "src/grpc/call",
                 "src/grpc/stream", "src/grpc/orca", "src/grpc/service_config",
                 "src/runtime"):
        sources.update(path.relative_to(repo).as_posix()
                       for path in (repo / tree).rglob("*.zig") if path.is_file())
    sources.update(path.relative_to(repo).as_posix() for path in directory.rglob("*")
                   if path.is_file() and path.suffix in {".zig", ".js", ".py", ".md"})
    sources.update("tools/interop/grpc_locality/" + name
                   for name in ("package.json", "package-lock.json"))
    return {name: digest(repo / name) for name in sorted(sources)}


def main():
    if not __debug__:
        raise RuntimeError("This gate requires Python assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    repo = directory.parents[2]
    dependencies = directory.parent / "grpc_locality"
    if not (dependencies / "node_modules/@grpc/grpc-js-xds").exists():
        subprocess.run(["npm", "ci", "--prefix", str(dependencies), "--ignore-scripts", "--no-audit", "--no-fund"], check=True, timeout=60)
    client = args.client.resolve(strict=True)
    before = source_hashes(repo, directory)
    binary_hash = digest(client)
    result = subprocess.run(["node", str(directory / "peer.js"), str(client)], capture_output=True, text=True, timeout=45)
    if result.returncode:
        prefix = "AUTOMATIC_LRS_FAILURE "
        failure_line = next((line for line in result.stderr.splitlines() if line.startswith(prefix)), None)
        if failure_line and args.output:
            failure = json.loads(failure_line[len(prefix):])
            failure["source_sha256"] = before
            failure["client_sha256"] = binary_hash
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(failure, indent=2) + "\n")
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    assert report["status"] == "passed"
    assert report["mode"] == "sotw"
    for contract in ("managed_factory", "real_application_traffic", "source_pinned_reports", "unavailable_lrs_did_not_block_publication"):
        assert report[contract] is True
    provenance = report["provenance"]
    for contract in ("cached_cds_retained_a", "identical_replacement_moved_to_b", "held_completion_retained_a", "nack_preserved_a", "default_stats_enabled_automatically"):
        assert provenance[contract] is True
    assert provenance["explicit_lrs_options"] is False
    assert provenance["source_a"] != provenance["source_b"]
    assert report["source_reports"]["A"]["totals"]["issued"] == 3
    assert report["source_reports"]["A"]["totals"]["successful"] == 3
    assert report["source_reports"]["B"]["totals"]["issued"] == 1
    assert report["source_reports"]["B"]["totals"]["failed"] == 1
    assert report["source_reports"]["C"]["initial_requests"] == 0
    assert report["refused_network"]["listener_closed_before_cds"] is True
    assert report["refused_network"]["existing_ads_connections"] == 1
    assert len(report["application_calls"]) == 7
    if before != source_hashes(repo, directory) or binary_hash != digest(client):
        raise RuntimeError("Automatic LRS sources or executable changed during execution")
    report["source_sha256"] = before
    report["client_sha256"] = binary_hash
    proto_root = dependencies / "node_modules/@grpc/grpc-js-xds/deps/envoy-api"
    protos = ["envoy/service/discovery/v3/ads.proto", "envoy/service/load_stats/v3/lrs.proto",
              "envoy/config/listener/v3/listener.proto", "envoy/config/cluster/v3/cluster.proto",
              "envoy/config/core/v3/config_source.proto", "envoy/config/endpoint/v3/endpoint.proto",
              "envoy/config/endpoint/v3/load_report.proto", "envoy/config/route/v3/route.proto",
              "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto"]
    report["reference_proto_sha256"] = {name: digest(proto_root / name) for name in protos}
    orca = dependencies / "node_modules/@grpc/grpc-js/proto/xds/xds/data/orca/v3/orca_load_report.proto"
    report["reference_proto_sha256"]["grpc-js/xds/data/orca/v3/orca_load_report.proto"] = digest(orca)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
