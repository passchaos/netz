#!/usr/bin/env python3
"""Bounded real-wire C-Core/native xDS target and listener-template oracle."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import time

DIRECTORY = Path(__file__).resolve().parent
REPO = DIRECTORY.parents[2]
LDS = "type.googleapis.com/envoy.config.listener.v3.Listener"
CDS = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
EDS = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment"
FIELDS = ("listener_name", "discovery_authority", "listener_resource_authority", "data_authority")
# The emitter uses std.process/std.Io directly; it does not consume the netz
# network runtime. Keep its public facades and conservative codec type inputs
# stable, without making unrelated xDS transport/runtime edits a gate failure.
EMITTER_SOURCE_INPUTS = (
    "build.zig", "build.zig.zon", "src/root.zig", "src/grpc/mod.zig", "src/grpc/xds/mod.zig",
    "src/grpc/xds/bootstrap.zig", "src/grpc/xds/resource_name.zig", "src/grpc/xds/uri.zig",
    "src/grpc/xds/client_target.zig", "src/grpc/xds/ads.zig", "src/grpc/xds/ads/codec.zig",
    "src/grpc/protobuf.zig", "src/grpc/status_details.zig", "src/grpc/metadata.zig", "src/grpc/wire.zig",
)
FIXTURE_INPUTS = ("emit.zig", "reference.py", "capture.py", "peer.js", "run.py", "vectors.json", "requirements.txt", "README.md")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def stability_paths(vectors_path):
    paths = [REPO / name for name in EMITTER_SOURCE_INPUTS]
    paths += [DIRECTORY / name for name in FIXTURE_INPUTS]
    paths += [DIRECTORY.parent / "grpc_locality" / name for name in ("package.json", "package-lock.json")]
    paths.append(vectors_path.resolve())
    return sorted(set(paths))


def input_hashes(paths):
    return {str(path.relative_to(REPO)) if path.is_relative_to(REPO) else str(path): digest(path) for path in paths}


def source_hashes(vectors_path):
    # Retain the complete xDS source inventory as context for each report.
    paths = set((REPO / "src/grpc/xds").rglob("*.zig"))
    paths.update(stability_paths(vectors_path))
    return input_hashes(sorted(paths))


def child_json(command, directory, name, timeout, environment=None):
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, env=environment)
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        (directory / f"{name}.stdout").write_bytes(stdout.encode() if isinstance(stdout, str) else stdout)
        (directory / f"{name}.stderr").write_bytes(stderr.encode() if isinstance(stderr, str) else stderr)
        raise RuntimeError(f"{name} process exceeded {timeout}s") from error
    (directory / f"{name}.stdout").write_text(result.stdout)
    (directory / f"{name}.stderr").write_text(result.stderr)
    require(result.returncode == 0, f"{name} exited {result.returncode}: {result.stderr[-2000:]}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{name} did not emit one JSON object: {result.stdout[-2000:]}") from error
    require(isinstance(value, dict), f"{name} result is not an object")
    return value


def ready(peer, timeout):
    with selectors.DefaultSelector() as selector:
        selector.register(peer.stdout, selectors.EVENT_READ)
        require(selector.select(timeout), f"peer did not become ready within {timeout}s")
        line = peer.stdout.readline()
    require(line, f"peer exited before readiness (exit={peer.poll()})")
    value = json.loads(line)
    require(value.get("status") == "ready", f"invalid peer readiness: {value}")
    return value


def stop(peer):
    if peer.poll() is None:
        try:
            peer.communicate("stop\n", timeout=3)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.communicate(timeout=3)
            raise RuntimeError("peer failed to stop within 3s")
    require(peer.returncode == 0, f"peer exited {peer.returncode}")


def bootstrap(vector, ports):
    configuration = copy.deepcopy(vector["bootstrap"])
    form = vector.get("server_target_form", "bare")
    require(form in ("bare", "dns"), f"unsupported bootstrap server target form: {form}")

    def server(port):
        address = f"127.0.0.1:{port}"
        return {"server_uri": address if form == "bare" else "dns:///" + address,
                "channel_creds": [{"type": "insecure"}], "server_features": ["xds_v3"]}

    configuration["xds_servers"] = [server(ports["root"])]
    configuration["node"] = {"id": "target-" + vector["id"]}
    if vector.get("separate_authority_servers", True):
        for name, authority in configuration.get("authorities", {}).items():
            authority["xds_servers"] = [server(ports[name])]
    return configuration


def check(vector, native, reference, wire, capture):
    require(capture.get("status") == "ok" and not capture["errors"], f"raw HTTP/2 capture errors: {capture['errors']}")
    rejection = vector.get("expected_http2_rejection")
    if rejection:
        require(rejection["code"] == "PROTOCOL_ERROR", "unsupported explicit HTTP/2 rejection contract")
        errors = wire["session_errors"]
        require(any(error["code"] == "ERR_HTTP2_ERROR" and error["message"] == "Protocol error" for error in errors),
                f"missing Node HTTP/2 protocol rejection: {errors}")
        require(all((error["code"], error["message"]) in
                    (("ERR_HTTP2_ERROR", "Protocol error"), ("ECONNRESET", "read ECONNRESET")) for error in errors),
                f"unexpected HTTP/2 session error: {errors}")
        require(wire["errors"] == ["HTTP/2 session: " + error["message"] for error in errors],
                f"unexpected peer failure accompanying HTTP/2 rejection: {wire['errors']}")
    else:
        require(not wire["errors"] and not wire["session_errors"], f"peer errors: {wire['errors']}")
    lds = [request for request in wire["requests"] if request["type_url"] == LDS and request["names"]]
    if "expected_error" in vector:
        require(native.get("status") == "error" and native.get("err") == vector["expected_error"],
                f"native negative mismatch: {native}")
        error = vector["expected_reference_error"]
        require(reference.get("status") == "error" and reference.get("code") == error["code"] and
                reference.get("details") == error["details"],
                f"C-Core negative mismatch: expected {error}, got {reference.get('code')}: {reference.get('details')}")
        require(not lds, f"invalid target subscribed to LDS: {lds}")
        require(not wire["requests"], f"invalid target sent ADS requests: {wire['requests']}")
        require(not wire["backend_calls"], "invalid target reached the data plane")
        require(not capture["connections"], "invalid target opened a backend TCP connection")
        return
    expected = vector["expected"]
    require(native.get("status") == "ok", f"native resolution failed: {native}")
    for field in FIELDS:
        require(native.get(field) == expected.get(field),
                f"native {field}: expected {expected.get(field)!r}, got {native.get(field)!r}")
    require(lds, "C-Core emitted no LDS subscription")
    for request in lds:
        require(request["names"] == [expected["listener_name"]],
                f"C-Core LDS names: expected {[expected['listener_name']]!r}, got {request['names']!r}")
        require(request["scope"] == expected["subscription_scope"],
                f"C-Core LDS scope: expected {expected['subscription_scope']!r}, got {request['scope']!r}")
        require(request["names"] == [native["listener_name"]], "native/C-Core listener mismatch")
    raw_requests = [request for connection in capture["connections"] for request in connection["requests"]
                    if any(name == ":authority" for name, _value in request["headers"])]
    require(raw_requests, "C-Core emitted no captured backend HEADERS")
    for request in raw_requests:
        headers = request["headers"]
        authorities = [value for name, value in headers if name == ":authority"]
        require(authorities == [expected["data_authority"]] == [native["data_authority"]],
                f"raw C-Core/native :authority mismatch: {authorities}, expected {expected['data_authority']!r}")
        require([value for name, value in headers if name == ":method"] == ["POST"], "captured gRPC method mismatch")
        require([value for name, value in headers if name == ":path"] == ["/fixture.Target/Unary"], "captured gRPC path mismatch")
    rejections = [event for connection in capture["connections"] for event in connection["rejections"] if event["code"]]
    if rejection:
        require(reference.get("status") == "error" and reference.get("code") == rejection["grpc_code"] and
                reference.get("details") == rejection["grpc_details"],
                f"C-Core authority rejection mismatch: {reference.get('code')}: {reference.get('details')}")
        require(not wire["backend_calls"], "invalid userinfo authority reached the Node application")
        require("@" in expected["data_authority"], "userinfo rejection vector omitted the literal at-sign")
        require(rejections and all(event["code"] == 1 for event in rejections),
                f"expected only HTTP/2 PROTOCOL_ERROR rejection frames: {rejections}")
        require(all(any(event["connection"] == request["connection"] for event in rejections) for request in raw_requests),
                "captured invalid authority had no protocol rejection on its connection")
    else:
        require(reference.get("status") == "ok", f"C-Core call failed: {reference.get('code')}: {reference.get('details')}")
        require(reference.get("response_base64") == base64.b64encode(b"target-probe").decode(),
                "C-Core response did not echo the original payload")
        require(not rejections, f"unexpected HTTP/2 rejection frames: {rejections}")
        require(len(raw_requests) == 1, f"expected one captured gRPC request, got {len(raw_requests)}")
        require(len(wire["backend_calls"]) == 1, f"expected one data-plane RPC: {wire['backend_calls']}")
        authority = wire["backend_calls"][0]["authority"]
        require(authority == expected["data_authority"] == native["data_authority"],
                f"C-Core/native :authority mismatch: wire={authority!r}, expected={expected['data_authority']!r}")
    # Validate the complete independent LDS -> inline RDS -> CDS -> EDS chain.
    for type_url, names in ((LDS, [expected["listener_name"]]), (CDS, ["backend"]), (EDS, ["backend-eds"])):
        requests = [request for request in wire["requests"] if request["type_url"] == type_url]
        require(any(request["names"] == names and not request["nonce"] for request in requests),
                f"missing initial subscription for {type_url}")
        require(any(request["names"] == names and request["version"] == "v1-" +
                    {LDS: "lds", CDS: "cds", EDS: "eds"}[type_url] and request["nonce"] == request["version"]
                    and not request["error"] for request in requests), f"missing successful ACK for {type_url}")
    require(any(request["node_id"] == "target-" + vector["id"] for request in wire["requests"]),
            "C-Core did not use the supplied bootstrap node")


def run_case(vector, args, case_directory):
    case_directory.mkdir(parents=True, exist_ok=True)
    scopes = ["root"] + list(vector["bootstrap"].get("authorities", {}))
    require(len(set(scopes)) == len(scopes), "authority 'root' conflicts with fixture scope name")
    peer_config = case_directory / "peer-config.json"
    wire_path = case_directory / "wire.json"
    write_json(peer_config, {"scopes": scopes, "peer_timeout_ms": int((args.timeout + 20) * 1000)})
    observed = {"id": vector["id"], "target": vector["target"], "status": "failed",
                "artifact_directory": str(case_directory)}
    peer = None
    failure = None
    started = time.monotonic()
    with (case_directory / "peer.stderr").open("w") as stderr:
        try:
            peer = subprocess.Popen([args.node, str(DIRECTORY / "peer.js"), str(peer_config), str(wire_path)],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True)
            peer_ready = ready(peer, 8)
            write_json(case_directory / "peer-ready.json", peer_ready)
            configuration = bootstrap(vector, peer_ready["ports"])
            bootstrap_path = case_directory / "bootstrap.json"
            write_json(bootstrap_path, configuration)
            observed["bootstrap_sha256"] = digest(bootstrap_path)
            native_command = [str(args.native), str(bootstrap_path), vector["target"]]
            reference_command = [str(args.reference_python), str(DIRECTORY / "reference.py"), vector["target"],
                                 "--timeout", str(args.timeout if "expected_error" not in vector else min(args.timeout, 2))]
            if "default_authority" in vector:
                native_command.append(vector["default_authority"])
                reference_command += ["--default-authority", vector["default_authority"]]
            environment = os.environ.copy()
            for key in ("GRPC_XDS_BOOTSTRAP_CONFIG", "GRPC_XDS_BOOTSTRAP", "GRPC_TRACE", "GRPC_VERBOSITY"):
                environment.pop(key, None)
            environment.update(GRPC_XDS_BOOTSTRAP=str(bootstrap_path), GRPC_EXPERIMENTAL_XDS_FEDERATION="true")
            # Both clients consume the identical file; no native-only rewrite.
            observed["native"] = child_json(native_command, case_directory, "native", 5)
            observed["reference"] = child_json(reference_command, case_directory, "reference", args.timeout + 4, environment)
            require(digest(bootstrap_path) == observed["bootstrap_sha256"], "bootstrap changed during comparison")
        except Exception as error:
            failure = str(error)
        finally:
            if peer is not None:
                try:
                    stop(peer)
                except Exception as error:
                    failure = (failure + "; " if failure else "") + str(error)
            if wire_path.exists():
                wire = json.loads(wire_path.read_text())
                observed["wire"] = {key: wire[key] for key in ("requests", "backend_calls", "errors", "session_errors")}
                observed["peer_provenance"] = {key: wire[key] for key in
                                               ("proto_sha256", "builtin_proto_provenance", "dependencies") if key in wire}
            else:
                failure = (failure + "; " if failure else "") + "peer omitted wire artifact"
    if failure is None:
        try:
            observed["capture"] = child_json([str(args.reference_python), str(DIRECTORY / "capture.py"), str(wire_path)],
                                             case_directory, "capture", 5)
            check(vector, observed["native"], observed["reference"], observed["wire"], observed["capture"])
            observed["status"] = "passed"
            observed["outcome"] = ("invalid-target-rejected" if "expected_error" in vector else
                                   "authority-rejected-after-lds" if "expected_http2_rejection" in vector else "echoed")
        except Exception as error:
            failure = str(error)
    if failure:
        observed["failure"] = failure
    observed["elapsed_seconds"] = round(time.monotonic() - started, 3)
    write_json(case_directory / "result.json", observed)
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path, help="prebuilt emit.zig executable")
    parser.add_argument("--reference-python", required=True, type=Path, help="dedicated pinned grpcio venv interpreter")
    parser.add_argument("--node", default="node")
    parser.add_argument("--output", type=Path, default=Path("/tmp/netz-grpc-client-target/report.json"))
    parser.add_argument("--vectors", type=Path, default=DIRECTORY / "vectors.json")
    parser.add_argument("--case", action="append", dest="case_ids", help="repeat to select a bounded subset")
    parser.add_argument("--timeout", type=float, default=5.0, help="per positive RPC deadline, 1..10 seconds")
    args = parser.parse_args()
    require(1 <= args.timeout <= 10, "RPC timeout must be within 1..10 seconds")
    # Preserve the venv path: resolving its interpreter symlink would bypass it.
    args.reference_python = Path(os.path.abspath(args.reference_python))
    args.native = args.native.resolve()
    args.node = shutil.which(args.node) or args.node
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    case_root = args.output.parent / (args.output.stem + "-cases")
    require(not case_root.exists(), f"artifact directory already exists: {case_root}; choose a new --output")
    case_root.mkdir()
    report = {"status": "failed", "oracle": "grpcio-1.76.0-c-core-real-wire", "results": [], "failures": []}
    try:
        require(args.native.is_file() and os.access(args.native, os.X_OK), "native executable is missing or not executable")
        require(args.reference_python.is_file(), "reference interpreter is missing")
        require((DIRECTORY.parent / "grpc_locality/node_modules/@grpc/grpc-js-xds").is_dir(),
                "existing grpc_locality Node dependencies are missing; prepare them before running")
        report["source_sha256"] = source_hashes(args.vectors)
        report["stability_input_sha256"] = input_hashes(stability_paths(args.vectors))
        report["executable_sha256"] = {"native": digest(args.native), "reference_python": digest(args.reference_python),
                                       "node": digest(Path(args.node))}
        report["executables"] = {"native": str(args.native), "reference_python": str(args.reference_python), "node": args.node}
        vectors = json.loads(args.vectors.read_text())
        report["vectors_sha256"] = digest(args.vectors)
        require(isinstance(vectors, list) and 0 < len(vectors) <= 64, "expected 1..64 target vectors")
        ids = [vector["id"] for vector in vectors]
        require(len(set(ids)) == len(ids), "duplicate vector IDs")
        require(all(re.fullmatch(r"[a-z0-9-]+", name) for name in ids), "invalid vector artifact ID")
        if args.case_ids:
            require(set(args.case_ids) <= set(ids), "unknown --case selection")
            vectors = [vector for vector in vectors if vector["id"] in args.case_ids]
        report["reference"] = child_json([str(args.reference_python), str(DIRECTORY / "reference.py"),
                                          "xds:///unused", "--metadata-only"], case_root, "reference-metadata", 10)
        report["capture_reference"] = child_json([str(args.reference_python), str(DIRECTORY / "capture.py"),
                                                  "--metadata-only"], case_root, "capture-metadata", 5)
        for vector in vectors:
            result = run_case(vector, args, case_root / vector["id"])
            provenance = result.pop("peer_provenance", None)
            if provenance:
                if "peer_provenance" in report and provenance != report["peer_provenance"]:
                    result["status"] = "failed"
                    result["failure"] = "peer dependency/protobuf hashes changed between vectors"
                report["peer_provenance"] = provenance
            reference = result.get("reference")
            reference_failures = []
            if reference is not None:
                if reference.get("core_sha256") != report["reference"]["core_sha256"]:
                    reference_failures.append("reference C-Core extension hash mismatch")
                if reference.get("dependency_sha256") != report["reference"]["dependency_sha256"]:
                    reference_failures.append("reference dependency source hashes mismatch")
            elif result["status"] == "passed":
                reference_failures.append("successful case omitted required reference result and provenance")
            if reference_failures:
                result["status"] = "failed"
                result["failure"] = "; ".join(filter(None, [result.get("failure"), *reference_failures]))
            capture = result.get("capture")
            if capture is not None and any(capture.get(key) != report["capture_reference"][key]
                                           for key in ("hpack", "dependency_sha256")):
                result["status"] = "failed"
                result["failure"] = "; ".join(filter(None, [result.get("failure"), "independent HPACK decoder hashes mismatch"]))
            elif capture is None and result["status"] == "passed":
                result["status"] = "failed"
                result["failure"] = "successful case omitted required raw HTTP/2 capture result"
            report["results"].append(result)
            if result["status"] != "passed":
                report["failures"].append({"id": result["id"], "failure": result.get("failure", "unknown")})
            print(f"{result['status'].upper()} {vector['id']}: {result.get('failure', result.get('outcome'))}", file=sys.stderr, flush=True)
            write_json(args.output, report)
        require(input_hashes(stability_paths(args.vectors)) == report["stability_input_sha256"],
                "consumed target-emitter, fixture, vector, or dependency inputs changed during the oracle run")
        require(digest(args.native) == report["executable_sha256"]["native"], "native executable changed during the oracle run")
        if not report["failures"]:
            report["status"] = "passed"
    except Exception as error:
        report["failures"].append({"id": "harness", "failure": str(error)})
    report["passed"] = sum(result["status"] == "passed" for result in report["results"])
    report["total"] = len(report["results"])
    write_json(args.output, report)
    print(json.dumps({"status": report["status"], "passed": report["passed"], "total": report["total"],
                      "report": str(args.output), "failures": report["failures"]}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
