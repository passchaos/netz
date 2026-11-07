# /// script
# requires-python = ">=3.12"
# dependencies = ["hpack==4.1.0"]
# ///
"""Independent WebTransport protocol negotiation and scoped rejection gate."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import time
import hpack
import wire

REFERENCE_HEAD = "b2a4cfde90641be15777892eb36cd07dec0a7ee3"
ESCAPED = 'q"u\\oted'
AVAILABLE = '"q\\"u\\\\oted", "p1"'
SELECTED = '"q\\"u\\\\oted"'
ALPN_ERROR = 0x0817b3dd
SESSION_GONE = 0x170d7b68


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources(repo, directory, reference):
    names = {"build.zig", "src/runtime.zig", "src/internal/structured_field.zig", "src/internal/webtransport_error.zig"}
    for tree in ("src/webtransport", "src/http3", "src/quic", "src/tls"):
        names.update(path.relative_to(repo).as_posix() for path in (repo / tree).rglob("*.zig"))
    names.update(path.relative_to(repo).as_posix() for path in directory.rglob("*") if path.is_file()
                 and "target" not in path.relative_to(directory).parts and path.suffix in {".zig", ".rs", ".py", ".md", ".toml", ".lock"})
    native = {name: digest(repo / name) for name in sorted(names)}
    rust = {"Cargo.toml": digest(reference / "Cargo.toml")}
    for name in ("web-transport-quinn", "web-transport-proto", "web-transport-trait"):
        root = reference / "rs" / name
        rust.update({path.relative_to(reference).as_posix(): digest(path) for path in sorted(root.rglob("*"))
                     if path.is_file() and (path.suffix == ".rs" or path.name == "Cargo.toml")})
    return native, dict(sorted(rust.items()))


class Running:
    def __init__(self, command, name, logs):
        self.name = name
        self.lines = []
        self.ready = queue.Queue()
        self.process = subprocess.Popen(list(map(str, command)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()
        logs[name] = self.lines

    def read(self):
        for line in self.process.stdout:
            self.lines.append(line)
            self.ready.put(line)
        self.ready.put(None)

    def port(self, prefix):
        until = time.monotonic() + 10
        while True:
            line = self.ready.get(timeout=max(0, until - time.monotonic()))
            if line is None:
                raise RuntimeError(self.name + " ended before readiness\n" + "".join(self.lines))
            if line.startswith(prefix):
                return int(line[len(prefix):])

    def finish(self):
        code = self.process.wait(timeout=10)
        self.thread.join(timeout=2)
        if code:
            raise RuntimeError(self.name + " failed\n" + "".join(self.lines))

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        self.thread.join(timeout=2)


def execute(command, name, logs):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=30)
    logs[name] = [result.stdout, result.stderr]
    if result.returncode:
        raise RuntimeError(name + " failed\n" + result.stdout + result.stderr)


def records(logs, name, prefix):
    return [json.loads(line[len(prefix):]) for line in "".join(logs[name]).splitlines() if line.startswith(prefix)]


def identity(work):
    def openssl(*arguments):
        subprocess.run(["openssl", *map(str, arguments)], check=True, capture_output=True, timeout=10)
    pem, key, certificate, pk8, scalar = [work / name for name in ("certificate.pem", "key.pem", "certificate.der", "key.pk8", "scalar.bin")]
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", key, "-out", pem)
    openssl("x509", "-in", pem, "-outform", "DER", "-out", certificate)
    openssl("pkcs8", "-topk8", "-nocrypt", "-in", key, "-outform", "DER", "-out", pk8)
    sec1 = work / "key.sec1"
    openssl("ec", "-in", key, "-outform", "DER", "-out", sec1)
    encoded = sec1.read_bytes()
    def element(offset):
        tag, length = encoded[offset:offset + 2]
        start = offset + 2
        if length & 0x80:
            width = length & 0x7f
            length = int.from_bytes(encoded[start:start + width], "big")
            start += width
        return tag, encoded[start:start + length], start + length, start
    tag, _, _, start = element(0)
    assert tag == 0x30
    tag, _, next_offset, _ = element(start)
    assert tag == 2
    tag, secret, _, _ = element(next_offset)
    assert tag == 4 and len(secret) == 32
    scalar.write_bytes(secret)
    return certificate, pk8, scalar


def verify(logs):
    server_cases = records(logs, "netz-server", "WT_PROTOCOL_NETZ_SERVER_CASE ")
    assert [case["name"] for case in server_cases] == ["ordered", "escaped", "required-no-overlap"]
    assert server_cases[0]["available_wire"] == '"p2", "p1"' and server_cases[0]["selected"] == "p2"
    assert server_cases[1]["available_wire"] == AVAILABLE and server_cases[1]["selected"] == ESCAPED
    assert server_cases[2]["status"] == 406 and server_cases[2]["application_streams"] == server_cases[2]["application_datagrams"] == 0
    server = records(logs, "netz-server", "WT_PROTOCOL_NETZ_SERVER_RESULT ")[0]
    assert server["ordered_overlap"] and server["escaped_identifiers"] and server["required_rejection_before_application_io"]
    assert server["accepted"] == 2 and server["rejected"] == 1
    reference_client = records(logs, "reference-client", "WT_PROTOCOL_REFERENCE_CLIENT_RESULT ")[0]
    assert reference_client["semantic_session_protocol"] is True
    assert reference_client["required_rejected_before_application_io"] is True
    assert reference_client["cases"][0]["selected"] == "p2" and reference_client["cases"][1]["selected"] == ESCAPED
    assert reference_client["cases"][2]["status"] == 406
    assert reference_client["cases"][2]["application_datagrams"] == reference_client["cases"][2]["application_streams"] == 0
    native_client = records(logs, "netz-client", "WT_PROTOCOL_NETZ_CLIENT_RESULT ")[0]
    reference_server = records(logs, "reference-server", "WT_PROTOCOL_REFERENCE_SERVER_RESULT ")[0]
    accepted = records(logs, "netz-client", "WT_PROTOCOL_NETZ_CLIENT_CASE ")
    rejected = records(logs, "netz-client", "WT_PROTOCOL_NETZ_CLIENT_REJECTION ")
    assert [case["path"] for case in accepted] == ["/ordered", "/escaped", "/reuse"]
    assert accepted[1]["selected"] == ESCAPED and accepted[1]["selected_wire"] == SELECTED
    assert [case["path"] for case in rejected] == ["/missing", "/unoffered"]
    assert all(case["reset_code"] == ALPN_ERROR and case["sibling_session_count"] == 1 and case["connection_alive"] for case in rejected)
    requests = reference_server["requests"]
    assert [request["path"] for request in requests] == ["/ordered", "/missing", "/unoffered", "/escaped", "/reuse"]
    assert [request["session_id"] for request in requests] == [0, 4, 8, 12, 20]
    field_bytes = []
    for request in requests:
        path = request["path"]
        expected = '"p2", "p1"' if path == "/ordered" else AVAILABLE if path == "/escaped" else '"p1"'
        actual = wire.header(request["request_head_hex"], "wt-available-protocols")
        assert actual == expected
        selected = wire.header(request["response_head_hex"], "wt-protocol")
        assert selected == ('"p2"' if path == "/ordered" else SELECTED if path == "/escaped" else None if path == "/missing" else '"unoffered"' if path == "/unoffered" else '"p1"')
        field_bytes.append({"path": path, "available_wire": actual, "selected_wire": selected, "decoded_offers": json.loads("[" + actual + "]")})
    assert len(reference_server["resets"]) == 2
    assert [reset["session_id"] for reset in reference_server["resets"]] == [4, 8]
    assert all(reset["reset_code"] == reset["stop_code"] == ALPN_ERROR and reset["optimistic_stop_code"] == SESSION_GONE and reset["connection_alive"] for reset in reference_server["resets"])
    assert len(reference_server["datagrams"]) == 5 and len(reference_server["streams"]) == 1
    assert [item["body"] for item in reference_server["datagrams"]] == ["before-errors", "after-missing", "after-unoffered", "escaped-live", "new-session-live"]
    assert reference_server["streams"][0] == {"session_id": 0, "body": "sibling-stream"}
    for result in (server, reference_client, native_client, reference_server):
        assert result["status"] == "passed"
    assert native_client["scoped_alpn_resets"] == 2 and native_client["existing_sibling_preserved"] and native_client["new_session_after_errors"]
    assert native_client["optimistic_streams_not_delivered"] and native_client["connection_count"] == 1
    assert native_client["application_datagrams"] == 5 and native_client["application_streams"] == 1
    assert reference_server["optimistic_streams_scoped"] and reference_server["connection_count"] == 1
    return {"status": "passed", "reference_client": reference_client, "native_server": server, "native_server_cases": server_cases,
            "native_client": native_client, "native_client_cases": accepted, "native_rejections": rejected,
            "reference_server": reference_server, "actual_negotiation_fields": field_bytes}


def main():
    if not __debug__:
        raise RuntimeError("This gate requires Python assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("netz_server", type=Path)
    parser.add_argument("netz_client", type=Path)
    parser.add_argument("rust_peer", type=Path)
    parser.add_argument("--reference-root", type=Path, default=Path.home() / "Work/web-transport")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    repo, reference = directory.parents[2], args.reference_root.resolve()
    head = subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(reference), "status", "--porcelain"], text=True).strip()
    assert head == REFERENCE_HEAD and not dirty, "the reviewed Rust reference must match its pinned clean commit"
    wire.sanity()
    binaries = {name: path.resolve(strict=True) for name, path in (("netz_server", args.netz_server), ("netz_client", args.netz_client), ("rust_peer", args.rust_peer))}
    binary_hashes = {name: digest(path) for name, path in binaries.items()}
    before = sources(repo, directory, reference)
    logs, running = {}, []
    try:
        with tempfile.TemporaryDirectory(prefix="netz-wt-protocol-") as work:
            certificate, key, scalar = identity(Path(work))
            server = Running([binaries["netz_server"], certificate, scalar], "netz-server", logs)
            running.append(server)
            port = server.port("WT_PROTOCOL_NETZ_PORT=")
            execute([binaries["rust_peer"], "client", port, certificate], "reference-client", logs)
            server.finish()
            server = Running([binaries["rust_peer"], "server", certificate, key], "reference-server", logs)
            running.append(server)
            port = server.port("WT_PROTOCOL_REFERENCE_PORT=")
            execute([binaries["netz_client"], port], "netz-client", logs)
            server.finish()
            report = verify(logs)
        assert before == sources(repo, directory, reference), "sources changed during the gate"
        assert binary_hashes == {name: digest(path) for name, path in binaries.items()}, "executables changed during the gate"
        report.update(source_sha256=before[0], reference_source_sha256=before[1], reference_commit=head,
                      executable_sha256=binary_hashes, hpack_version=hpack.__version__, logs={name: "".join(lines) for name, lines in logs.items()})
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    except Exception as error:
        failure = {"status": "failed", "reason": str(error), "logs": {name: "".join(lines) for name, lines in logs.items()},
                   "source_sha256": before[0], "reference_source_sha256": before[1], "executable_sha256": binary_hashes}
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(failure, indent=2) + "\n")
        print(json.dumps(failure, indent=2))
        raise
    finally:
        for process in running:
            process.stop()


if __name__ == "__main__":
    main()
