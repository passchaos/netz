#!/usr/bin/env python3
"""Pinned quic-go / Netz RFC9530 HTTP3 gate, both roles and QUIC versions."""
import argparse
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

PATHS = ["/encoded", "/trailer", "/corrupt", "/head", "/range", "/stream", "/generated", "/finish"]


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for part in iter(lambda: source.read(1024 * 1024), b""):
            value.update(part)
    return value.hexdigest()


def results(output):
    return [json.loads(line[7:]) for line in output.splitlines() if line.startswith("RESULT ")]


def pair(server_args, client_args, version, expected_server, expected_client):
    process = subprocess.Popen(server_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    startup = []
    try:
        while True:
            line = process.stdout.readline()
            if not line:
                raise RuntimeError("server failed to start: " + "".join(startup))
            startup.append(line)
            if line.startswith("READY "):
                port = line.split()[1]
                break
        command = [str(arg).replace("{port}", port) for arg in client_args]
        client = subprocess.run(command, capture_output=True, text=True, timeout=25)
        remaining, _ = process.communicate(timeout=20)
        server_output = "".join(startup) + remaining
        client_output = client.stdout + client.stderr
        if process.returncode or client.returncode:
            raise RuntimeError(server_output + client_output)
        server_result, client_result = results(server_output), results(client_output)
        assert len(server_result) == len(client_result) == 1
        for result, role in ((server_result[0], expected_server), (client_result[0], expected_client)):
            assert result["role"] == role and result["version"] == version and result["requests"] == 8, result
        go_result = server_result[0] if expected_server.startswith("quic-go") else client_result[0]
        assert go_result["connections"] == 1 and go_result["paths"] == PATHS
        assert go_result["tls"] == "TLSv1.3" and go_result["alpn"] == "h3"
        print(server_output.strip())
        print(client_output.strip())
        return {"version": version, "server": server_result[0], "client": client_result[0]}
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def main():
    if not __debug__:
        raise RuntimeError("HTTP3 digest gate requires Python assertions")
    parser = argparse.ArgumentParser()
    parser.add_argument("driver", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    module = root / "tools/interop/quic_go_module"
    go = os.environ.get("GO_BIN") or shutil.which("go") or "/nav_env/Temp/go1.24.13/bin/go"
    if not Path(go).is_file():
        raise RuntimeError("Go is required; set GO_BIN to the Go executable")
    environment = {**os.environ, "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"}
    subprocess.run([go, "test", "-mod=readonly", "./http3_digest"], cwd=module, env=environment, check=True)
    traces = []
    with tempfile.TemporaryDirectory(prefix="netz-http3-digest-") as tmp:
        directory = Path(tmp)
        peer = directory / "peer"
        subprocess.run([go, "build", "-mod=readonly", "-o", str(peer), "./http3_digest"], cwd=module, env=environment, check=True)
        for version in (1, 2):
            ca, cert, key = (directory / f"{version}-{suffix}.pem" for suffix in ("ca", "cert", "key"))
            identity_args = [str(peer), "-mode=identity", "-ca=" + str(ca), "-cert=" + str(cert), "-key=" + str(key)]
            subprocess.run(identity_args, check=True)
            traces.append(pair(
                [str(peer), "-mode=server", "-addr=127.0.0.1:0", f"-version={version}", "-ca=" + str(ca), "-cert=" + str(cert), "-key=" + str(key)],
                [str(args.driver.resolve()), "client", "{port}", str(version), str(ca)],
                version, "quic-go-server", "netz-client"))
            traces.append(pair(
                [str(args.driver.resolve()), "server", "0", str(version), str(cert), str(key)],
                [str(peer), "-mode=client", "-addr=127.0.0.1:{port}", f"-version={version}", "-ca=" + str(ca)],
                version, "netz-server", "quic-go-client"))
        dependencies = subprocess.check_output([go, "version", "-m", str(peer)], text=True)
        assert "github.com/quic-go/quic-go\tv0.59.0" in dependencies
        files = list((module / "http3_digest").glob("*.go")) + list(Path(__file__).parent.glob("*.zig")) + [Path(__file__), module / "go.mod", module / "go.sum"]
        report = {"status": "passed", "standard": "RFC9530", "transport": "HTTP3", "traces": traces,
                  "peer_dependencies": dependencies, "peer_sha256": digest(peer), "driver_sha256": digest(args.driver),
                  "source_sha256": {str(path.relative_to(root)): digest(path) for path in files}}
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(encoded + "\n")
    print(encoded)
    print("HTTP3 digest quic-go interoperability passed: directions=2 versions=2 requests=32 reuse=true")


if __name__ == "__main__":
    main()
