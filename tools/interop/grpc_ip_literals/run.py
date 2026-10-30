#!/usr/bin/env python3
"""Check IP host endpoints, authority, SNI and certificate identity independently."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import tempfile


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True, timeout=15)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    sdk = root.parent / "grpc_response"
    if not (sdk / "node_modules/@grpc/grpc-js").exists():
        subprocess.run(["npm", "ci", "--prefix", str(sdk), "--ignore-scripts", "--no-audit", "--no-fund"], check=True, timeout=60)
    with tempfile.TemporaryDirectory(prefix="netz-grpc-ip-") as directory:
        work = Path(directory)
        ca, ca_key = work / "ca.pem", work / "ca.key"
        key, csr, cert, bad = (work / name for name in ("leaf.key", "leaf.csr", "leaf.pem", "dns-only.pem"))
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
                "-subj", "/CN=netz numeric CA", "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", ca_key, "-out", ca)
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-subj", "/CN=localhost", "-keyout", key, "-out", csr)
        for destination, names, serial in ((cert, "IP:127.0.0.1,IP:::1", "1"), (bad, "DNS:localhost", "2")):
            extensions = work / "extensions.cnf"
            extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=" + names + "\n")
            openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-set_serial", serial,
                    "-days", "1", "-extfile", extensions, "-out", destination)
        result = subprocess.run(["node", str(root / "peer.js"), str(Path(args.client).resolve()), str(key), str(cert), str(ca), str(bad)], check=True, timeout=120, stdout=subprocess.PIPE, text=True)
        record = json.loads(result.stdout)
        record["reference_source_sha256"] = hashlib.sha256((sdk / "node_modules/@grpc/grpc-js/build/src/channel-credentials.js").read_bytes()).hexdigest()
        repo = root.parents[2]
        sources = ["src/internal/endpoint_host.zig", "src/http2/runtime/client/host_connect.zig", "src/http2/runtime.zig", "src/grpc/channel.zig", "src/grpc/channel/resolver.zig", "src/grpc/channel/shared/source.zig", "tools/interop/grpc_ip_literals/client.zig", "tools/interop/grpc_ip_literals/peer.js", "tools/interop/grpc_ip_literals/run.py"]
        record["source_sha256"] = {"netz/" + name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in sources}
        for name in ["src/tls/client_hello.zig", "src/tls/client_hello/sni.zig"]:
            record["source_sha256"]["vail/" + name] = hashlib.sha256((repo.parent / "vail" / name).read_bytes()).hexdigest()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(record))


if __name__ == "__main__":
    main()
