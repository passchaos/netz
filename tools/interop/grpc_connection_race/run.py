#!/usr/bin/env python3
"""Independent gRPC address competition with stalled HTTP/2/TLS handshakes."""
import argparse
import hashlib
import json
from pathlib import Path
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
    with tempfile.TemporaryDirectory(prefix="netz-grpc-race-") as directory:
        work = Path(directory)
        ca, ca_key, key, csr, cert = (work / name for name in ("ca.pem", "ca.key", "leaf.key", "leaf.csr", "leaf.pem"))
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1", "-subj", "/CN=netz race CA", "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", ca_key, "-out", ca)
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=fixture.test", "-keyout", key, "-out", csr)
        extensions = work / "extensions.cnf"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:fixture.test\n")
        openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-set_serial", "1", "-days", "1", "-extfile", extensions, "-out", cert)
        result = subprocess.run(["node", str(root / "peer.js"), str(Path(args.client).resolve()), str(key), str(cert), str(ca)], check=True, stdout=subprocess.PIPE, text=True, timeout=60)
        record = json.loads(result.stdout)
        repo = root.parents[2]
        sources = ["src/internal/connection_race.zig", "src/internal/happy_eyeballs.zig", "src/internal/tcp_connect.zig", "src/internal/accept.zig", "src/internal/stream_io/timed_write.zig", "src/grpc/channel.zig", "src/grpc/channel/connect_race.zig", "src/grpc/channel/connect_race/context.zig", "src/grpc/channel/connect_race/allocator.zig", "tools/interop/grpc_connection_race/client.zig", "tools/interop/grpc_connection_race/peer.js", "tools/interop/grpc_connection_race/run.py"]
        record["source_sha256"] = {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in sources}
        record["reference_source_sha256"] = hashlib.sha256((sdk / "node_modules/@grpc/grpc-js/build/src/load-balancer-pick-first.js").read_bytes()).hexdigest()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(record))


if __name__ == "__main__":
    main()
