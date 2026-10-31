#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["h2==4.3.0", "hpack==4.1.0", "hyperframe==6.1.0", "http-sfv==0.9.9"]
# ///
"""RFC9530 digests over real HTTPS connections with independent HTTP peers."""
import argparse
from pathlib import Path
import hashlib
import json
import ssl
import subprocess
import sys
import tempfile
import threading
from importlib.metadata import version

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mqtt_socks5 import create_identity, listener
from peer import serve_h1, serve_h2


def main() -> None:
    if not __debug__:
        raise RuntimeError("HTTP digest gate requires Python assertions")
    parser = argparse.ArgumentParser()
    parser.add_argument("driver", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    traces, errors = [], []
    with tempfile.TemporaryDirectory(prefix="netz-http-digest-") as tmp:
        ca, cert, key = create_identity(Path(tmp), "origin.internal")
        with listener() as h1, listener() as h2:
            def run(serve, server, alpn):
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                    context.set_alpn_protocols([alpn])
                    context.load_cert_chain(cert, key)
                    traces.append(serve(server, context))
                except BaseException as error:
                    errors.append(error)
            threads = [threading.Thread(target=run, args=(serve_h1, h1, "http/1.1"), daemon=True), threading.Thread(target=run, args=(serve_h2, h2, "h2"), daemon=True)]
            for thread in threads:
                thread.start()
            result = subprocess.run([str(args.driver), str(h1.getsockname()[1]), str(h2.getsockname()[1]), str(ca)], capture_output=True, text=True, timeout=20)
            for thread in threads:
                thread.join(timeout=10)
            if any(thread.is_alive() for thread in threads) or errors or result.returncode:
                raise RuntimeError(result.stdout + result.stderr + repr(errors))
    for protocol in ("h1", "h2"):
        assert f"HTTP digest {protocol} passed: requests=8" in result.stderr, result.stderr
    assert len(traces) == 2 and all(t["requests"] == 8 and t["generated_verified"] for t in traces)
    directory = Path(__file__).resolve().parent
    report = {"status": "passed", "standard": "RFC9530", "traces": sorted(traces, key=lambda t: t["protocol"]),
              "python_packages": {name: version(name) for name in ("h2", "hpack", "hyperframe", "http-sfv")},
              "driver_sha256": hashlib.sha256(args.driver.read_bytes()).hexdigest(),
              "source_sha256": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in ("driver.zig", "peer.py", "run.py")}}
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(encoded + "\n")
    print(result.stderr.strip())
    print(encoded)
    print("HTTP digest Python interoperability passed: protocols=2 requests=16 independent_hashlib=true independent_sfv=true")


if __name__ == "__main__":
    main()
