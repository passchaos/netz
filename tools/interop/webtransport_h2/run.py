#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["h2==4.3.0", "hpack==4.1.0", "hyperframe==6.1.0"]
# ///
"""Bidirectional TLS/h2 WebTransport interoperability with a Python peer."""
import argparse
from pathlib import Path
import hashlib
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import h2
import hpack
import hyperframe

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mqtt_socks5 import create_identity, listener
from peer import Peer
from wire import check_vectors


def context(ca: Path, cert: Path, key: Path, server: bool) -> ssl.SSLContext:
    value = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) if server else ssl.create_default_context(cafile=str(ca))
    value.minimum_version = ssl.TLSVersion.TLSv1_3
    value.maximum_version = ssl.TLSVersion.TLSv1_3
    value.set_alpn_protocols(["h2"])
    if server:
        value.load_cert_chain(cert, key)
    return value


def main() -> None:
    if not __debug__:
        raise RuntimeError("This interoperability gate requires Python assertions")
    parser = argparse.ArgumentParser()
    parser.add_argument("driver", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    check_vectors()
    traces = []
    outputs = []
    with tempfile.TemporaryDirectory(prefix="netz-wt-h2-") as tmp:
        ca, cert, key = create_identity(Path(tmp), "origin.internal")
        with listener() as server:
            errors = []
            def run_server() -> None:
                try:
                    raw, _ = server.accept()
                    with raw, context(ca, cert, key, True).wrap_socket(raw, server_side=True) as tls:
                        peer = Peer(tls, False)
                        traces.append(peer.run())
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=run_server, daemon=True)
            thread.start()
            result = subprocess.run([str(args.driver), "client", str(server.getsockname()[1]),
                                     str(ca), str(cert), str(key)], capture_output=True, text=True, timeout=15)
            thread.join(timeout=10)
            if thread.is_alive():
                raise TimeoutError("independent server did not finish")
            if errors or result.returncode:
                raise RuntimeError(result.stdout + result.stderr + repr(errors))
            outputs.append(result.stderr)

        def native_server(mode, exchange):
            process = subprocess.Popen([str(args.driver), mode, "0", str(ca), str(cert), str(key)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready = process.stderr.readline()
                startup = ready
                while ready and not ready.startswith("READY "):
                    ready = process.stderr.readline()
                    startup += ready
                if not ready:
                    raise RuntimeError("Netz server failed to start: " + startup)
                address = ("127.0.0.1", int(ready.split()[1]))
                admission = {}
                if mode == "listener":
                    # One worker and one connection slot: each timeout must
                    # release both before the next authenticated peer can run.
                    with socket.create_connection(address, timeout=2) as silent:
                        assert silent.recv(1) == b"", "silent TLS peer retained the worker"
                    admission["silent_tls_closed"] = True
                    for prefix in (b"", b"PRI * HTTP/2.0\r\n"):
                        with socket.create_connection(address, timeout=2) as raw:
                            with context(ca, cert, key, False).wrap_socket(raw, server_hostname="origin.internal") as silent:
                                assert silent.version() == "TLSv1.3" and silent.selected_alpn_protocol() == "h2"
                                if prefix:
                                    silent.sendall(prefix)
                                assert silent.recv(1) == b"", "silent or partial HTTP2 preface retained the worker"
                    admission.update(silent_http2_closed=True, partial_preface_closed=True,
                                     connection_timeout_ms=250, accept_workers=1, max_connections=1)
                with socket.create_connection(address, timeout=8) as raw:
                    with context(ca, cert, key, False).wrap_socket(raw, server_hostname="origin.internal") as tls:
                        peer = Peer(tls, True)
                        trace = exchange(peer)
                        if admission:
                            trace["connection_admission"] = admission
                stdout, stderr = process.communicate(timeout=10)
                if process.returncode:
                    raise RuntimeError(stdout + stderr)
                return stderr, trace
            except BaseException as error:
                try:
                    stdout, stderr = process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                raise RuntimeError(f"Python client failed: {error}\nNetz server:\n{stdout}{stderr}") from error
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()


        output, trace = native_server("server", Peer.run)
        outputs.append(output)
        traces.append(trace)
        listener_output, listener_trace = native_server("listener", Peer.listener_exchange)

    for mode, output in zip(("client", "server"), outputs):
        assert f"WebTransport HTTP2 {mode} passed:" in output, output
        if mode == "client":
            assert "WebTransport HTTP2 EndpointClient queue passed: connect+datagram+receive owned_results=true reuse_after_error=true" in output, output
            assert "WebTransport HTTP2 EndpointClient dropped cleanup passed: canceled=1 slot_reused=true" in output, output
        else:
            assert "WebTransport HTTP2 EndpointServer pending cleanup passed: canceled=1 slot_reused=true queue=true" in output, output
        print(output.strip())
    assert "WebTransport HTTP2 EndpointListener passed: accepted=true stream=true datagram=true close=19" in listener_output, listener_output
    print(listener_output.strip())
    directory = Path(__file__).resolve().parent
    report = {"status": "passed", "protocol": "draft-ietf-webtrans-http2-15",
              "python_packages": {"h2": h2.__version__, "hpack": hpack.__version__, "hyperframe": hyperframe.__version__},
              "tls": "TLSv1.3", "alpn": "h2", "traces": traces, "native_listener": listener_trace,
              "native_client_endpoint_queue": {"connect": True, "datagram": True, "receive": True, "owned_results": True, "reuse_after_error": True},
              "native_client_dropped_cleanup": {"reset_code": 8, "slot_reused": True},
              "native_server_pending_cleanup": {"reset_code": 8, "slot_reused": True, "queue": True},
              "driver_sha256": hashlib.sha256(args.driver.read_bytes()).hexdigest(),
              "source_sha256": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                                for name in ("peer.py", "wire.py", "run.py", "driver.zig")}}
    encoded = json.dumps(report, sort_keys=True, indent=2)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(encoded + "\n")
    print(encoded)
    print("WebTransport HTTP2 Python interoperability passed: directions=2 rejected=429 independent_capsules=true")


if __name__ == "__main__":
    main()
