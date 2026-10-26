#!/usr/bin/env python3
"""Run the official grpc-web JS SDK in Chromium against the HTTP/1.1 adapter."""
import argparse
import base64
import functools
import hashlib
import http.server
import os
from pathlib import Path
import re
import selectors
import socket
import ssl
import subprocess
import tempfile
import threading


def run(args, **kwargs):
    return subprocess.check_output(args, **kwargs)


def tls_files(work):
    key = work / "key.pem"
    cert = work / "cert.pem"
    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)])
    run(["openssl", "req", "-new", "-x509", "-key", str(key), "-out", str(cert), "-days", "13", "-sha256", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth"], stderr=subprocess.DEVNULL)
    der = work / "cert.der"
    run(["openssl", "x509", "-in", str(cert), "-outform", "der", "-out", str(der)])
    description = run(["openssl", "ec", "-in", str(key), "-text", "-noout"], stderr=subprocess.DEVNULL).decode()
    private = description.split("priv:", 1)[1].split("pub:", 1)[0]
    scalar = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", private))
    if len(scalar) != 32:
        raise RuntimeError("unexpected P-256 scalar")
    scalar_file = work / "scalar.bin"
    scalar_file.write_bytes(scalar)
    public = run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"])
    spki = run(["openssl", "pkey", "-pubin", "-outform", "der"], input=public)
    return [str(der), str(scalar_file)], base64.b64encode(hashlib.sha256(spki).digest()).decode()


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("server")
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()
    client_dir = Path(__file__).with_name("grpc_web_chrome")
    if not (client_dir / "node_modules/grpc-web").exists():
        subprocess.run(["npm", "ci", "--prefix", str(client_dir), "--ignore-scripts", "--no-audit", "--no-fund"], check=True)
    with tempfile.TemporaryDirectory(prefix="netz-grpc-web-") as directory:
        work = Path(directory)
        (work / "index.html").write_text('<!doctype html><title>gRPC-Web interop</title><link rel="icon" href="data:,">')
        origin_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=directory))
        origin_thread = threading.Thread(target=origin_server.serve_forever, daemon=True)
        origin_thread.start()
        origin = f"http://localhost:{origin_server.server_port}"
        server_args = [args.server, "0", origin]
        environment = os.environ.copy()
        scheme = "http"
        if args.tls:
            files, spki = tls_files(work)
            server_args.extend(files)
            environment["CERTIFICATE_SPKI_SHA256"] = spki
            scheme = "https"
        server = subprocess.Popen(server_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        log = []
        try:
            selector = selectors.DefaultSelector()
            selector.register(server.stdout, selectors.EVENT_READ)
            if not selector.select(30):
                raise RuntimeError("server readiness timeout")
            ready = server.stdout.readline()
            log.append(ready)
            match = re.search(r"gRPC-Web browser listening port=(\d+) scheme=" + scheme + r" io=zio-std-io", ready)
            if not match:
                raise RuntimeError("unexpected server readiness: " + ready)
            endpoint = f"{scheme}://localhost:{match.group(1)}"
            if args.tls:
                # Browsers may abandon a speculative TLS connection without
                # close_notify. Exercise that idle boundary before any RPC.
                trust = ssl.create_default_context(cafile=str(work / "cert.pem"))
                trust.set_alpn_protocols(["http/1.1"])
                with socket.create_connection(("localhost", int(match.group(1))), timeout=5) as raw:
                    idle = trust.wrap_socket(raw, server_hostname="localhost")
                    os.close(idle.detach())
            subprocess.run(["node", str(client_dir / "client.js"), endpoint, origin, directory], env=environment, check=True, timeout=30)
            output, _ = server.communicate(timeout=10)
            log.append(output)
            if server.returncode != 0 or "gRPC-Web browser complete rpc=6" not in output:
                raise RuntimeError("missing successful server completion")
            print("".join(log), end="")
        except Exception:
            if server.poll() is None:
                server.terminate()
            output, _ = server.communicate(timeout=10)
            log.append(output)
            print("".join(log), end="")
            raise
        finally:
            if server.poll() is None:
                server.kill()
                server.wait()
            origin_server.shutdown()
            origin_server.server_close()
            origin_thread.join()


if __name__ == "__main__":
    main()
