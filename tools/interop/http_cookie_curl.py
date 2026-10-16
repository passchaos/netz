#!/usr/bin/env python3
"""Compare Netz CookieJar path/order behavior with curl's cookie engine."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import tempfile
import threading


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    observed: dict[str, str] = {}

    def do_GET(self) -> None:
        if self.path == "/docs/seed":
            self.send_response(302)
            self.send_header("Location", "/docs/item")
            self.send_header("Set-Cookie", "root=one; Path=/")
            self.send_header("Set-Cookie", "docs=two")
            self.send_header("Set-Cookie", "deep=three; Path=/docs/deep")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path in ("/docs/item", "/docs/deep/item"):
            self.observed[self.path] = self.headers.get("Cookie", "")
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def log_message(self, *_: object) -> None:
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("peer", type=Path)
    return parser.parse_args()


def run_curl(url: str, jar: Path, seed: bool = False) -> None:
    command = [
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--cookie",
        "" if seed else str(jar),
        "--cookie-jar",
        str(jar),
    ]
    if seed:
        command.append("--location")
    command.append(url)
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("curl cookie arm failed: " + result.stdout)


def parse_peer(peer: Path) -> dict[str, str]:
    result = subprocess.run(
        [str(peer)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Netz cookie peer failed: " + result.stdout)
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            values[name] = value
    if values.get("client_io") != "netz-cookie-jar":
        raise AssertionError("Netz cookie peer identity missing: " + result.stdout)
    return values


def main() -> None:
    args = parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / "curl-cookies.txt"
            run_curl(f"http://127.0.0.1:{port}/docs/seed", jar, seed=True)
            run_curl(f"http://127.0.0.1:{port}/docs/deep/item", jar)
        curl_values = {
            "ordinary": Handler.observed.get("/docs/item", ""),
            "deep": Handler.observed.get("/docs/deep/item", ""),
        }
        netz_values = parse_peer(args.peer)
        if netz_values.get("ordinary") != curl_values["ordinary"]:
            raise AssertionError(
                f"ordinary cookie mismatch: netz={netz_values.get('ordinary')!r} "
                f"curl={curl_values['ordinary']!r}"
            )
        if netz_values.get("deep") != curl_values["deep"]:
            raise AssertionError(
                f"deep cookie mismatch: netz={netz_values.get('deep')!r} "
                f"curl={curl_values['deep']!r}"
            )
        print(
            "HTTP CookieJar curl parity passed: "
            f"ordinary={curl_values['ordinary']!r} "
            f"deep={curl_values['deep']!r} "
            "client_io=netz-cookie-jar reference_io=libcurl-cookie-engine"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
