"""Verify HTTP/1 stapled-OCSP policy against an OpenSSL TLS 1.3 server."""

import os
from pathlib import Path
import select
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from mqtt_broker_config_bridge import _create_tls_material, _distinct_ports
from mqtt_broker_config_ocsp import (
    _create_ocsp_response,
    _start_openssl_stapling_server,
    _stop_openssl_server,
)


def _read_http_head(
    server: subprocess.Popen[bytes], timeout: float = 10
) -> bytes:
    assert server.stdout is not None
    deadline = time.monotonic() + timeout
    result = bytearray()
    while b"\r\n\r\n" not in result:
        if len(result) >= 16 * 1024:
            raise AssertionError("HTTP/1 OCSP request head exceeded 16 KiB")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out reading HTTP/1 OCSP request")
        ready, _, _ = select.select((server.stdout,), (), (), remaining)
        if not ready:
            raise TimeoutError("timed out reading HTTP/1 OCSP request")
        chunk = os.read(server.stdout.fileno(), 4096)
        if not chunk:
            raise EOFError("OpenSSL server closed before the HTTP/1 request")
        result.extend(chunk)
    return bytes(result)


def _run_case(
    client: Path,
    directory: Path,
    label: str,
    response: Path | None,
    accepted: bool,
    tls_version: str = "tls1_3",
) -> None:
    port = _distinct_ports(1)[0]
    ca = directory / "bridge-ca.pem"
    certificate = directory / "bridge-server.pem"
    key = directory / "bridge-server.key"
    server = _start_openssl_stapling_server(
        port,
        certificate,
        key,
        response,
        alpn="http/1.1",
        tls_version=tls_version,
    )
    process = None
    try:
        process = subprocess.Popen(
            [
                str(client),
                str(port),
                str(ca.resolve()),
                *(["tls12"] if tls_version == "tls1_2" else []),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if accepted:
            try:
                request = _read_http_head(server)
            except Exception as error:
                client_output = process.communicate(timeout=5)[0].decode(
                    errors="replace"
                )
                raise AssertionError(
                    f"{label} client={client_output!r}"
                ) from error
            if not request.startswith(b"GET /ocsp HTTP/1.1\r\n") or \
                    b"\r\nHost: localhost\r\n" not in request:
                raise AssertionError(f"unexpected HTTP/1 request: {request!r}")
            assert server.stdin is not None
            server.stdin.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n"
                b"Connection: close\r\n\r\nocsp-ok"
            )
            server.stdin.flush()
        output = process.communicate(timeout=10)[0].decode(errors="replace")
        if accepted:
            expected = (
                f"tls={'1.2' if tls_version == 'tls1_2' else '1.3'} "
                "status=200"
            )
            if process.returncode != 0 or expected not in output:
                raise AssertionError(f"good OCSP HTTP/1 client failed: {output}")
        elif process.returncode == 0 or "CertificateUntrusted" not in output:
            raise AssertionError(
                f"{label} OCSP HTTP/1 connection was not rejected: {output}"
            )
        if not accepted:
            assert server.stdout is not None
            ready, _, _ = select.select((server.stdout,), (), (), 0)
            if ready and os.read(server.stdout.fileno(), 1):
                raise AssertionError(
                    f"{label} OCSP client sent HTTP bytes after TLS rejection"
                )
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        _stop_openssl_server(server)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: http1_ocsp_client.py CLIENT")
    client = Path(sys.argv[1]).resolve()
    with TemporaryDirectory(prefix="netz-http1-ocsp-") as raw:
        directory = Path(raw)
        ca, certificate, _, _, _ = _create_tls_material(directory)
        good = _create_ocsp_response(
            directory, ca, certificate, revoked=False
        )
        revoked = _create_ocsp_response(
            directory, ca, certificate, revoked=True
        )
        _run_case(client, directory, "good", good, True)
        _run_case(client, directory, "missing", None, False)
        _run_case(client, directory, "revoked", revoked, False)
        _run_case(client, directory, "TLS 1.2 good", good, True, "tls1_2")
        _run_case(client, directory, "TLS 1.2 missing", None, False, "tls1_2")
        _run_case(client, directory, "TLS 1.2 revoked", revoked, False, "tls1_2")
    print("HTTP/1 OpenSSL TLS 1.2/1.3 OCSP good/missing/revoked interop passed")


if __name__ == "__main__":
    main()
