#!/usr/bin/env python3
"""Exercise netz HTTP servers with installed curl and nghttp2 clients."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import tempfile


CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
"""

PRIVATE_KEY_PEM = """-----BEGIN EC PRIVATE KEY-----
MDECAQEEIBI0VniavN7xI0VniavN7xI0VniavN7xI0VniavN7xI0oAoGCCqGSM49AwEH
-----END EC PRIVATE KEY-----
"""

NGHTTP_REQUEST_BODY = b"nghttp-request-body"
NGHTTP_REQUEST_TRAILER = "x-nghttp-request-complete: yes"
NGHTTP_RESPONSE_TRAILER = "x-netz-response-complete"
NGHTTPD_REQUEST_BODIES = (
    b"netz-nghttpd-first-body",
    b"netz-nghttpd-second-body",
)
NGHTTPD_RESPONSE_TRAILER = "x-nghttpd-response-complete: yes"
NGHTTPD_REUSE_BODY = b"nghttpd-after-reuse"


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def required_tool(environment_name: str, default: str) -> str:
    configured = os.environ.get(environment_name, default)
    resolved = shutil.which(configured)
    if resolved is None:
        raise RuntimeError(f"required external client not found: {configured}")
    return resolved


def wait_for_line(process: subprocess.Popen[str], expected: str) -> str:
    assert process.stdout is not None
    output: list[str] = []
    while True:
        ready, _, _ = select.select([process.stdout], [], [], 10)
        if not ready:
            raise RuntimeError(f"timed out waiting for server: {''.join(output)}")
        line = process.stdout.readline()
        if line == "":
            raise RuntimeError(
                f"server exited {process.poll()} before readiness: {''.join(output)}"
            )
        output.append(line)
        if expected in line:
            return "".join(output)


def stop_server(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.kill()
        process.wait()


def finish_server(
    process: subprocess.Popen[str], initial_output: str, expected: str
) -> None:
    try:
        suffix, _ = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        suffix, _ = process.communicate()
        raise RuntimeError("netz external-client server did not finish")
    output = initial_output + suffix
    if process.returncode != 0 or expected not in output:
        raise RuntimeError(
            f"netz external-client server failed ({process.returncode}): {output}"
        )


def start_server(
    server: Path, protocol: str, client: str, tls: bool
) -> tuple[subprocess.Popen[str], int, str]:
    port = free_port()
    command = [str(server), protocol, str(port), client]
    if tls:
        command.append("--tls")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        initial = wait_for_line(process, "server listening")
        return process, port, initial
    except BaseException:
        stop_server(process)
        raise


def header_contains(path: Path, name: str, value: str) -> bool:
    expected = f"{name}: {value}".lower()
    return any(line.strip().lower() == expected for line in path.read_text().splitlines())


def run_curl_case(
    server: Path, curl: str, directory: Path, protocol: str, tls: bool
) -> None:
    process, port, initial = start_server(server, protocol, "curl", tls)
    label = f"curl-{protocol}-{'tls' if tls else 'cleartext'}"
    first_headers = directory / f"{label}-first.headers"
    second_headers = directory / f"{label}-second.headers"
    first_body = directory / f"{label}-first.body"
    second_body = directory / f"{label}-second.body"
    scheme = "https" if tls else "http"
    host = "localhost" if tls else "127.0.0.1"
    common = [
        curl,
        "--disable",
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--noproxy",
        "*",
        "--max-time",
        "10",
    ]
    protocol_args = (
        ["--http1.1"]
        if protocol == "http1"
        else (["--http2"] if tls else ["--http2-prior-knowledge"])
    )
    tls_args = (
        [
            "--cacert",
            str(directory / "localhost.pem"),
            "--resolve",
            f"localhost:{port}:127.0.0.1",
        ]
        if tls
        else []
    )
    first_url = f"{scheme}://{host}:{port}/upload?client=curl"
    second_url = f"{scheme}://{host}:{port}/reuse?client=curl"
    command = (
        common
        + protocol_args
        + tls_args
        + [
            "--header",
            "x-interop-client: curl",
            "--data-binary",
            "curl-request-body",
            "--dump-header",
            str(first_headers),
            "--output",
            str(first_body),
            "--write-out",
            "first|%{http_version}|%{http_code}|%{num_connects}\n",
            first_url,
            "--next",
        ]
        + common[1:]
        + protocol_args
        + tls_args
        + [
            "--header",
            "x-interop-client: curl",
            "--request",
            "GET",
            "--dump-header",
            str(second_headers),
            "--output",
            str(second_body),
            "--write-out",
            "second|%{http_version}|%{http_code}|%{num_connects}\n",
            second_url,
        ]
    )
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=25)
        expected_version = "1.1" if protocol == "http1" else "2"
        expected_lines = {
            f"first|{expected_version}|200|1",
            f"second|{expected_version}|200|0",
        }
        actual_lines = {line.strip() for line in result.stdout.splitlines()}
        if result.returncode != 0 or actual_lines != expected_lines:
            raise RuntimeError(
                f"{label} failed ({result.returncode}): "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        if first_body.read_bytes() != b"netz-curl-upload":
            raise AssertionError(f"{label}: first response body mismatch")
        if second_body.read_bytes() != b"netz-curl-reuse":
            raise AssertionError(f"{label}: second response body mismatch")
        if not header_contains(first_headers, "x-netz-sequence", "1"):
            raise AssertionError(f"{label}: first response header missing")
        if not header_contains(second_headers, "x-netz-sequence", "2"):
            raise AssertionError(f"{label}: second response header missing")
        finish_server(
            process,
            initial,
            f"completed protocol={protocol} transport="
            f"{'tls' if tls else 'cleartext'} client=curl requests=2 "
            "connections=1",
        )
    finally:
        stop_server(process)


def run_nghttp_case(
    server: Path, nghttp: str, directory: Path, tls: bool
) -> None:
    process, port, initial = start_server(server, "http2", "nghttp", tls)
    label = f"nghttp-http2-{'tls' if tls else 'cleartext'}"
    scheme = "https" if tls else "http"
    host = "localhost" if tls else "127.0.0.1"
    environment = os.environ.copy()
    if tls:
        environment["SSL_CERT_FILE"] = str(directory / "localhost.pem")
    request_body = directory / f"{label}-request.body"
    request_body.write_bytes(NGHTTP_REQUEST_BODY)
    # nghttp applies -d and --trailer to every URI in this same-origin group;
    # each stream independently reads the complete file and sends the trailer.
    command = [
        nghttp,
        "--verbose",
        "--timeout=10",
        "--header=x-interop-client: nghttp",
        f"--data={request_body}",
        f"--trailer={NGHTTP_REQUEST_TRAILER}",
        f"{scheme}://{host}:{port}/first?client=nghttp",
        f"{scheme}://{host}:{port}/second?client=nghttp",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=25, env=environment
        )
        transcript = result.stdout + result.stderr
        if result.returncode != 0:
            raise RuntimeError(
                f"{label} failed ({result.returncode}): {transcript}"
            )
        if (
            result.stdout.count("netz-nghttp-first") != 1
            or result.stdout.count("netz-nghttp-second") != 1
        ):
            raise AssertionError(
                f"{label}: response bodies mismatch: {result.stdout!r}"
            )
        if transcript.count(":status: 200") != 2:
            raise AssertionError(f"{label}: expected two HTTP 200 response heads")
        for sequence in ("1", "2"):
            if f"x-netz-sequence: {sequence}" not in transcript:
                raise AssertionError(
                    f"{label}: response header {sequence} missing"
                )
        for route in ("first", "second"):
            trailer = f"{NGHTTP_RESPONSE_TRAILER}: {route}"
            if not received_end_stream_trailer(transcript, trailer):
                raise AssertionError(
                    f"{label}: terminal response trailer missing: {trailer}"
                )
        if tls and "The negotiated protocol: h2" not in transcript:
            raise AssertionError(f"{label}: TLS ALPN h2 not observed")
        if tls and "certificate verification failed" in transcript.lower():
            raise AssertionError(f"{label}: TLS certificate verification failed")
        finish_server(
            process,
            initial,
            f"completed protocol=http2 transport="
            f"{'tls' if tls else 'cleartext'} client=nghttp requests=2 "
            f"connections=1 streams=2 body_bytes={len(NGHTTP_REQUEST_BODY) * 2} "
            "request_trailers=2 response_trailers=2",
        )
    finally:
        stop_server(process)


def received_end_stream_trailer(transcript: str, trailer: str) -> bool:
    lines = transcript.splitlines()
    for index, line in enumerate(lines):
        if " recv " not in line or trailer not in line:
            continue
        frame_tail = "\n".join(lines[index + 1 : index + 5])
        if "recv HEADERS frame" in frame_tail and "END_STREAM" in frame_tail:
            return True
    return False


def stop_and_collect_server(
    process: subprocess.Popen[str], initial_output: str
) -> str:
    if process.poll() is None:
        process.terminate()
    try:
        suffix, _ = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        suffix, _ = process.communicate()
    return initial_output + suffix


def run_nghttpd_case(
    client: Path, nghttpd: str, directory: Path, tls: bool
) -> None:
    port = free_port()
    label = f"netz-nghttpd-{'tls' if tls else 'h2c'}"
    command = [
        nghttpd,
        "--verbose",
        "--echo-upload",
        f"--trailer={NGHTTPD_RESPONSE_TRAILER}",
        "--address=127.0.0.1",
        f"--htdocs={directory}",
    ]
    if tls:
        command += [
            str(port),
            str(directory / "localhost-key.pem"),
            str(directory / "localhost.pem"),
        ]
    else:
        command += ["--no-tls", str(port)]
    server = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    initial = ""
    result: subprocess.CompletedProcess[str] | None = None
    client_error: BaseException | None = None
    try:
        initial = wait_for_line(server, f"IPv4: listen 127.0.0.1:{port}")
        client_command = [str(client), str(port)]
        if tls:
            client_command.append(str(directory / "localhost.pem"))
        result = subprocess.run(
            client_command,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except BaseException as exc:
        client_error = exc
    server_output = stop_and_collect_server(server, initial)
    if client_error is not None:
        raise RuntimeError(
            f"{label}: client execution failed: {client_error}; "
            f"server={server_output!r}"
        ) from client_error
    assert result is not None
    client_output = result.stdout + result.stderr
    request_body_bytes = sum(len(body) for body in NGHTTPD_REQUEST_BODIES)
    expected_client = (
        "netz HTTP/2 client interoperated with nghttpd: "
        f"transport={'tls' if tls else 'h2c'} requests=3 connections=1 "
        f"streams=3 request_body_bytes={request_body_bytes} "
        "request_trailers=2 response_trailers=3 reuse=true "
        f"alpn={'h2' if tls else 'n/a'} "
        "client_io=zio-std-io server_io=nghttp2"
    )
    if result.returncode != 0 or expected_client not in client_output:
        raise RuntimeError(
            f"{label} failed ({result.returncode}): "
            f"client={client_output!r} server={server_output!r}"
        )

    scheme = "https" if tls else "http"
    expected_server_fields = (
        "[id=1]",
        "recv (stream_id=1) :method: POST",
        "recv (stream_id=1) :path: /first?client=netz",
        f"recv (stream_id=1) :scheme: {scheme}",
        "recv (stream_id=1) x-netz-request: first",
        "recv (stream_id=1) trailer: x-netz-request-complete",
        "recv (stream_id=3) :method: POST",
        "recv (stream_id=3) :path: /second?client=netz",
        f"recv (stream_id=3) :scheme: {scheme}",
        "recv (stream_id=3) x-netz-request: second",
        "recv (stream_id=3) trailer: x-netz-request-complete",
        "recv (stream_id=5) :method: GET",
        "recv (stream_id=5) :path: /after.txt?client=netz",
        f"recv (stream_id=5) :scheme: {scheme}",
    )
    for field in expected_server_fields:
        if field not in server_output:
            raise AssertionError(
                f"{label}: nghttpd transcript missing {field!r}: "
                f"{server_output!r}"
            )
    for route in ("first", "second"):
        trailer = f"x-netz-request-complete: {route}"
        if not received_end_stream_trailer(server_output, trailer):
            raise AssertionError(
                f"{label}: terminal request trailer missing: {trailer}"
            )
    if "[id=2]" in server_output:
        raise AssertionError(f"{label}: nghttpd observed more than one connection")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("server", type=Path)
    parser.add_argument("client", type=Path)
    args = parser.parse_args()
    curl = required_tool("CURL", "curl")
    nghttp = required_tool("NGHTTP", "nghttp")
    nghttpd = required_tool("NGHTTPD", "nghttpd")
    curl_version = subprocess.run(
        [curl, "--version"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    if not curl_version or "HTTP2" not in " ".join(curl_version):
        raise RuntimeError("curl lacks HTTP/2 support")
    nghttp_version = subprocess.run(
        [nghttp, "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    nghttpd_version = subprocess.run(
        [nghttpd, "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()

    with tempfile.TemporaryDirectory(prefix="netz-http-clients-") as raw_dir:
        directory = Path(raw_dir)
        (directory / "localhost.pem").write_text(CERTIFICATE_PEM)
        (directory / "localhost-key.pem").write_text(PRIVATE_KEY_PEM)
        (directory / "after.txt").write_bytes(NGHTTPD_REUSE_BODY)
        for protocol in ("http1", "http2"):
            for tls in (False, True):
                run_curl_case(args.server, curl, directory, protocol, tls)
        for tls in (False, True):
            run_nghttp_case(args.server, nghttp, directory, tls)
        for tls in (False, True):
            run_nghttpd_case(args.client, nghttpd, directory, tls)

    print(
        "External HTTP interop passed in both endpoint roles: curl HTTP/1.1+h2 "
        "and nghttp2 h2 clients against Netz, plus Netz h2 against nghttpd; "
        "cleartext+certificate-verified TLS, persistent multiplexed body/trailer "
        "traffic verified; "
        f"curl={curl_version[0]} nghttp={nghttp_version} "
        f"nghttpd={nghttpd_version} netz_io=zio-std-io"
    )


if __name__ == "__main__":
    main()
