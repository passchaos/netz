"""TLS 1.3 OCSP stapling checks for configured MQTT bridges."""

from datetime import datetime, timezone
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import time

from mqtt_broker_config_bridge import (
    _connect_limits,
    _create_tls_material,
    _distinct_ports,
    _openssl,
    _packet,
    _start_broker,
    _stop,
    _wait_for_log,
)


def _openssl_output(*arguments: object) -> str:
    result = subprocess.run(
        ["openssl", *(str(argument) for argument in arguments)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=True,
    )
    return result.stdout.strip()


def _create_ocsp_response(
    directory: Path,
    ca: Path,
    certificate: Path,
    *,
    revoked: bool,
) -> Path:
    serial = _openssl_output(
        "x509", "-in", certificate, "-noout", "-serial"
    ).split("=", 1)[1]
    expires_text = _openssl_output(
        "x509",
        "-in",
        certificate,
        "-noout",
        "-enddate",
    ).split("=", 1)[1]
    expires = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(expires_text), timezone.utc
    ).strftime("%y%m%d%H%M%SZ")
    subject = _openssl_output(
        "x509", "-in", certificate, "-noout", "-subject", "-nameopt", "compat"
    ).split("=", 1)[1].strip()
    status = "R" if revoked else "V"
    revoked_at = (
        datetime.now(timezone.utc).strftime("%y%m%d%H%M%SZ")
        if revoked
        else ""
    )
    label = "revoked" if revoked else "good"
    index = directory / f"bridge-ocsp-{label}.index"
    index.write_text(
        "\t".join((status, expires, revoked_at, serial, "unknown", subject))
        + "\n"
    )
    response = directory / f"bridge-ocsp-{label}.der"
    _openssl(
        "ocsp",
        "-index",
        index,
        "-rsigner",
        ca,
        "-rkey",
        directory / "bridge-ca.key",
        "-CA",
        ca,
        "-issuer",
        ca,
        "-cert",
        certificate,
        "-no_nonce",
        "-respout",
        response,
        "-ndays",
        1,
    )
    return response


def _start_openssl_stapling_server(
    port: int,
    certificate: Path,
    key: Path,
    response: Path | None,
) -> subprocess.Popen[bytes]:
    command = [
        "openssl",
        "s_server",
        "-quiet",
        "-accept",
        f"127.0.0.1:{port}",
        "-cert",
        str(certificate),
        "-key",
        str(key),
        "-tls1_3",
        "-alpn",
        "mqtt",
    ]
    if response is not None:
        command.extend(("-status_file", str(response)))
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 5
    while True:
        if process.poll() is not None:
            raise RuntimeError(
                "OpenSSL OCSP server failed to start: "
                + process.stderr.read().decode(errors="replace")
            )
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError("OpenSSL OCSP server did not listen")
            time.sleep(0.02)
        else:
            probe.close()
            break
    return process


def _read_process_exact(
    process: subprocess.Popen[bytes], length: int, timeout: float
) -> bytes:
    assert process.stdout is not None
    deadline = time.monotonic() + timeout
    result = bytearray()
    while len(result) != length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out reading OpenSSL application data")
        ready, _, _ = select.select((process.stdout,), (), (), remaining)
        if not ready:
            raise TimeoutError("timed out reading OpenSSL application data")
        chunk = os.read(process.stdout.fileno(), length - len(result))
        if not chunk:
            assert process.stderr is not None
            error = (
                process.stderr.read().decode(errors="replace")
                if process.poll() is not None
                else ""
            )
            raise EOFError(f"OpenSSL server closed before MQTT data: {error}")
        result.extend(chunk)
    return bytes(result)


def _read_openssl_packet(
    process: subprocess.Popen[bytes], timeout: float = 10
) -> bytes:
    packet = bytearray(_read_process_exact(process, 1, timeout))
    remaining = 0
    multiplier = 1
    for _ in range(4):
        byte = _read_process_exact(process, 1, timeout)[0]
        packet.append(byte)
        remaining += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            packet.extend(_read_process_exact(process, remaining, timeout))
            return bytes(packet)
        multiplier *= 128
    raise AssertionError("OpenSSL bridge emitted an overlong MQTT packet")


def _stop_openssl_server(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def run_bridge_ocsp_case(broker: Path, directory: Path) -> None:
    ports = _distinct_ports(6)
    ca, certificate, key, _, _ = _create_tls_material(directory)
    good = _create_ocsp_response(directory, ca, certificate, revoked=False)
    revoked = _create_ocsp_response(directory, ca, certificate, revoked=True)
    cases = (
        ("good", good, True),
        ("missing", None, False),
        ("revoked", revoked, False),
    )
    for index, (label, response, accepted) in enumerate(cases):
        remote_port = ports[index * 2]
        local_port = ports[index * 2 + 1]
        server = _start_openssl_stapling_server(
            remote_port, certificate, key, response
        )
        config = directory / f"bridge-ocsp-{label}.conf"
        config.write_text(
            f"listener {local_port} 127.0.0.1\nallow_anonymous true\n"
            "max_connections 1\n"
            f"connection ocsp-{label}\naddress localhost:{remote_port}\n"
            "topic # in 0\nbridge_protocol_version mqttv50\n"
            "bridge_attempt_unsubscribe false\nnotifications false\n"
            f"bridge_cafile {ca}\nbridge_alpn mqtt\n"
            "bridge_require_ocsp true\nstart_type once\n"
        )
        log = directory / f"bridge-ocsp-{label}.log"
        process = output = None
        try:
            process, output = _start_broker(broker, config, log)
            if accepted:
                connect = _read_openssl_packet(server)
                _connect_limits(connect, 5)
                assert server.stdin is not None
                server.stdin.write(_packet(0x20, b"\x00\x00\x00"))
                server.stdin.flush()
            else:
                _wait_for_log(
                    process,
                    log,
                    "completed start_type=once error=CertificateUntrusted",
                )
                assert server.stdout is not None
                ready, _, _ = select.select((server.stdout,), (), (), 0)
                if ready and os.read(server.stdout.fileno(), 1):
                    raise AssertionError(
                        f"{label} OCSP bridge sent MQTT data after TLS rejection"
                    )
        finally:
            if process is not None:
                _stop(process, output)
            _stop_openssl_server(server)
