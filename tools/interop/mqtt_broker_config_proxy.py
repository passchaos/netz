"""Mosquitto-style PROXY protocol listener configuration scenarios."""

from __future__ import annotations

import base64
from pathlib import Path
import socket
import subprocess

from mqtt_commit_log_support import (
    connect_packet,
    free_port,
    publish_packet,
    read_packet,
)


PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def _proxy_v2_header(
    *,
    tls: bool = False,
    verified: bool = False,
    certificate_connection: bool = False,
    certificate_session: bool = False,
    common_name: bytes | None = None,
) -> bytes:
    address = (
        b"\xc0\x00\x02\x05"
        + b"\x7f\x00\x00\x01"
        + b"\x18\x83\x07\x5b"
    )
    tlvs = b""
    if tls or certificate_connection or certificate_session or common_name is not None:
        flags = (
            int(tls)
            | (int(certificate_connection) << 1)
            | (int(certificate_session) << 2)
        )
        ssl_value = bytes((flags,)) + (0 if verified else 1).to_bytes(4, "big")
        ssl_value += b"\x21\x00\x07TLSv1.3"
        if common_name is not None:
            ssl_value += (
                b"\x22"
                + len(common_name).to_bytes(2, "big")
                + common_name
            )
        tlvs = b"\x20" + len(ssl_value).to_bytes(2, "big") + ssl_value
    payload = address + tlvs
    return (
        PROXY_V2_SIGNATURE
        + b"\x21\x11"
        + len(payload).to_bytes(2, "big")
        + payload
    )


def _run_broker(broker: Path, config: Path) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 1 clients" not in ready:
        process.terminate()
        process.wait(timeout=2)
        raise RuntimeError(f"PROXY broker failed to start: {ready}")
    return process


def _finish(process: subprocess.Popen[str]) -> None:
    try:
        if process.wait(timeout=5) != 0:
            raise RuntimeError("PROXY broker failed: " + process.stdout.read())
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)


def _expect_transport_rejection(
    broker: Path,
    config: Path,
    port: int,
    header: bytes,
) -> None:
    process = _run_broker(broker, config)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(
                header
                + connect_packet(
                    "proxy-v2-rejected", clean_start=True, protocol=5,
                )
            )
            try:
                unexpected = client.recv(1)
            except ConnectionResetError:
                unexpected = b""
            if unexpected:
                raise AssertionError(
                    "rejected PROXY v2 assertion received MQTT bytes: "
                    + unexpected.hex()
                )
        if process.wait(timeout=5) == 0:
            raise AssertionError("invalid PROXY v2 assertion was accepted")
        output = process.stdout.read()
        if "InvalidHeader" not in output:
            raise AssertionError(
                "PROXY v2 rejection omitted InvalidHeader: " + output
            )
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)


def _websocket_upgrade(sock: socket.socket, port: int) -> None:
    key = base64.b64encode(b"netz-proxy-test!").decode()
    request = (
        "GET /mqtt HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: mqtt\r\n\r\n"
    )
    sock.sendall(request.encode())
    response = bytearray()
    while b"\r\n\r\n" not in response:
        byte = sock.recv(1)
        if not byte:
            raise AssertionError("PROXY WebSocket closed during Upgrade")
        response.extend(byte)
    if not response.startswith(b"HTTP/1.1 101 "):
        raise AssertionError(f"PROXY WebSocket Upgrade failed: {response!r}")


def _send_websocket_binary(sock: socket.socket, payload: bytes) -> None:
    if len(payload) >= 126:
        raise AssertionError("PROXY test packet exceeded short WS frame")
    mask = b"\x12\x34\x56\x78"
    masked = bytes(
        byte ^ mask[index % len(mask)]
        for index, byte in enumerate(payload)
    )
    sock.sendall(bytes((0x82, 0x80 | len(payload))) + mask + masked)


def _recv_websocket_binary(sock: socket.socket) -> bytes:
    header = sock.recv(2)
    if len(header) != 2 or header[0] != 0x82 or header[1] & 0x80:
        raise AssertionError(f"unexpected WebSocket frame: {header.hex()}")
    length = header[1]
    if length >= 126:
        raise AssertionError("unexpected extended WebSocket frame")
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise AssertionError("WebSocket closed before complete MQTT packet")
        result.extend(part)
    return bytes(result)


def run_proxy_protocol_case(broker: Path, directory: Path) -> None:
    """Port Mosquitto's v1 and WebSocket v2 PROXY success scenarios."""
    v1_port = free_port()
    v1_config = directory / "proxy-v1.conf"
    v1_config.write_text(
        f"listener {v1_port} 127.0.0.1\n"
        "enable_proxy_protocol 1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    process = _run_broker(broker, v1_config)
    try:
        with socket.create_connection(("127.0.0.1", v1_port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(
                b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1883\r\n"
                + connect_packet("proxy-v1-config", clean_start=True, protocol=5)
            )
            first, body = read_packet(client)
            if first != 0x20 or len(body) < 2 or body[1] != 0:
                raise AssertionError(f"PROXY v1 CONNACK: {first:02x}{body.hex()}")
            client.sendall(b"\xe0\x00")
        _finish(process)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)

    v2_port = free_port()
    v2_config = directory / "proxy-v2-websocket.conf"
    v2_config.write_text(
        f"listener {v2_port} 127.0.0.1\n"
        "protocol websockets\n"
        "enable_proxy_protocol 2\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    process = _run_broker(broker, v2_config)
    try:
        with socket.create_connection(("127.0.0.1", v2_port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(_proxy_v2_header())
            _websocket_upgrade(client, v2_port)
            _send_websocket_binary(client, connect_packet(
                "proxy-v2-ws-config", clean_start=True, protocol=5,
            ))
            connack = _recv_websocket_binary(client)
            if len(connack) < 4 or connack[0] != 0x20 or connack[3] != 0:
                raise AssertionError(f"PROXY v2 WS CONNACK: {connack.hex()}")
            _send_websocket_binary(client, b"\xe0\x00")
        _finish(process)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)

    tls_port = free_port()
    tls_config = directory / "proxy-v2-require-tls.conf"
    tls_config.write_text(
        f"listener {tls_port} 127.0.0.1\n"
        "enable_proxy_protocol 2\n"
        "proxy_protocol_v2_require_tls true\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    process = _run_broker(broker, tls_config)
    try:
        with socket.create_connection(("127.0.0.1", tls_port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(
                _proxy_v2_header(tls=True)
                + connect_packet(
                    "proxy-v2-tls", clean_start=True, protocol=5,
                )
            )
            first, body = read_packet(client)
            if first != 0x20 or len(body) < 2 or body[1] != 0:
                raise AssertionError(
                    f"PROXY v2 TLS CONNACK: {first:02x}{body.hex()}"
                )
            client.sendall(b"\xe0\x00")
        _finish(process)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)

    tls_rejection_port = free_port()
    tls_rejection_config = directory / "proxy-v2-require-tls-reject.conf"
    tls_rejection_config.write_text(
        f"listener {tls_rejection_port} 127.0.0.1\n"
        "enable_proxy_protocol 2\n"
        "proxy_protocol_v2_require_tls true\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    _expect_transport_rejection(
        broker,
        tls_rejection_config,
        tls_rejection_port,
        _proxy_v2_header(),
    )

    for label, header in (
        ("missing", _proxy_v2_header()),
        (
            "unverified",
            _proxy_v2_header(tls=True, certificate_session=True),
        ),
        ("no-certificate", _proxy_v2_header(tls=True, verified=True)),
    ):
        certificate_port = free_port()
        certificate_config = directory / f"proxy-v2-cert-{label}.conf"
        certificate_config.write_text(
            f"listener {certificate_port} 127.0.0.1\n"
            "enable_proxy_protocol 2\n"
            "require_certificate true\n"
            "allow_anonymous true\n"
            "max_connections 1\n"
        )
        _expect_transport_rejection(
            broker,
            certificate_config,
            certificate_port,
            header,
        )

    certificate_port = free_port()
    certificate_config = directory / "proxy-v2-cert-success.conf"
    certificate_config.write_text(
        f"listener {certificate_port} 127.0.0.1\n"
        "enable_proxy_protocol 2\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    process = _run_broker(broker, certificate_config)
    try:
        with socket.create_connection(
            ("127.0.0.1", certificate_port), timeout=5,
        ) as client:
            client.settimeout(5)
            client.sendall(
                _proxy_v2_header(
                    tls=True,
                    verified=True,
                    certificate_session=True,
                )
                + connect_packet(
                    "proxy-v2-cert", clean_start=True, protocol=5,
                )
            )
            first, body = read_packet(client)
            if first != 0x20 or len(body) < 2 or body[1] != 0:
                raise AssertionError(
                    f"PROXY v2 certificate CONNACK: {first:02x}{body.hex()}"
                )
            client.sendall(b"\xe0\x00")
        _finish(process)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)

    identity_acl = directory / "proxy-v2-identity.acl"
    identity_acl.write_text("user proxy-client\ntopic write proxy/allowed\n")
    identity_port = free_port()
    identity_config = directory / "proxy-v2-identity.conf"
    identity_config.write_text(
        f"acl_file {identity_acl}\n"
        f"listener {identity_port} 127.0.0.1\n"
        "enable_proxy_protocol 2\n"
        "require_certificate true\n"
        "use_identity_as_username true\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    process = _run_broker(broker, identity_config)
    try:
        with socket.create_connection(
            ("127.0.0.1", identity_port), timeout=5,
        ) as client:
            client.settimeout(5)
            client.sendall(
                _proxy_v2_header(
                    tls=True,
                    verified=True,
                    certificate_connection=True,
                    common_name=b"proxy-client",
                )
                + connect_packet(
                    "proxy-v2-identity", clean_start=True, protocol=5,
                )
            )
            first, body = read_packet(client)
            if first != 0x20 or len(body) < 2 or body[1] != 0:
                raise AssertionError(
                    f"PROXY v2 identity CONNACK: {first:02x}{body.hex()}"
                )
            client.sendall(
                publish_packet(
                    "proxy/allowed",
                    b"authenticated CN",
                    1,
                    protocol=5,
                )
            )
            first, body = read_packet(client)
            if first != 0x40 or body[:2] != b"\x00\x01":
                raise AssertionError(
                    f"PROXY v2 identity PUBACK: {first:02x}{body.hex()}"
                )
            client.sendall(b"\xe0\x00")
        _finish(process)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)

    for label, common_name in (
        ("missing-cn", None),
        ("empty-cn", b""),
        ("invalid-cn", b"bad\x00name"),
    ):
        identity_rejection_port = free_port()
        identity_rejection_config = (
            directory / f"proxy-v2-identity-{label}.conf"
        )
        identity_rejection_config.write_text(
            f"listener {identity_rejection_port} 127.0.0.1\n"
            "enable_proxy_protocol 2\n"
            "require_certificate true\n"
            "use_identity_as_username true\n"
            "allow_anonymous true\n"
            "max_connections 1\n"
        )
        process = _run_broker(broker, identity_rejection_config)
        try:
            with socket.create_connection(
                ("127.0.0.1", identity_rejection_port), timeout=5,
            ) as client:
                client.settimeout(5)
                client.sendall(
                    _proxy_v2_header(
                        tls=True,
                        verified=True,
                        certificate_connection=True,
                        common_name=common_name,
                    )
                    + connect_packet(
                        "proxy-v2-no-identity",
                        clean_start=True,
                        protocol=5,
                    )
                )
                first, body = read_packet(client)
                if first != 0x20 or len(body) < 2 or body[1] != 0x87:
                    raise AssertionError(
                        "invalid PROXY v2 CN was not refused: "
                        f"{first:02x}{body.hex()}"
                    )
            _finish(process)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=2)

    invalid_combinations = {
        "require-tls-without-v2": "proxy_protocol_v2_require_tls true\n",
        "require-tls-with-v1": (
            "enable_proxy_protocol 1\n"
            "proxy_protocol_v2_require_tls true\n"
        ),
        "v2-subject": (
            "enable_proxy_protocol 2\n"
            "require_certificate true\n"
            "use_subject_as_username true\n"
        ),
        "v2-local-tls": (
            "enable_proxy_protocol 2\n"
            "certfile missing.pem\n"
            "keyfile missing.key\n"
        ),
    }
    for label, directives in invalid_combinations.items():
        invalid_config = directory / f"proxy-{label}.conf"
        invalid_config.write_text(
            f"listener {free_port()} 127.0.0.1\n"
            + directives
            + "allow_anonymous true\nmax_connections 1\n"
        )
        result = subprocess.run(
            [str(broker), f"--config={invalid_config}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0 or "InvalidDirective" not in result.stdout:
            raise AssertionError(
                f"invalid PROXY combination {label} was accepted: "
                + result.stdout
            )
