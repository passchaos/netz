#!/usr/bin/env python3
"""Verify configured MQTT TLS 1.2/1.3 ticket resumption with Python/OpenSSL."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile

from mqtt_broker_config import (
    FINITE_TEST_ENV,
    assert_openssl_mqtt_success,
    connect_packet,
    connack_reason,
    free_port,
    read_listener_lines,
    read_mqtt_packet,
    read_websocket_binary,
    send_websocket_binary,
    websocket_mqtt_ping,
)
from mqtt_broker_config_bridge import _create_tls_material


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("broker", type=Path)
    parser.add_argument(
        "mode",
        choices=("tls12", "tls13"),
        default="tls12",
        nargs="?",
    )
    return parser.parse_args()


def run_client(
    context: ssl.SSLContext,
    port: int,
    client_id: str,
    session: ssl.SSLSession | None,
    expect_resumed: bool,
    expected_version: str,
) -> ssl.SSLSession:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    raw.settimeout(5)
    client = context.wrap_socket(
        raw,
        server_hostname="localhost",
        session=session,
    )
    try:
        if client.version() != expected_version:
            raise AssertionError(f"unexpected TLS version: {client.version()}")
        if client.selected_alpn_protocol() != "mqtt":
            raise AssertionError(
                f"unexpected ALPN: {client.selected_alpn_protocol()!r}"
            )
        if client.session_reused != expect_resumed:
            raise AssertionError(
                f"expected resumed={expect_resumed}, "
                f"got {client.session_reused}"
            )
        client.sendall(connect_packet(client_id) + b"\xc0\x00")
        connack = read_mqtt_packet(client)
        pingresp = read_mqtt_packet(client)
        combined = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=connack + pingresp,
            stderr=b"",
        )
        assert_openssl_mqtt_success(combined)
        negotiated = client.session
        if not negotiated.has_ticket:
            raise AssertionError("configured broker did not issue a TLS ticket")
        client.sendall(b"\xe0\x00")
        return negotiated
    finally:
        client.close()


def run_websocket_client(
    context: ssl.SSLContext,
    port: int,
    client_id: str,
    session: ssl.SSLSession | None,
    expect_resumed: bool,
    expected_version: str,
) -> ssl.SSLSession:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    raw.settimeout(5)
    client = context.wrap_socket(
        raw,
        server_hostname="localhost",
        session=session,
    )
    try:
        if client.version() != expected_version:
            raise AssertionError(f"unexpected WSS TLS version: {client.version()}")
        if client.selected_alpn_protocol() is not None:
            raise AssertionError(
                f"unexpected configured WSS ALPN: "
                f"{client.selected_alpn_protocol()!r}"
            )
        if client.session_reused != expect_resumed:
            raise AssertionError(
                f"expected WSS resumed={expect_resumed}, "
                f"got {client.session_reused}"
            )
        request = (
            "GET /mqtt HTTP/1.1\r\n"
            f"Host: localhost:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: bmV0ei10aWNrZXQtdGVzdA==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Protocol: mqtt\r\n\r\n"
        )
        client.sendall(request.encode())
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = client.recv(1)
            if not chunk:
                raise EOFError("WSS server closed during Upgrade")
            response.extend(chunk)
            if len(response) > 16 * 1024:
                raise AssertionError("oversized WSS response head")
        if not response.startswith(b"HTTP/1.1 101 "):
            raise AssertionError(f"WSS Upgrade failed: {response!r}")
        send_websocket_binary(client, connect_packet(client_id))
        if connack_reason(read_websocket_binary(client)) != 0:
            raise AssertionError("configured WSS CONNECT failed")
        websocket_mqtt_ping(client)
        negotiated = client.session
        if not negotiated.has_ticket:
            raise AssertionError("configured WSS listener did not issue a ticket")
        send_websocket_binary(client, b"\xe0\x00")
        return negotiated
    finally:
        client.close()


def main() -> None:
    args = parse_args()
    tls13 = args.mode == "tls13"
    configured_version = "tlsv1.3" if tls13 else "tlsv1.2"
    expected_version = "TLSv1.3" if tls13 else "TLSv1.2"
    ticket_directives = (
        "tls13_session_tickets true\n"
        "tls13_session_ticket_server_id localhost\n"
        "tls13_session_ticket_lifetime 3600\n"
        if tls13
        else
        "ciphers ECDHE-ECDSA-AES128-GCM-SHA256\n"
        "tls12_session_tickets true\n"
        "tls12_session_ticket_server_id localhost\n"
        "tls12_session_ticket_lifetime 3600\n"
    )
    with tempfile.TemporaryDirectory(prefix="netz-mqtt-ticket-") as raw:
        directory = Path(raw)
        ca, certificate, key, _, _ = _create_tls_material(directory)
        port = free_port()
        websocket_port = free_port()
        while websocket_port == port:
            websocket_port = free_port()
        config = directory / "broker.conf"
        config.write_text(
            f"listener {port} 127.0.0.1\n"
            f"certfile {certificate}\n"
            f"keyfile {key}\n"
            f"tls_version {configured_version}\n"
            f"{ticket_directives}"
            "allow_anonymous true\n"
            "max_connections 2\n"
            f"listener {websocket_port} 127.0.0.1\n"
            "protocol websockets\n"
            f"certfile {certificate}\n"
            f"keyfile {key}\n"
            f"tls_version {configured_version}\n"
            f"{ticket_directives}"
            "allow_anonymous true\n"
            "max_connections 2\n"
        )
        environment = os.environ.copy()
        environment[FINITE_TEST_ENV] = "1"
        process = subprocess.Popen(
            [str(args.broker), f"--config={config}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
        )
        try:
            listeners = read_listener_lines(
                process,
                2,
                f"{expected_version} ticket broker",
            )
            if not any(line.startswith("mqtts ") for line in listeners):
                raise AssertionError(
                    f"missing MQTT/TLS listener: {listeners!r}"
                )
            if not any(line.startswith("wss ") for line in listeners):
                raise AssertionError(
                    f"missing MQTT/WSS listener: {listeners!r}"
                )
            context = ssl.create_default_context(cafile=str(ca))
            context.minimum_version = (
                ssl.TLSVersion.TLSv1_3
                if tls13
                else ssl.TLSVersion.TLSv1_2
            )
            context.maximum_version = context.minimum_version
            if not tls13:
                context.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
            context.set_alpn_protocols(["mqtt"])
            session = run_client(
                context,
                port,
                "configured-ticket-first",
                None,
                False,
                expected_version,
            )
            run_client(
                context,
                port,
                "configured-ticket-second",
                session,
                True,
                expected_version,
            )
            websocket_context = ssl.create_default_context(cafile=str(ca))
            websocket_context.minimum_version = context.minimum_version
            websocket_context.maximum_version = context.maximum_version
            if not tls13:
                websocket_context.set_ciphers(
                    "ECDHE-ECDSA-AES128-GCM-SHA256"
                )
            websocket_session = run_websocket_client(
                websocket_context,
                websocket_port,
                "configured-wss-ticket-first",
                None,
                False,
                expected_version,
            )
            run_websocket_client(
                websocket_context,
                websocket_port,
                "configured-wss-ticket-second",
                websocket_session,
                True,
                expected_version,
            )
            if process.wait(timeout=5) != 0:
                raise RuntimeError(
                    f"configured {expected_version} ticket broker failed: "
                    + (process.stdout.read() if process.stdout else "")
                )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    standard = "RFC 8446" if tls13 else "RFC 5077"
    print(
        f"configured MQTT TLS/WSS {expected_version} "
        f"{standard} resumption passed"
    )


if __name__ == "__main__":
    main()
