#!/usr/bin/env python3
"""Port Mosquitto's bad-Origin WebSocket test to a netz MQTT server."""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import subprocess
import sys


RUNTIME = "client_io=python-socket server_io=zio-std-io"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("server", type=Path)
    parser.add_argument(
        "--mosquitto-test-root",
        type=Path,
        default=Path.home() / "Work/mosquitto/test",
    )
    return parser.parse_args()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def request(origin: str) -> bytes:
    return (
        b"GET /mqtt HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: 1JaITHdgDZVd/4OE2AzTTA==\r\n"
        b"Sec-WebSocket-Protocol: mqtt\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        + f"Origin: {origin}\r\n".encode()
        + b"\r\n"
    )


def main() -> None:
    args = parse_args()
    sys.path.insert(0, str(args.mosquitto_test_root))
    import mqtt_packets  # type: ignore
    from mosq_test import WebsocketWrapper  # type: ignore

    port = free_port()
    process = subprocess.Popen(
        [str(args.server), "origin", "v5", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    line = process.stdout.readline()
    expected_ready = f"netz MQTT WS interop server listening {RUNTIME}"
    if line.strip() != expected_ready:
        raise RuntimeError(f"netz Origin server failed to start: {line}")

    with socket.create_connection(("127.0.0.1", port), timeout=5) as denied:
        denied.sendall(request("https://denied.example"))
        if denied.recv(1):
            raise AssertionError("disallowed Origin unexpectedly upgraded")

    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        raw.sendall(request("https://example.org"))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = raw.recv(4096)
            if not chunk:
                raise AssertionError("allowed Origin closed before upgrade")
            response.extend(chunk)
        if not response.startswith(b"HTTP/1.1 101 " ):
            raise AssertionError(f"allowed Origin response: {response!r}")

        # Reuse Mosquitto's audited frame adapter after performing the exact
        # raw opening request from 13-websocket-bad-origin.py ourselves.
        peer = object.__new__(WebsocketWrapper)
        peer.connected = True
        peer._ssl = False
        peer._host = "localhost"
        peer._port = port
        peer._socket = raw
        peer._path = "/mqtt"
        peer._sendbuffer = bytearray()
        peer._readbuffer = bytearray()
        peer._requested_size = 0
        peer._payload_head = 0
        peer._readbuffer_head = 0
        peer.send(mqtt_packets.gen_connect("origin-allowed", proto_ver=5))
        connack = peer.recv(64)
        if not connack or connack[0] != 0x20:
            raise AssertionError(f"allowed Origin missing CONNACK: {connack!r}")
        peer.send(mqtt_packets.gen_disconnect(proto_ver=5))

    return_code = process.wait(timeout=5)
    if return_code != 0:
        raise RuntimeError(
            f"netz Origin server exited {return_code}: " + process.stdout.read()
        )
    print(
        "Mosquitto-derived MQTT WebSocket Origin allowlist passed "
        + RUNTIME
    )


if __name__ == "__main__":
    main()
