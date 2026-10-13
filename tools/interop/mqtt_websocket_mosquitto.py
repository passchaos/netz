#!/usr/bin/env python3
"""Exercise netz MQTT WS/WSS with Mosquitto's audited wire helpers."""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time


CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
"""
PAYLOAD = b"abcdefghijklmnopqrstuvwxyz0123456789" * 1821
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


def recv_exact(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise AssertionError("WebSocket closed before complete frame")
        result.extend(part)
    return bytes(result)


def recv_binary_message(peer) -> bytes:
    """Read one unfragmented server message without relying on recv sizing."""
    sock = peer._socket
    first, second = recv_exact(sock, 2)
    if first != 0x82 or second & 0x80:
        raise AssertionError(
            f"unexpected server WebSocket frame header: {first:02x}{second:02x}"
        )
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(sock, 8), "big")
    return recv_exact(sock, length)


def expected_connack(mqtt_packets, mqtt5_props, proto_ver: int) -> bytes:
    if proto_ver != 5:
        return mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    properties = (
        mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
        + mqtt5_props.gen_uint32_prop(
            mqtt5_props.MAXIMUM_PACKET_SIZE, 128 * 1024
        )
        + mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10)
    )
    return mqtt_packets.gen_connack(
        rc=0,
        proto_ver=5,
        properties=properties,
        property_helper=False,
    )


def run_case(server: Path, websocket_wrapper, do_send, mqtt_packets, mqtt5_props,
             transport: str, proto_ver: int, cafile: Path) -> None:
    port = free_port()
    protocol_name = (
        "v31" if proto_ver == 3 else "v311" if proto_ver == 4 else "v5"
    )
    process = subprocess.Popen(
        [str(server), transport, protocol_name, str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    line = process.stdout.readline()
    carrier = "WSS" if transport in ("wss", "proxy_wss") else "WS"
    expected_ready = f"netz MQTT {carrier} interop server listening {RUNTIME}"
    if line.strip() != expected_ready:
        raise RuntimeError(f"netz {transport} server failed to start: {line}")

    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    raw.settimeout(5)
    if transport == "proxy_ws":
        raw.sendall(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1883\r\n")
    elif transport == "proxy_wss":
        address = (
            b"\xc0\x00\x02\x05"
            + b"\x7f\x00\x00\x01"
            + b"\x18\x83\x07\x5b"
        )
        raw.sendall(
            b"\x0d\x0a\x0d\x0a\x00\x0d\x0aQUIT\x0a"
            + b"\x21\x11"
            + len(address).to_bytes(2, "big")
            + address
        )
    secure = transport in ("wss", "proxy_wss")
    if secure:
        context = ssl.create_default_context(cafile=str(cafile))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        raw = context.wrap_socket(raw, server_hostname="localhost")
    peer = websocket_wrapper(
        raw, "localhost", port, secure, "/mqtt", None
    )

    try:
        client_id = (
            "mosquitto-ws-v31"
            if proto_ver == 3
            else "mosquitto-ws-v311"
            if proto_ver == 4
            else "mosquitto-ws-v5"
        )
        do_send(peer, mqtt_packets.gen_connect(client_id, proto_ver=proto_ver))
        connack = recv_binary_message(peer)
        expected = expected_connack(mqtt_packets, mqtt5_props, proto_ver)
        if connack != expected:
            raise AssertionError(
                f"{transport}/{protocol_name} CONNACK: "
                f"expected {expected.hex()}, received {connack.hex()}"
            )

        publish = mqtt_packets.gen_publish(
            "interop/mosquitto/to-netz",
            qos=1,
            mid=1,
            payload=PAYLOAD,
            proto_ver=proto_ver,
        )
        # Mosquitto's WebsocketWrapper creates two distinct binary messages.
        # The second also carries a following MQTT packet, proving that netz
        # treats message boundaries as transport details in both directions.
        do_send(peer, publish[:3])
        do_send(peer, publish[3:] + mqtt_packets.gen_pingreq())

        puback = recv_binary_message(peer)
        expected_ack = mqtt_packets.gen_puback(1, proto_ver=proto_ver)
        if puback != expected_ack:
            raise AssertionError(
                f"{transport}/{protocol_name} PUBACK: "
                f"expected {expected_ack.hex()}, received {puback.hex()}"
            )
        pingresp = recv_binary_message(peer)
        if pingresp != mqtt_packets.gen_pingresp():
            raise AssertionError(
                f"{transport}/{protocol_name} PINGRESP: {pingresp.hex()}"
            )

        # Send another application packet immediately before a legal
        # client-originated PINGREQ. The server must retain the MQTT byte-stream
        # ordering across the WebSocket message boundary and answer only after
        # it consumes the complete PUBLISH.
        do_send(
            peer,
            mqtt_packets.gen_publish(
                "interop/mosquitto/during-ping",
                qos=0,
                payload=b"interleaved-publish",
                proto_ver=proto_ver,
            ) + mqtt_packets.gen_pingreq(),
        )
        pingresp = recv_binary_message(peer)
        if pingresp != mqtt_packets.gen_pingresp():
            raise AssertionError(
                f"{transport}/{protocol_name} second PINGRESP: {pingresp.hex()}"
            )

        outgoing = recv_binary_message(peer)
        expected_publish = mqtt_packets.gen_publish(
            "interop/netz/to-mosquitto",
            qos=1,
            mid=1,
            payload=b"netz-websocket-reply",
            proto_ver=proto_ver,
        )
        if outgoing != expected_publish:
            raise AssertionError(
                f"{transport}/{protocol_name} outbound PUBLISH mismatch"
            )
        do_send(peer, mqtt_packets.gen_puback(1, proto_ver=proto_ver))
        do_send(peer, mqtt_packets.gen_disconnect(proto_ver=proto_ver))
    finally:
        peer.close()

    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError(f"netz {transport}/{protocol_name} did not exit")
    if return_code != 0:
        raise RuntimeError(
            f"netz {transport}/{protocol_name} exited {return_code}: "
            + process.stdout.read()
        )
    print(
        f"Mosquitto-derived MQTT {transport.upper()} {protocol_name} "
        f"interop passed: {len(PAYLOAD)}-byte split PUBLISH, coalesced "
        "PING, ordered second PUBLISH/PING, "
        f"bidirectional QoS 1 {RUNTIME}"
    )


def main() -> None:
    args = parse_args()
    sys.path.insert(0, str(args.mosquitto_test_root))
    import mqtt5_props  # type: ignore
    import mqtt_packets  # type: ignore
    from mosq_test import WebsocketWrapper, do_send  # type: ignore

    with tempfile.TemporaryDirectory() as directory:
        cafile = Path(directory) / "ca.pem"
        cafile.write_text(CERTIFICATE_PEM)
        for transport in ("ws", "wss"):
            for proto_ver in (3, 4, 5):
                run_case(
                    args.server,
                    WebsocketWrapper,
                    do_send,
                    mqtt_packets,
                    mqtt5_props,
                    transport,
                    proto_ver,
                    cafile,
                )
        # The MQTT handshake is transport-version independent; one MQTT 5 case
        # per carrier proves PROXY is consumed before HTTP Upgrade and before
        # TLS, respectively.
        for transport in ("proxy_ws", "proxy_wss"):
            run_case(
                args.server,
                WebsocketWrapper,
                do_send,
                mqtt_packets,
                mqtt5_props,
                transport,
                5,
                cafile,
            )


if __name__ == "__main__":
    main()
