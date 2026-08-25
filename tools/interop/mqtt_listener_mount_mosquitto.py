#!/usr/bin/env python3
"""Port Mosquitto's 10-listener-mount-point.py to the netz process gate."""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import subprocess
import sys


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
            raise AssertionError("broker closed before complete packet")
        result.extend(part)
    return bytes(result)


def read_packet(sock: socket.socket) -> bytes:
    packet = bytearray(recv_exact(sock, 1))
    remaining_length = 0
    multiplier = 1
    for _ in range(4):
        byte = recv_exact(sock, 1)[0]
        packet.append(byte)
        remaining_length += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            packet.extend(recv_exact(sock, remaining_length))
            return bytes(packet)
        multiplier *= 128
    raise AssertionError("malformed MQTT Remaining Length")


def connect_client(
    port: int, mqtt_packets, client_id: str, proto_ver: int
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(mqtt_packets.gen_connect(client_id, proto_ver=proto_ver))
    connack = read_packet(sock)
    minimum_len = 5 if proto_ver == 5 else 4
    if (
        connack[0] != 0x20
        or len(connack) < minimum_len
        or connack[2] != 0
        or connack[3] >= 0x80
    ):
        sock.close()
        raise AssertionError(f"invalid successful CONNACK: {connack.hex()}")
    return sock


def subscribe_all(sock: socket.socket, mqtt_packets, proto_ver: int) -> None:
    sock.sendall(mqtt_packets.gen_subscribe(1, "#", 0, proto_ver=proto_ver))
    actual = read_packet(sock)
    expected = mqtt_packets.gen_suback(1, 0, proto_ver=proto_ver)
    if actual != expected:
        raise AssertionError(
            f"SUBACK mismatch: expected {expected.hex()}, got {actual.hex()}"
        )


def run_case(server: Path, mqtt_packets, proto_ver: int) -> None:
    global_port = free_port()
    mounted_port = free_port()
    while mounted_port == global_port:
        mounted_port = free_port()
    process = subprocess.Popen(
        [str(server), str(global_port), str(mounted_port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    line = process.stdout.readline()
    if "listening" not in line:
        raise RuntimeError(f"netz mount server failed to start: {line}")

    clients: list[socket.socket] = []
    try:
        global_subscriber = connect_client(
            global_port, mqtt_packets, "global-subscriber", proto_ver
        )
        clients.append(global_subscriber)
        subscribe_all(global_subscriber, mqtt_packets, proto_ver)

        mounted_subscriber = connect_client(
            mounted_port, mqtt_packets, "mounted-subscriber", proto_ver
        )
        clients.append(mounted_subscriber)
        subscribe_all(mounted_subscriber, mqtt_packets, proto_ver)

        publisher = connect_client(
            mounted_port, mqtt_packets, "mounted-publisher", proto_ver
        )
        clients.append(publisher)
        publisher.sendall(
            mqtt_packets.gen_publish(
                "10/listener/mount/test",
                qos=0,
                payload=b"mount point",
                proto_ver=proto_ver,
            )
        )

        global_expected = mqtt_packets.gen_publish(
            "mount/10/listener/mount/test",
            qos=0,
            payload=b"mount point",
            proto_ver=proto_ver,
        )
        mounted_expected = mqtt_packets.gen_publish(
            "10/listener/mount/test",
            qos=0,
            payload=b"mount point",
            proto_ver=proto_ver,
        )
        global_actual = read_packet(global_subscriber)
        mounted_actual = read_packet(mounted_subscriber)
        if global_actual != global_expected:
            raise AssertionError(
                "global listener did not expose canonical mounted topic: "
                f"expected {global_expected.hex()}, got {global_actual.hex()}"
            )
        if mounted_actual != mounted_expected:
            raise AssertionError(
                "mounted listener did not strip its prefix: "
                f"expected {mounted_expected.hex()}, got {mounted_actual.hex()}"
            )

        disconnect = mqtt_packets.gen_disconnect(proto_ver=proto_ver)
        for client in clients:
            client.sendall(disconnect)
    finally:
        for client in clients:
            client.close()

    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("netz mount server did not exit")
    if return_code != 0:
        raise RuntimeError(
            f"netz mount server exited {return_code}: "
            + process.stdout.read()
        )


def main() -> None:
    args = parse_args()
    sys.path.insert(0, str(args.mosquitto_test_root))
    import mqtt_packets  # type: ignore

    for proto_ver in (4, 5):
        run_case(args.server, mqtt_packets, proto_ver)
    print(
        "Mosquitto-derived MQTT listener mount-point interop passed: "
        "v3.1.1 and v5 canonical ingress plus per-listener egress"
    )


if __name__ == "__main__":
    main()
