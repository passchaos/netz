#!/usr/bin/env python3
"""Run selected upstream Mosquitto MQTT 5 wire vectors against netz.

This intentionally imports Mosquitto's packet generators but does not pretend
to run its broker/config/plugin harness. The selected cases depend only on raw
MQTT bytes and therefore remain meaningful against a different broker process.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("broker", type=Path)
    parser.add_argument(
        "--mosquitto-test-root",
        type=Path,
        default=Path.home() / "Work/mosquitto/test",
    )
    return parser.parse_args()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def read_packet(sock: socket.socket) -> bytes:
    fixed = recv_exact(sock, 1)
    remaining_bytes = bytearray()
    multiplier = 1
    remaining = 0
    while True:
        encoded = recv_exact(sock, 1)[0]
        remaining_bytes.append(encoded)
        remaining += (encoded & 0x7F) * multiplier
        if encoded & 0x80 == 0:
            break
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            raise AssertionError("malformed MQTT Remaining Length")
    return fixed + bytes(remaining_bytes) + recv_exact(sock, remaining)


def recv_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError("broker closed before complete packet")
        result.extend(part)
    return bytes(result)


def expect_packet(sock: socket.socket, expected: bytes, label: str) -> None:
    actual = read_packet(sock)
    if actual != expected:
        raise AssertionError(
            f"{label}: expected {expected.hex()}, received {actual.hex()}"
        )


class NetzBroker:
    def __init__(
        self, executable: Path, connections: int = 1, ignore_errors: bool = False
    ):
        self.executable = executable
        self.connections = connections
        self.ignore_errors = ignore_errors
        self.port = free_port()
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> "NetzBroker":
        command = [
                str(self.executable),
                f"--bind=127.0.0.1:{self.port}",
                f"--connections={self.connections}",
                "--max-queued-deliveries=1024",
                "--max-outgoing-inflight=64",
                "--no-restore",
            ]
        if self.ignore_errors:
            command.append("--ignore-connection-errors")
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if "listening" not in line:
            raise RuntimeError(f"netz broker failed to start: {line.strip()}")
        return self

    def connect(self) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        sock.settimeout(5)
        return sock

    def __exit__(self, exc_type, exc, traceback) -> None:
        assert self.process is not None
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=5)
            if exc_type is None:
                raise RuntimeError("netz broker did not exit after DISCONNECT")
        if exc_type is None and self.process.returncode != 0:
            assert self.process.stdout is not None
            raise RuntimeError(
                f"netz broker exited {self.process.returncode}: "
                + self.process.stdout.read()
            )


def connect_client(
    sock: socket.socket, mqtt_packets, client_id: str, proto_ver: int
) -> None:
    sock.sendall(mqtt_packets.gen_connect(client_id, proto_ver=proto_ver))
    connack = read_packet(sock)
    minimum_len = 5 if proto_ver == 5 else 4
    if connack[0] != 0x20 or len(connack) < minimum_len or connack[3] >= 0x80:
        raise AssertionError(f"invalid successful CONNACK: {connack.hex()}")


def connect_v5(sock: socket.socket, mqtt_packets, client_id: str) -> None:
    connect_client(sock, mqtt_packets, client_id, 5)


def no_matching_subscribers(executable: Path, mqtt_packets, mqtt5_rc) -> None:
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "03-pub-qos1-no-subs")
            topics = [
                "03B/no/subs/pub",
                "03B/no/subs/pub/qos1",
                "03B/no/subs/pub/qos1/test",
            ]
            mid = 1
            for topic in topics:
                packet = mqtt_packets.gen_publish(
                    topic, qos=1, mid=mid, payload="message", proto_ver=5
                )
                sock.sendall(packet)
                expect_packet(
                    sock,
                    mqtt_packets.gen_puback(
                        mid,
                        proto_ver=5,
                        reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS,
                    ),
                    f"no-match PUBACK {mid}",
                )
                mid += 1
            retained = mqtt_packets.gen_publish(
                topics[-1],
                qos=1,
                mid=mid,
                payload="message",
                proto_ver=5,
                retain=True,
            )
            sock.sendall(retained)
            expect_packet(
                sock,
                mqtt_packets.gen_puback(
                    mid,
                    proto_ver=5,
                    reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS,
                ),
                "retained no-match PUBACK",
            )
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def subscription_identifiers(executable: Path, mqtt_packets, mqtt5_props) -> None:
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "02-subpub-subid")
            subscriptions = [
                (1, "02/subpub/subid/id1", 1),
                (2, "02/subpub/subid/+/id2", 14),
                (3, "02/subpub/subid/noid", None),
                (4, "02/subpub/subid/id1", None),
                (5, "02/subpub/subid/+/id2", 19),
                (6, "02/subpub/subid/noid", 21),
            ]
            for mid, topic, identifier in subscriptions:
                props = (
                    mqtt5_props.gen_varint_prop(
                        mqtt5_props.SUBSCRIPTION_IDENTIFIER, identifier
                    )
                    if identifier is not None
                    else b""
                )
                sock.sendall(
                    mqtt_packets.gen_subscribe(
                        mid, topic, 0, proto_ver=5, properties=props
                    )
                )
                expect_packet(
                    sock,
                    mqtt_packets.gen_suback(mid, 0, proto_ver=5),
                    f"SUBACK {mid}",
                )

            publishes = [
                ("02/subpub/subid/test/id2", "message2", 19),
                ("02/subpub/subid/noid", "message3", 21),
                ("02/subpub/subid/id1", "message1", None),
            ]
            for topic, payload, identifier in publishes:
                sock.sendall(
                    mqtt_packets.gen_publish(
                        topic, qos=0, payload=payload, proto_ver=5
                    )
                )
                props = (
                    mqtt5_props.gen_varint_prop(
                        mqtt5_props.SUBSCRIPTION_IDENTIFIER, identifier
                    )
                    if identifier is not None
                    else b""
                )
                expect_packet(
                    sock,
                    mqtt_packets.gen_publish(
                        topic,
                        qos=0,
                        payload=payload,
                        proto_ver=5,
                        properties=props,
                    ),
                    f"forwarded PUBLISH {topic}",
                )
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def hostile_initial_packets(executable: Path, mqtt_packets) -> None:
    # Derived from Mosquitto 01-bad-initial-packets.py. A huge declared
    # Remaining Length must be rejected before payload allocation/read, and a
    # later well-formed connection proves the finite broker remains usable.
    packet_types = range(2, 16)
    with NetzBroker(
        executable, connections=len(packet_types) + 1, ignore_errors=True
    ) as broker:
        for packet_type in packet_types:
            with broker.connect() as sock:
                sock.sendall(bytes([packet_type << 4, 0x80, 0x80, 0x80, 0x74]))
                try:
                    data = sock.recv(1)
                    if data:
                        raise AssertionError(
                            f"initial packet type {packet_type} received {data.hex()}"
                        )
                except (ConnectionResetError, BrokenPipeError):
                    pass
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "after-hostile-initial")
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def qos2_routes_at_pubrel(executable: Path, mqtt_packets) -> None:
    # Mosquitto's QoS 2 regression vectors require that the Application
    # Message is invisible until PUBREL and then completes an independent
    # broker-to-subscriber QoS 2 handshake.
    topic = "pub/qos2/reuse"
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as subscriber, broker.connect() as publisher:
            connect_v5(subscriber, mqtt_packets, "sub-qos2-test")
            subscriber.sendall(
                mqtt_packets.gen_subscribe(1, topic, 2, proto_ver=5)
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_suback(1, 2, proto_ver=5),
                "QoS2 SUBACK",
            )
            connect_v5(publisher, mqtt_packets, "pub-qos2-test")

            incoming_mid = 312
            publisher.sendall(
                mqtt_packets.gen_publish(
                    topic,
                    qos=2,
                    mid=incoming_mid,
                    payload="message",
                    proto_ver=5,
                )
            )
            expect_packet(
                publisher,
                mqtt_packets.gen_pubrec(incoming_mid, proto_ver=5),
                "publisher PUBREC",
            )
            subscriber.settimeout(0.05)
            try:
                early = subscriber.recv(1)
                if early:
                    raise AssertionError(
                        f"QoS2 PUBLISH routed before PUBREL: {early.hex()}"
                    )
            except socket.timeout:
                pass
            finally:
                subscriber.settimeout(5)

            publisher.sendall(
                mqtt_packets.gen_pubrel(incoming_mid, proto_ver=5)
            )
            expect_packet(
                publisher,
                mqtt_packets.gen_pubcomp(incoming_mid, proto_ver=5),
                "publisher PUBCOMP",
            )

            outgoing_mid = 1
            expect_packet(
                subscriber,
                mqtt_packets.gen_publish(
                    topic,
                    qos=2,
                    mid=outgoing_mid,
                    payload="message",
                    proto_ver=5,
                ),
                "downstream QoS2 PUBLISH",
            )
            subscriber.sendall(
                mqtt_packets.gen_pubrec(outgoing_mid, proto_ver=5)
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_pubrel(outgoing_mid, proto_ver=5),
                "downstream PUBREL",
            )
            subscriber.sendall(
                mqtt_packets.gen_pubcomp(outgoing_mid, proto_ver=5)
            )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def mixed_version_qos1(executable: Path, mqtt_packets) -> None:
    topic = "mixed/version/qos1"
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as subscriber, broker.connect() as publisher:
            connect_client(subscriber, mqtt_packets, "mixed-v3-sub", 4)
            subscriber.sendall(
                mqtt_packets.gen_subscribe(1, topic, 1, proto_ver=4)
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_suback(1, 1, proto_ver=4),
                "MQTT 3.1.1 SUBACK",
            )
            connect_v5(publisher, mqtt_packets, "mixed-v5-pub")
            publisher.sendall(
                mqtt_packets.gen_publish(
                    topic,
                    qos=1,
                    mid=77,
                    payload="cross-version",
                    proto_ver=5,
                )
            )
            expect_packet(
                publisher,
                mqtt_packets.gen_puback(77, proto_ver=5),
                "MQTT 5 publisher PUBACK",
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_publish(
                    topic,
                    qos=1,
                    mid=1,
                    payload="cross-version",
                    proto_ver=4,
                ),
                "MQTT 3.1.1 forwarded PUBLISH",
            )
            subscriber.sendall(mqtt_packets.gen_puback(1, proto_ver=4))
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=4))


def main() -> None:
    args = parse_args()
    sys.path.insert(0, str(args.mosquitto_test_root))
    import mqtt5_props  # type: ignore
    import mqtt5_rc  # type: ignore
    import mqtt_packets  # type: ignore

    no_matching_subscribers(args.broker, mqtt_packets, mqtt5_rc)
    subscription_identifiers(args.broker, mqtt_packets, mqtt5_props)
    hostile_initial_packets(args.broker, mqtt_packets)
    qos2_routes_at_pubrel(args.broker, mqtt_packets)
    mixed_version_qos1(args.broker, mqtt_packets)
    print("Mosquitto-derived MQTT wire vectors passed: 5 scenarios")


if __name__ == "__main__":
    main()
