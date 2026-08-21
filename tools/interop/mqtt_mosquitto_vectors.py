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


def expect_packets_unordered(
    sock: socket.socket, expected: list[bytes], label: str
) -> None:
    remaining = expected.copy()
    for _ in expected:
        actual = read_packet(sock)
        try:
            remaining.remove(actual)
        except ValueError as exc:
            raise AssertionError(
                f"{label}: unexpected {actual.hex()}, remaining "
                + ", ".join(packet.hex() for packet in remaining)
            ) from exc


def expected_connack(
    mqtt_packets,
    mqtt5_props,
    *,
    maximum_packet_size: int = 16 * 1024 * 1024,
    topic_alias_maximum: int = 16,
    extra_properties: bytes = b"",
) -> bytes:
    # Keep this in the exact property order emitted by runtime.writeConnAck.
    # Centralizing it makes each negative vector state only the capability it
    # changes while retaining a byte-for-byte CONNACK assertion.
    properties = (
        mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 64)
        + mqtt5_props.gen_uint32_prop(
            mqtt5_props.MAXIMUM_PACKET_SIZE, maximum_packet_size
        )
        + mqtt5_props.gen_uint16_prop(
            mqtt5_props.TOPIC_ALIAS_MAXIMUM, topic_alias_maximum
        )
        + extra_properties
    )
    return mqtt_packets.gen_connack(
        rc=0, proto_ver=5, properties=properties, property_helper=False
    )


class NetzBroker:
    def __init__(
        self,
        executable: Path,
        connections: int = 1,
        ignore_errors: bool = False,
        extra_args: tuple[str, ...] = (),
    ):
        self.executable = executable
        self.connections = connections
        self.ignore_errors = ignore_errors
        self.extra_args = extra_args
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
            *self.extra_args,
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


def assigned_client_identifier(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto 12-prop-assigned-client-identifier.py.
    # Tighten its prefix-only assertion: require the complete netz CONNACK
    # property sequence, validate the UUID-shaped ID, then prove the first
    # anonymous connection remains live after a second ID is assigned.
    with NetzBroker(executable, connections=2) as broker:
        assigned_ids = []
        with broker.connect() as first, broker.connect() as second:
            for index, sock in enumerate((first, second), 1):
                sock.sendall(
                    mqtt_packets.gen_connect(
                        None, clean_session=True, proto_ver=5
                    )
                )
                connack = read_packet(sock)
                if (
                    connack[0] != 0x20
                    or connack[2:4] != b"\x00\x00"
                    or len(connack) < 5
                ):
                    raise AssertionError(
                        f"assigned client {index} invalid CONNACK: "
                        f"{connack.hex()}"
                    )
                property_length = connack[4]
                if 5 + property_length != len(connack):
                    raise AssertionError(
                        f"assigned client {index} malformed property length: "
                        f"{connack.hex()}"
                    )
                properties = connack[5 : 5 + property_length]
                if (
                    len(properties) < 3
                    or properties[0]
                    != mqtt5_props.ASSIGNED_CLIENT_IDENTIFIER
                ):
                    raise AssertionError(
                        f"assigned client {index} missing property: "
                        f"{connack.hex()}"
                    )
                value_len = int.from_bytes(properties[1:3], "big")
                value = properties[3 : 3 + value_len]
                if len(value) != value_len:
                    raise AssertionError(
                        f"assigned client {index} malformed property: "
                        f"{connack.hex()}"
                    )
                client_id = value.decode("ascii")
                parts = client_id.removeprefix("netz-").split("-")
                if (
                    not client_id.startswith("netz-")
                    or [len(part) for part in parts] != [8, 4, 4, 4, 12]
                    or any(
                        char not in "0123456789abcdef"
                        for part in parts
                        for char in part
                    )
                ):
                    raise AssertionError(
                        f"assigned client {index} invalid identifier: {client_id!r}"
                    )
                # The assigned identifier is emitted first because it is the
                # result of CONNECT processing; fixed broker capabilities
                # follow in runtime.writeConnAck's stable wire order. Compare
                # the remainder exactly so duplicate or unknown properties do
                # not slip through this interoperability gate.
                base_properties = expected_connack(
                    mqtt_packets, mqtt5_props
                )[5:]
                if properties[3 + value_len :] != base_properties:
                    raise AssertionError(
                        f"assigned client {index} invalid capabilities: "
                        f"{connack.hex()}"
                    )
                assigned_ids.append(client_id)

            if assigned_ids[0] == assigned_ids[1]:
                raise AssertionError(
                    "anonymous clients received duplicate identifiers"
                )
            first.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                first, mqtt_packets.gen_pingresp(),
                "first anonymous client remains live",
            )
            first.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            second.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def server_keep_alive(executable: Path, mqtt_packets, mqtt5_props) -> None:
    # Direct wire port of Mosquitto 12-prop-server-keepalive.py. Unlike the
    # upstream test's Mosquitto-specific defaults, compare netz's complete
    # stable CONNACK capability sequence and prove the connection remains
    # usable after the negotiated override is installed.
    override_seconds = 60
    with NetzBroker(
        executable,
        extra_args=(f"--server-keep-alive={override_seconds}",),
    ) as broker:
        with broker.connect() as sock:
            sock.sendall(
                mqtt_packets.gen_connect(
                    "server-keep-alive",
                    proto_ver=5,
                    keepalive=override_seconds + 1,
                )
            )
            expected = expected_connack(
                mqtt_packets,
                mqtt5_props,
                extra_properties=mqtt5_props.gen_uint16_prop(
                    mqtt5_props.SERVER_KEEP_ALIVE, override_seconds
                ),
            )
            expect_packet(sock, expected, "Server Keep Alive CONNACK")
            sock.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                sock, mqtt_packets.gen_pingresp(),
                "PINGRESP after Server Keep Alive",
            )
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def connect_persistent_v5(
    sock: socket.socket, mqtt_packets, client_id: str, session_present: bool
) -> None:
    sock.sendall(
        mqtt_packets.gen_connect(
            client_id,
            clean_session=False,
            proto_ver=5,
            session_expiry=60,
        )
    )
    connack = read_packet(sock)
    if (
        connack[0] != 0x20
        or len(connack) < 5
        or connack[2] != int(session_present)
        or connack[3] != 0
    ):
        raise AssertionError(
            f"invalid persistent CONNACK (present={session_present}): "
            f"{connack.hex()}"
        )


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


def multiple_subscription_identifiers(
    executable: Path, mqtt_packets, mqtt5_props, mqtt5_opts
) -> None:
    topic = "multi/subid/value"
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "multi-subscription-id")
            subscriptions = (
                (1, "multi/subid/value", 3, 0),
                (
                    2,
                    "multi/subid/+",
                    9,
                    1 | mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED,
                ),
            )
            for mid, topic_filter, identifier, options in subscriptions:
                properties = mqtt5_props.gen_varint_prop(
                    mqtt5_props.SUBSCRIPTION_IDENTIFIER, identifier
                )
                sock.sendall(mqtt_packets.gen_subscribe(
                    mid, topic_filter, options, proto_ver=5, properties=properties
                ))
                expect_packet(
                    sock, mqtt_packets.gen_suback(mid, options & 0x03, proto_ver=5),
                    f"multi-subid SUBACK {mid}",
                )
            sock.sendall(mqtt_packets.gen_publish(
                topic, qos=1, mid=10, payload="both", retain=True, proto_ver=5
            ))
            expect_packet(
                sock, mqtt_packets.gen_puback(10, proto_ver=5),
                "multi-subid publisher PUBACK",
            )
            properties = (
                mqtt5_props.gen_varint_prop(
                    mqtt5_props.SUBSCRIPTION_IDENTIFIER, 3
                )
                + mqtt5_props.gen_varint_prop(
                    mqtt5_props.SUBSCRIPTION_IDENTIFIER, 9
                )
            )
            expect_packet(
                sock, mqtt_packets.gen_publish(
                    topic, qos=1, mid=1, payload="both", retain=True, proto_ver=5,
                    properties=properties,
                ), "multi-subid forwarded PUBLISH",
            )
            sock.sendall(mqtt_packets.gen_puback(1, proto_ver=5))
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


def publish_capability_disconnects(
    executable: Path, mqtt_packets, mqtt5_props, mqtt5_rc
) -> None:
    # Directly port the two cases in Mosquitto 03-publish-bad-flags.py.
    # The broker advertises each restriction and must send the matching MQTT 5
    # DISCONNECT when a raw client ignores it.
    cases = (
        (
            ("--maximum-qos=1",),
            mqtt_packets.gen_publish(
                "test/topic", qos=2, mid=1, proto_ver=5
            ),
            mqtt5_props.gen_byte_prop(mqtt5_props.MAXIMUM_QOS, 1),
            mqtt5_rc.QOS_NOT_SUPPORTED,
            "qos above Maximum QoS",
        ),
        (
            ("--no-retain",),
            mqtt_packets.gen_publish(
                "test/topic", qos=0, retain=True, payload="a",
                proto_ver=5,
            ),
            mqtt5_props.gen_byte_prop(mqtt5_props.RETAIN_AVAILABLE, 0),
            mqtt5_rc.RETAIN_NOT_SUPPORTED,
            "retain unavailable",
        ),
    )
    for args, publish, advertised_property, reason, label in cases:
        with NetzBroker(executable, extra_args=args) as broker:
            with broker.connect() as sock:
                sock.sendall(
                    mqtt_packets.gen_connect(
                        "publish-capability", proto_ver=5
                    )
                )
                expected = expected_connack(
                    mqtt_packets,
                    mqtt5_props,
                    extra_properties=advertised_property,
                )
                expect_packet(sock, expected, f"{label} CONNACK")
                sock.sendall(publish)
                expect_packet(
                    sock,
                    mqtt_packets.gen_disconnect(
                        reason_code=reason, proto_ver=5
                    ),
                    f"{label} DISCONNECT",
                )


def maximum_packet_size_disconnect(
    executable: Path, mqtt_packets, mqtt5_props, mqtt5_rc
) -> None:
    # Port Mosquitto 12-prop-maximum-packet-size-broker.py: a boundary-fitting
    # PUBLISH keeps the connection alive, then one extra payload byte produces
    # the precise Packet Too Large DISCONNECT.
    with NetzBroker(executable, extra_args=("--max-packet-size=50",)) as broker:
        with broker.connect() as sock:
            sock.sendall(
                mqtt_packets.gen_connect(
                    "12-max-packet-broker", proto_ver=5
                )
            )
            expect_packet(
                sock,
                expected_connack(
                    mqtt_packets,
                    mqtt5_props,
                    maximum_packet_size=50,
                ),
                "maximum packet size CONNACK",
            )
            topic = "12/max/packet/size/broker/test/topic"
            sock.sendall(mqtt_packets.gen_publish(
                topic, qos=0, payload="012345678", proto_ver=5
            ))
            sock.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                sock, mqtt_packets.gen_pingresp(),
                "maximum packet size boundary PINGRESP",
            )
            sock.sendall(mqtt_packets.gen_publish(
                topic, qos=0, payload="0123456789", proto_ver=5
            ))
            expect_packet(
                sock,
                mqtt_packets.gen_disconnect(
                    reason_code=mqtt5_rc.PACKET_TOO_LARGE, proto_ver=5
                ),
                "maximum packet size DISCONNECT",
            )


def topic_alias_disconnect(
    executable: Path, mqtt_packets, mqtt5_props, mqtt5_rc
) -> None:
    # Mosquitto handle_publish.c returns TOPIC_ALIAS_INVALID when the peer uses
    # an alias above the limit advertised by this listener.
    with NetzBroker(executable, extra_args=("--topic-alias-maximum=1",)) as broker:
        with broker.connect() as sock:
            sock.sendall(
                mqtt_packets.gen_connect(
                    "topic-alias-invalid", proto_ver=5
                )
            )
            expect_packet(
                sock,
                expected_connack(
                    mqtt_packets,
                    mqtt5_props,
                    topic_alias_maximum=1,
                ),
                "topic alias limit CONNACK",
            )
            properties = mqtt5_props.gen_uint16_prop(
                mqtt5_props.TOPIC_ALIAS, 2
            )
            sock.sendall(mqtt_packets.gen_publish(
                "alias/too-large", qos=0, payload="blocked",
                proto_ver=5, properties=properties,
            ))
            expect_packet(
                sock,
                mqtt_packets.gen_disconnect(
                    reason_code=mqtt5_rc.TOPIC_ALIAS_INVALID, proto_ver=5
                ),
                "topic alias invalid DISCONNECT",
            )


def receive_maximum_disconnect(
    executable: Path, mqtt_packets, mqtt5_rc
) -> None:
    # Bounded port of Mosquitto 03-publish-qos2-max-inflight-exceeded.py.
    with NetzBroker(
        executable, extra_args=("--max-outgoing-inflight=1",)
    ) as broker:
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "receive-maximum-exceeded")
            sock.sendall(mqtt_packets.gen_publish(
                "receive/maximum/one", qos=2, mid=1, proto_ver=5
            ))
            sock.sendall(mqtt_packets.gen_publish(
                "receive/maximum/two", qos=2, mid=2, proto_ver=5
            ))
            expect_packet(
                sock, mqtt_packets.gen_pubrec(1, proto_ver=5),
                "receive maximum first PUBREC",
            )
            expect_packet(
                sock,
                mqtt_packets.gen_disconnect(
                    reason_code=mqtt5_rc.RECEIVE_MAXIMUM_EXCEEDED,
                    proto_ver=5,
                ),
                "receive maximum DISCONNECT",
            )


def subscription_capability_disconnects(
    executable: Path, mqtt_packets, mqtt5_props, mqtt5_rc
) -> None:
    cases = (
        (
            ("--no-wildcard-subscriptions",),
            "wildcard/+",
            b"",
            mqtt5_props.WILDCARD_SUB_AVAILABLE,
            mqtt5_rc.WILDCARD_SUBS_NOT_SUPPORTED,
            "wildcard subscription unavailable",
        ),
        (
            ("--no-shared-subscriptions",),
            "$share/workers/shared/topic",
            b"",
            mqtt5_props.SHARED_SUB_AVAILABLE,
            mqtt5_rc.SHARED_SUBS_NOT_SUPPORTED,
            "shared subscription unavailable",
        ),
        (
            ("--no-subscription-identifiers",),
            "identifier/topic",
            mqtt5_props.gen_varint_prop(
                mqtt5_props.SUBSCRIPTION_IDENTIFIER, 7
            ),
            mqtt5_props.SUBSCRIPTION_ID_AVAILABLE,
            mqtt5_rc.SUBSCRIPTION_IDS_NOT_SUPPORTED,
            "subscription identifier unavailable",
        ),
    )
    for args, topic, subscribe_props, advertised_id, reason, label in cases:
        # The broker counts rejected protocol connections as completed serve
        # slots, so run one finite process per negative case instead of asking
        # a single process to survive intentional connection failures.
        with NetzBroker(
            executable, ignore_errors=True, extra_args=args
        ) as broker:
            with broker.connect() as sock:
                sock.sendall(
                    mqtt_packets.gen_connect(
                        "subscription-capability", proto_ver=5
                    )
                )
                expect_packet(
                    sock,
                    expected_connack(
                        mqtt_packets,
                        mqtt5_props,
                        extra_properties=mqtt5_props.gen_byte_prop(
                            advertised_id, 0
                        ),
                    ),
                    f"{label} CONNACK",
                )
                sock.sendall(mqtt_packets.gen_subscribe(
                    1, topic, 0, proto_ver=5, properties=subscribe_props
                ))
                expect_packet(
                    sock,
                    mqtt_packets.gen_disconnect(
                        reason_code=reason, proto_ver=5
                    ),
                    f"{label} DISCONNECT",
                )


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


def persistent_no_local(executable: Path, mqtt_packets) -> None:
    # Portable wire subset of Mosquitto 11-persistent-subscription-no-local.py.
    # It keeps the broker process alive, but still proves both Session Present
    # restoration and that the no-local option survives disconnect/reconnect.
    client_id = "persistent-subscription-test"
    topic = "subpub/nolocal"
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as first:
            connect_persistent_v5(
                first, mqtt_packets, client_id, session_present=False
            )
            first.sendall(
                mqtt_packets.gen_subscribe(1, topic, 5, proto_ver=5)
            )
            expect_packet(
                first,
                mqtt_packets.gen_suback(1, 1, proto_ver=5),
                "persistent no-local SUBACK",
            )
            first.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

        with broker.connect() as resumed:
            connect_persistent_v5(
                resumed, mqtt_packets, client_id, session_present=True
            )
            resumed.sendall(
                mqtt_packets.gen_publish(
                    topic,
                    qos=1,
                    mid=1,
                    payload="message",
                    proto_ver=5,
                )
            )
            expect_packet(
                resumed,
                mqtt_packets.gen_puback(1, proto_ver=5),
                "persistent no-local PUBACK",
            )
            resumed.settimeout(0.05)
            try:
                local = resumed.recv(1)
                if local:
                    raise AssertionError(
                        "restored no-local subscription forwarded self "
                        f"publish: {local.hex()}"
                    )
            except socket.timeout:
                pass
            finally:
                resumed.settimeout(5)

            # Re-subscribing to the same filter replaces its options. The next
            # self-publish must therefore produce both PUBACK and one forwarded
            # QoS 1 PUBLISH, in either scheduler order.
            resumed.sendall(
                mqtt_packets.gen_subscribe(2, topic, 1, proto_ver=5)
            )
            expect_packet(
                resumed,
                mqtt_packets.gen_suback(2, 1, proto_ver=5),
                "local replacement SUBACK",
            )
            resumed.sendall(
                mqtt_packets.gen_publish(
                    topic,
                    qos=1,
                    mid=3,
                    payload="message",
                    proto_ver=5,
                )
            )
            expect_packets_unordered(
                resumed,
                [
                    mqtt_packets.gen_puback(3, proto_ver=5),
                    mqtt_packets.gen_publish(
                        topic,
                        qos=1,
                        mid=1,
                        payload="message",
                        proto_ver=5,
                    ),
                ],
                "local replacement publish/PUBACK",
            )
            resumed.sendall(mqtt_packets.gen_puback(1, proto_ver=5))
            resumed.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def retained_subscription_handling(
    executable: Path, mqtt_packets, mqtt5_opts
) -> None:
    # Direct wire port of Mosquitto 02-subpub-qos0-send-retain.py. The three
    # retained messages are installed before subscribing; each option is then
    # exercised twice to distinguish always/new/never behavior.
    topics = {
        "always": "02/subpub/send-retain/always",
        "new": "02/subpub/send-retain/new",
        "never": "02/subpub/send-retain/never",
    }
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "02-subpub-qos0-send-retain")
            for topic in topics.values():
                sock.sendall(
                    mqtt_packets.gen_publish(
                        topic,
                        qos=0,
                        retain=True,
                        payload="message",
                        proto_ver=5,
                    )
                )

            cases = [
                (
                    532,
                    topics["never"],
                    mqtt5_opts.MQTT_SUB_OPT_SEND_RETAIN_NEVER,
                    False,
                    False,
                ),
                (
                    531,
                    topics["new"],
                    mqtt5_opts.MQTT_SUB_OPT_SEND_RETAIN_NEW,
                    True,
                    False,
                ),
                (
                    530,
                    topics["always"],
                    mqtt5_opts.MQTT_SUB_OPT_SEND_RETAIN_ALWAYS,
                    True,
                    True,
                ),
            ]
            for mid, topic, option, first_delivery, second_delivery in cases:
                for attempt, expect_delivery in enumerate(
                    (first_delivery, second_delivery), start=1
                ):
                    sock.sendall(
                        mqtt_packets.gen_subscribe(
                            mid, topic, option, proto_ver=5
                        )
                    )
                    expect_packet(
                        sock,
                        mqtt_packets.gen_suback(mid, 0, proto_ver=5),
                        f"retain handling SUBACK {mid}/{attempt}",
                    )
                    if expect_delivery:
                        expect_packet(
                            sock,
                            mqtt_packets.gen_publish(
                                topic,
                                qos=0,
                                retain=True,
                                payload="message",
                                proto_ver=5,
                            ),
                            f"retained delivery {mid}/{attempt}",
                        )
                    else:
                        sock.settimeout(0.05)
                        try:
                            unexpected = sock.recv(1)
                            if unexpected:
                                raise AssertionError(
                                    f"retain handling {mid}/{attempt} "
                                    f"received {unexpected.hex()}"
                                )
                        except socket.timeout:
                            pass
                        finally:
                            sock.settimeout(5)
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def incoming_topic_alias(executable: Path, mqtt_packets, mqtt5_props) -> None:
    # Direct wire port of Mosquitto 02-subpub-qos0-topic-alias.py. Establish an
    # alias before the subscriber exists, then publish with an empty Topic Name
    # and require the forwarded packet to contain the resolved topic and no
    # connection-scoped Topic Alias property.
    topic = "02/subpub/topic-alias/alias"
    alias_property = mqtt5_props.gen_uint16_prop(
        mqtt5_props.TOPIC_ALIAS, 3
    )
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as publisher, broker.connect() as subscriber:
            connect_v5(
                publisher, mqtt_packets, "02-subpub-qos0-topic-alias"
            )
            connect_v5(
                subscriber,
                mqtt_packets,
                "02-subpub-qos0-topic-alias-helper",
            )
            publisher.sendall(
                mqtt_packets.gen_publish(
                    topic,
                    qos=0,
                    payload="message",
                    proto_ver=5,
                    properties=alias_property,
                )
            )
            subscriber.sendall(
                mqtt_packets.gen_subscribe(1, topic, 0, proto_ver=5)
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "topic alias SUBACK",
            )
            publisher.sendall(
                mqtt_packets.gen_publish(
                    "",
                    qos=0,
                    payload="message",
                    proto_ver=5,
                    properties=alias_property,
                )
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_publish(
                    topic,
                    qos=0,
                    payload="message",
                    proto_ver=5,
                ),
                "resolved topic alias PUBLISH",
            )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def outgoing_topic_alias(executable: Path, mqtt_packets, mqtt5_props) -> None:
    # Bounded port of Mosquitto 02-subpub-b2c-topic-alias.py. The subscriber
    # advertises two aliases; first delivery establishes alias 1 with the full
    # topic, and the repeated topic must use an empty Topic Name plus alias 1.
    topic = "02/b2c/topic/alias/1"
    maximum_property = mqtt5_props.gen_uint16_prop(
        mqtt5_props.TOPIC_ALIAS_MAXIMUM, 2
    )
    alias_property = mqtt5_props.gen_uint16_prop(
        mqtt5_props.TOPIC_ALIAS, 1
    )
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as subscriber, broker.connect() as publisher:
            subscriber.sendall(
                mqtt_packets.gen_connect(
                    "02-b2c-topic-alias",
                    proto_ver=5,
                    properties=maximum_property,
                )
            )
            connack = read_packet(subscriber)
            if connack[0] != 0x20 or connack[3] != 0:
                raise AssertionError(f"invalid alias CONNACK: {connack.hex()}")
            connect_v5(
                publisher, mqtt_packets, "02-b2c-topic-alias-helper"
            )
            subscriber.sendall(
                mqtt_packets.gen_subscribe(1, topic, 0, proto_ver=5)
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "outgoing topic alias SUBACK",
            )
            publisher.sendall(
                mqtt_packets.gen_publish(
                    topic, qos=0, payload="first", proto_ver=5
                )
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_publish(
                    topic,
                    qos=0,
                    payload="first",
                    proto_ver=5,
                    properties=alias_property,
                ),
                "outgoing topic alias establish",
            )
            publisher.sendall(
                mqtt_packets.gen_publish(
                    topic, qos=0, payload="second", proto_ver=5
                )
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_publish(
                    "",
                    qos=0,
                    payload="second",
                    proto_ver=5,
                    properties=alias_property,
                ),
                "outgoing topic alias reuse",
            )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def request_response_properties(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Wire-level request/response subset of Mosquitto
    # 12-prop-response-topic-correlation-data.py. The request carries both
    # properties through broker fanout; the responder then publishes on the
    # advertised response topic and the requester receives the exact response.
    normal_topic = "normal/topic"
    response_topic = "response/topic"
    properties = (
        mqtt5_props.gen_string_prop(
            mqtt5_props.RESPONSE_TOPIC, response_topic
        )
        + mqtt5_props.gen_string_prop(
            mqtt5_props.CORRELATION_DATA, "45vyvynq30q3vt4 nuy893b4v3"
        )
    )
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as responder, broker.connect() as requester:
            connect_v5(responder, mqtt_packets, "response-client")
            connect_v5(requester, mqtt_packets, "request-client")
            responder.sendall(
                mqtt_packets.gen_subscribe(1, normal_topic, 0, proto_ver=5)
            )
            expect_packet(
                responder,
                mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "request responder SUBACK",
            )
            requester.sendall(
                mqtt_packets.gen_subscribe(1, response_topic, 0, proto_ver=5)
            )
            expect_packet(
                requester,
                mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "response requester SUBACK",
            )
            request = mqtt_packets.gen_publish(
                normal_topic,
                qos=0,
                payload="2",
                proto_ver=5,
                properties=properties,
            )
            requester.sendall(request)
            expect_packet(responder, request, "request property forwarding")
            response = mqtt_packets.gen_publish(
                response_topic,
                qos=0,
                payload="22",
                proto_ver=5,
            )
            responder.sendall(response)
            expect_packet(requester, response, "response topic delivery")
            responder.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            requester.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def disconnect_with_will_properties(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Combine the externally observable cores of Mosquitto's
    # 07-will-properties.py and 07-will-disconnect-with-will.py. This uses
    # Will Delay as the first property to exercise the historical ordering
    # edge, then requires it to be stripped while every Application Message
    # property is forwarded in its original order.
    topic = "will/properties"
    will_properties = (
        mqtt5_props.gen_uint32_prop(mqtt5_props.WILL_DELAY_INTERVAL, 0)
        + mqtt5_props.gen_string_pair_prop(
            mqtt5_props.USER_PROPERTY, "key1", "value1"
        )
        + mqtt5_props.gen_string_prop(
            mqtt5_props.RESPONSE_TOPIC, "response/topic"
        )
        + mqtt5_props.gen_string_prop(
            mqtt5_props.CORRELATION_DATA, "correlation-data"
        )
        + mqtt5_props.gen_byte_prop(
            mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1
        )
        + mqtt5_props.gen_string_prop(
            mqtt5_props.CONTENT_TYPE, "text/plain"
        )
        + mqtt5_props.gen_string_pair_prop(
            mqtt5_props.USER_PROPERTY, "key2", "value2"
        )
    )
    forwarded_properties = will_properties[5:]

    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as subscriber, broker.connect() as source:
            connect_v5(subscriber, mqtt_packets, "will-property-subscriber")
            subscriber.sendall(
                mqtt_packets.gen_subscribe(1, topic, 0, proto_ver=5)
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "Will property SUBACK",
            )
            source.sendall(
                mqtt_packets.gen_connect(
                    "will-property-source",
                    proto_ver=5,
                    will_topic=topic,
                    will_payload=b"will payload",
                    will_properties=will_properties,
                )
            )
            connack = read_packet(source)
            if connack[0] != 0x20 or connack[2:4] != b"\x00\x00":
                raise AssertionError(
                    f"Will source invalid CONNACK: {connack.hex()}"
                )

            source.sendall(
                mqtt_packets.gen_disconnect(reason_code=4, proto_ver=5)
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_publish(
                    topic,
                    qos=0,
                    payload="will payload",
                    proto_ver=5,
                    properties=forwarded_properties,
                ),
                "DISCONNECT 0x04 Will property forwarding",
            )
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def retained_message_expiry(
    executable: Path, mqtt_packets, mqtt5_props, mqtt5_rc
) -> None:
    # Timing-tolerant MQTT 5 port of Mosquitto
    # 02-subpub-qos1-message-expiry-retain.py. Immediate retained replay may
    # legitimately report either two or one seconds remaining; after three
    # seconds the expiring value must be absent while the control remains.
    expired_topic = "subpub/expired"
    kept_topic = "subpub/kept"
    expiry_two = mqtt5_props.gen_uint32_prop(
        mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 2
    )
    with NetzBroker(executable, connections=3) as broker:
        with broker.connect() as publisher:
            connect_v5(publisher, mqtt_packets, "expiry-helper")
            publisher.sendall(
                mqtt_packets.gen_publish(
                    expired_topic,
                    qos=1,
                    mid=1,
                    retain=True,
                    payload="message1",
                    proto_ver=5,
                    properties=expiry_two,
                )
            )
            expect_packet(
                publisher,
                mqtt_packets.gen_puback(
                    1,
                    proto_ver=5,
                    reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS,
                ),
                "expiring retained PUBACK",
            )
            publisher.sendall(
                mqtt_packets.gen_publish(
                    kept_topic,
                    qos=1,
                    mid=2,
                    retain=True,
                    payload="message2",
                    proto_ver=5,
                )
            )
            expect_packet(
                publisher,
                mqtt_packets.gen_puback(
                    2,
                    proto_ver=5,
                    reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS,
                ),
                "kept retained PUBACK",
            )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

        with broker.connect() as immediate:
            connect_v5(immediate, mqtt_packets, "expiry-immediate")
            immediate.sendall(
                mqtt_packets.gen_subscribe(1, expired_topic, 0, proto_ver=5)
            )
            expect_packet(
                immediate,
                mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "immediate expiry SUBACK",
            )
            actual = read_packet(immediate)
            expiry_variants = [
                mqtt_packets.gen_publish(
                    expired_topic,
                    qos=0,
                    retain=True,
                    payload="message1",
                    proto_ver=5,
                    properties=mqtt5_props.gen_uint32_prop(
                        mqtt5_props.MESSAGE_EXPIRY_INTERVAL, remaining
                    ),
                )
                for remaining in (2, 1)
            ]
            if actual not in expiry_variants:
                raise AssertionError(
                    "immediate retained expiry mismatch: " + actual.hex()
                )
            immediate.sendall(
                mqtt_packets.gen_subscribe(2, kept_topic, 0, proto_ver=5)
            )
            expect_packet(
                immediate,
                mqtt_packets.gen_suback(2, 0, proto_ver=5),
                "immediate kept SUBACK",
            )
            expect_packet(
                immediate,
                mqtt_packets.gen_publish(
                    kept_topic,
                    qos=0,
                    retain=True,
                    payload="message2",
                    proto_ver=5,
                ),
                "immediate kept replay",
            )
            immediate.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

        time.sleep(3)
        with broker.connect() as expired:
            connect_v5(expired, mqtt_packets, "expiry-late")
            expired.sendall(
                mqtt_packets.gen_subscribe(1, expired_topic, 0, proto_ver=5)
            )
            expect_packet(
                expired,
                mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "late expiry SUBACK",
            )
            expired.sendall(
                mqtt_packets.gen_subscribe(2, kept_topic, 0, proto_ver=5)
            )
            expect_packet(
                expired,
                mqtt_packets.gen_suback(2, 0, proto_ver=5),
                "late kept SUBACK",
            )
            expect_packet(
                expired,
                mqtt_packets.gen_publish(
                    kept_topic,
                    qos=0,
                    retain=True,
                    payload="message2",
                    proto_ver=5,
                ),
                "late kept replay",
            )
            expired.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def qos2_receive_maximum_one(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Bounded wire port of Mosquitto 02-subpub-qos2-receive-maximum-1.py. Two
    # QoS 2 messages are released to the broker, but the subscriber must not
    # receive the second PUBLISH until the first transaction returns credit.
    topic = "subpub/qos2/receive/maximum1"
    receive_one = mqtt5_props.gen_uint16_prop(
        mqtt5_props.RECEIVE_MAXIMUM, 1
    )
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as subscriber, broker.connect() as publisher:
            subscriber.sendall(
                mqtt_packets.gen_connect(
                    "subpub-qos2-receive-max1",
                    proto_ver=5,
                    properties=receive_one,
                )
            )
            connack = read_packet(subscriber)
            if connack[0] != 0x20 or connack[3] != 0:
                raise AssertionError(
                    f"invalid Receive Maximum CONNACK: {connack.hex()}"
                )
            subscriber.sendall(
                mqtt_packets.gen_subscribe(1, topic, 2, proto_ver=5)
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_suback(1, 2, proto_ver=5),
                "Receive Maximum SUBACK",
            )
            connect_v5(
                publisher, mqtt_packets, "subpub-qos2-recv-max1-helper"
            )
            for mid in (1, 2):
                publisher.sendall(
                    mqtt_packets.gen_publish(
                        topic,
                        qos=2,
                        mid=mid,
                        payload=f"message{mid}",
                        proto_ver=5,
                    )
                )
                expect_packet(
                    publisher,
                    mqtt_packets.gen_pubrec(mid, proto_ver=5),
                    f"Receive Maximum publisher PUBREC {mid}",
                )
                publisher.sendall(
                    mqtt_packets.gen_pubrel(mid, proto_ver=5)
                )
                expect_packet(
                    publisher,
                    mqtt_packets.gen_pubcomp(mid, proto_ver=5),
                    f"Receive Maximum publisher PUBCOMP {mid}",
                )

            for mid in (1, 2):
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_publish(
                        topic,
                        qos=2,
                        mid=mid,
                        payload=f"message{mid}",
                        proto_ver=5,
                    ),
                    f"Receive Maximum downstream PUBLISH {mid}",
                )
                if mid == 1:
                    subscriber.settimeout(0.05)
                    try:
                        early = subscriber.recv(1)
                        if early:
                            raise AssertionError(
                                "Receive Maximum leaked second PUBLISH: "
                                + early.hex()
                            )
                    except socket.timeout:
                        pass
                    finally:
                        subscriber.settimeout(5)
                subscriber.sendall(
                    mqtt_packets.gen_pubrec(mid, proto_ver=5)
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_pubrel(mid, proto_ver=5),
                    f"Receive Maximum downstream PUBREL {mid}",
                )
                subscriber.sendall(
                    mqtt_packets.gen_pubcomp(mid, proto_ver=5)
                )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def maximum_packet_size_qos1(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto
    # 12-prop-maximum-packet-size-publish-qos1.py. Oversized self-deliveries
    # are discarded without stalling publisher ACKs or poisoning the socket; a
    # boundary-fitting third PUBLISH is forwarded.
    topic = "12/max/publish/qos1/test/topic"
    maximum = mqtt5_props.gen_uint32_prop(
        mqtt5_props.MAXIMUM_PACKET_SIZE, 40
    )
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            sock.sendall(
                mqtt_packets.gen_connect(
                    "12-max-publish-qos1",
                    proto_ver=5,
                    properties=maximum,
                )
            )
            connack = read_packet(sock)
            if connack[0] != 0x20 or connack[3] != 0:
                raise AssertionError(
                    f"invalid max-packet CONNACK: {connack.hex()}"
                )
            sock.sendall(
                mqtt_packets.gen_subscribe(1, topic, 1, proto_ver=5)
            )
            expect_packet(
                sock,
                mqtt_packets.gen_suback(1, 1, proto_ver=5),
                "maximum packet SUBACK",
            )

            oversized = [
                mqtt_packets.gen_publish(
                    topic,
                    mid=1,
                    qos=1,
                    payload="1234",
                    proto_ver=5,
                ),
                mqtt_packets.gen_publish(
                    topic,
                    mid=2,
                    qos=1,
                    payload="56",
                    proto_ver=5,
                    properties=mqtt5_props.gen_byte_prop(
                        mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1
                    ),
                ),
            ]
            for mid, packet in enumerate(oversized, start=1):
                sock.sendall(packet)
                expect_packet(
                    sock,
                    mqtt_packets.gen_puback(mid, proto_ver=5),
                    f"maximum packet PUBACK {mid}",
                )
                sock.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    sock,
                    mqtt_packets.gen_pingresp(),
                    f"maximum packet PINGRESP {mid}",
                )

            fitting = mqtt_packets.gen_publish(
                topic,
                mid=3,
                qos=1,
                payload="789",
                proto_ver=5,
            )
            sock.sendall(fitting)
            expect_packets_unordered(
                sock,
                [mqtt_packets.gen_puback(3, proto_ver=5), fitting],
                "maximum packet fitting publish/PUBACK",
            )
            sock.sendall(mqtt_packets.gen_puback(3, proto_ver=5))
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def maximum_packet_size_qos2(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto's QoS 2 companion vector. The first
    # released Application Message is too large for the subscriber and must be
    # discarded without leaving an outgoing QoS2 transaction; the next fitting
    # message completes the full independent downstream handshake.
    topic = "12/max/publish/qos2/test/topic"
    maximum = mqtt5_props.gen_uint32_prop(
        mqtt5_props.MAXIMUM_PACKET_SIZE, 40
    )
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            sock.sendall(
                mqtt_packets.gen_connect(
                    "12-max-publish-qos2",
                    proto_ver=5,
                    properties=maximum,
                )
            )
            connack = read_packet(sock)
            if connack[0] != 0x20 or connack[3] != 0:
                raise AssertionError(
                    f"invalid max-packet QoS2 CONNACK: {connack.hex()}"
                )
            sock.sendall(
                mqtt_packets.gen_subscribe(1, topic, 2, proto_ver=5)
            )
            expect_packet(
                sock,
                mqtt_packets.gen_suback(1, 2, proto_ver=5),
                "maximum packet QoS2 SUBACK",
            )

            for mid, payload in ((1, "1234"), (2, "789")):
                publish = mqtt_packets.gen_publish(
                    topic,
                    mid=mid,
                    qos=2,
                    payload=payload,
                    proto_ver=5,
                )
                sock.sendall(publish)
                expect_packet(
                    sock,
                    mqtt_packets.gen_pubrec(mid, proto_ver=5),
                    f"maximum packet QoS2 publisher PUBREC {mid}",
                )
                sock.sendall(mqtt_packets.gen_pubrel(mid, proto_ver=5))
                if mid == 1:
                    expect_packet(
                        sock,
                        mqtt_packets.gen_pubcomp(mid, proto_ver=5),
                        "maximum packet QoS2 oversized PUBCOMP",
                    )
                    sock.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        sock,
                        mqtt_packets.gen_pingresp(),
                        "maximum packet QoS2 PINGRESP",
                    )
                else:
                    expect_packets_unordered(
                        sock,
                        [
                            mqtt_packets.gen_pubcomp(mid, proto_ver=5),
                            publish,
                        ],
                        "maximum packet QoS2 fitting release",
                    )
                    sock.sendall(
                        mqtt_packets.gen_pubrec(mid, proto_ver=5)
                    )
                    expect_packet(
                        sock,
                        mqtt_packets.gen_pubrel(mid, proto_ver=5),
                        "maximum packet QoS2 downstream PUBREL",
                    )
                    sock.sendall(
                        mqtt_packets.gen_pubcomp(mid, proto_ver=5)
                    )
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def retained_repeated_lifecycle(executable: Path, mqtt_packets) -> None:
    # Direct MQTT 5 port of Mosquitto 04-retain-qos0-repeated.py plus a final
    # zero-length retained PUBLISH clear. It covers SUBSCRIBE replay, UNSUBACK,
    # resubscribe replay, and removal from the retained index on one connection.
    topic = "retain/qos0/repeated"
    retained = mqtt_packets.gen_publish(
        topic,
        qos=0,
        payload="retained message",
        retain=True,
        proto_ver=5,
    )
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "retain-qos0-rep-test")
            sock.sendall(retained)
            for attempt in (1, 2):
                sock.sendall(
                    mqtt_packets.gen_subscribe(16, topic, 0, proto_ver=5)
                )
                expect_packet(
                    sock,
                    mqtt_packets.gen_suback(16, 0, proto_ver=5),
                    f"retained repeated SUBACK {attempt}",
                )
                expect_packet(
                    sock, retained, f"retained repeated replay {attempt}"
                )
                if attempt == 1:
                    sock.sendall(
                        mqtt_packets.gen_unsubscribe(
                            13, topic, proto_ver=5
                        )
                    )
                    expect_packet(
                        sock,
                        mqtt_packets.gen_unsuback(13, proto_ver=5),
                        "retained repeated UNSUBACK",
                    )

            # Remove the live subscription before publishing the tombstone,
            # matching Mosquitto's separate send_retain helper and avoiding an
            # unrelated live empty-PUBLISH delivery.
            sock.sendall(
                mqtt_packets.gen_unsubscribe(14, topic, proto_ver=5)
            )
            expect_packet(
                sock,
                mqtt_packets.gen_unsuback(14, proto_ver=5),
                "retained clear UNSUBACK",
            )
            sock.sendall(
                mqtt_packets.gen_publish(
                    topic,
                    qos=0,
                    payload=None,
                    retain=True,
                    proto_ver=5,
                )
            )
            # Re-add the subscription to force a retained lookup.
            sock.sendall(
                mqtt_packets.gen_subscribe(17, topic, 0, proto_ver=5)
            )
            expect_packet(
                sock,
                mqtt_packets.gen_suback(17, 0, proto_ver=5),
                "retained clear SUBACK",
            )
            sock.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                sock, mqtt_packets.gen_pingresp(), "retained clear PINGRESP"
            )
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def retained_multilevel_clear(executable: Path, mqtt_packets) -> None:
    # Single-process MQTT 5 port of Mosquitto 04-retain-clear-multiple.py.
    # Nested retained nodes are removed independently; wildcard replay after
    # each tombstone proves trie compaction preserves ancestors and children.
    topics = ["1", "1/2/3/4", "1/2/3/4/5/6/7"]
    payload = "retained message"
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "retain-clear-test")
            for mid, topic in enumerate(topics, start=1):
                sock.sendall(
                    mqtt_packets.gen_publish(
                        topic, qos=1, mid=mid, payload=payload,
                        retain=True, proto_ver=5,
                    )
                )
                expect_packet(
                    sock, mqtt_packets.gen_puback(
                        mid, proto_ver=5, reason_code=0x10
                    ),
                    f"multilevel retained set {topic}",
                )

            def replay(mid: int, expected_topics: list[str]) -> None:
                sock.sendall(mqtt_packets.gen_subscribe(mid, "#", 0, proto_ver=5))
                expect_packet(
                    sock, mqtt_packets.gen_suback(mid, 0, proto_ver=5),
                    f"multilevel retained SUBACK {mid}",
                )
                expect_packets_unordered(
                    sock,
                    [mqtt_packets.gen_publish(
                        topic, qos=0, payload=payload, retain=True, proto_ver=5
                    ) for topic in expected_topics],
                    f"multilevel retained replay {mid}",
                )
                sock.sendall(mqtt_packets.gen_unsubscribe(mid, "#", proto_ver=5))
                expect_packet(
                    sock, mqtt_packets.gen_unsuback(mid, proto_ver=5),
                    f"multilevel retained UNSUBACK {mid}",
                )

            replay(10, topics)
            remaining = topics.copy()
            for mid, topic in enumerate(
                ("1/2/3/4", "1/2/3/4/5/6/7"), start=20
            ):
                sock.sendall(mqtt_packets.gen_publish(
                    topic, qos=1, mid=mid, payload=None,
                    retain=True, proto_ver=5,
                ))
                expect_packet(
                    sock, mqtt_packets.gen_puback(
                        mid, proto_ver=5, reason_code=0x10
                    ),
                    f"multilevel retained clear {topic}",
                )
                remaining.remove(topic)
                replay(mid + 20, remaining)
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def shared_subscription_rotation(executable: Path, mqtt_packets) -> None:
    # Direct wire port of Mosquitto 02-shared-qos0-v5.py. One ordinary
    # subscriber sees every message while each shared group selects exactly one
    # member and advances its own cursor independently.
    topic = "02A/share/test"
    with NetzBroker(executable, connections=5) as broker:
        sockets = [broker.connect() for _ in range(5)]
        try:
            for index, sock in enumerate(sockets, start=1):
                connect_v5(sock, mqtt_packets, f"02-shared-client{index}")
            filters = [
                (0, "02A/#"),
                (1, "$share/one/02A/share/test"),
                (2, "$share/one/02A/share/test"),
                (2, "$share/two/02A/share/test"),
                (3, "$share/two/02A/share/test"),
                (4, "$share/one/02A/share/test"),
            ]
            for socket_index, topic_filter in filters:
                sock = sockets[socket_index]
                sock.sendall(mqtt_packets.gen_subscribe(1, topic_filter, 0, proto_ver=5))
                expect_packet(
                    sock, mqtt_packets.gen_suback(1, 0, proto_ver=5),
                    f"shared SUBACK {socket_index}/{topic_filter}",
                )

            expected_receivers = ((0, 1, 2), (0, 2, 3), (0, 2, 4))
            for message_index, receivers in enumerate(
                expected_receivers, start=1
            ):
                packet = mqtt_packets.gen_publish(
                    topic, qos=0, payload=f"message{message_index}", proto_ver=5
                )
                sockets[0].sendall(packet)
                for receiver in receivers:
                    expect_packet(
                        sockets[receiver], packet,
                        f"shared publish {message_index}/{receiver}",
                    )
            for sock in sockets:
                sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
        finally:
            for sock in sockets:
                sock.close()


def qos2_duplicate_publish(executable: Path, mqtt_packets) -> None:
    # Core wire semantics from Mosquitto 03-c2b-qos2-disconnect.py without the
    # process-specific reconnect harness: a DUP PUBLISH with the same Packet
    # Identifier receives the same PUBREC, does not replace/route early, and
    # one PUBREL releases exactly one downstream QoS 2 transaction.
    topic = "03/c2b/qos2/duplicate/test"
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as subscriber, broker.connect() as publisher:
            connect_v5(subscriber, mqtt_packets, "qos2-dup-subscriber")
            subscriber.sendall(
                mqtt_packets.gen_subscribe(1, topic, 2, proto_ver=5)
            )
            expect_packet(
                subscriber, mqtt_packets.gen_suback(1, 2, proto_ver=5),
                "QoS2 DUP SUBACK",
            )
            connect_v5(publisher, mqtt_packets, "qos2-dup-publisher")
            for dup in (False, True):
                publisher.sendall(mqtt_packets.gen_publish(
                    topic, qos=2, mid=7, payload="original",
                    dup=dup, proto_ver=5,
                ))
                expect_packet(
                    publisher, mqtt_packets.gen_pubrec(7, proto_ver=5),
                    f"QoS2 DUP PUBREC {dup}",
                )
                subscriber.settimeout(0.05)
                try:
                    early = subscriber.recv(1)
                    if early:
                        raise AssertionError(
                            "QoS2 DUP routed before PUBREL: " + early.hex()
                        )
                except socket.timeout:
                    pass
                finally:
                    subscriber.settimeout(5)

            publisher.sendall(mqtt_packets.gen_pubrel(7, proto_ver=5))
            expect_packet(
                publisher, mqtt_packets.gen_pubcomp(7, proto_ver=5),
                "QoS2 DUP publisher PUBCOMP",
            )
            expect_packet(
                subscriber, mqtt_packets.gen_publish(
                    topic, qos=2, mid=1, payload="original", proto_ver=5
                ),
                "QoS2 DUP downstream PUBLISH",
            )
            subscriber.sendall(mqtt_packets.gen_pubrec(1, proto_ver=5))
            expect_packet(
                subscriber, mqtt_packets.gen_pubrel(1, proto_ver=5),
                "QoS2 DUP downstream PUBREL",
            )
            subscriber.sendall(mqtt_packets.gen_pubcomp(1, proto_ver=5))
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def qos2_repeated_pubrel(executable: Path, mqtt_packets) -> None:
    # Mosquitto treats a repeated/unknown PUBREL as idempotent because PUBCOMP
    # may have been lost. Complete one routed transaction, repeat PUBREL, then
    # send a wholly unknown Packet Identifier; both receive PUBCOMP and neither
    # can create another downstream PUBLISH.
    topic = "qos2/repeated/pubrel"
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as subscriber, broker.connect() as publisher:
            connect_v5(subscriber, mqtt_packets, "repeat-rel-sub")
            subscriber.sendall(mqtt_packets.gen_subscribe(1, topic, 2, proto_ver=5))
            expect_packet(subscriber, mqtt_packets.gen_suback(1, 2, proto_ver=5), "repeat PUBREL SUBACK")
            connect_v5(publisher, mqtt_packets, "repeat-rel-pub")
            publisher.sendall(mqtt_packets.gen_publish(
                topic, qos=2, mid=9, payload="once", proto_ver=5
            ))
            expect_packet(publisher, mqtt_packets.gen_pubrec(9, proto_ver=5), "repeat PUBREL PUBREC")
            publisher.sendall(mqtt_packets.gen_pubrel(9, proto_ver=5))
            expect_packet(publisher, mqtt_packets.gen_pubcomp(9, proto_ver=5), "repeat PUBREL first PUBCOMP")
            expect_packet(subscriber, mqtt_packets.gen_publish(
                topic, qos=2, mid=1, payload="once", proto_ver=5
            ), "repeat PUBREL downstream PUBLISH")
            subscriber.sendall(mqtt_packets.gen_pubrec(1, proto_ver=5))
            expect_packet(subscriber, mqtt_packets.gen_pubrel(1, proto_ver=5), "repeat PUBREL downstream PUBREL")
            subscriber.sendall(mqtt_packets.gen_pubcomp(1, proto_ver=5))

            for mid in (9, 77):
                publisher.sendall(mqtt_packets.gen_pubrel(mid, proto_ver=5))
                expect_packet(
                    publisher, mqtt_packets.gen_pubcomp(mid, proto_ver=5),
                    f"idempotent PUBCOMP {mid}",
                )
            subscriber.settimeout(0.05)
            try:
                duplicate = subscriber.recv(1)
                if duplicate:
                    raise AssertionError(
                        "repeated PUBREL duplicated delivery: " + duplicate.hex()
                    )
            except socket.timeout:
                pass
            finally:
                subscriber.settimeout(5)
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def reject_publish_subscription_identifier(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Subscription Identifier is server-generated on forwarded PUBLISH only.
    # A client-to-server occurrence is a protocol error; reject it before
    # routing and prove the finite broker remains healthy for a later client.
    illegal = mqtt5_props.gen_varint_prop(
        mqtt5_props.SUBSCRIPTION_IDENTIFIER, 7
    )
    with NetzBroker(
        executable, connections=2, ignore_errors=True
    ) as broker:
        with broker.connect() as bad:
            connect_v5(bad, mqtt_packets, "illegal-publish-subid")
            bad.sendall(mqtt_packets.gen_publish(
                "illegal/subid", qos=0, payload="bad", proto_ver=5,
                properties=illegal,
            ))
            try:
                response = bad.recv(1)
                if response:
                    raise AssertionError(
                        "illegal Subscription Identifier got response: "
                        + response.hex()
                    )
            except (ConnectionResetError, BrokenPipeError):
                pass
        with broker.connect() as healthy:
            connect_v5(healthy, mqtt_packets, "after-illegal-subid")
            healthy.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                healthy, mqtt_packets.gen_pingresp(),
                "healthy PINGRESP after illegal Subscription Identifier",
            )
            healthy.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def unsubscribe_reason_codes(executable: Path, mqtt_packets) -> None:
    topic = "unsubscribe/reason/existing"
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as subscriber, broker.connect() as publisher:
            connect_v5(subscriber, mqtt_packets, "unsubscribe-reasons")
            subscriber.sendall(
                mqtt_packets.gen_subscribe(1, topic, 0, proto_ver=5)
            )
            expect_packet(
                subscriber, mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "unsubscribe reason SUBACK",
            )
            subscriber.sendall(mqtt_packets.gen_unsubscribe_multiple(
                2, [topic, "unsubscribe/reason/missing"], proto_ver=5
            ))
            expect_packet(
                subscriber,
                mqtt_packets.gen_unsuback(
                    2, reason_code=[0x00, 0x11], proto_ver=5
                ),
                "multi-filter UNSUBACK reasons",
            )
            connect_v5(publisher, mqtt_packets, "unsubscribe-publisher")
            publisher.sendall(mqtt_packets.gen_publish(
                topic, qos=0, payload="not-routed", proto_ver=5
            ))
            subscriber.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                subscriber, mqtt_packets.gen_pingresp(),
                "PINGRESP after unsubscribe",
            )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def retain_as_published_live(
    executable: Path, mqtt_packets, mqtt5_opts
) -> None:
    topic = "retain/as/published/live"
    with NetzBroker(executable, connections=3) as broker:
        with (
            broker.connect() as cleared,
            broker.connect() as preserved,
            broker.connect() as publisher,
        ):
            connect_v5(cleared, mqtt_packets, "rap-clear")
            connect_v5(preserved, mqtt_packets, "rap-preserve")
            for sock, options, label in (
                (cleared, 0, "clear"),
                (
                    preserved,
                    mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED,
                    "preserve",
                ),
            ):
                sock.sendall(mqtt_packets.gen_subscribe(1, topic, options, proto_ver=5))
                expect_packet(
                    sock, mqtt_packets.gen_suback(1, 0, proto_ver=5),
                    f"RAP {label} SUBACK",
                )
            connect_v5(publisher, mqtt_packets, "rap-publisher")
            publisher.sendall(mqtt_packets.gen_publish(
                topic, qos=1, mid=1, payload="retained-live",
                retain=True, proto_ver=5,
            ))
            expect_packet(
                publisher, mqtt_packets.gen_puback(1, proto_ver=5),
                "RAP publisher PUBACK",
            )
            expect_packet(
                cleared, mqtt_packets.gen_publish(
                    topic, qos=0, payload="retained-live",
                    retain=False, proto_ver=5,
                ), "RAP cleared PUBLISH",
            )
            expect_packet(
                preserved, mqtt_packets.gen_publish(
                    topic, qos=0, payload="retained-live",
                    retain=True, proto_ver=5,
                ), "RAP preserved PUBLISH",
            )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            cleared.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            preserved.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def retained_replacement(executable: Path, mqtt_packets, mqtt5_props) -> None:
    topic = "retained/replacement"
    old_property = mqtt5_props.gen_string_pair_prop(
        mqtt5_props.USER_PROPERTY, "version", "old"
    )
    new_property = mqtt5_props.gen_string_pair_prop(
        mqtt5_props.USER_PROPERTY, "version", "new"
    )
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as publisher, broker.connect() as subscriber:
            connect_v5(publisher, mqtt_packets, "retained-replace-pub")
            for mid, payload, properties in (
                (1, "old-value", old_property),
                (2, "new-value", new_property),
            ):
                publisher.sendall(mqtt_packets.gen_publish(
                    topic, qos=1, mid=mid, payload=payload, retain=True,
                    proto_ver=5, properties=properties,
                ))
                expect_packet(
                    publisher, mqtt_packets.gen_puback(
                        mid, proto_ver=5, reason_code=0x10
                    ), f"retained replacement PUBACK {mid}",
                )
            connect_v5(subscriber, mqtt_packets, "retained-replace-sub")
            subscriber.sendall(mqtt_packets.gen_subscribe(1, topic, 0, proto_ver=5))
            expect_packet(
                subscriber, mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "retained replacement SUBACK",
            )
            expect_packet(
                subscriber, mqtt_packets.gen_publish(
                    topic, qos=0, payload="new-value", retain=True,
                    proto_ver=5, properties=new_property,
                ), "retained replacement latest PUBLISH",
            )
            subscriber.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                subscriber, mqtt_packets.gen_pingresp(),
                "retained replacement single replay",
            )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def retained_publish_property_bundle(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # In-process wire subset of Mosquitto 11-pub-props.py. The complete
    # Application Message property bundle must survive retained storage/replay.
    topic = "retained/property/bundle"
    properties = (
        mqtt5_props.gen_byte_prop(
            mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1
        )
        + mqtt5_props.gen_string_prop(
            mqtt5_props.CONTENT_TYPE, "plain/text"
        )
        + mqtt5_props.gen_string_prop(
            mqtt5_props.RESPONSE_TOPIC, "response/property/bundle"
        )
        + mqtt5_props.gen_string_prop(
            mqtt5_props.CORRELATION_DATA, "2357289375902345"
        )
        + mqtt5_props.gen_string_pair_prop(
            mqtt5_props.USER_PROPERTY, "name", "value"
        )
    )
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "retained-property-bundle")
            sock.sendall(mqtt_packets.gen_publish(
                topic, qos=1, mid=1, payload="message", retain=True,
                proto_ver=5, properties=properties,
            ))
            expect_packet(
                sock, mqtt_packets.gen_puback(
                    1, proto_ver=5, reason_code=0x10
                ), "property bundle PUBACK",
            )
            sock.sendall(mqtt_packets.gen_subscribe(2, topic, 0, proto_ver=5))
            expect_packet(
                sock, mqtt_packets.gen_suback(2, 0, proto_ver=5),
                "property bundle SUBACK",
            )
            expect_packet(
                sock, mqtt_packets.gen_publish(
                    topic, qos=0, payload="message", retain=True,
                    proto_ver=5, properties=properties,
                ), "property bundle retained PUBLISH",
            )
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def retained_tombstone_properties(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    topic = "retained/tombstone/properties"
    old_property = mqtt5_props.gen_string_pair_prop(
        mqtt5_props.USER_PROPERTY, "state", "old"
    )
    tombstone_property = mqtt5_props.gen_string_pair_prop(
        mqtt5_props.USER_PROPERTY, "state", "deleted"
    )
    new_property = mqtt5_props.gen_string_pair_prop(
        mqtt5_props.USER_PROPERTY, "state", "new"
    )
    with NetzBroker(executable) as broker:
        with broker.connect() as sock:
            connect_v5(sock, mqtt_packets, "retained-tombstone")
            for mid, payload, properties in (
                (1, "old", old_property),
                (2, None, tombstone_property),
            ):
                sock.sendall(mqtt_packets.gen_publish(
                    topic, qos=1, mid=mid, payload=payload, retain=True,
                    proto_ver=5, properties=properties,
                ))
                expect_packet(
                    sock, mqtt_packets.gen_puback(
                        mid, proto_ver=5, reason_code=0x10
                    ), f"tombstone PUBACK {mid}",
                )
            sock.sendall(mqtt_packets.gen_subscribe(3, topic, 0, proto_ver=5))
            expect_packet(sock, mqtt_packets.gen_suback(3, 0, proto_ver=5), "tombstone empty SUBACK")
            sock.sendall(mqtt_packets.gen_pingreq())
            expect_packet(sock, mqtt_packets.gen_pingresp(), "tombstone empty replay")
            sock.sendall(mqtt_packets.gen_publish(
                topic, qos=1, mid=4, payload="new", retain=True,
                proto_ver=5, properties=new_property,
            ))
            expect_packets_unordered(
                sock,
                [
                    mqtt_packets.gen_puback(4, proto_ver=5),
                    mqtt_packets.gen_publish(
                        topic, qos=0, payload="new", retain=False,
                        proto_ver=5, properties=new_property,
                    ),
                ],
                "tombstone new live publish",
            )
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def main() -> None:
    args = parse_args()
    sys.path.insert(0, str(args.mosquitto_test_root))
    import mqtt5_props  # type: ignore
    import mqtt5_rc  # type: ignore
    import mqtt5_opts  # type: ignore
    import mqtt_packets  # type: ignore

    no_matching_subscribers(args.broker, mqtt_packets, mqtt5_rc)
    subscription_identifiers(args.broker, mqtt_packets, mqtt5_props)
    multiple_subscription_identifiers(
        args.broker, mqtt_packets, mqtt5_props, mqtt5_opts
    )
    hostile_initial_packets(args.broker, mqtt_packets)
    publish_capability_disconnects(
        args.broker, mqtt_packets, mqtt5_props, mqtt5_rc
    )
    maximum_packet_size_disconnect(
        args.broker, mqtt_packets, mqtt5_props, mqtt5_rc
    )
    topic_alias_disconnect(
        args.broker, mqtt_packets, mqtt5_props, mqtt5_rc
    )
    receive_maximum_disconnect(args.broker, mqtt_packets, mqtt5_rc)
    subscription_capability_disconnects(
        args.broker, mqtt_packets, mqtt5_props, mqtt5_rc
    )
    qos2_routes_at_pubrel(args.broker, mqtt_packets)
    mixed_version_qos1(args.broker, mqtt_packets)
    persistent_no_local(args.broker, mqtt_packets)
    retained_subscription_handling(args.broker, mqtt_packets, mqtt5_opts)
    incoming_topic_alias(args.broker, mqtt_packets, mqtt5_props)
    outgoing_topic_alias(args.broker, mqtt_packets, mqtt5_props)
    request_response_properties(args.broker, mqtt_packets, mqtt5_props)
    disconnect_with_will_properties(
        args.broker, mqtt_packets, mqtt5_props
    )
    retained_message_expiry(
        args.broker, mqtt_packets, mqtt5_props, mqtt5_rc
    )
    qos2_receive_maximum_one(args.broker, mqtt_packets, mqtt5_props)
    maximum_packet_size_qos1(args.broker, mqtt_packets, mqtt5_props)
    maximum_packet_size_qos2(args.broker, mqtt_packets, mqtt5_props)
    retained_repeated_lifecycle(args.broker, mqtt_packets)
    retained_multilevel_clear(args.broker, mqtt_packets)
    shared_subscription_rotation(args.broker, mqtt_packets)
    qos2_duplicate_publish(args.broker, mqtt_packets)
    qos2_repeated_pubrel(args.broker, mqtt_packets)
    reject_publish_subscription_identifier(
        args.broker, mqtt_packets, mqtt5_props
    )
    unsubscribe_reason_codes(args.broker, mqtt_packets)
    retain_as_published_live(args.broker, mqtt_packets, mqtt5_opts)
    retained_replacement(args.broker, mqtt_packets, mqtt5_props)
    retained_publish_property_bundle(args.broker, mqtt_packets, mqtt5_props)
    retained_tombstone_properties(args.broker, mqtt_packets, mqtt5_props)
    assigned_client_identifier(args.broker, mqtt_packets, mqtt5_props)
    server_keep_alive(args.broker, mqtt_packets, mqtt5_props)
    print("Mosquitto-derived MQTT wire vectors passed: 37 scenarios")


if __name__ == "__main__":
    main()
