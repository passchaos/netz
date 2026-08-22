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
    session_present: bool = False,
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
        flags=int(session_present),
        rc=0,
        proto_ver=5,
        properties=properties,
        property_helper=False,
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


def duplicate_client_takeover(
    executable: Path, mqtt_packets, mqtt5_props, mqtt5_rc
) -> None:
    # Direct wire port of Mosquitto 01-connect-take-over.py. The replacement
    # connection must receive a normal CONNACK, while the displaced MQTT 5
    # connection receives the specified Session Taken Over reason rather than
    # an unexplained EOF.
    client_id = "take-over"
    connect_packet = mqtt_packets.gen_connect(client_id, proto_ver=5)
    connack_packet = expected_connack(mqtt_packets, mqtt5_props)
    with NetzBroker(executable, connections=2) as broker:
        with broker.connect() as first, broker.connect() as replacement:
            first.sendall(connect_packet)
            expect_packet(first, connack_packet, "initial takeover CONNACK")
            replacement.sendall(connect_packet)
            expect_packet(
                replacement, connack_packet, "replacement takeover CONNACK"
            )
            expect_packet(
                first,
                mqtt_packets.gen_disconnect(
                    reason_code=mqtt5_rc.SESSION_TAKEN_OVER,
                    proto_ver=5,
                ),
                "displaced client DISCONNECT",
            )
            replacement.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                replacement,
                mqtt_packets.gen_pingresp(),
                "replacement PINGRESP",
            )
            replacement.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def will_takeover_session_matrix(
    executable: Path, mqtt_packets, mqtt5_props, mqtt5_rc
) -> None:
    # Direct wire port of Mosquitto 07-will-takeover.py. Exercise both
    # protocol versions and all old/replacement Session combinations. The old
    # Will is suppressed only when the replacement continues the same durable
    # Session; a clean/transient Session on either side makes it due.
    for proto_ver in (4, 5):
        for old_clean in (True, False):
            for replacement_clean in (True, False):
                helper_id = (
                    f"will-takeover-helper-{proto_ver}-"
                    f"{int(old_clean)}-{int(replacement_clean)}"
                )
                client_id = (
                    f"will-takeover-{proto_ver}-"
                    f"{int(old_clean)}-{int(replacement_clean)}"
                )
                topic = "will/takeover/test"
                ready = mqtt_packets.gen_publish(
                    topic, 0, b"Client ready", proto_ver=proto_ver
                )
                expected_will = mqtt_packets.gen_publish(
                    topic, 0, b"LWT", proto_ver=proto_ver
                )

                def session_expiry(clean: bool) -> int:
                    return 0 if clean else 60

                def connect_packet(
                    *, clean: bool, with_will: bool
                ) -> bytes:
                    options = {
                        "clean_session": clean,
                        "proto_ver": proto_ver,
                    }
                    if proto_ver == 5:
                        options["session_expiry"] = session_expiry(clean)
                    if with_will:
                        options.update(
                            will_topic=topic,
                            will_payload=b"LWT",
                        )
                    return mqtt_packets.gen_connect(client_id, **options)

                with NetzBroker(executable, connections=3) as broker:
                    with (
                        broker.connect() as helper,
                        broker.connect() as original,
                        broker.connect() as replacement,
                    ):
                        connect_client(
                            helper, mqtt_packets, helper_id, proto_ver
                        )
                        helper.sendall(
                            mqtt_packets.gen_subscribe(
                                1, topic, 0, proto_ver=proto_ver
                            )
                        )
                        expect_packet(
                            helper,
                            mqtt_packets.gen_suback(
                                1, 0, proto_ver=proto_ver
                            ),
                            "Will takeover SUBACK",
                        )

                        original.sendall(
                            connect_packet(clean=old_clean, with_will=True)
                        )
                        expect_packet(
                            original,
                            expected_connack(
                                mqtt_packets, mqtt5_props
                            )
                            if proto_ver == 5
                            else mqtt_packets.gen_connack(proto_ver=4),
                            "original Will takeover CONNACK",
                        )
                        replacement.sendall(
                            connect_packet(
                                clean=replacement_clean, with_will=False
                            )
                        )
                        session_present = (
                            not old_clean and not replacement_clean
                        )
                        expect_packet(
                            replacement,
                            expected_connack(
                                mqtt_packets,
                                mqtt5_props,
                                session_present=session_present,
                            )
                            if proto_ver == 5
                            else mqtt_packets.gen_connack(
                                flags=int(session_present), proto_ver=4
                            ),
                            "replacement Will takeover CONNACK",
                        )
                        if proto_ver == 5:
                            expect_packet(
                                original,
                                mqtt_packets.gen_disconnect(
                                    reason_code=mqtt5_rc.SESSION_TAKEN_OVER,
                                    proto_ver=5,
                                ),
                                "Will takeover displaced DISCONNECT",
                            )

                        will_is_due = old_clean or replacement_clean
                        if will_is_due:
                            expect_packet(
                                helper, expected_will, "takeover Will"
                            )
                        else:
                            # PINGRESP is ordered behind any queued Will on the
                            # helper connection, so an erroneous publication
                            # cannot hide behind a timeout-only silence check.
                            helper.sendall(mqtt_packets.gen_pingreq())
                            expect_packet(
                                helper,
                                mqtt_packets.gen_pingresp(),
                                "PINGRESP without takeover Will",
                            )

                        replacement.sendall(ready)
                        expect_packet(
                            helper, ready, "post-takeover live PUBLISH"
                        )
                        if proto_ver == 5:
                            replacement.sendall(
                                mqtt_packets.gen_disconnect(proto_ver=5)
                            )
                            helper.sendall(
                                mqtt_packets.gen_disconnect(proto_ver=5)
                            )


def disconnect_session_expiry(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Timing-tolerant subset of Mosquitto 05-session-expiry-v5.py. A
    # DISCONNECT override extends the CONNECT value, later expires at that
    # updated deadline, and a zero override removes the Session immediately.
    client_id = "session-expiry"
    connect_packet = mqtt_packets.gen_connect(
        client_id,
        clean_session=False,
        proto_ver=5,
        session_expiry=1,
    )
    expiry_three = mqtt5_props.gen_uint32_prop(
        mqtt5_props.SESSION_EXPIRY_INTERVAL, 3
    )
    expiry_zero = mqtt5_props.gen_uint32_prop(
        mqtt5_props.SESSION_EXPIRY_INTERVAL, 0
    )

    def connect(sock: socket.socket, session_present: bool, label: str) -> None:
        sock.sendall(connect_packet)
        expect_packet(
            sock,
            expected_connack(
                mqtt_packets,
                mqtt5_props,
                session_present=session_present,
            ),
            label,
        )

    def disconnect(sock: socket.socket, properties: bytes) -> None:
        sock.sendall(
            mqtt_packets.gen_disconnect(
                proto_ver=5, properties=properties
            )
        )
        if sock.recv(1) != b"":
            raise AssertionError("broker sent data after DISCONNECT")

    with NetzBroker(executable, connections=4) as broker:
        with broker.connect() as first:
            connect(first, False, "initial Session Expiry CONNACK")
            disconnect(first, expiry_three)

        # The one-second CONNECT interval has elapsed, so Session Present here
        # proves the DISCONNECT value replaced rather than merely supplemented
        # it. Reapply three seconds to test that updated expiry itself fires.
        time.sleep(2)
        with broker.connect() as extended:
            connect(extended, True, "extended Session Expiry CONNACK")
            disconnect(extended, expiry_three)

        time.sleep(4)
        with broker.connect() as expired:
            connect(expired, False, "expired Session CONNACK")
            disconnect(expired, expiry_zero)

        with broker.connect() as removed:
            connect(removed, False, "zero Session Expiry CONNACK")
            removed.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


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


def malformed_will_connects(executable: Path, mqtt_packets) -> None:
    # Direct wire ports of Mosquitto 07-will-no-flag.py and
    # 07-will-null-topic.py for MQTT 3.1.1 and MQTT 5. A malformed CONNECT is
    # rejected before Session/Will installation; a final valid connection
    # proves the finite broker remains usable after all four failures.
    cases: list[tuple[str, bytes]] = []
    for proto_ver in (4, 5):
        complete = mqtt_packets.gen_connect(
            f"will-missing-payload-{proto_ver}",
            will_topic="will/malformed/topic",
            will_qos=1,
            will_retain=True,
            proto_ver=proto_ver,
        )
        malformed = bytearray(complete[:-2])
        # These small fixtures have a one-byte Remaining Length. Removing the
        # final binary-length field must be reflected in that byte so the
        # parser reaches the truncated Will payload rather than rejecting the
        # packet envelope first.
        if malformed[1] & 0x80:
            raise AssertionError("unexpected multi-byte CONNECT length")
        malformed[1] -= 2
        cases.append((f"missing Will payload v{proto_ver}", bytes(malformed)))
        cases.append((
            f"empty Will Topic v{proto_ver}",
            mqtt_packets.gen_connect(
                f"will-empty-topic-{proto_ver}",
                will_topic="",
                will_payload=b"will-message",
                proto_ver=proto_ver,
            ),
        ))

    with NetzBroker(
        executable, connections=len(cases) + 1, ignore_errors=True
    ) as broker:
        for label, packet in cases:
            with broker.connect() as sock:
                sock.sendall(packet)
                try:
                    response = sock.recv(1)
                    if response:
                        raise AssertionError(
                            f"{label} received unexpected bytes: "
                            + response.hex()
                        )
                except (ConnectionResetError, BrokenPipeError):
                    pass
        with broker.connect() as healthy:
            connect_v5(healthy, mqtt_packets, "after-malformed-wills")
            healthy.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                healthy,
                mqtt_packets.gen_pingresp(),
                "healthy PINGRESP after malformed Wills",
            )
            healthy.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def zero_length_will_payload(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto 07-will-null.py. A zero-length Will Payload
    # is valid and distinct from the malformed case where its two-byte length
    # field is absent. Verify exact delivery for both protocol versions and use
    # PING ordering to reject a duplicate or non-empty publication.
    topic = "will/null/test"
    for proto_ver in (4, 5):
        with NetzBroker(executable, connections=2) as broker:
            with broker.connect() as subscriber, broker.connect() as source:
                connect_client(
                    subscriber,
                    mqtt_packets,
                    f"will-null-subscriber-{proto_ver}",
                    proto_ver,
                )
                subscriber.sendall(
                    mqtt_packets.gen_subscribe(
                        53, topic, 0, proto_ver=proto_ver
                    )
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(53, 0, proto_ver=proto_ver),
                    f"zero-length Will SUBACK v{proto_ver}",
                )
                source.sendall(
                    mqtt_packets.gen_connect(
                        f"will-null-source-{proto_ver}",
                        will_topic=topic,
                        will_payload=b"",
                        proto_ver=proto_ver,
                    )
                )
                expect_packet(
                    source,
                    expected_connack(mqtt_packets, mqtt5_props)
                    if proto_ver == 5
                    else mqtt_packets.gen_connack(proto_ver=4),
                    f"zero-length Will source CONNACK v{proto_ver}",
                )
                # Closing the socket without DISCONNECT publishes the Will.
                source.close()
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_publish(
                        topic, qos=0, payload=None, proto_ver=proto_ver
                    ),
                    f"zero-length Will PUBLISH v{proto_ver}",
                )
                subscriber.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_pingresp(),
                    f"PINGRESP after zero-length Will v{proto_ver}",
                )
                if proto_ver == 5:
                    subscriber.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=5)
                    )


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


def clean_session_qos1(executable: Path, mqtt_packets, mqtt5_props) -> None:
    # MQTT 5 wire port of Mosquitto 05-clean-session-qos1.py. A persistent
    # subscriber disconnects before publication, receives the queued QoS 1
    # message with Session Present on resume, then Clean Start removes both
    # the subscription and any future offline delivery route.
    client_id = "05-clean-session"
    topic = "qos1/05-clean_session/test"
    persistent_connect = mqtt_packets.gen_connect(
        client_id,
        clean_session=False,
        proto_ver=5,
        session_expiry=60,
    )
    clean_connect = mqtt_packets.gen_connect(
        client_id,
        clean_session=True,
        proto_ver=5,
        session_expiry=0,
    )

    with NetzBroker(executable, connections=5) as broker:
        with broker.connect() as first:
            first.sendall(persistent_connect)
            expect_packet(
                first,
                expected_connack(mqtt_packets, mqtt5_props),
                "clean-session initial CONNACK",
            )
            first.sendall(
                mqtt_packets.gen_subscribe(
                    109, topic, 1, proto_ver=5
                )
            )
            expect_packet(
                first,
                mqtt_packets.gen_suback(109, 1, proto_ver=5),
                "clean-session SUBACK",
            )
            first.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

        with broker.connect() as publisher:
            connect_v5(publisher, mqtt_packets, "05-clean-qos1-helper")
            publisher.sendall(
                mqtt_packets.gen_publish(
                    topic,
                    qos=1,
                    mid=128,
                    payload="clean-session-message",
                    proto_ver=5,
                )
            )
            expect_packet(
                publisher,
                mqtt_packets.gen_puback(128, proto_ver=5),
                "offline publisher PUBACK",
            )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

        with broker.connect() as resumed:
            resumed.sendall(persistent_connect)
            expect_packet(
                resumed,
                expected_connack(
                    mqtt_packets,
                    mqtt5_props,
                    session_present=True,
                ),
                "clean-session resumed CONNACK",
            )
            expect_packet(
                resumed,
                mqtt_packets.gen_publish(
                    topic,
                    qos=1,
                    mid=1,
                    payload="clean-session-message",
                    proto_ver=5,
                ),
                "clean-session queued PUBLISH",
            )
            resumed.sendall(mqtt_packets.gen_puback(1, proto_ver=5))
            resumed.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

        with broker.connect() as cleared:
            cleared.sendall(clean_connect)
            expect_packet(
                cleared,
                expected_connack(mqtt_packets, mqtt5_props),
                "clean-session clearing CONNACK",
            )
            cleared.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

        # Reopening persistently after Clean Start must create a new Session.
        # PINGRESP must be next, proving no stale queued message was retained.
        with broker.connect() as fresh:
            fresh.sendall(persistent_connect)
            expect_packet(
                fresh,
                expected_connack(mqtt_packets, mqtt5_props),
                "clean-session fresh CONNACK",
            )
            fresh.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                fresh,
                mqtt_packets.gen_pingresp(),
                "clean-session fresh PINGRESP",
            )
            fresh.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def outgoing_qos1_reconnect_dup(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto 03-publish-b2c-disconnect-qos1.py for both
    # MQTT 3.1.1 and MQTT 5. The first delivery is read but deliberately left
    # unacknowledged before an abrupt disconnect. Resumption must retain both
    # its Packet Identifier and payload while setting DUP=1.
    topic = "03/b2c/qos1/disconnect/test"
    payload = "disconnect-message"
    for proto_ver in (4, 5):
        client_id = f"03-b2c-disco-qos1-v{proto_ver}"
        persistent_connect = mqtt_packets.gen_connect(
            client_id,
            clean_session=False,
            proto_ver=proto_ver,
            session_expiry=60,
        )

        def connack(session_present: bool) -> bytes:
            if proto_ver == 5:
                return expected_connack(
                    mqtt_packets,
                    mqtt5_props,
                    session_present=session_present,
                )
            return mqtt_packets.gen_connack(
                flags=int(session_present),
                rc=0,
                proto_ver=proto_ver,
            )

        with NetzBroker(executable, connections=3) as broker:
            subscriber = broker.connect()
            try:
                subscriber.sendall(persistent_connect)
                expect_packet(
                    subscriber,
                    connack(False),
                    f"QoS1 retransmit initial CONNACK v{proto_ver}",
                )
                subscriber.sendall(
                    mqtt_packets.gen_subscribe(
                        3265, topic, 1, proto_ver=proto_ver
                    )
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(
                        3265, 1, proto_ver=proto_ver
                    ),
                    f"QoS1 retransmit SUBACK v{proto_ver}",
                )

                with broker.connect() as publisher:
                    connect_client(
                        publisher,
                        mqtt_packets,
                        f"03-b2c-disco-helper-v{proto_ver}",
                        proto_ver,
                    )
                    publisher.sendall(
                        mqtt_packets.gen_publish(
                            topic,
                            qos=1,
                            mid=128,
                            payload=payload,
                            proto_ver=proto_ver,
                        )
                    )
                    expect_packet(
                        publisher,
                        mqtt_packets.gen_puback(128, proto_ver=proto_ver),
                        f"QoS1 retransmit publisher PUBACK v{proto_ver}",
                    )
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_publish(
                            topic,
                            qos=1,
                            mid=1,
                            payload=payload,
                            proto_ver=proto_ver,
                        ),
                        f"QoS1 initial downstream PUBLISH v{proto_ver}",
                    )
                    # No PUBACK: closing the Network Connection leaves this
                    # exact outgoing transaction in the durable Session.
                    subscriber.close()
                    publisher.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                    )
            finally:
                subscriber.close()

            with broker.connect() as resumed:
                resumed.sendall(persistent_connect)
                expect_packet(
                    resumed,
                    connack(True),
                    f"QoS1 retransmit resumed CONNACK v{proto_ver}",
                )
                expect_packet(
                    resumed,
                    mqtt_packets.gen_publish(
                        topic,
                        qos=1,
                        mid=1,
                        payload=payload,
                        dup=True,
                        proto_ver=proto_ver,
                    ),
                    f"QoS1 DUP retransmission v{proto_ver}",
                )
                resumed.sendall(mqtt_packets.gen_puback(1, proto_ver=proto_ver))
                resumed.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    resumed,
                    mqtt_packets.gen_pingresp(),
                    f"QoS1 post-retransmit PINGRESP v{proto_ver}",
                )
                resumed.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                )


def offline_qos0_queue_policy(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Mosquitto's queue_qos0_messages defaults to false and is explicitly an
    # opt-in for persistent clients. Exercise both policy states with MQTT
    # 3.1.1 and MQTT 5: Session Present proves the subscription survived, and
    # the following PINGRESP proves either exact single delivery or exact drop.
    topic = "03/b2c/qos0/offline/test"
    payload = "offline-qos0"
    for proto_ver in (4, 5):
        for enabled in (False, True):
            client_id = f"offline-qos0-{proto_ver}-{int(enabled)}"
            persistent_connect = mqtt_packets.gen_connect(
                client_id,
                clean_session=False,
                proto_ver=proto_ver,
                session_expiry=60 if proto_ver == 5 else None,
            )

            def connack(session_present: bool) -> bytes:
                if proto_ver == 5:
                    return expected_connack(
                        mqtt_packets,
                        mqtt5_props,
                        session_present=session_present,
                    )
                return mqtt_packets.gen_connack(
                    flags=int(session_present),
                    rc=0,
                    proto_ver=proto_ver,
                )

            extra_args = ("--queue-qos0-messages",) if enabled else ()
            with NetzBroker(
                executable,
                connections=3,
                extra_args=extra_args,
            ) as broker:
                with broker.connect() as subscriber:
                    subscriber.sendall(persistent_connect)
                    expect_packet(
                        subscriber,
                        connack(False),
                        f"offline QoS0 initial CONNACK v{proto_ver} "
                        f"enabled={enabled}",
                    )
                    subscriber.sendall(mqtt_packets.gen_subscribe(
                        1, topic, 0, proto_ver=proto_ver
                    ))
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_suback(1, 0, proto_ver=proto_ver),
                        f"offline QoS0 SUBACK v{proto_ver} "
                        f"enabled={enabled}",
                    )
                    subscriber.sendall(mqtt_packets.gen_disconnect(
                        proto_ver=proto_ver
                    ))

                with broker.connect() as publisher:
                    connect_client(
                        publisher,
                        mqtt_packets,
                        f"offline-qos0-pub-{proto_ver}-{int(enabled)}",
                        proto_ver,
                    )
                    publisher.sendall(mqtt_packets.gen_publish(
                        topic, qos=0, payload=payload, proto_ver=proto_ver
                    ))
                    # QoS 0 has no acknowledgement. PINGRESP establishes that
                    # routing completed while the subscriber was offline.
                    publisher.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        publisher,
                        mqtt_packets.gen_pingresp(),
                        f"offline QoS0 publisher PINGRESP v{proto_ver} "
                        f"enabled={enabled}",
                    )
                    publisher.sendall(mqtt_packets.gen_disconnect(
                        proto_ver=proto_ver
                    ))

                with broker.connect() as resumed:
                    resumed.sendall(persistent_connect)
                    expect_packet(
                        resumed,
                        connack(True),
                        f"offline QoS0 resumed CONNACK v{proto_ver} "
                        f"enabled={enabled}",
                    )
                    if enabled:
                        expect_packet(
                            resumed,
                            mqtt_packets.gen_publish(
                                topic,
                                qos=0,
                                payload=payload,
                                proto_ver=proto_ver,
                            ),
                            f"offline QoS0 queued PUBLISH v{proto_ver}",
                        )
                    resumed.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        resumed,
                        mqtt_packets.gen_pingresp(),
                        f"offline QoS0 single/drop PINGRESP v{proto_ver} "
                        f"enabled={enabled}",
                    )
                    resumed.sendall(mqtt_packets.gen_disconnect(
                        proto_ver=proto_ver
                    ))


def outgoing_qos2_reconnect_stages(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto 03-publish-b2c-disconnect-qos2.py for both
    # MQTT 3.1.1 and MQTT 5. Exercise both durable outbound states: an
    # unacknowledged PUBLISH resumes with DUP and its original Packet
    # Identifier, while a transaction already acknowledged with PUBREC resumes
    # directly at PUBREL without delivering the Application Message again.
    topic = "03/b2c/qos2/disconnect/test"
    payload = "disconnect-message"
    for proto_ver in (4, 5):
        client_id = f"03-b2c-disco-qos2-v{proto_ver}"
        persistent_connect = mqtt_packets.gen_connect(
            client_id,
            clean_session=False,
            proto_ver=proto_ver,
            session_expiry=60,
        )

        def connack(session_present: bool) -> bytes:
            if proto_ver == 5:
                return expected_connack(
                    mqtt_packets,
                    mqtt5_props,
                    session_present=session_present,
                )
            return mqtt_packets.gen_connack(
                flags=int(session_present),
                rc=0,
                proto_ver=proto_ver,
            )

        with NetzBroker(executable, connections=4) as broker:
            subscriber = broker.connect()
            try:
                subscriber.sendall(persistent_connect)
                expect_packet(
                    subscriber,
                    connack(False),
                    f"QoS2 reconnect initial CONNACK v{proto_ver}",
                )
                subscriber.sendall(
                    mqtt_packets.gen_subscribe(
                        3265, topic, 2, proto_ver=proto_ver
                    )
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(
                        3265, 2, proto_ver=proto_ver
                    ),
                    f"QoS2 reconnect SUBACK v{proto_ver}",
                )

                with broker.connect() as publisher:
                    connect_client(
                        publisher,
                        mqtt_packets,
                        f"03-b2c-disco-qos2-helper-v{proto_ver}",
                        proto_ver,
                    )
                    publisher.sendall(
                        mqtt_packets.gen_publish(
                            topic,
                            qos=2,
                            mid=312,
                            payload=payload,
                            proto_ver=proto_ver,
                        )
                    )
                    expect_packet(
                        publisher,
                        mqtt_packets.gen_pubrec(312, proto_ver=proto_ver),
                        f"QoS2 reconnect publisher PUBREC v{proto_ver}",
                    )
                    publisher.sendall(
                        mqtt_packets.gen_pubrel(312, proto_ver=proto_ver)
                    )
                    expect_packet(
                        publisher,
                        mqtt_packets.gen_pubcomp(312, proto_ver=proto_ver),
                        f"QoS2 reconnect publisher PUBCOMP v{proto_ver}",
                    )
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_publish(
                            topic,
                            qos=2,
                            mid=1,
                            payload=payload,
                            proto_ver=proto_ver,
                        ),
                        f"QoS2 initial downstream PUBLISH v{proto_ver}",
                    )
                    # Leave the transaction awaiting PUBREC and force a
                    # Network Connection failure rather than a clean MQTT
                    # DISCONNECT.
                    subscriber.close()
                    publisher.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                    )
            finally:
                subscriber.close()

            second = broker.connect()
            try:
                second.sendall(persistent_connect)
                expect_packet(
                    second,
                    connack(True),
                    f"QoS2 reconnect second CONNACK v{proto_ver}",
                )
                expect_packet(
                    second,
                    mqtt_packets.gen_publish(
                        topic,
                        qos=2,
                        mid=1,
                        payload=payload,
                        dup=True,
                        proto_ver=proto_ver,
                    ),
                    f"QoS2 DUP retransmission v{proto_ver}",
                )
                second.sendall(mqtt_packets.gen_pubrec(1, proto_ver=proto_ver))
                expect_packet(
                    second,
                    mqtt_packets.gen_pubrel(1, proto_ver=proto_ver),
                    f"QoS2 first PUBREL v{proto_ver}",
                )
                # Leave the transaction awaiting PUBCOMP.
                second.close()
            finally:
                second.close()

            with broker.connect() as third:
                third.sendall(persistent_connect)
                expect_packet(
                    third,
                    connack(True),
                    f"QoS2 reconnect third CONNACK v{proto_ver}",
                )
                expect_packet(
                    third,
                    mqtt_packets.gen_pubrel(1, proto_ver=proto_ver),
                    f"QoS2 resumed PUBREL v{proto_ver}",
                )
                third.sendall(mqtt_packets.gen_pubcomp(1, proto_ver=proto_ver))
                third.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    third,
                    mqtt_packets.gen_pingresp(),
                    f"QoS2 post-completion PINGRESP v{proto_ver}",
                )
                third.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                )


def incoming_qos2_disconnect_recovery(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto 03-publish-c2b-disconnect-qos2.py for the
    # MQTT versions supported by netz. A durable publisher drops the first
    # connection after PUBREC, repeats PUBLISH with DUP after reconnect, then
    # drops again after PUBCOMP. A final repeated PUBREL must be acknowledged
    # without releasing the Application Message twice.
    topic = "03/c2b/qos2/disconnect/test"
    payload = "disconnect-message"
    packet_id = 3265
    for proto_ver in (4, 5):
        client_id = f"03-c2b-qos2-disco-v{proto_ver}"
        persistent_connect = mqtt_packets.gen_connect(
            client_id,
            clean_session=False,
            proto_ver=proto_ver,
            session_expiry=60,
        )

        def connack(session_present: bool) -> bytes:
            if proto_ver == 5:
                return expected_connack(
                    mqtt_packets,
                    mqtt5_props,
                    session_present=session_present,
                )
            return mqtt_packets.gen_connack(
                flags=int(session_present),
                rc=0,
                proto_ver=proto_ver,
            )

        # Subscriber, three publisher generations, and one Clean Start clear.
        with NetzBroker(executable, connections=5) as broker:
            subscriber = broker.connect()
            try:
                connect_client(
                    subscriber,
                    mqtt_packets,
                    f"03-c2b-qos2-helper-v{proto_ver}",
                    proto_ver,
                )
                subscriber.sendall(
                    mqtt_packets.gen_subscribe(
                        1, topic, 2, proto_ver=proto_ver
                    )
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(1, 2, proto_ver=proto_ver),
                    f"incoming QoS2 recovery SUBACK v{proto_ver}",
                )

                first = broker.connect()
                try:
                    first.sendall(persistent_connect)
                    expect_packet(
                        first,
                        connack(False),
                        f"incoming QoS2 first CONNACK v{proto_ver}",
                    )
                    first.sendall(
                        mqtt_packets.gen_publish(
                            topic,
                            qos=2,
                            mid=packet_id,
                            payload=payload,
                            proto_ver=proto_ver,
                        )
                    )
                    expect_packet(
                        first,
                        mqtt_packets.gen_pubrec(
                            packet_id, proto_ver=proto_ver
                        ),
                        f"incoming QoS2 first PUBREC v{proto_ver}",
                    )
                finally:
                    first.close()

                second = broker.connect()
                try:
                    second.sendall(persistent_connect)
                    expect_packet(
                        second,
                        connack(True),
                        f"incoming QoS2 second CONNACK v{proto_ver}",
                    )
                    second.sendall(
                        mqtt_packets.gen_publish(
                            topic,
                            qos=2,
                            mid=packet_id,
                            payload=payload,
                            dup=True,
                            proto_ver=proto_ver,
                        )
                    )
                    expect_packet(
                        second,
                        mqtt_packets.gen_pubrec(
                            packet_id, proto_ver=proto_ver
                        ),
                        f"incoming QoS2 DUP PUBREC v{proto_ver}",
                    )
                    second.sendall(
                        mqtt_packets.gen_pubrel(
                            packet_id, proto_ver=proto_ver
                        )
                    )
                    expect_packet(
                        second,
                        mqtt_packets.gen_pubcomp(
                            packet_id, proto_ver=proto_ver
                        ),
                        f"incoming QoS2 PUBCOMP v{proto_ver}",
                    )
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_publish(
                            topic,
                            qos=2,
                            mid=1,
                            payload=payload,
                            proto_ver=proto_ver,
                        ),
                        f"incoming QoS2 delivery v{proto_ver}",
                    )
                    subscriber.sendall(
                        mqtt_packets.gen_pubrec(1, proto_ver=proto_ver)
                    )
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_pubrel(1, proto_ver=proto_ver),
                        f"incoming QoS2 downstream PUBREL v{proto_ver}",
                    )
                    subscriber.sendall(
                        mqtt_packets.gen_pubcomp(1, proto_ver=proto_ver)
                    )
                finally:
                    # Pretend the successful PUBCOMP was lost.
                    second.close()

                third = broker.connect()
                try:
                    third.sendall(persistent_connect)
                    expect_packet(
                        third,
                        connack(True),
                        f"incoming QoS2 third CONNACK v{proto_ver}",
                    )
                    third.sendall(
                        mqtt_packets.gen_pubrel(
                            packet_id,
                            dup=proto_ver == 4,
                            proto_ver=proto_ver,
                        )
                    )
                    expect_packet(
                        third,
                        mqtt_packets.gen_pubcomp(
                            packet_id, proto_ver=proto_ver
                        ),
                        f"incoming QoS2 repeated PUBCOMP v{proto_ver}",
                    )
                    subscriber.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_pingresp(),
                        f"incoming QoS2 no duplicate delivery v{proto_ver}",
                    )
                finally:
                    third.close()

                subscriber.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                )
                with broker.connect() as clear:
                    clear.sendall(
                        mqtt_packets.gen_connect(
                            client_id, proto_ver=proto_ver
                        )
                    )
                    expect_packet(
                        clear,
                        connack(False),
                        f"incoming QoS2 clear CONNACK v{proto_ver}",
                    )
                    clear.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                    )
            finally:
                subscriber.close()


def incoming_qos2_reconnect_reuse(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto issue 1322. A durable publisher repeatedly
    # reconnects and reuses Packet Identifier 1 for completed QoS2
    # transactions while subscriptions change. No stale Application Message
    # may be released under a later transaction's topology.
    topic_one = "02/subpub/qos2/1322/topic1"
    topic_two = "02/subpub/qos2/1322/topic2"
    for proto_ver in (4, 5):
        publisher_id = f"qos2-1322-publisher-{proto_ver}"
        persistent_connect = mqtt_packets.gen_connect(
            publisher_id, clean_session=False, proto_ver=proto_ver,
            session_expiry=60,
        )

        def connack(session_present: bool) -> bytes:
            if proto_ver == 5:
                return expected_connack(
                    mqtt_packets, mqtt5_props,
                    session_present=session_present,
                )
            return mqtt_packets.gen_connack(
                flags=int(session_present), proto_ver=proto_ver,
            )

        # Two subscribers plus five separate publisher Network Connections.
        with NetzBroker(executable, connections=7) as broker:
            subscriber_one = broker.connect()
            subscriber_two = None
            try:
                connect_client(
                    subscriber_one, mqtt_packets,
                    f"qos2-1322-sub1-{proto_ver}", proto_ver,
                )
                subscriber_one.sendall(mqtt_packets.gen_subscribe(
                    1, topic_one, 0, proto_ver=proto_ver,
                ))
                expect_packet(
                    subscriber_one, mqtt_packets.gen_suback(
                        1, 0, proto_ver=proto_ver,
                    ), f"QoS2 1322 topic1 SUBACK v{proto_ver}",
                )

                for attempt, (topic, payload, target) in enumerate((
                    (topic_one, "message1", subscriber_one),
                    (topic_two, "message2", None),
                    (topic_one, "message3", subscriber_one),
                )):
                    with broker.connect() as publisher:
                        publisher.sendall(persistent_connect)
                        expect_packet(
                            publisher, connack(attempt != 0),
                            f"QoS2 1322 publisher CONNACK {attempt} "
                            f"v{proto_ver}",
                        )
                        publish = mqtt_packets.gen_publish(
                            topic, qos=2, mid=1, payload=payload,
                            proto_ver=proto_ver,
                        )
                        publisher.sendall(publish)
                        expect_packet(
                            publisher, mqtt_packets.gen_pubrec(
                                1, proto_ver=proto_ver,
                            ), f"QoS2 1322 PUBREC {attempt} v{proto_ver}",
                        )
                        publisher.sendall(mqtt_packets.gen_pubrel(
                            1, proto_ver=proto_ver,
                        ))
                        expect_packet(
                            publisher, mqtt_packets.gen_pubcomp(
                                1, proto_ver=proto_ver,
                            ), f"QoS2 1322 PUBCOMP {attempt} v{proto_ver}",
                        )
                        if target is not None:
                            expect_packet(
                                target, mqtt_packets.gen_publish(
                                    topic, qos=0, payload=payload,
                                    proto_ver=proto_ver,
                                ), f"QoS2 1322 delivery {attempt} "
                                f"v{proto_ver}",
                            )
                    # The publisher drops its TCP connection after completing
                    # each transaction, matching mosquitto_pub -c invocations.

                subscriber_two = broker.connect()
                connect_client(
                    subscriber_two, mqtt_packets,
                    f"qos2-1322-sub2-{proto_ver}", proto_ver,
                )
                subscriber_two.sendall(mqtt_packets.gen_subscribe(
                    1, topic_two, 0, proto_ver=proto_ver,
                ))
                expect_packet(
                    subscriber_two, mqtt_packets.gen_suback(
                        1, 0, proto_ver=proto_ver,
                    ), f"QoS2 1322 topic2 SUBACK v{proto_ver}",
                )

                for attempt, payload in enumerate(
                    ("message4", "message5"), start=3
                ):
                    with broker.connect() as publisher:
                        publisher.sendall(persistent_connect)
                        expect_packet(
                            publisher, connack(True),
                            f"QoS2 1322 publisher CONNACK {attempt} "
                            f"v{proto_ver}",
                        )
                        publisher.sendall(mqtt_packets.gen_publish(
                            topic_one, qos=2, mid=1, payload=payload,
                            proto_ver=proto_ver,
                        ))
                        expect_packet(
                            publisher, mqtt_packets.gen_pubrec(
                                1, proto_ver=proto_ver,
                            ), f"QoS2 1322 PUBREC {attempt} v{proto_ver}",
                        )
                        publisher.sendall(mqtt_packets.gen_pubrel(
                            1, proto_ver=proto_ver,
                        ))
                        expect_packet(
                            publisher, mqtt_packets.gen_pubcomp(
                                1, proto_ver=proto_ver,
                            ), f"QoS2 1322 PUBCOMP {attempt} v{proto_ver}",
                        )
                        expect_packet(
                            subscriber_one, mqtt_packets.gen_publish(
                                topic_one, qos=0, payload=payload,
                                proto_ver=proto_ver,
                            ), f"QoS2 1322 topic1 delivery {attempt} "
                            f"v{proto_ver}",
                        )
                    subscriber_two.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        subscriber_two, mqtt_packets.gen_pingresp(),
                        f"QoS2 1322 no stale topic2 delivery {attempt} "
                        f"v{proto_ver}",
                    )

                if proto_ver == 5:
                    subscriber_one.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=5)
                    )
                    subscriber_two.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=5)
                    )
            finally:
                subscriber_one.close()
                if subscriber_two is not None:
                    subscriber_two.close()


def offline_message_expiry(executable: Path, mqtt_packets, mqtt5_props) -> None:
    # Direct wire port of Mosquitto 02-subpub-qos1-message-expiry.py. Keep a
    # persistent subscriber offline while two QoS 1 messages are queued, then
    # prove the expired message is removed and the surviving message carries a
    # reduced interval when the Session reconnects.
    client_id = "02-offline-message-expiry"
    topic = "subpub/qos1/message-expiry"
    persistent_connect = mqtt_packets.gen_connect(
        client_id,
        clean_session=False,
        proto_ver=5,
        session_expiry=60,
    )
    with NetzBroker(executable, connections=3) as broker:
        with broker.connect() as subscriber:
            subscriber.sendall(persistent_connect)
            expect_packet(
                subscriber,
                expected_connack(mqtt_packets, mqtt5_props),
                "message expiry initial CONNACK",
            )
            subscriber.sendall(
                mqtt_packets.gen_subscribe(53, topic, 1, proto_ver=5)
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_suback(53, 1, proto_ver=5),
                "message expiry SUBACK",
            )

        with broker.connect() as publisher:
            connect_v5(publisher, mqtt_packets, "message-expiry-helper")
            for mid, payload, expiry in (
                (1, "message1", 1),
                (2, "message2", 10),
            ):
                properties = mqtt5_props.gen_uint32_prop(
                    mqtt5_props.MESSAGE_EXPIRY_INTERVAL, expiry
                )
                publisher.sendall(
                    mqtt_packets.gen_publish(
                        topic,
                        qos=1,
                        mid=mid,
                        payload=payload,
                        proto_ver=5,
                        properties=properties,
                    )
                )
                expect_packet(
                    publisher,
                    mqtt_packets.gen_puback(mid, proto_ver=5),
                    f"message expiry publisher PUBACK {mid}",
                )
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

        time.sleep(2)
        with broker.connect() as resumed:
            resumed.sendall(persistent_connect)
            expect_packet(
                resumed,
                expected_connack(
                    mqtt_packets, mqtt5_props, session_present=True
                ),
                "message expiry resumed CONNACK",
            )
            actual = read_packet(resumed)
            surviving_variants = [
                mqtt_packets.gen_publish(
                    topic,
                    qos=1,
                    mid=1,
                    payload="message2",
                    proto_ver=5,
                    properties=mqtt5_props.gen_uint32_prop(
                        mqtt5_props.MESSAGE_EXPIRY_INTERVAL, remaining
                    ),
                )
                for remaining in (9, 8, 7, 6)
            ]
            if actual not in surviving_variants:
                raise AssertionError(
                    "offline message expiry mismatch: " + actual.hex()
                )
            resumed.sendall(mqtt_packets.gen_puback(1, proto_ver=5))
            resumed.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                resumed,
                mqtt_packets.gen_pingresp(),
                "message expiry PINGRESP after surviving PUBLISH",
            )
            resumed.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def offline_will_message_expiry(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto
    # 02-subpub-qos1-message-expiry-will.py. Message Expiry starts when the
    # Will is published, not when CONNECT installs it. Keep the durable
    # subscriber offline after publication and require a reduced interval on
    # reconnect, then prove a second short-lived Will expires from its queue.
    client_id = "02-offline-will-expiry"
    topic = "subpub/qos1/will-expiry"
    persistent_connect = mqtt_packets.gen_connect(
        client_id, clean_session=False, proto_ver=5, session_expiry=60
    )
    expiry_ten = mqtt5_props.gen_uint32_prop(
        mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 10
    )
    expiry_one = mqtt5_props.gen_uint32_prop(
        mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 1
    )

    # Initial subscriber + two Will sources + resumed subscriber.
    with NetzBroker(executable, connections=4) as broker:
        with broker.connect() as subscriber:
            subscriber.sendall(persistent_connect)
            expect_packet(
                subscriber, expected_connack(mqtt_packets, mqtt5_props),
                "Will expiry initial CONNACK",
            )
            subscriber.sendall(mqtt_packets.gen_subscribe(
                53, topic, 1, proto_ver=5,
            ))
            expect_packet(
                subscriber, mqtt_packets.gen_suback(53, 1, proto_ver=5),
                "Will expiry SUBACK",
            )

        for source_id, payload, properties in (
            ("will-expiry-long", b"survives", expiry_ten),
            ("will-expiry-short", b"expires", expiry_one),
        ):
            with broker.connect() as source:
                source.sendall(mqtt_packets.gen_connect(
                    source_id, proto_ver=5, will_topic=topic, will_qos=1,
                    will_payload=payload, will_properties=properties,
                ))
                expect_packet(
                    source, expected_connack(mqtt_packets, mqtt5_props),
                    f"{source_id} CONNACK",
                )
                # No DISCONNECT: both Wills are published and queued at this
                # point, so their independent expiry clocks start now.

        time.sleep(2)
        with broker.connect() as resumed:
            resumed.sendall(persistent_connect)
            expect_packet(
                resumed, expected_connack(
                    mqtt_packets, mqtt5_props, session_present=True,
                ), "Will expiry resumed CONNACK",
            )
            actual = read_packet(resumed)
            surviving_variants = [
                mqtt_packets.gen_publish(
                    topic, qos=1, mid=1, payload="survives", proto_ver=5,
                    properties=mqtt5_props.gen_uint32_prop(
                        mqtt5_props.MESSAGE_EXPIRY_INTERVAL, remaining
                    ),
                )
                for remaining in (9, 8, 7, 6)
            ]
            if actual not in surviving_variants:
                raise AssertionError(
                    "offline Will expiry mismatch: " + actual.hex()
                )
            resumed.sendall(mqtt_packets.gen_puback(1, proto_ver=5))
            resumed.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                resumed, mqtt_packets.gen_pingresp(),
                "PINGRESP after expired queued Will",
            )
            resumed.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def offline_queued_payload_bytes(executable: Path, mqtt_packets) -> None:
    # Wire-level behavior derived from Mosquitto
    # 03-publish-qos1-queued-bytes.py. Bound each durable outgoing queue by
    # payload bytes, prove the packet that reaches the threshold is retained,
    # and require subsequent publications to be dropped without changing the
    # publisher's successful QoS 1 acknowledgement.
    topic = "test/publish/queueing/value"
    for proto_ver in (4, 5):
        with NetzBroker(
            executable,
            connections=3,
            extra_args=("--max-session-queued-payload-bytes=10",),
        ) as broker:
            subscriber = broker.connect()
            publisher = broker.connect()
            try:
                subscriber.sendall(mqtt_packets.gen_connect(
                    f"queued-bytes-sub-{proto_ver}",
                    clean_session=False,
                    proto_ver=proto_ver,
                    session_expiry=60 if proto_ver == 5 else None,
                ))
                read_packet(subscriber)
                subscriber.sendall(mqtt_packets.gen_subscribe(
                    1, topic, 1, proto_ver=proto_ver
                ))
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(1, 1, proto_ver=proto_ver),
                    f"queued bytes SUBACK v{proto_ver}",
                )
                subscriber.close()

                connect_client(
                    publisher, mqtt_packets,
                    f"queued-bytes-pub-{proto_ver}", proto_ver,
                )
                for mid, payload in enumerate(("123456", "789012", "drop"), 1):
                    publisher.sendall(mqtt_packets.gen_publish(
                        topic, qos=1, mid=mid, payload=payload,
                        proto_ver=proto_ver,
                    ))
                    expect_packet(
                        publisher,
                        mqtt_packets.gen_puback(mid, proto_ver=proto_ver),
                        f"queued bytes publisher PUBACK v{proto_ver}/{mid}",
                    )

                subscriber = broker.connect()
                subscriber.sendall(mqtt_packets.gen_connect(
                    f"queued-bytes-sub-{proto_ver}",
                    clean_session=False,
                    proto_ver=proto_ver,
                    session_expiry=60 if proto_ver == 5 else None,
                ))
                connack = read_packet(subscriber)
                if connack[2] != 1 or connack[3] != 0:
                    raise AssertionError(
                        f"queued bytes missing Session Present v{proto_ver}: "
                        f"{connack.hex()}"
                    )
                for packet_id, payload in enumerate(("123456", "789012"), 1):
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_publish(
                            topic, qos=1, mid=packet_id, payload=payload,
                            proto_ver=proto_ver,
                        ),
                        f"queued bytes delivery v{proto_ver}/{packet_id}",
                    )
                    subscriber.sendall(mqtt_packets.gen_puback(
                        packet_id, proto_ver=proto_ver
                    ))
                subscriber.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    subscriber, mqtt_packets.gen_pingresp(),
                    f"queued bytes no dropped delivery v{proto_ver}",
                )
                publisher.sendall(mqtt_packets.gen_disconnect(
                    proto_ver=proto_ver
                ))
                subscriber.sendall(mqtt_packets.gen_disconnect(
                    proto_ver=proto_ver
                ))
            finally:
                publisher.close()
                subscriber.close()


def outgoing_inflight_payload_bytes(executable: Path, mqtt_packets) -> None:
    # Bounded process-level port of Mosquitto
    # 02-subpub-qos2-max-inflight-bytes.py. The subscriber advertises ample
    # Receive Maximum, so the broker's independent byte window must hold the
    # third QoS 1 delivery until one earlier PUBACK releases payload budget.
    topic = "subpub/qos1/inflight-bytes"
    for proto_ver in (4, 5):
        with NetzBroker(
            executable,
            connections=2,
            extra_args=("--max-session-inflight-payload-bytes=10",),
        ) as broker:
            with broker.connect() as subscriber, broker.connect() as publisher:
                subscriber.sendall(mqtt_packets.gen_connect(
                    f"inflight-bytes-sub-{proto_ver}",
                    clean_session=False,
                    proto_ver=proto_ver,
                    session_expiry=60 if proto_ver == 5 else None,
                ))
                connack = read_packet(subscriber)
                if connack[2] != 0 or connack[3] != 0:
                    raise AssertionError(
                        f"inflight bytes invalid CONNACK v{proto_ver}: "
                        f"{connack.hex()}"
                    )
                subscriber.sendall(mqtt_packets.gen_subscribe(
                    1, topic, 1, proto_ver=proto_ver
                ))
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(1, 1, proto_ver=proto_ver),
                    f"inflight bytes SUBACK v{proto_ver}",
                )
                connect_client(
                    publisher, mqtt_packets,
                    f"inflight-bytes-pub-{proto_ver}", proto_ver,
                )
                for mid, payload in enumerate(("123456", "789012", "third"), 1):
                    publisher.sendall(mqtt_packets.gen_publish(
                        topic, qos=1, mid=mid, payload=payload,
                        proto_ver=proto_ver,
                    ))
                    expect_packet(
                        publisher,
                        mqtt_packets.gen_puback(mid, proto_ver=proto_ver),
                        f"inflight bytes publisher PUBACK v{proto_ver}/{mid}",
                    )

                first = []
                for packet_id, payload in enumerate(("123456", "789012"), 1):
                    packet = mqtt_packets.gen_publish(
                        topic, qos=1, mid=packet_id, payload=payload,
                        proto_ver=proto_ver,
                    )
                    first.append(packet)
                expect_packets_unordered(
                    subscriber, first, f"inflight bytes first window v{proto_ver}"
                )
                subscriber.settimeout(0.1)
                try:
                    unexpected = subscriber.recv(1)
                    if unexpected:
                        raise AssertionError(
                            f"inflight byte window leaked third PUBLISH "
                            f"v{proto_ver}: {unexpected.hex()}"
                        )
                except socket.timeout:
                    pass
                finally:
                    subscriber.settimeout(5)

                subscriber.sendall(mqtt_packets.gen_puback(1, proto_ver=proto_ver))
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_publish(
                        topic, qos=1, mid=3, payload="third",
                        proto_ver=proto_ver,
                    ),
                    f"inflight bytes released delivery v{proto_ver}",
                )
                subscriber.sendall(mqtt_packets.gen_puback(2, proto_ver=proto_ver))
                subscriber.sendall(mqtt_packets.gen_puback(3, proto_ver=proto_ver))
                publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=proto_ver))
                subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=proto_ver))


def acknowledgement_length_forms(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct process-boundary coverage from Mosquitto
    # 03-publish-b2c-qos{1,2}-len.py. Exercise the four legal MQTT 5 ACK forms:
    # Packet Identifier only, explicit reason, reason plus empty Property
    # Length, and reason plus a User Property. A following PING proves each
    # form advanced and released the broker's outgoing state.
    user_property = mqtt5_props.gen_string_pair_prop(
        mqtt5_props.USER_PROPERTY, "key", "value"
    )
    ack_forms = (
        (-1, None),
        (0, None),
        (0, ""),
        (0, user_property),
    )
    scenario = 0
    for qos in (1, 2):
        for reason_code, properties in ack_forms:
            scenario += 1
            topic = f"03/b2c/qos{qos}/len/test/{scenario}"
            with NetzBroker(executable, connections=2) as broker:
                with broker.connect() as subscriber, broker.connect() as publisher:
                    connect_v5(
                        subscriber, mqtt_packets,
                        f"ack-len-sub-{qos}-{scenario}",
                    )
                    subscriber.sendall(mqtt_packets.gen_subscribe(
                        3265, topic, qos, proto_ver=5
                    ))
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_suback(3265, qos, proto_ver=5),
                        f"ACK length SUBACK qos{qos}/{scenario}",
                    )
                    connect_v5(
                        publisher, mqtt_packets,
                        f"ack-len-pub-{qos}-{scenario}",
                    )
                    publisher.sendall(mqtt_packets.gen_publish(
                        topic, qos=qos, mid=77, payload="len-message",
                        proto_ver=5,
                    ))
                    if qos == 1:
                        expect_packet(
                            publisher, mqtt_packets.gen_puback(77, proto_ver=5),
                            f"ACK length publisher PUBACK {scenario}",
                        )
                    else:
                        expect_packet(
                            publisher, mqtt_packets.gen_pubrec(77, proto_ver=5),
                            f"ACK length publisher PUBREC {scenario}",
                        )
                        publisher.sendall(mqtt_packets.gen_pubrel(77, proto_ver=5))
                        expect_packet(
                            publisher, mqtt_packets.gen_pubcomp(77, proto_ver=5),
                            f"ACK length publisher PUBCOMP {scenario}",
                        )
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_publish(
                            topic, qos=qos, mid=1, payload="len-message",
                            proto_ver=5,
                        ),
                        f"ACK length downstream PUBLISH qos{qos}/{scenario}",
                    )
                    if qos == 1:
                        subscriber.sendall(mqtt_packets.gen_puback(
                            1, proto_ver=5, reason_code=reason_code,
                            properties=properties,
                        ))
                    else:
                        subscriber.sendall(mqtt_packets.gen_pubrec(
                            1, proto_ver=5, reason_code=reason_code,
                            properties=properties,
                        ))
                        expect_packet(
                            subscriber, mqtt_packets.gen_pubrel(1, proto_ver=5),
                            f"ACK length downstream PUBREL {scenario}",
                        )
                        subscriber.sendall(mqtt_packets.gen_pubcomp(
                            1, proto_ver=5, reason_code=reason_code,
                            properties=properties,
                        ))
                    subscriber.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        subscriber, mqtt_packets.gen_pingresp(),
                        f"ACK length PINGRESP qos{qos}/{scenario}",
                    )
                    publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
                    subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


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


def delayed_will_reconnect_cancels(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto 07-will-delay-reconnect.py. An ungraceful
    # disconnect schedules the Will, but reconnecting the same durable Session
    # before its deadline must cancel that pending publication.
    client_id = "will-delay-reconnect-helper"
    topic = "will/delay/reconnect/test"
    session_expiry = mqtt5_props.gen_uint32_prop(
        mqtt5_props.SESSION_EXPIRY_INTERVAL, 60
    )
    will_delay = mqtt5_props.gen_uint32_prop(
        mqtt5_props.WILL_DELAY_INTERVAL, 3
    )
    with NetzBroker(executable, connections=3) as broker:
        with broker.connect() as subscriber:
            connect_v5(
                subscriber, mqtt_packets, "will-delay-reconnect-test"
            )
            subscriber.sendall(
                mqtt_packets.gen_subscribe(
                    1, topic, 0, proto_ver=5
                )
            )
            expect_packet(
                subscriber,
                mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "Will Delay reconnect SUBACK",
            )

            with broker.connect() as source:
                source.sendall(
                    mqtt_packets.gen_connect(
                        client_id,
                        proto_ver=5,
                        clean_session=False,
                        properties=session_expiry,
                        will_topic=topic,
                        will_payload=b"will delay",
                        will_properties=will_delay,
                    )
                )
                expect_packet(
                    source,
                    expected_connack(mqtt_packets, mqtt5_props),
                    "Will Delay source CONNACK",
                )

            time.sleep(1)
            with broker.connect() as resumed:
                resumed.sendall(
                    mqtt_packets.gen_connect(
                        client_id,
                        proto_ver=5,
                        clean_session=False,
                    )
                )
                expect_packet(
                    resumed,
                    expected_connack(
                        mqtt_packets,
                        mqtt5_props,
                        session_present=True,
                    ),
                    "Will Delay resumed CONNACK",
                )
                # Wait beyond the old Will deadline. PINGRESP must be the next
                # packet, proving reconnect removed rather than deferred it.
                time.sleep(3)
                subscriber.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_pingresp(),
                    "PINGRESP after canceled delayed Will",
                )
                resumed.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def clean_disconnect_will_reconnect(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of Mosquitto issue 1273. A normal DISCONNECT permanently
    # cancels the old Will even when a durable Session is resumed immediately
    # with another CONNECT carrying a fresh Will. PINGRESP ordering proves no
    # stale Will was queued before the replacement's live publication.
    topic = "will/reconnect/test"
    for proto_ver in (4, 5):
        client_id = f"will-1273-{proto_ver}"
        session_expiry = 60 if proto_ver == 5 else -1
        with NetzBroker(executable, connections=3) as broker:
            with broker.connect() as subscriber:
                connect_client(
                    subscriber, mqtt_packets,
                    f"will-1273-subscriber-{proto_ver}", proto_ver,
                )
                subscriber.sendall(mqtt_packets.gen_subscribe(
                    1, topic, 0, proto_ver=proto_ver,
                ))
                expect_packet(
                    subscriber, mqtt_packets.gen_suback(
                        1, 0, proto_ver=proto_ver,
                    ), f"Will reconnect SUBACK v{proto_ver}",
                )
                with broker.connect() as original:
                    original.sendall(mqtt_packets.gen_connect(
                        client_id, clean_session=False, proto_ver=proto_ver,
                        session_expiry=session_expiry, will_topic=topic,
                        will_payload=b"stale will",
                    ))
                    expect_packet(
                        original, expected_connack(
                            mqtt_packets, mqtt5_props,
                        ) if proto_ver == 5 else mqtt_packets.gen_connack(
                            proto_ver=4,
                        ), f"Will reconnect initial CONNACK v{proto_ver}",
                    )
                    original.sendall(mqtt_packets.gen_publish(
                        topic, qos=0, payload="alive-before",
                        proto_ver=proto_ver,
                    ))
                    expect_packet(
                        subscriber, mqtt_packets.gen_publish(
                            topic, qos=0, payload="alive-before",
                            proto_ver=proto_ver,
                        ), f"Will reconnect initial PUBLISH v{proto_ver}",
                    )
                    original.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                    )

                with broker.connect() as resumed:
                    resumed.sendall(mqtt_packets.gen_connect(
                        client_id, clean_session=False, proto_ver=proto_ver,
                        session_expiry=session_expiry, will_topic=topic,
                        will_payload=b"replacement will",
                    ))
                    expect_packet(
                        resumed, expected_connack(
                            mqtt_packets, mqtt5_props, session_present=True,
                        ) if proto_ver == 5 else mqtt_packets.gen_connack(
                            flags=1, proto_ver=4,
                        ), f"Will reconnect resumed CONNACK v{proto_ver}",
                    )
                    resumed.sendall(mqtt_packets.gen_publish(
                        topic, qos=0, payload="alive-after",
                        proto_ver=proto_ver,
                    ))
                    expect_packet(
                        subscriber, mqtt_packets.gen_publish(
                            topic, qos=0, payload="alive-after",
                            proto_ver=proto_ver,
                        ), f"Will reconnect resumed PUBLISH v{proto_ver}",
                    )
                    subscriber.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        subscriber, mqtt_packets.gen_pingresp(),
                        f"no stale Will after reconnect v{proto_ver}",
                    )
                    resumed.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                    )
                if proto_ver == 5:
                    subscriber.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=5)
                    )


def will_delay_session_expiry_minimum(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire coverage for Mosquitto's paired
    # 07-will-delay-session-expiry{,2}.py cases. The Will fires at the earlier
    # of its own delay and Session Expiry, including the immediate-zero edge.
    cases = (
        ("expiry-first", 4, 2, 1.0),
        ("delay-first", 2, 4, 1.0),
        ("zero-expiry", 60, 0, 0.0),
    )
    for label, delay_seconds, expiry_seconds, disconnect_after in cases:
        topic = f"will/session-expiry/{label}"
        source_id = f"will-session-expiry-{label}"
        connect_properties = mqtt5_props.gen_uint32_prop(
            mqtt5_props.SESSION_EXPIRY_INTERVAL, expiry_seconds
        )
        will_properties = mqtt5_props.gen_uint32_prop(
            mqtt5_props.WILL_DELAY_INTERVAL, delay_seconds
        )
        with NetzBroker(executable, connections=2) as broker:
            with broker.connect() as subscriber, broker.connect() as source:
                connect_v5(
                    subscriber, mqtt_packets, f"will-min-subscriber-{label}"
                )
                subscriber.sendall(
                    mqtt_packets.gen_subscribe(
                        1, topic, 0, proto_ver=5
                    )
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(1, 0, proto_ver=5),
                    f"Will minimum {label} SUBACK",
                )
                source.sendall(
                    mqtt_packets.gen_connect(
                        source_id,
                        proto_ver=5,
                        clean_session=False,
                        properties=connect_properties,
                        will_topic=topic,
                        will_payload=b"will delay",
                        will_qos=2,
                        will_properties=will_properties,
                    )
                )
                expect_packet(
                    source,
                    expected_connack(mqtt_packets, mqtt5_props),
                    f"Will minimum {label} source CONNACK",
                )
                if disconnect_after != 0:
                    time.sleep(disconnect_after)
                source.close()

                started = time.monotonic()
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_publish(
                        topic,
                        qos=0,
                        payload="will delay",
                        proto_ver=5,
                    ),
                    f"Will minimum {label} PUBLISH",
                )
                elapsed = time.monotonic() - started
                if expiry_seconds == 0:
                    if elapsed >= 1.0:
                        raise AssertionError(
                            f"zero Session Expiry delayed Will for {elapsed:.3f}s"
                        )
                else:
                    expected_remaining = min(
                        delay_seconds, expiry_seconds
                    ) - disconnect_after
                    if not (expected_remaining - 0.5 <= elapsed <=
                            expected_remaining + 1.5):
                        raise AssertionError(
                            f"Will minimum {label} fired after {elapsed:.3f}s"
                        )
                subscriber.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=5)
                )


def delayed_will_delivery(
    executable: Path, mqtt_packets, mqtt5_props
) -> None:
    # Direct wire port of both branches in Mosquitto 07-will-delay.py. The
    # broker must neither publish before three seconds nor lose the Will for
    # clean and persistent Sessions.
    will_delay = mqtt5_props.gen_uint32_prop(
        mqtt5_props.WILL_DELAY_INTERVAL, 3
    )
    session_expiry = mqtt5_props.gen_uint32_prop(
        mqtt5_props.SESSION_EXPIRY_INTERVAL, 60
    )
    for clean_start in (True, False):
        label = "clean" if clean_start else "persistent"
        topic = f"will/delay/{label}"
        with NetzBroker(executable, connections=2) as broker:
            with broker.connect() as subscriber, broker.connect() as source:
                connect_v5(
                    subscriber, mqtt_packets, f"will-delay-sub-{label}"
                )
                subscriber.sendall(
                    mqtt_packets.gen_subscribe(
                        1, topic, 0, proto_ver=5
                    )
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(1, 0, proto_ver=5),
                    f"delayed Will {label} SUBACK",
                )
                source.sendall(
                    mqtt_packets.gen_connect(
                        f"will-delay-source-{label}",
                        proto_ver=5,
                        clean_session=clean_start,
                        properties=session_expiry,
                        will_topic=topic,
                        will_payload=b"will delay",
                        will_qos=2,
                        will_properties=will_delay,
                    )
                )
                expect_packet(
                    source,
                    expected_connack(mqtt_packets, mqtt5_props),
                    f"delayed Will {label} source CONNACK",
                )
                source.close()

                subscriber.settimeout(2.0)
                try:
                    early = subscriber.recv(1)
                    if early:
                        raise AssertionError(
                            f"delayed Will {label} published early: "
                            + early.hex()
                        )
                except socket.timeout:
                    pass
                finally:
                    subscriber.settimeout(5)

                started = time.monotonic()
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_publish(
                        topic,
                        qos=0,
                        payload="will delay",
                        proto_ver=5,
                    ),
                    f"delayed Will {label} PUBLISH",
                )
                elapsed = time.monotonic() - started
                if elapsed > 2.0:
                    raise AssertionError(
                        f"delayed Will {label} published late: {elapsed:.3f}s"
                    )
                subscriber.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=5)
                )


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


def outgoing_qos_upgrade(executable: Path, mqtt_packets) -> None:
    # Direct wire port of Mosquitto 04-retain-upgrade-outgoing-qos.py. This is
    # deliberately opt-in because upgrading a QoS 0 Application Message to
    # the subscription grant is a Mosquitto extension forbidden by MQTT.
    topic = "retain/qos0/test"
    for proto_ver in (4, 5):
        with NetzBroker(
            executable,
            extra_args=("--upgrade-outgoing-qos",),
        ) as broker:
            with broker.connect() as sock:
                connect_client(
                    sock,
                    mqtt_packets,
                    f"retain-qos-upgrade-v{proto_ver}",
                    proto_ver,
                )
                sock.sendall(
                    mqtt_packets.gen_publish(
                        topic,
                        qos=0,
                        payload="retained message",
                        retain=True,
                        proto_ver=proto_ver,
                    )
                )
                sock.sendall(
                    mqtt_packets.gen_subscribe(
                        16, topic, 1, proto_ver=proto_ver
                    )
                )
                expect_packet(
                    sock,
                    mqtt_packets.gen_suback(16, 1, proto_ver=proto_ver),
                    f"retained QoS upgrade SUBACK v{proto_ver}",
                )
                expect_packet(
                    sock,
                    mqtt_packets.gen_publish(
                        topic,
                        mid=1,
                        qos=1,
                        payload="retained message",
                        retain=True,
                        proto_ver=proto_ver,
                    ),
                    f"retained QoS upgrade PUBLISH v{proto_ver}",
                )
                sock.sendall(mqtt_packets.gen_puback(1, proto_ver=proto_ver))
                sock.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                )

        # The same policy applies to ordinary live fanout, not only retained
        # replay. Keep this as one additional scenario per protocol version.
        with NetzBroker(
            executable,
            connections=2,
            extra_args=("--upgrade-outgoing-qos",),
        ) as broker:
            with broker.connect() as subscriber, broker.connect() as publisher:
                connect_client(
                    subscriber,
                    mqtt_packets,
                    f"live-qos-upgrade-sub-v{proto_ver}",
                    proto_ver,
                )
                subscriber.sendall(
                    mqtt_packets.gen_subscribe(
                        17, topic, 1, proto_ver=proto_ver
                    )
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(17, 1, proto_ver=proto_ver),
                    f"live QoS upgrade SUBACK v{proto_ver}",
                )
                connect_client(
                    publisher,
                    mqtt_packets,
                    f"live-qos-upgrade-pub-v{proto_ver}",
                    proto_ver,
                )
                publisher.sendall(
                    mqtt_packets.gen_publish(
                        topic,
                        qos=0,
                        payload="live message",
                        proto_ver=proto_ver,
                    )
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_publish(
                        topic,
                        mid=1,
                        qos=1,
                        payload="live message",
                        proto_ver=proto_ver,
                    ),
                    f"live QoS upgrade PUBLISH v{proto_ver}",
                )
                subscriber.sendall(
                    mqtt_packets.gen_puback(1, proto_ver=proto_ver)
                )
                publisher.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                )
                subscriber.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                )


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


def qos2_reuse_packet_identifier(executable: Path, mqtt_packets) -> None:
    # Direct wire port of Mosquitto 03-publish-qos2-reuse-mid.py. A second
    # non-DUP PUBLISH is a new transaction even though it reuses an identifier
    # that is waiting for PUBREL, so only the replacement message is released.
    for proto_ver in (4, 5):
        topic = f"qos2/reuse/v{proto_ver}"
        replacement_topic = f"{topic}/replacement"
        with NetzBroker(executable, connections=2) as broker:
            with broker.connect() as subscriber, broker.connect() as publisher:
                connect_client(
                    subscriber,
                    mqtt_packets,
                    f"qos2-reuse-sub-{proto_ver}",
                    proto_ver,
                )
                subscriber.sendall(
                    mqtt_packets.gen_subscribe(
                        1, f"{topic}/#", 2, proto_ver=proto_ver
                    )
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(1, 2, proto_ver=proto_ver),
                    f"QoS2 reuse SUBACK v{proto_ver}",
                )
                connect_client(
                    publisher,
                    mqtt_packets,
                    f"qos2-reuse-pub-{proto_ver}",
                    proto_ver,
                )

                packet_id = 312
                for publish_topic, payload in (
                    (topic, "original"),
                    (replacement_topic, "replacement"),
                ):
                    publisher.sendall(
                        mqtt_packets.gen_publish(
                            publish_topic,
                            qos=2,
                            mid=packet_id,
                            payload=payload,
                            dup=False,
                            proto_ver=proto_ver,
                        )
                    )
                    expect_packet(
                        publisher,
                        mqtt_packets.gen_pubrec(
                            packet_id, proto_ver=proto_ver
                        ),
                        f"QoS2 reuse PUBREC v{proto_ver}/{publish_topic}",
                    )

                publisher.sendall(
                    mqtt_packets.gen_pubrel(packet_id, proto_ver=proto_ver)
                )
                expect_packet(
                    publisher,
                    mqtt_packets.gen_pubcomp(
                        packet_id, proto_ver=proto_ver
                    ),
                    f"QoS2 reuse PUBCOMP v{proto_ver}",
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_publish(
                        replacement_topic, qos=2, mid=1,
                        payload="replacement", proto_ver=proto_ver,
                    ),
                    f"QoS2 replacement delivery v{proto_ver}",
                )
                subscriber.sendall(
                    mqtt_packets.gen_pubrec(1, proto_ver=proto_ver)
                )
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_pubrel(1, proto_ver=proto_ver),
                    f"QoS2 replacement PUBREL v{proto_ver}",
                )
                subscriber.sendall(
                    mqtt_packets.gen_pubcomp(1, proto_ver=proto_ver)
                )
                subscriber.settimeout(0.05)
                try:
                    stale = subscriber.recv(1)
                    if stale:
                        raise AssertionError(
                            "replaced QoS2 message was also delivered: "
                            + stale.hex()
                        )
                except socket.timeout:
                    pass
                finally:
                    subscriber.settimeout(5)
                publisher.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                )
                subscriber.sendall(
                    mqtt_packets.gen_disconnect(proto_ver=proto_ver)
                )


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
    malformed_will_connects(args.broker, mqtt_packets)
    zero_length_will_payload(args.broker, mqtt_packets, mqtt5_props)
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
    clean_session_qos1(args.broker, mqtt_packets, mqtt5_props)
    outgoing_qos1_reconnect_dup(args.broker, mqtt_packets, mqtt5_props)
    offline_qos0_queue_policy(args.broker, mqtt_packets, mqtt5_props)
    offline_queued_payload_bytes(args.broker, mqtt_packets)
    outgoing_inflight_payload_bytes(args.broker, mqtt_packets)
    acknowledgement_length_forms(args.broker, mqtt_packets, mqtt5_props)
    outgoing_qos2_reconnect_stages(args.broker, mqtt_packets, mqtt5_props)
    incoming_qos2_disconnect_recovery(
        args.broker, mqtt_packets, mqtt5_props
    )
    incoming_qos2_reconnect_reuse(args.broker, mqtt_packets, mqtt5_props)
    offline_message_expiry(args.broker, mqtt_packets, mqtt5_props)
    offline_will_message_expiry(args.broker, mqtt_packets, mqtt5_props)
    retained_subscription_handling(args.broker, mqtt_packets, mqtt5_opts)
    outgoing_qos_upgrade(args.broker, mqtt_packets)
    incoming_topic_alias(args.broker, mqtt_packets, mqtt5_props)
    outgoing_topic_alias(args.broker, mqtt_packets, mqtt5_props)
    request_response_properties(args.broker, mqtt_packets, mqtt5_props)
    disconnect_with_will_properties(
        args.broker, mqtt_packets, mqtt5_props
    )
    delayed_will_reconnect_cancels(
        args.broker, mqtt_packets, mqtt5_props
    )
    clean_disconnect_will_reconnect(
        args.broker, mqtt_packets, mqtt5_props
    )
    will_delay_session_expiry_minimum(
        args.broker, mqtt_packets, mqtt5_props
    )
    delayed_will_delivery(args.broker, mqtt_packets, mqtt5_props)
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
    qos2_reuse_packet_identifier(args.broker, mqtt_packets)
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
    duplicate_client_takeover(
        args.broker, mqtt_packets, mqtt5_props, mqtt5_rc
    )
    will_takeover_session_matrix(
        args.broker, mqtt_packets, mqtt5_props, mqtt5_rc
    )
    disconnect_session_expiry(args.broker, mqtt_packets, mqtt5_props)
    print("Mosquitto-derived MQTT wire vectors passed: 94 scenarios")


if __name__ == "__main__":
    main()
