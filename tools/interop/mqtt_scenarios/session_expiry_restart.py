"""Source-derived Session expiry with shared queued and retained ownership."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import socket
import time

from mqtt_broker_config_persistence_support import configured_persistent_broker as configured_broker, expect_packet, ping
from mqtt_commit_log_support import (
    ack_packet, connect_client, free_port, mqtt_string, packet,
    publish_packet, read_packet, remaining_length, subscribe_packet,
)
from mqtt_scenarios.session_expiry_sources import MOSQUITTO_SESSION_EXPIRY_SOURCES

SOURCE = next(iter(MOSQUITTO_SESSION_EXPIRY_SOURCES))
TOPIC = "test-session-expiry"
COUNT = 100
INFLIGHT = 5


@dataclass(frozen=True)
class Case:
    name: str
    resubscribe: bool
    sibling_count: int = 0
    retain_count: int = 0
    qos: int = 1
    source: str | None = SOURCE


CASES = (
    Case("queue", False),
    Case("queue-resubscribe", True),
    Case("shared-queue", False, sibling_count=20),
    Case("shared-queue-resubscribe", True, sibling_count=20),
    Case("retained-queue", False, retain_count=30),
    Case("shared-retained-qos2", False, sibling_count=40, retain_count=30, qos=2, source=None),
)


def payload(index: int) -> bytes:
    return f"queued message {index:3}".encode()


def connect(port: int, name: str, *, present: bool, transient: bool = False) -> socket.socket:
    return connect_client(port, name, clean_start=transient, session_present=present, session_expiry=0 if transient else 60)


def disconnect(sock: socket.socket, *, expiry: int | None = None) -> None:
    properties = b"" if expiry is None else b"\x11" + expiry.to_bytes(4, "big")
    sock.sendall(packet(0xE0, b"" if expiry is None else b"\x00" + remaining_length(len(properties)) + properties))
    sock.shutdown(socket.SHUT_WR)
    if sock.recv(1) != b"":
        raise AssertionError("unexpected output after Session-expiry DISCONNECT")


def subscribe(sock: socket.socket, case: Case) -> None:
    sock.sendall(subscribe_packet(1, TOPIC, subscription_identifier=None, qos=case.qos))
    expect_packet(sock, packet(0x90, b"\x00\x01\x00" + bytes((case.qos,))), "Session-expiry SUBACK")


def delivery(first: int, body: bytes, case: Case, index: int, *, retain: bool = False) -> int:
    expected_first = 0x30 | case.qos << 1 | int(retain)
    offset = 2 + len(TOPIC.encode())
    if first != expected_first or len(body) < offset + 3:
        raise AssertionError(f"unexpected delivery envelope: {first:#x} {body.hex()}")
    mid = int.from_bytes(body[offset:offset + 2], "big")
    if mid == 0:
        raise AssertionError("zero delivery Packet Identifier")
    expected = mqtt_string(TOPIC) + mid.to_bytes(2, "big") + b"\x00" + payload(index)
    if body != expected:
        raise AssertionError(f"delivery {index}: expected {expected.hex()}, got {body.hex()}")
    return mid


def consume(sock: socket.socket, case: Case, indices: range, *, retain: bool = False) -> None:
    expected = list(indices)
    cursor = 0
    pending: set[int] = set()
    while cursor < len(expected) or pending:
        first, body = read_packet(sock)
        if first == 0x62 and case.qos == 2:
            if len(body) != 2:
                raise AssertionError("unexpected PUBREL reason or properties")
            mid = int.from_bytes(body, "big")
            if mid not in pending:
                raise AssertionError(f"duplicate or unknown PUBREL {mid}")
            pending.remove(mid)
            sock.sendall(ack_packet(0x70, mid))
            continue
        if cursor == len(expected):
            raise AssertionError(f"extra PUBLISH after expected queue: {first:#x} {body.hex()}")
        mid = delivery(first, body, case, expected[cursor], retain=retain)
        cursor += 1
        if mid in pending:
            raise AssertionError(f"in-use delivery Packet Identifier {mid}")
        if case.qos == 2:
            pending.add(mid)
            sock.sendall(ack_packet(0x50, mid))
        else:
            sock.sendall(ack_packet(0x40, mid))
    ping(sock, "all deliveries completed without an extra packet")


def publish(sock: socket.socket, case: Case, index: int, *, matched: bool = True) -> None:
    mid = 10 + index
    sock.sendall(publish_packet(TOPIC, payload(index), mid, qos=case.qos, retain=index < case.retain_count))
    reason = b"\x10" if case.qos == 1 and not matched else b""
    expect_packet(sock, packet(0x40 if case.qos == 1 else 0x50, mid.to_bytes(2, "big") + reason), f"source acknowledgement {index}")
    if case.qos == 2:
        sock.sendall(ack_packet(0x62, mid))
        expect_packet(sock, ack_packet(0x70, mid), f"source PUBCOMP {index}")


def run_case(broker: Path, directory: Path, case: Case) -> dict:
    directory.mkdir()
    snapshot = directory / "broker.db"
    config = directory / "broker.conf"
    port = free_port()
    stages = 0

    def start(count: int):
        nonlocal stages
        stages += 1
        config.write_text(
            "persistence true\n"
            f"persistence_location {directory}\npersistence_file {snapshot.name}\n"
            "autosave_interval 0\n"
            f"listener {port} 127.0.0.1\nlistener_allow_anonymous true\n"
            f"max_connections {count}\nmax_queued_messages {COUNT}\nmax_inflight_messages {INFLIGHT}\n"
        )
        return configured_broker(broker, config, count, f"Session-expiry {case.name} generation {stages}")

    started = time.monotonic()
    # Preserve the upstream queue count, split point, retained-prefix count and
    # both resubscribe variants. All original queues exist in a real snapshot.
    with start(2 + int(case.sibling_count != 0)):
        with connect(port, "test-expired-session-subscriber", present=False) as short:
            subscribe(short, case)
            disconnect(short)
        with connect(port, "test-expired-session-publisher", present=False, transient=True) as source:
            split = COUNT - case.sibling_count
            for index in range(split):
                publish(source, case, index)
            if case.sibling_count:
                with connect(port, "second-subscriber", present=False) as sibling:
                    subscribe(sibling, case)
                    if case.retain_count:
                        consume(sibling, case, range(case.retain_count - 1, case.retain_count), retain=True)
                    disconnect(sibling)
            for index in range(split, COUNT):
                publish(source, case, index)
            ping(source, "all source publications committed")
            disconnect(source)
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError("Session-expiry snapshot missing")

    # The upstream edits its private DB expiry timestamp. Use MQTT 5's actual
    # DISCONNECT expiry update instead, after verifying five saved deliveries.
    # They stay unacknowledged to cover inflight as well as queued ownership.
    with start(1):
        with connect(port, "test-expired-session-subscriber", present=True) as short:
            seen: set[int] = set()
            for index in range(INFLIGHT):
                mid = delivery(*read_packet(short), case, index)
                if mid in seen:
                    raise AssertionError("duplicate restored inflight Packet Identifier")
                seen.add(mid)
            disconnect(short, expiry=1)
    stopped_at = time.monotonic()
    time.sleep(1.2)
    downtime = time.monotonic() - stopped_at

    # Expired ownership must disappear while shared publications and retained
    # state remain intact. PING before any SUBSCRIBE rejects an old queue.
    with start(1 + int(case.sibling_count != 0) + int(case.retain_count != 0)):
        with connect(port, "test-expired-session-subscriber", present=False) as short:
            ping(short, "expired queue absent before replacement SUBSCRIBE")
            if case.resubscribe:
                subscribe(short, case)
                ping(short, "new subscription has no old queued delivery")
            disconnect(short)
        if case.sibling_count:
            with connect(port, "second-subscriber", present=True) as sibling:
                consume(sibling, case, range(COUNT - case.sibling_count, COUNT))
                disconnect(sibling)
        if case.retain_count:
            with connect(port, "retained-owner-probe", present=False, transient=True) as retained:
                subscribe(retained, case)
                consume(retained, case, range(case.retain_count - 1, case.retain_count), retain=True)
                disconnect(retained)

    # Another save/restore proves Session pruning and completed sibling QoS
    # transactions are durable. New routing checks retained subscription state
    # against the resubscribe decision, then cleans every Session explicitly.
    with start(2 + int(case.sibling_count != 0) + int(case.retain_count != 0)):
        with connect(port, "test-expired-session-subscriber", present=True) as short:
            ping(short, "expired queue deletion persisted")
            with connect(port, "final-routing-source", present=False, transient=True) as source:
                marker = COUNT
                publish(source, case, marker, matched=case.resubscribe or bool(case.sibling_count))
                if case.resubscribe:
                    consume(short, case, range(marker, marker + 1))
                else:
                    ping(short, "expired subscription deletion persisted")
                disconnect(source)
            disconnect(short, expiry=0)
        if case.sibling_count:
            with connect(port, "second-subscriber", present=True) as sibling:
                consume(sibling, case, range(COUNT, COUNT + 1))
                disconnect(sibling, expiry=0)
        if case.retain_count:
            with connect(port, "final-retained-probe", present=False, transient=True) as retained:
                subscribe(retained, case)
                consume(retained, case, range(case.retain_count - 1, case.retain_count), retain=True)
                disconnect(retained)
    return {
        "case": case.name, "source": case.source, "qos": case.qos,
        "published": COUNT, "shared_queue": case.sibling_count,
        "retained_prefix": case.retain_count, "resubscribe": case.resubscribe,
        "unacknowledged_before_expiry": INFLIGHT, "generations": stages,
        "downtime_seconds": round(downtime, 6),
        "elapsed_seconds": round(time.monotonic() - started, 6),
    }


def run_cases(broker: Path, directory: Path) -> list[dict]:
    return [run_case(broker, directory / case.name, case) for case in CASES]
