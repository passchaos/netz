"""Independent MQTT-3.3.4-4 wire and journal oracle for equal identifiers."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mqtt_vectors.broker import NetzBroker, free_port
from mqtt_commit_log_support import connect_packet, packet, read_varint, recv_exact

TOPIC = b"a/x"
SUBSCRIBE = bytes.fromhex(
    "82 17 00 01 02 0b 07 "
    "00 03 61 2f 23 01 00 03 61 2f 2b 01 00 03 61 2f 78 01"
)
SUBACK_BODY = bytes.fromhex("00 01 00 01 01 01")
PINGREQ = bytes.fromhex("c0 00")
DISCONNECT = bytes.fromhex("e0 00")
SCENARIO_COUNT = 5
LIVE_CASES = ((False, 0), (False, 1), (True, 0), (True, 1))
MAX_PACKET_BYTES = 4096


@dataclass(frozen=True)
class Delivery:
    qos: int
    packet_id: int | None
    duplicate: bool
    identifiers: tuple[int, ...]
    payload: bytes


def read_packet(sock: socket.socket) -> tuple[int, bytes]:
    first = recv_exact(sock, 1)[0]
    remaining = 0
    multiplier = 1
    for _ in range(4):
        value = recv_exact(sock, 1)[0]
        remaining += (value & 0x7F) * multiplier
        if not value & 0x80:
            if remaining > MAX_PACKET_BYTES:
                raise AssertionError("equal-ID peer packet exceeds fixture bound")
            return first, recv_exact(sock, remaining)
        multiplier *= 128
    raise AssertionError("malformed MQTT Remaining Length")


def expect(sock: socket.socket, first: int, body: bytes, label: str) -> None:
    actual = read_packet(sock)
    if actual != (first, body):
        raise AssertionError(
            f"{label}: expected {first:02x}/{body.hex()}, "
            f"got {actual[0]:02x}/{actual[1].hex()}"
        )


def connect(sock: socket.socket, client_id: str, *, persistent: bool,
            present: bool = False) -> None:
    sock.sendall(connect_packet(
        client_id, clean_start=not persistent,
        session_expiry=120 if persistent else 0,
    ))
    first, body = read_packet(sock)
    if first != 0x20 or len(body) < 3 or body[:2] != bytes((int(present), 0)):
        raise AssertionError(f"unexpected equal-ID CONNACK: {first:02x}/{body.hex()}")
    length, start = read_varint(body, 2)
    if start + length != len(body):
        raise AssertionError("invalid equal-ID CONNACK property boundary")


def publish_bytes(qos: int, payload: bytes) -> bytes:
    if qos not in (0, 1):
        raise ValueError("equal-ID fixture supports QoS0/1")
    body = b"\x00\x03a/x" + (b"\x00\x13" if qos else b"") + b"\x00" + payload
    return packet(0x30 | (qos << 1), body)


def decode_publish(first: int, body: bytes) -> Delivery:
    if first & 0xF0 != 0x30 or first & 1:
        raise AssertionError(f"unexpected equal-ID delivery flags: {first:02x}")
    qos = (first >> 1) & 3
    if qos not in (0, 1) or len(body) < 2:
        raise AssertionError("invalid equal-ID delivery QoS/header")
    topic_len = int.from_bytes(body[:2], "big")
    offset = 2 + topic_len
    if offset > len(body) or body[2:offset] != TOPIC:
        raise AssertionError("equal-ID delivery Topic Name changed")
    packet_id = None
    if qos:
        if offset + 2 > len(body):
            raise AssertionError("truncated equal-ID Packet Identifier")
        packet_id = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if not packet_id:
            raise AssertionError("zero equal-ID Packet Identifier")
    property_len, offset = read_varint(body, offset)
    end = offset + property_len
    if end > len(body):
        raise AssertionError("truncated equal-ID properties")
    identifiers = []
    while offset < end:
        property_id, offset = read_varint(body, offset)
        if property_id != 0x0B:
            raise AssertionError(f"unexpected equal-ID PUBLISH property {property_id}")
        identifier, offset = read_varint(body, offset)
        if identifier == 0 or offset > end:
            raise AssertionError("invalid equal-ID Subscription Identifier")
        # Preserve occurrences: using a set here would hide the target bug.
        identifiers.append(identifier)
    return Delivery(qos, packet_id, bool(first & 8), tuple(identifiers), body[end:])


def validate_copies(deliveries: list[Delivery], *, qos: int,
                    payload: bytes, duplicate: bool = False) -> None:
    if len(deliveries) not in (1, 3):
        raise AssertionError(f"expected one coalesced or three per-filter copies, got {len(deliveries)}")
    wanted = (7, 7, 7) if len(deliveries) == 1 else (7,)
    for delivery in deliveries:
        if (delivery.qos, delivery.payload, delivery.duplicate, delivery.identifiers) != (
            qos, payload, duplicate, wanted
        ):
            raise AssertionError(f"equal-ID occurrence/payload mismatch: {delivery!r}, wanted IDs {wanted}")
    packet_ids = [delivery.packet_id for delivery in deliveries if qos]
    if len(packet_ids) != len(set(packet_ids)):
        raise AssertionError("separate QoS1 copies reused a live Packet Identifier")


def collect(sock: socket.socket, *, acknowledge: bool) -> list[Delivery]:
    sock.sendall(PINGREQ)
    deliveries = []
    while True:
        first, body = read_packet(sock)
        if (first, body) == (0xD0, b""):
            return deliveries
        delivery = decode_publish(first, body)
        deliveries.append(delivery)
        if len(deliveries) > 3:
            raise AssertionError("unexpected extra equal-ID delivery")
        if acknowledge and delivery.qos:
            sock.sendall(packet(0x40, delivery.packet_id.to_bytes(2, "big")))


def quiet_ping(sock: socket.socket) -> None:
    sock.sendall(PINGREQ)
    expect(sock, 0xD0, b"", "equal-ID empty delivery barrier")


def disconnect(sock: socket.socket) -> None:
    sock.sendall(DISCONNECT)
    if sock.recv(1) != b"":
        raise AssertionError("equal-ID peer sent bytes after DISCONNECT")


def live(executable: Path, broker_type=NetzBroker) -> list[dict]:
    results = []
    for persistent, qos in LIVE_CASES:
        with broker_type(executable, connections=2) as broker:
            with broker.connect() as subscriber, broker.connect() as publisher:
                connect(subscriber, "equal-live-subscriber", persistent=persistent)
                connect(publisher, "equal-live-publisher", persistent=False)
                subscriber.sendall(SUBSCRIBE)
                expect(subscriber, 0x90, SUBACK_BODY, "equal-ID three-filter SUBACK")
                publisher.sendall(publish_bytes(qos, b"live"))
                if qos:
                    expect(publisher, 0x40, b"\x00\x13", "equal-ID publisher PUBACK")
                # QoS0 has no acknowledgement. This source-side barrier proves
                # the publication was routed before the subscriber's barrier.
                quiet_ping(publisher)
                deliveries = collect(subscriber, acknowledge=True)
                validate_copies(deliveries, qos=qos, payload=b"live")
                quiet_ping(subscriber)
                results.append({"persistent": persistent, "qos": qos,
                                "packets": len(deliveries),
                                "identifiers": [list(item.identifiers) for item in deliveries]})
                disconnect(subscriber)
                disconnect(publisher)
    return results


def journal(executable: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="netz-equal-id-journal-") as directory:
        path = Path(directory) / "broker.log"
        extra = (f"--commit-log={path}",)
        # Journal mode always restores an existing generation or atomically
        # creates the initial one; the runner rejects --no-restore with it.
        with NetzBroker(executable, connections=2, restore=True, extra_args=extra) as broker:
            with broker.connect() as subscriber:
                connect(subscriber, "equal-journal-subscriber", persistent=True)
                subscriber.sendall(SUBSCRIBE)
                expect(subscriber, 0x90, SUBACK_BODY, "equal-ID journal SUBACK")
                disconnect(subscriber)
            with broker.connect() as publisher:
                connect(publisher, "equal-journal-publisher", persistent=False)
                publisher.sendall(publish_bytes(1, b"queued"))
                expect(publisher, 0x40, b"\x00\x13", "equal-ID durable queue PUBACK")
                broker.crash()
        with NetzBroker(executable, connections=1, restore=True, extra_args=extra) as broker:
            with broker.connect() as subscriber:
                connect(subscriber, "equal-journal-subscriber", persistent=True, present=True)
                original = collect(subscriber, acknowledge=False)
                validate_copies(original, qos=1, payload=b"queued")
                broker.crash()
        with NetzBroker(executable, connections=1, restore=True, extra_args=extra) as broker:
            with broker.connect() as subscriber:
                connect(subscriber, "equal-journal-subscriber", persistent=True, present=True)
                replay = collect(subscriber, acknowledge=False)
                validate_copies(replay, qos=1, payload=b"queued", duplicate=True)
                if [(item.packet_id, item.identifiers) for item in replay] != [
                    (item.packet_id, item.identifiers) for item in original
                ]:
                    raise AssertionError("equal-ID DUP replay changed packet ownership/occurrences")
                for item in replay:
                    subscriber.sendall(packet(0x40, item.packet_id.to_bytes(2, "big")))
                quiet_ping(subscriber)
                broker.crash()
        with NetzBroker(executable, connections=1, restore=True, extra_args=extra) as broker:
            with broker.connect() as subscriber:
                connect(subscriber, "equal-journal-subscriber", persistent=True, present=True)
                quiet_ping(subscriber)
                disconnect(subscriber)
        return {"generations": 4, "sigkills": 3, "packets": len(original),
                "packet_ids": [item.packet_id for item in original],
                "identifiers": [list(item.identifiers) for item in replay],
                "durable_ack_removal": True}


class MosquittoBroker:
    """Optional prebuilt reference; its valid per-filter copies stay allowed."""
    def __init__(self, executable: Path, connections: int = 2):
        self.executable = executable
        self.port = free_port()

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="equal-id-mosquitto-")
        directory = Path(self.temporary.name)
        config = directory / "broker.conf"
        config.write_text(f"listener {self.port} 127.0.0.1\nallow_anonymous true\npersistence false\n")
        self.output = (directory / "broker.log").open("wb")
        self.process = subprocess.Popen([str(self.executable), "-c", str(config)],
                                        stdout=self.output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.__exit__(RuntimeError, None, None)
                raise RuntimeError("prebuilt reference broker failed to start")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return self
            except OSError:
                time.sleep(0.02)
        self.__exit__(RuntimeError, None, None)
        raise TimeoutError("prebuilt reference broker startup")

    def connect(self) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        sock.settimeout(5)
        return sock

    def __exit__(self, exc_type, exc, traceback):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.output.close()
        self.temporary.cleanup()


def run(executable: Path, *, reference: bool = False) -> dict:
    executable = executable.resolve()
    if not executable.is_file():
        raise RuntimeError(f"prebuilt broker executable not found: {executable}")
    results = live(executable, MosquittoBroker if reference else NetzBroker)
    root = Path(__file__).resolve().parents[1]
    sources = ("mqtt_vectors/equal_subscription_identifiers.py", "mqtt_vectors/broker.py", "mqtt_commit_log_support.py")
    report = {"status": "passed", "fixture": "mqtt5-equal-subscription-identifiers",
              "normative_clause": "MQTT-3.3.4-4", "scenarios": 4 if reference else SCENARIO_COUNT,
              "implementation": "mosquitto" if reference else "netz", "live": results,
              "subscribe_hex": SUBSCRIBE.hex(),
              "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sources},
              "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}
    if not reference:
        report["journal"] = journal(executable)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("broker", type=Path)
    parser.add_argument("--reference-mosquitto", action="store_true",
                        help="run only live normative cases against a prebuilt Mosquitto")
    args = parser.parse_args()
    print(json.dumps(run(args.broker, reference=args.reference_mosquitto), sort_keys=True))


if __name__ == "__main__":
    main()
