"""Exact MQTT 5 metadata fanout and snapshot ownership through real peers."""
from __future__ import annotations

from pathlib import Path

from mqtt_broker_config_persistence_support import configured_broker, expect_packet, ping
from mqtt_commit_log_support import (
    ack_packet, connect_client, free_port, mqtt_string, packet,
    remaining_length, subscribe_packet,
)
from mqtt_scenarios.session_expiry_restart import disconnect

TOPIC = "shared/property/value"
PAYLOAD = b"original-payload"
PROPERTIES = (
    b"\x03" + mqtt_string("application/octet-stream")
    + b"\x08" + mqtt_string("response/property/value")
    + b"\x09" + (256).to_bytes(2, "big") + bytes(range(256))
    + b"\x26" + mqtt_string("trace") + mqtt_string("T" * 512)
    + b"\x26" + mqtt_string("trace") + mqtt_string("second-value")
)


def encoded(qos: int, mid: int, identifier: int | None = None, *, source: bool = False) -> bytes:
    properties = PROPERTIES
    if source:
        properties += b"\x23\x00\x01"  # Publisher-scoped Topic Alias.
    if identifier is not None:
        properties += b"\x0b" + remaining_length(identifier)
    return packet(0x30 | qos << 1, mqtt_string(TOPIC) + mid.to_bytes(2, "big") + remaining_length(len(properties)) + properties + PAYLOAD)


def subscribe(peer, qos: int, identifier: int) -> None:
    peer.sendall(subscribe_packet(1, TOPIC, qos=qos, subscription_identifier=identifier))
    expect_packet(peer, packet(0x90, b"\x00\x01\x00" + bytes((qos,))), "shared property SUBACK")


def consume(peer, qos: int, identifier: int) -> None:
    expect_packet(peer, encoded(qos, 1, identifier), f"exact shared properties for subscription {identifier}")
    peer.sendall(ack_packet(0x40 if qos == 1 else 0x50, 1))
    if qos == 2:
        expect_packet(peer, ack_packet(0x62, 1), "shared property PUBREL")
        peer.sendall(ack_packet(0x70, 1))
    ping(peer, "shared property completion without duplicate delivery")


def run_case(broker: Path, directory: Path, qos: int) -> None:
    directory.mkdir()
    config = directory / "broker.conf"
    snapshot = directory / "broker.db"
    port = free_port()

    def start(count: int, generation: int):
        config.write_text(
            "persistence true\n"
            f"persistence_location {directory}\npersistence_file {snapshot.name}\n"
            "autosave_interval 0\n"
            f"listener {port} 127.0.0.1\nlistener_allow_anonymous true\nmax_connections {count}\n"
        )
        return configured_broker(broker, config, count, f"shared properties QoS {qos} generation {generation}")

    with start(3, 1):
        for identifier in (17, 29):
            with connect_client(port, f"metadata-{identifier}", clean_start=False, session_present=False) as peer:
                subscribe(peer, qos, identifier)
                disconnect(peer)
        with connect_client(port, "metadata-source", clean_start=True, session_present=False, session_expiry=0) as peer:
            peer.sendall(encoded(qos, 9, source=True))
            expect_packet(peer, ack_packet(0x40 if qos == 1 else 0x50, 9), "source metadata acknowledgement")
            if qos == 2:
                peer.sendall(ack_packet(0x62, 9))
                expect_packet(peer, ack_packet(0x70, 9), "source metadata PUBCOMP")
            ping(peer, "original source packet storage released")
            disconnect(peer)
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError("shared property snapshot missing")
    with start(2, 2):
        for identifier in (17, 29):
            with connect_client(port, f"metadata-{identifier}", clean_start=False, session_present=True) as peer:
                consume(peer, qos, identifier)
                disconnect(peer, expiry=0)
    with start(2, 3):
        for identifier in (17, 29):
            with connect_client(port, f"metadata-{identifier}", clean_start=False, session_present=False) as peer:
                ping(peer, "completed shared properties cannot revive")
                disconnect(peer, expiry=0)


def run(broker: Path, directory: Path) -> None:
    for qos in (1, 2):
        run_case(broker, directory / f"shared-properties-qos{qos}", qos)
