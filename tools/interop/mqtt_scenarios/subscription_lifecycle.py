"""Mosquitto-derived subscription ownership and queued-metadata restart gate."""

from __future__ import annotations

from pathlib import Path
import socket

from mqtt_commit_log_support import (
    ack_packet, connect_client, free_port, mqtt_string, packet,
    publish_packet, read_packet, remaining_length,
)
from mqtt_broker_config_persistence_support import configured_broker, ping


_LOCAL_TOPIC = "subpub/local"
_NO_LOCAL_TOPIC = "subpub/nolocal"
_CLIENT_ID = "persistent-subscription-test"


def _properties(protocol: int, identifier: int) -> bytes:
    if protocol != 5:
        return b""
    fields = b"\x0b" + remaining_length(identifier)
    return remaining_length(len(fields)) + fields


def _subscribe(
    sock: socket.socket, protocol: int, topic: str,
    identifier: int, *, no_local: bool = False,
) -> None:
    sock.sendall(packet(
        0x82,
        b"\x02\x12" + _properties(protocol, identifier)
        + mqtt_string(topic) + bytes((1 | (4 if no_local else 0),)),
    ))
    expected = packet(0x90, b"\x02\x12" + (b"\x00" if protocol == 5 else b"") + b"\x01")
    first, body = read_packet(sock)
    if packet(first, body) != expected:
        raise AssertionError(f"MQTT {protocol} SUBACK {topic}: {first:#x} {body.hex()}")


def _delivery(
    first: int, body: bytes, protocol: int, topic: str,
    payload: bytes, identifier: int,
) -> int:
    if first != 0x32 or len(body) < 4:
        raise AssertionError(f"expected initial QoS 1 delivery, got {first:#x} {body.hex()}")
    identifier_offset = 2 + int.from_bytes(body[:2], "big")
    if len(body) < identifier_offset + 2:
        raise AssertionError("truncated delivery Packet Identifier")
    packet_id = int.from_bytes(body[identifier_offset:identifier_offset + 2], "big")
    if packet_id == 0:
        raise AssertionError("zero delivery Packet Identifier")
    expected = mqtt_string(topic) + packet_id.to_bytes(2, "big") + _properties(protocol, identifier) + payload
    if body != expected:
        raise AssertionError(f"MQTT {protocol} delivery {topic}: expected {expected.hex()}, got {body.hex()}")
    return packet_id


def _puback(first: int, body: bytes, packet_id: int, protocol: int, *, matched: bool) -> None:
    accepted = {ack_packet(0x40, packet_id)}
    # MQTT 5 permits success 0x10 when routing has no eligible destination,
    # including No Local. Every other reason, identifier, or property fails.
    if protocol == 5 and not matched:
        accepted.add(packet(0x40, packet_id.to_bytes(2, "big") + b"\x10"))
    if packet(first, body) not in accepted:
        raise AssertionError(f"unexpected PUBACK for {packet_id}: {first:#x} {body.hex()}")


def _self_publish(sock: socket.socket, protocol: int, identifier: int, label: str) -> None:
    sock.sendall(publish_packet(_LOCAL_TOPIC, b"message", 300, protocol=protocol))
    seen_ack = seen_publish = False
    for _ in range(2):
        first, body = read_packet(sock)
        if first == 0x40 and not seen_ack:
            _puback(first, body, 300, protocol, matched=True)
            seen_ack = True
        elif not seen_publish:
            packet_id = _delivery(first, body, protocol, _LOCAL_TOPIC, b"message", identifier)
            sock.sendall(ack_packet(0x40, packet_id))
            seen_publish = True
        else:
            raise AssertionError(f"{label}: duplicate response {first:#x} {body.hex()}")
    if not seen_ack or not seen_publish:
        raise AssertionError(f"{label}: missing PUBACK or self-delivery")
    ping(sock, f"{label}: one self-delivery and committed PUBACK")
    if protocol == 5:
        sock.sendall(publish_packet(_NO_LOCAL_TOPIC, b"message", 301, protocol=protocol))
        _puback(*read_packet(sock), 301, protocol, matched=False)
        ping(sock, f"{label}: No Local excludes self-delivery")


def _disconnect(sock: socket.socket) -> None:
    try:
        sock.sendall(packet(0xE0, b""))
        sock.shutdown(socket.SHUT_WR)
        # Observe transport close before publishing to the now-offline Session.
        # This keeps queued messages provably unsent before the snapshot.
        if sock.recv(1) != b"":
            raise AssertionError("unexpected delivery after DISCONNECT")
    finally:
        sock.close()


def _connect(port: int, protocol: int, *, present: bool, clean: bool = False, transient: bool = False) -> socket.socket:
    return connect_client(
        port, _CLIENT_ID, clean_start=clean, session_present=present,
        protocol=protocol, session_expiry=0 if transient else 60,
    )


def _helper_publish(port: int, protocol: int, payload: bytes, *, include_no_local: bool, matched_no_local: bool = True) -> None:
    helper = connect_client(port, "helper", clean_start=True, session_present=False, protocol=protocol, session_expiry=0)
    try:
        topics = ((_LOCAL_TOPIC, True),)
        if include_no_local:
            topics += ((_NO_LOCAL_TOPIC, matched_no_local),)
        for packet_id, (topic, matched) in enumerate(topics, 1):
            helper.sendall(publish_packet(topic, payload, packet_id, protocol=protocol))
            _puback(*read_packet(helper), packet_id, protocol, matched=matched)
        ping(helper, "helper publications committed")
        _disconnect(helper)
    finally:
        helper.close()


def _read_delivery(sock: socket.socket, protocol: int, topic: str, payload: bytes, identifier: int) -> None:
    packet_id = _delivery(*read_packet(sock), protocol, topic, payload, identifier)
    sock.sendall(ack_packet(0x40, packet_id))


def _run(broker: Path, directory: Path, protocol: int) -> None:
    port = free_port()
    snapshot = directory / f"subscription-lifecycle-v{protocol}.db"
    config = directory / f"subscription-lifecycle-v{protocol}.conf"

    def start(count: int, generation: int):
        config.write_text(
            "persistence true\n"
            f"persistence_location {directory}\npersistence_file {snapshot.name}\n"
            "autosave_interval 0\n"
            f"listener {port} 127.0.0.1\nlistener_allow_anonymous true\nmax_connections {count}\n"
        )
        return configured_broker(broker, config, count, f"MQTT {protocol} subscription generation {generation}")

    with start(2, 1):
        subscriber = _connect(port, protocol, present=False)
        try:
            _subscribe(subscriber, protocol, _LOCAL_TOPIC, 53)
            if protocol == 5:
                _subscribe(subscriber, protocol, _NO_LOCAL_TOPIC, 54, no_local=True)
            _self_publish(subscriber, protocol, 53, "initial subscription")
            _disconnect(subscriber)
            _helper_publish(port, protocol, b"queued message", include_no_local=protocol == 5)
        finally:
            subscriber.close()
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError("subscription/queued-message snapshot was not written")

    with start(4, 2):
        subscriber = _connect(port, protocol, present=True)
        try:
            # No new SUBSCRIBE: both the queued message's identifier and the
            # subscription's independent routing metadata must survive restart.
            _read_delivery(subscriber, protocol, _LOCAL_TOPIC, b"queued message", 53)
            if protocol == 5:
                _read_delivery(subscriber, protocol, _NO_LOCAL_TOPIC, b"queued message", 54)
            ping(subscriber, "restored queue has no duplicate delivery")
            _self_publish(subscriber, protocol, 53, "restored subscription")
            _disconnect(subscriber)
        finally:
            subscriber.close()
        transient = _connect(port, protocol, present=False, clean=True, transient=True)
        try:
            _subscribe(transient, protocol, _LOCAL_TOPIC, 130)
            _disconnect(transient)
        finally:
            transient.close()
        fresh = _connect(port, protocol, present=False)
        try:
            _subscribe(fresh, protocol, _LOCAL_TOPIC, 131)
            _helper_publish(port, protocol, b"after flipflop", include_no_local=False)
            _read_delivery(fresh, protocol, _LOCAL_TOPIC, b"after flipflop", 131)
            ping(fresh, "persistent/transient/persistent has one subscription owner")
            _disconnect(fresh)
        finally:
            fresh.close()

    with start(2, 3):
        subscriber = _connect(port, protocol, present=True)
        try:
            _helper_publish(port, protocol, b"final message", include_no_local=protocol == 5, matched_no_local=False)
            _read_delivery(subscriber, protocol, _LOCAL_TOPIC, b"final message", 131)
            ping(subscriber, "new subscription persisted; old No Local subscription was removed")
            _disconnect(subscriber)
        finally:
            subscriber.close()


def run_subscription_lifecycle_case(broker: Path, directory: Path) -> None:
    """Port self-delivery, No Local, queued identifier and Clean Start sources."""
    for protocol in (4, 5):
        _run(broker, directory, protocol)
