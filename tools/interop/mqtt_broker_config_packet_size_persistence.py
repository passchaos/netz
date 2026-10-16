"""MQTT 5 connection-scoped Maximum Packet Size across snapshots."""

from __future__ import annotations

from pathlib import Path
import socket

from mqtt_broker_config_persistence_support import (
    configured_broker,
    disconnect,
    expect_packet,
    ping,
)
from mqtt_commit_log_support import (
    ack_packet,
    connect_client,
    free_port,
    publish_packet,
    subscribe_packet,
)


_SMALL_MAXIMUM = 40
_LARGE_MAXIMUM = 256
_TOPIC = "persist/packet-size/value"
_PAYLOAD_A = b"A" * 32
_PAYLOAD_B = b"B" * 32


def _write_config(
    config: Path,
    directory: Path,
    snapshot: Path,
    port: int,
    connection_count: int,
) -> None:
    config.write_text(
        "persistence true\n"
        f"persistence_location {directory}\n"
        f"persistence_file {snapshot.name}\n"
        "autosave_interval 0\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_queued_messages 4\n"
        f"max_connections {connection_count}\n"
    )


def _connect_subscriber(
    port: int,
    maximum_packet_size: int,
    session_present: bool,
) -> socket.socket:
    return connect_client(
        port,
        "persist-packet-size-subscriber",
        clean_start=False,
        session_present=session_present,
        protocol=5,
        session_expiry=60,
        maximum_packet_size=maximum_packet_size,
    )


def _subscribe(subscriber: socket.socket) -> None:
    subscriber.sendall(subscribe_packet(
        1,
        _TOPIC,
        subscription_identifier=None,
        qos=1,
        protocol=5,
    ))
    expect_packet(
        subscriber,
        bytes.fromhex("90 04 0001 00 01"),
        "packet-size persistent SUBACK",
    )


def _queue_message(
    port: int,
    packet_id: int,
    payload: bytes,
) -> None:
    publisher = connect_client(
        port,
        f"persist-packet-size-publisher-{packet_id}",
        clean_start=True,
        session_present=False,
        protocol=5,
        session_expiry=0,
    )
    try:
        publisher.sendall(publish_packet(
            _TOPIC,
            payload,
            packet_id,
            qos=1,
            protocol=5,
        ))
        expect_packet(
            publisher,
            ack_packet(0x40, packet_id),
            f"packet-size publisher PUBACK {packet_id}",
        )
        ping(publisher, f"packet-size publisher barrier {packet_id}")
        disconnect(publisher)
    finally:
        publisher.close()


def run_packet_size_connection_scope_case(
    broker: Path,
    directory: Path,
) -> None:
    """Apply Maximum Packet Size from each reconnect, never the snapshot."""
    oversized_a = publish_packet(
        _TOPIC,
        _PAYLOAD_A,
        1,
        qos=1,
        protocol=5,
    )
    if len(oversized_a) <= _SMALL_MAXIMUM:
        raise AssertionError("packet-size fixture does not exceed small limit")

    port = free_port()
    snapshot = directory / "packet-size-connection-scope.db"
    config = directory / "packet-size-connection-scope.conf"

    _write_config(config, directory, snapshot, port, 2)
    with configured_broker(
        broker,
        config,
        2,
        "initial packet-size persistence broker",
    ):
        subscriber = _connect_subscriber(port, _SMALL_MAXIMUM, False)
        try:
            _subscribe(subscriber)
            disconnect(subscriber)
        finally:
            subscriber.close()
        _queue_message(port, 10, _PAYLOAD_A)
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError("packet-size snapshot was not written")

    _write_config(config, directory, snapshot, port, 2)
    with configured_broker(
        broker,
        config,
        2,
        "large-limit packet-size restore broker",
    ):
        subscriber = _connect_subscriber(port, _LARGE_MAXIMUM, True)
        try:
            expect_packet(
                subscriber,
                oversized_a,
                "queued PUBLISH under replacement large limit",
            )
            subscriber.sendall(ack_packet(0x40, 1))
            ping(subscriber, "large-limit completion barrier")
            disconnect(subscriber)
        finally:
            subscriber.close()
        _queue_message(port, 11, _PAYLOAD_B)

    _write_config(config, directory, snapshot, port, 1)
    with configured_broker(
        broker,
        config,
        1,
        "small-limit packet-size restore broker",
    ):
        subscriber = _connect_subscriber(port, _SMALL_MAXIMUM, True)
        try:
            ping(subscriber, "small-limit oversized discard")
            disconnect(subscriber)
        finally:
            subscriber.close()

    _write_config(config, directory, snapshot, port, 1)
    with configured_broker(
        broker,
        config,
        1,
        "final packet-size persistence broker",
    ):
        subscriber = _connect_subscriber(port, _LARGE_MAXIMUM, True)
        try:
            ping(subscriber, "persisted oversized discard")
            disconnect(subscriber)
        finally:
            subscriber.close()
