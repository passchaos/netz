"""Mosquitto-derived outgoing QoS 2 snapshot state-machine scenarios."""

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
    packet,
    publish_packet,
    subscribe_packet,
)


_TOPIC = "persist/outgoing-qos2/value"
_PAYLOAD = b"outgoing QoS 2 snapshot state"
_DELIVERY_PACKET_ID = 1


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
        "listener_allow_anonymous true\n"
        "max_inflight_messages 1\n"
        "max_queued_messages 4\n"
        f"max_connections {connection_count}\n"
    )


def _connect_subscriber(
    port: int,
    protocol: int,
    session_present: bool,
) -> socket.socket:
    return connect_client(
        port,
        f"persist-outgoing-qos2-v{protocol}",
        clean_start=False,
        session_present=session_present,
        protocol=protocol,
        session_expiry=60,
    )


def _subscribe(subscriber: socket.socket, protocol: int) -> None:
    subscriber.sendall(subscribe_packet(
        1,
        _TOPIC,
        subscription_identifier=None,
        qos=2,
        protocol=protocol,
    ))
    expect_packet(
        subscriber,
        packet(
            0x90,
            b"\x00\x01" + (b"\x00" if protocol == 5 else b"")
            + b"\x02",
        ),
        f"MQTT {protocol} outgoing QoS 2 SUBACK",
    )


def _queue_qos2(port: int, protocol: int) -> None:
    publisher = connect_client(
        port,
        f"persist-outgoing-qos2-publisher-v{protocol}",
        clean_start=True,
        session_present=False,
        protocol=protocol,
        session_expiry=0,
    )
    try:
        publisher.sendall(publish_packet(
            _TOPIC,
            _PAYLOAD,
            18,
            qos=2,
            protocol=protocol,
        ))
        expect_packet(
            publisher,
            ack_packet(0x50, 18),
            f"MQTT {protocol} source PUBREC",
        )
        publisher.sendall(ack_packet(0x62, 18))
        expect_packet(
            publisher,
            ack_packet(0x70, 18),
            f"MQTT {protocol} source PUBCOMP",
        )
        ping(publisher, f"MQTT {protocol} source queue barrier")
        disconnect(publisher)
    finally:
        publisher.close()


def _expect_publish(
    subscriber: socket.socket,
    protocol: int,
    dup: bool,
) -> None:
    expect_packet(
        subscriber,
        publish_packet(
            _TOPIC,
            _PAYLOAD,
            _DELIVERY_PACKET_ID,
            qos=2,
            dup=dup,
            protocol=protocol,
        ),
        f"MQTT {protocol} outgoing QoS 2 PUBLISH dup={dup}",
    )


def _run_outgoing_qos2_snapshot_case(
    broker: Path,
    directory: Path,
    protocol: int,
) -> None:
    port = free_port()
    snapshot = directory / f"outgoing-qos2-v{protocol}.db"
    config = directory / f"outgoing-qos2-v{protocol}.conf"

    _write_config(config, directory, snapshot, port, 2)
    with configured_broker(
        broker,
        config,
        2,
        f"initial MQTT {protocol} outgoing QoS 2 broker",
    ):
        subscriber = _connect_subscriber(port, protocol, False)
        try:
            _subscribe(subscriber, protocol)
            disconnect(subscriber)
        finally:
            subscriber.close()
        _queue_qos2(port, protocol)
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError(
            f"MQTT {protocol} outgoing QoS 2 snapshot was not written"
        )

    _write_config(config, directory, snapshot, port, 2)
    with configured_broker(
        broker,
        config,
        2,
        f"MQTT {protocol} outgoing QoS 2 DUP broker",
    ):
        subscriber = _connect_subscriber(port, protocol, True)
        try:
            _expect_publish(subscriber, protocol, False)
        finally:
            subscriber.close()
        subscriber = _connect_subscriber(port, protocol, True)
        try:
            _expect_publish(subscriber, protocol, True)
        finally:
            subscriber.close()

    _write_config(config, directory, snapshot, port, 1)
    with configured_broker(
        broker,
        config,
        1,
        f"MQTT {protocol} outgoing QoS 2 PUBREC broker",
    ):
        subscriber = _connect_subscriber(port, protocol, True)
        try:
            _expect_publish(subscriber, protocol, True)
            subscriber.sendall(ack_packet(0x50, _DELIVERY_PACKET_ID))
            expect_packet(
                subscriber,
                ack_packet(0x62, _DELIVERY_PACKET_ID),
                f"MQTT {protocol} outgoing QoS 2 PUBREL",
            )
        finally:
            subscriber.close()

    _write_config(config, directory, snapshot, port, 1)
    with configured_broker(
        broker,
        config,
        1,
        f"MQTT {protocol} outgoing QoS 2 PUBCOMP broker",
    ):
        subscriber = _connect_subscriber(port, protocol, True)
        try:
            expect_packet(
                subscriber,
                ack_packet(0x62, _DELIVERY_PACKET_ID),
                f"MQTT {protocol} restored outgoing QoS 2 PUBREL",
            )
            subscriber.sendall(ack_packet(0x70, _DELIVERY_PACKET_ID))
            ping(subscriber, f"MQTT {protocol} outgoing QoS 2 completion")
            disconnect(subscriber)
        finally:
            subscriber.close()

    _write_config(config, directory, snapshot, port, 1)
    with configured_broker(
        broker,
        config,
        1,
        f"final MQTT {protocol} outgoing QoS 2 broker",
    ):
        subscriber = _connect_subscriber(port, protocol, True)
        try:
            ping(subscriber, f"MQTT {protocol} completed QoS 2 did not revive")
            disconnect(subscriber)
        finally:
            subscriber.close()


def run_outgoing_qos2_snapshot_case(
    broker: Path,
    directory: Path,
) -> None:
    """Persist PUBLISH/DUP/PUBREL/PUBCOMP across broker generations."""
    for protocol in (4, 5):
        _run_outgoing_qos2_snapshot_case(broker, directory, protocol)
