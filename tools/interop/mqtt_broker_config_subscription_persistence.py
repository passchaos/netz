"""Mosquitto-derived durable subscription snapshot/restart scenarios."""

from __future__ import annotations

from pathlib import Path
import socket

from mqtt_commit_log_support import (
    ack_packet,
    connect_client,
    free_port,
    mqtt_string,
    packet,
    publish_packet,
    qos0_publish_packet,
    read_packet,
    read_varint,
    subscribe_packet,
)
from mqtt_broker_config_persistence_support import (
    configured_persistent_broker as configured_broker,
    disconnect,
    expect_packet,
    ping,
)


_PAYLOAD = b"message"


def _connect(
    port: int,
    client_id: str,
    protocol: int,
    session_present: bool,
) -> socket.socket:
    return connect_client(
        port,
        client_id,
        clean_start=False,
        session_present=session_present,
        protocol=protocol,
        session_expiry=60,
    )


def _subscribe(
    sock: socket.socket,
    protocol: int,
    topic: str,
    qos: int,
    subscription_identifier: int,
) -> None:
    sock.sendall(subscribe_packet(
        1,
        topic,
        subscription_identifier=(
            subscription_identifier if protocol == 5 else None
        ),
        qos=qos,
        protocol=protocol,
    ))
    expect_packet(
        sock,
        packet(
            0x90,
            b"\x00\x01" + (b"\x00" if protocol == 5 else b"")
            + bytes((qos,)),
        ),
        f"MQTT {protocol} persistent subscription SUBACK qos={qos}",
    )


def _publish_ack(
    packet_type: int,
    packet_id: int,
    protocol: int,
    matched: bool,
) -> bytes:
    if protocol != 5 or matched or packet_type != 0x40:
        return ack_packet(packet_type, packet_id)
    return packet(
        packet_type,
        packet_id.to_bytes(2, "big") + b"\x10",
    )


def _publish_all(
    port: int,
    protocol: int,
    topics: tuple[str, str, str],
    qos2_matched: bool,
) -> None:
    publisher = connect_client(
        port,
        f"persist-subscription-helper-v{protocol}",
        clean_start=True,
        session_present=False,
        protocol=protocol,
        session_expiry=0,
    )
    try:
        publisher.sendall(qos0_publish_packet(
            topics[0],
            _PAYLOAD,
            retain=False,
            protocol=protocol,
        ))
        publisher.sendall(publish_packet(
            topics[1],
            _PAYLOAD,
            1,
            qos=1,
            protocol=protocol,
        ))
        expect_packet(
            publisher,
            _publish_ack(0x40, 1, protocol, True),
            f"MQTT {protocol} subscription publisher PUBACK",
        )
        publisher.sendall(publish_packet(
            topics[2],
            _PAYLOAD,
            2,
            qos=2,
            protocol=protocol,
        ))
        expect_packet(
            publisher,
            _publish_ack(0x50, 2, protocol, qos2_matched),
            f"MQTT {protocol} subscription publisher PUBREC",
        )
        publisher.sendall(ack_packet(0x62, 2))
        expect_packet(
            publisher,
            ack_packet(0x70, 2),
            f"MQTT {protocol} subscription publisher PUBCOMP",
        )
        if not qos2_matched:
            publisher.sendall(publish_packet(
                topics[2],
                b"removed-subscription-probe",
                3,
                qos=1,
                protocol=protocol,
            ))
            expect_packet(
                publisher,
                _publish_ack(0x40, 3, protocol, False),
                f"MQTT {protocol} removed subscription PUBACK",
            )
        ping(publisher, f"MQTT {protocol} subscription publisher barrier")
        disconnect(publisher)
    finally:
        publisher.close()


def _expect_delivery(
    subscriber: socket.socket,
    protocol: int,
    topic: str,
    qos: int,
    subscription_identifier: int,
) -> int | None:
    first, body = read_packet(subscriber)
    expected_first = 0x30 | (qos << 1)
    if first != expected_first:
        raise AssertionError(
            f"MQTT {protocol} QoS {qos} delivery flags: "
            f"expected {expected_first:#x}, got {first:#x}"
        )
    if len(body) < 2:
        raise AssertionError(f"MQTT {protocol} truncated delivery")
    topic_length = int.from_bytes(body[0:2], "big")
    topic_end = 2 + topic_length
    if body[2:topic_end] != topic.encode():
        raise AssertionError(
            f"MQTT {protocol} delivery topic mismatch: {body.hex()}"
        )
    offset = topic_end
    packet_id = None
    if qos:
        if len(body) < offset + 2:
            raise AssertionError(
                f"MQTT {protocol} missing delivery Packet Identifier"
            )
        packet_id = int.from_bytes(body[offset : offset + 2], "big")
        if packet_id == 0:
            raise AssertionError(
                f"MQTT {protocol} zero delivery Packet Identifier"
            )
        offset += 2
    if protocol == 5:
        properties_length, property_start = read_varint(body, offset)
        property_end = property_start + properties_length
        properties = body[property_start:property_end]
        expected_properties = bytes((0x0B, subscription_identifier))
        if properties != expected_properties:
            raise AssertionError(
                f"MQTT 5 subscription identifier mismatch: {body.hex()}"
            )
        offset = property_end
    if body[offset:] != _PAYLOAD:
        raise AssertionError(
            f"MQTT {protocol} delivery payload mismatch: {body.hex()}"
        )
    return packet_id


def _complete_delivery(
    subscriber: socket.socket,
    protocol: int,
    topic: str,
    qos: int,
    subscription_identifier: int,
) -> None:
    packet_id = _expect_delivery(
        subscriber,
        protocol,
        topic,
        qos,
        subscription_identifier,
    )
    if qos == 1:
        assert packet_id is not None
        subscriber.sendall(ack_packet(0x40, packet_id))
    elif qos == 2:
        assert packet_id is not None
        subscriber.sendall(ack_packet(0x50, packet_id))
        expect_packet(
            subscriber,
            ack_packet(0x62, packet_id),
            f"MQTT {protocol} persistent subscription PUBREL",
        )
        subscriber.sendall(ack_packet(0x70, packet_id))


def _unsubscribe(
    subscriber: socket.socket,
    protocol: int,
    packet_id: int,
    topic: str,
) -> None:
    subscriber.sendall(packet(
        0xA2,
        packet_id.to_bytes(2, "big")
        + (b"\x00" if protocol == 5 else b"")
        + mqtt_string(topic),
    ))
    expected_body = packet_id.to_bytes(2, "big")
    if protocol == 5:
        expected_body += b"\x00\x00"
    expect_packet(
        subscriber,
        packet(0xB0, expected_body),
        f"MQTT {protocol} persistent subscription UNSUBACK",
    )


def _run_persistent_subscription_case(
    broker: Path,
    directory: Path,
    protocol: int,
) -> None:
    port = free_port()
    snapshot = directory / f"persistent-subscription-v{protocol}.db"
    config = directory / f"persistent-subscription-v{protocol}.conf"

    def write_config(connection_count: int) -> None:
        config.write_text(
            "persistence true\n"
            f"persistence_location {directory}\n"
            f"persistence_file {snapshot.name}\n"
            "autosave_interval 0\n"
            f"listener {port} 127.0.0.1\n"
            "listener_allow_anonymous true\n"
            f"max_connections {connection_count}\n"
        )

    client_id = f"persist-subscription-v{protocol}"
    topics = (
        f"persist/subscription/v{protocol}/0",
        f"persist/subscription/v{protocol}/1",
        f"persist/subscription/v{protocol}/2",
    )
    identifiers = (100, 101, 102)

    write_config(1)
    with configured_broker(
        broker,
        config,
        1,
        f"initial MQTT {protocol} subscription broker",
    ):
        subscriber = _connect(
            port,
            client_id,
            protocol,
            False,
        )
        try:
            for qos, (topic, identifier) in enumerate(
                zip(topics, identifiers)
            ):
                _subscribe(
                    subscriber,
                    protocol,
                    topic,
                    qos,
                    identifier,
                )
            disconnect(subscriber)
        finally:
            subscriber.close()
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError(
            f"MQTT {protocol} subscription snapshot was not written"
        )

    write_config(2)
    with configured_broker(
        broker,
        config,
        2,
        f"restored MQTT {protocol} subscription broker",
    ):
        subscriber = _connect(
            port,
            client_id,
            protocol,
            True,
        )
        try:
            ping(subscriber, f"MQTT {protocol} restored subscription Session")
            _publish_all(port, protocol, topics, True)
            for qos, (topic, identifier) in enumerate(
                zip(topics, identifiers)
            ):
                _complete_delivery(
                    subscriber,
                    protocol,
                    topic,
                    qos,
                    identifier,
                )
            _unsubscribe(subscriber, protocol, 7, topics[2])
            ping(subscriber, f"MQTT {protocol} unsubscribe snapshot barrier")
            disconnect(subscriber)
        finally:
            subscriber.close()

    write_config(2)
    with configured_broker(
        broker,
        config,
        2,
        f"final MQTT {protocol} subscription broker",
    ):
        subscriber = _connect(
            port,
            client_id,
            protocol,
            True,
        )
        try:
            ping(subscriber, f"MQTT {protocol} final subscription Session")
            _publish_all(port, protocol, topics, False)
            for qos in (0, 1):
                _complete_delivery(
                    subscriber,
                    protocol,
                    topics[qos],
                    qos,
                    identifiers[qos],
                )
            ping(subscriber, f"MQTT {protocol} removed subscription barrier")
            disconnect(subscriber)
        finally:
            subscriber.close()


def run_persistent_subscription_snapshot_case(
    broker: Path,
    directory: Path,
) -> None:
    """Restore subscriptions, then persist one UNSUBSCRIBE across restart."""
    for protocol in (4, 5):
        _run_persistent_subscription_case(broker, directory, protocol)
