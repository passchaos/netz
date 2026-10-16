"""Mosquitto-derived expired-message snapshot cleanup scenarios."""

from __future__ import annotations

from pathlib import Path
import socket
import time

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


_EXPIRY_SECONDS = 2
_FILTER = "persist/expired/#"
_MESSAGE_COUNT = 4


def _connect_subscriber(
    port: int,
    client_id: str,
    session_present: bool,
) -> socket.socket:
    return connect_client(
        port,
        client_id,
        clean_start=False,
        session_present=session_present,
        protocol=5,
        session_expiry=60,
    )


def _subscribe(
    subscriber: socket.socket,
    packet_id: int,
    qos: int,
    label: str,
) -> None:
    subscriber.sendall(subscribe_packet(
        packet_id,
        _FILTER,
        subscription_identifier=None,
        qos=qos,
        protocol=5,
    ))
    expect_packet(
        subscriber,
        packet(
            0x90,
            packet_id.to_bytes(2, "big") + b"\x00" + bytes((qos,)),
        ),
        f"{label} SUBACK",
    )


def _create_offline_session(
    port: int,
    client_id: str,
) -> None:
    subscriber = _connect_subscriber(port, client_id, False)
    try:
        _subscribe(subscriber, 1, 1, client_id)
        disconnect(subscriber)
    finally:
        subscriber.close()


def _publish_expiring_messages(port: int) -> None:
    publisher = connect_client(
        port,
        "persist-expired-publisher",
        clean_start=True,
        session_present=False,
        protocol=5,
        session_expiry=0,
    )
    try:
        for index in range(_MESSAGE_COUNT):
            packet_id = index + 1
            publisher.sendall(publish_packet(
                f"persist/expired/{index}",
                f"expired-{index}".encode(),
                packet_id,
                qos=1,
                expiry_seconds=_EXPIRY_SECONDS,
                retain=index >= 2,
                protocol=5,
            ))
            expect_packet(
                publisher,
                ack_packet(0x40, packet_id),
                f"expiring publisher PUBACK {packet_id}",
            )
        ping(publisher, "expiring publisher snapshot barrier")
        disconnect(publisher)
    finally:
        publisher.close()


def _expect_empty_restored_sessions(
    port: int,
    generation: int,
    resubscribe_first: bool,
) -> None:
    for index in range(2):
        client_id = f"persist-expired-subscriber-{index}"
        subscriber = _connect_subscriber(port, client_id, True)
        try:
            ping(
                subscriber,
                f"expiry restore {generation} subscriber {index} queue",
            )
            if resubscribe_first and index == 0:
                _subscribe(
                    subscriber,
                    2,
                    1,
                    f"expiry restore {generation} resubscribe",
                )
                ping(
                    subscriber,
                    f"expiry restore {generation} resubscribe replay",
                )
            disconnect(subscriber)
        finally:
            subscriber.close()

    probe = connect_client(
        port,
        f"persist-expired-retained-probe-{generation}",
        clean_start=True,
        session_present=False,
        protocol=5,
        session_expiry=0,
    )
    try:
        _subscribe(
            probe,
            3,
            0,
            f"expiry restore {generation} retained probe",
        )
        ping(
            probe,
            f"expiry restore {generation} retained replay",
        )
        disconnect(probe)
    finally:
        probe.close()


def run_expired_message_persistence_case(
    broker: Path,
    directory: Path,
) -> None:
    """Drop shared queued and retained messages that expire while offline."""
    port = free_port()
    snapshot = directory / "expired-messages.db"
    config = directory / "expired-messages.conf"
    config.write_text(
        "persistence true\n"
        f"persistence_location {directory}\n"
        f"persistence_file {snapshot.name}\n"
        "autosave_interval 0\n"
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_queued_messages 8\n"
        "max_connections 3\n"
    )

    with configured_broker(
        broker,
        config,
        3,
        "initial expired-message broker",
    ):
        _create_offline_session(port, "persist-expired-subscriber-0")
        _create_offline_session(port, "persist-expired-subscriber-1")
        _publish_expiring_messages(port)
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise AssertionError("expired-message snapshot was not written")

    time.sleep(_EXPIRY_SECONDS + 0.2)

    with configured_broker(
        broker,
        config,
        3,
        "first expired-message restore broker",
    ):
        _expect_empty_restored_sessions(port, 1, True)

    with configured_broker(
        broker,
        config,
        3,
        "second expired-message restore broker",
    ):
        _expect_empty_restored_sessions(port, 2, False)
