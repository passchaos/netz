#!/usr/bin/env python3
"""Verify MQTT commit-log recovery without a periodic snapshot."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import socket
import tempfile
import time

from mqtt_commit_log_inflight import (
    verify_incoming_qos2_recovery,
    verify_outgoing_qos1_recovery,
    verify_outgoing_qos2_recovery,
)
from mqtt_commit_log_retained import verify_retained_delete_recovery
from mqtt_commit_log_session import verify_active_session_expiry_recovery
from mqtt_commit_log_support import (
    SUBSCRIPTION_IDENTIFIER,
    connect_client,
    free_port,
    publish_packet,
    qos0_publish_packet,
    read_packet,
    read_varint,
    start_broker,
    stop_broker,
    subscribe_packet,
    wait_for_journal_growth,
)
from mqtt_vectors import source_lock


MOSQUITTO_SOURCES = (
    "broker/03-publish-b2c-disconnect-qos1.py",
    "broker/03-publish-c2b-disconnect-qos2.py",
    "broker/04-retain-check-source-persist.py",
    "broker/11-message-expiry.py",
    "broker/11-subscription-id.py",
    "broker/15-persist-client-msg-out-v5-0.py",
    "broker/15-persist-client-expired-session.py",
    "broker/15-persist-retain-clear.py",
    "broker/15-persist-client-will-persistent.py",
    "broker/persist_client_will_core.py",
    "broker/persist_module_helper.py",
)
WILL_DELAY_SECONDS = 3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("broker", type=Path)
    parser.add_argument(
        "--mosquitto-test-root",
        type=Path,
        help="verify the referenced Mosquitto source before running",
    )
    return parser.parse_args()


def restored_publish(
    sock: socket.socket, *, expected_payload: bytes, expect_expiry: bool
) -> bytes:
    first, body = read_packet(sock)
    if first != 0x32:
        raise AssertionError(f"expected restored QoS 1 PUBLISH: {first:#x}")
    topic_len = int.from_bytes(body[0:2], "big")
    topic_end = 2 + topic_len
    if body[2:topic_end] != b"journal/value":
        raise AssertionError(f"unexpected topic: {body.hex()}")
    packet_id = body[topic_end : topic_end + 2]
    properties_len, property_start = read_varint(body, topic_end + 2)
    property_end = property_start + properties_len
    properties = body[property_start:property_end]
    if expect_expiry:
        expected_suffix = bytes((0x0B, SUBSCRIPTION_IDENTIFIER))
        if len(properties) != 7 or properties[0] != 0x02 or (
            properties[5:] != expected_suffix
        ):
            raise AssertionError(
                f"unexpected restored expiring properties: {body.hex()}"
            )
        remaining_expiry = int.from_bytes(properties[1:5], "big")
        if not 1 <= remaining_expiry < 100:
            raise AssertionError(
                f"Message Expiry was not reduced across restart: "
                f"{remaining_expiry}"
            )
    elif properties != bytes((0x0B, SUBSCRIPTION_IDENTIFIER)):
        raise AssertionError(
            f"unexpected restored non-expiring properties: {body.hex()}"
        )
    if body[property_end:] != expected_payload:
        raise AssertionError(f"unexpected payload: {body.hex()}")
    return packet_id


def verify_scheduled_will_recovery(executable: Path) -> None:
    topic = "journal/will"
    payload = b"survives-crash"
    with tempfile.TemporaryDirectory(prefix="netz-mqtt-will-journal-") as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        broker = start_broker(executable, port, journal, 3)
        observer = will_source = None
        try:
            observer = connect_client(
                port, "journal-will-observer",
                clean_start=False, session_present=False,
            )
            observer.sendall(subscribe_packet(
                1, topic, subscription_identifier=None, qos=1
            ))
            first, body = read_packet(observer)
            if first != 0x90 or body != b"\x00\x01\x00\x01":
                raise AssertionError(
                    f"unexpected Will observer SUBACK: {first:#x} {body.hex()}"
                )

            will_source = connect_client(
                port, "journal-will-source",
                clean_start=False, session_present=False,
                will_topic=topic, will_payload=payload,
                will_delay=WILL_DELAY_SECONDS, will_qos=1, will_retain=True,
            )
            baseline_size = journal.stat().st_size
            will_source.close()
            will_source = None
            wait_for_journal_growth(journal, baseline_size)
            broker.kill()
            broker.wait(timeout=5)
        finally:
            if observer is not None:
                observer.close()
            if will_source is not None:
                will_source.close()
            if broker.poll() is None:
                broker.kill()
                broker.wait()

        restored_port = free_port()
        restored = start_broker(executable, restored_port, journal, 2)
        observer = replay = None
        try:
            observer = connect_client(
                restored_port, "journal-will-observer",
                clean_start=False, session_present=True,
            )
            observer.settimeout(WILL_DELAY_SECONDS + 5)
            expected_live = publish_packet(
                topic, payload, 1, retain=False
            )
            actual = read_packet(observer)
            if actual != (expected_live[0], expected_live[2:]):
                raise AssertionError(
                    f"unexpected restored delayed Will: "
                    f"{actual[0]:#x} {actual[1].hex()}"
                )
            observer.sendall(b"\x40\x04\x00\x01\x00\x00")
            observer.sendall(b"\xe0\x00")
            observer.close()
            observer = None

            replay = connect_client(
                restored_port, "journal-will-replay",
                clean_start=True, session_present=False,
            )
            replay.sendall(subscribe_packet(
                1, topic, subscription_identifier=None, qos=1
            ))
            first, body = read_packet(replay)
            if first != 0x90 or body != b"\x00\x01\x00\x01":
                raise AssertionError(
                    f"unexpected Will replay SUBACK: {first:#x} {body.hex()}"
                )
            expected_retained = publish_packet(
                topic, payload, 1, retain=True
            )
            actual = read_packet(replay)
            if actual != (expected_retained[0], expected_retained[2:]):
                raise AssertionError(
                    f"unexpected retained Will replay: "
                    f"{actual[0]:#x} {actual[1].hex()}"
                )
            replay.sendall(b"\x40\x04\x00\x01\x00\x00")
            replay.sendall(b"\xc0\x00")
            if read_packet(replay) != (0xD0, b""):
                raise AssertionError("restored Will was delivered more than once")
            # This is a crash-recovery gate. Stop after the protocol barrier
            # instead of coupling the assertion to the example's independent
            # quiescent-shutdown snapshot policy while an offline Session is
            # still present.
            restored.kill()
            restored.wait(timeout=5)
        finally:
            if observer is not None:
                observer.close()
            if replay is not None:
                replay.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()


def verify_retained_source_recovery(executable: Path) -> None:
    topic = "retain/check-source"
    payload = b"retained across SIGKILL"
    source_client_id = "journal-retained-writer"
    with tempfile.TemporaryDirectory(prefix="netz-mqtt-retained-journal-") as raw:
        directory = Path(raw)
        source_journal = directory / "source.log"
        source_port = free_port()
        source = start_broker(executable, source_port, source_journal, 1)
        publisher = None
        try:
            publisher = connect_client(
                source_port,
                source_client_id, clean_start=True, session_present=False,
            )
            publisher.sendall(publish_packet(
                topic, payload, 7, retain=True
            ))
            first, body = read_packet(publisher)
            if first != 0x40 or body != b"\x00\x07\x10":
                raise AssertionError(
                    f"unexpected retained PUBACK: {first:#x} {body.hex()}"
                )
            source.kill()
            source.wait(timeout=5)
        finally:
            if publisher is not None:
                publisher.close()
            if source.poll() is None:
                source.kill()
                source.wait()

        denied_journal = directory / "denied.log"
        unchecked_journal = directory / "unchecked.log"
        shutil.copyfile(source_journal, denied_journal)
        shutil.copyfile(source_journal, unchecked_journal)

        cases = (
            ("denied", denied_journal, (), False),
            (
                "unchecked",
                unchecked_journal,
                ("--no-check-retain-source",),
                True,
            ),
        )
        for label, journal, policy_args, expect_replay in cases:
            port = free_port()
            broker = start_broker(
                executable,
                port,
                journal,
                1,
                extra_args=(
                    f"--deny-retained-source-client-id={source_client_id}",
                    *policy_args,
                ),
            )
            subscriber = None
            try:
                subscriber = connect_client(
                    port,
                    f"retained-reader-{label}",
                    clean_start=True,
                    session_present=False,
                )
                subscriber.sendall(subscribe_packet(
                    1, topic, subscription_identifier=None, qos=0
                ))
                first, body = read_packet(subscriber)
                if first != 0x90 or body != b"\x00\x01\x00\x00":
                    raise AssertionError(
                        f"unexpected retained SUBACK {label}: "
                        f"{first:#x} {body.hex()}"
                    )
                if expect_replay:
                    expected = qos0_publish_packet(
                        topic, payload, retain=True
                    )
                    expected_first = expected[0]
                    expected_length, expected_body_offset = read_varint(
                        expected, 1
                    )
                    expected_body = expected[expected_body_offset:]
                    if len(expected_body) != expected_length:
                        raise AssertionError(
                            "invalid expected retained PUBLISH framing"
                        )
                    actual = read_packet(subscriber)
                    if actual != (expected_first, expected_body):
                        raise AssertionError(
                            f"unexpected retained replay {label}: "
                            f"{actual[0]:#x} {actual[1].hex()}"
                        )
                subscriber.sendall(b"\xc0\x00")
                if read_packet(subscriber) != (0xD0, b""):
                    raise AssertionError(
                        f"unexpected retained source result {label}"
                    )
                subscriber.sendall(b"\xe0\x00")
                stop_broker(broker)
            finally:
                if subscriber is not None:
                    subscriber.close()
                if broker.poll() is None:
                    broker.kill()
                    broker.wait()


def main() -> None:
    args = parse_args()
    if args.mosquitto_test_root is not None:
        for source in MOSQUITTO_SOURCES:
            source_lock.verify_source_hash(
                args.mosquitto_test_root / source,
                source_lock.MOSQUITTO_SOURCE_SHA256[source],
            )
    with tempfile.TemporaryDirectory(prefix="netz-mqtt-journal-") as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        source = start_broker(args.broker, port, journal, 2)
        subscriber = publisher = None
        try:
            subscriber = connect_client(
                port, "journal-subscriber",
                clean_start=False, session_present=False,
            )
            subscriber.sendall(subscribe_packet(1, "journal/#"))
            first, body = read_packet(subscriber)
            if first != 0x90 or body[-1:] != b"\x01":
                raise AssertionError(f"unexpected SUBACK: {first:#x} {body.hex()}")
            subscriber.sendall(b"\xe0\x00")
            if subscriber.recv(1) != b"":
                raise AssertionError("subscriber remained open after DISCONNECT")
            subscriber.close()
            subscriber = None

            publisher = connect_client(
                port, "journal-publisher",
                clean_start=True, session_present=False,
            )
            for packet_id, payload, expiry_seconds in (
                (1, b"expires-during-downtime", 5),
                (2, b"survives-with-expiry", 100),
                (3, b"survives-without-expiry", None),
            ):
                publisher.sendall(publish_packet(
                    "journal/value", payload, packet_id,
                    expiry_seconds=expiry_seconds,
                ))
                first, body = read_packet(publisher)
                if first != 0x40 or body[0:2] != packet_id.to_bytes(2, "big"):
                    raise AssertionError(
                        f"unexpected PUBACK {packet_id}: {first:#x} {body.hex()}"
                    )

            # No timer/checkpoint is involved. PUBACK is sent only after the
            # commit record has been fsynced, so SIGKILL immediately after it
            # must still leave the queued delivery recoverable.
            source.kill()
            source.wait(timeout=5)
        finally:
            if subscriber is not None:
                subscriber.close()
            if publisher is not None:
                publisher.close()
            if source.poll() is None:
                source.kill()
                source.wait()

        # Cross the short message's expiry while the broker is stopped.
        time.sleep(6)
        restored_port = free_port()
        restored = start_broker(args.broker, restored_port, journal, 1)
        subscriber = None
        try:
            subscriber = connect_client(
                restored_port, "journal-subscriber",
                clean_start=False, session_present=True,
            )
            expiring_id = restored_publish(
                subscriber, expected_payload=b"survives-with-expiry",
                expect_expiry=True,
            )
            permanent_id = restored_publish(
                subscriber, expected_payload=b"survives-without-expiry",
                expect_expiry=False,
            )
            subscriber.sendall(b"\x40\x04" + expiring_id + b"\x00\x00")
            subscriber.sendall(b"\x40\x04" + permanent_id + b"\x00\x00")
            # PINGRESP must follow the two surviving deliveries. A stale first
            # PUBLISH would be read here instead and fail the exact check.
            subscriber.sendall(b"\xc0\x00")
            if read_packet(subscriber) != (0xD0, b""):
                raise AssertionError("expired PUBLISH survived broker restart")
            subscriber.sendall(b"\xe0\x00")
            restored.wait(timeout=5)
            if restored.returncode != 0:
                assert restored.stdout is not None
                raise RuntimeError(restored.stdout.read())
        finally:
            if subscriber is not None:
                subscriber.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()

    print(
        "MQTT incremental commit-log SIGKILL recovery passed with reduced "
        "Message Expiry and Subscription Identifier "
        f"{SUBSCRIPTION_IDENTIFIER}"
    )
    verify_retained_source_recovery(args.broker)
    print(
        "MQTT retained-source authorization survived commit-log SIGKILL "
        "recovery"
    )
    verify_retained_delete_recovery(args.broker)
    print(
        "MQTT 3.1.1/5 retained deletion survived commit-log SIGKILL "
        "recovery"
    )
    verify_active_session_expiry_recovery(args.broker)
    print(
        "MQTT expired Session deletion survived commit-log SIGKILL recovery"
    )
    verify_outgoing_qos2_recovery(args.broker)
    print(
        "MQTT outgoing QoS 2 resumed at PUBREL and completed across "
        "commit-log SIGKILL recovery"
    )
    verify_incoming_qos2_recovery(args.broker)
    print(
        "MQTT 3.1.1/5 incoming QoS 2 routed once across commit-log "
        "SIGKILL recovery"
    )
    verify_outgoing_qos1_recovery(args.broker)
    print(
        "MQTT 3.1.1/5 outgoing QoS 1 DUP state completed across "
        "commit-log SIGKILL recovery"
    )
    verify_scheduled_will_recovery(args.broker)
    print("MQTT delayed retained Will survived commit-log SIGKILL recovery")


if __name__ == "__main__":
    main()
