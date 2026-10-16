"""Crash recovery checks for MQTT delayed Will state."""

from __future__ import annotations

from pathlib import Path
import socket
import tempfile
import time

from mqtt_commit_log_support import (
    ack_packet,
    connect_client,
    free_port,
    mqtt_string,
    packet,
    publish_packet,
    read_packet,
    read_varint,
    start_broker,
    stop_broker,
    subscribe_packet,
    wait_for_journal_growth,
)


WILL_DELAY_SECONDS = 3
CLEAN_WILL_DELAY_SECONDS = 30
CLEAN_WILL_TOPIC = "journal/will/clean-session"
CLEAN_WILL_PAYLOAD = b"clean Session Will survives crash"
CLEAN_WILL_PROPERTIES = (
    b"\x01\x01"
    + b"\x03" + mqtt_string("text")
    + b"\x26"
    + mqtt_string("test-user-property")
    + mqtt_string("nothing important")
)


def _expect_clean_session_will(
    sock: socket.socket,
    retain: bool,
) -> int:
    first, body = read_packet(sock)
    expected_first = 0x33 if retain else 0x32
    if first != expected_first or len(body) < 4:
        raise AssertionError(
            f"unexpected clean Session Will header: {first:#x} {body.hex()}"
        )
    topic_length = int.from_bytes(body[0:2], "big")
    topic_end = 2 + topic_length
    if body[2:topic_end] != CLEAN_WILL_TOPIC.encode():
        raise AssertionError(
            f"unexpected clean Session Will topic: {body.hex()}"
        )
    packet_id = int.from_bytes(body[topic_end : topic_end + 2], "big")
    if packet_id == 0:
        raise AssertionError("clean Session Will used Packet Identifier zero")
    properties_length, property_start = read_varint(body, topic_end + 2)
    property_end = property_start + properties_length
    if body[property_start:property_end] != CLEAN_WILL_PROPERTIES:
        raise AssertionError(
            f"unexpected clean Session Will properties: {body.hex()}"
        )
    if body[property_end:] != CLEAN_WILL_PAYLOAD:
        raise AssertionError(
            f"unexpected clean Session Will payload: {body.hex()}"
        )
    return packet_id


def verify_clean_session_will_recovery(executable: Path) -> None:
    """Recover a retained QoS 1 Will without restoring its clean Session."""
    observer_id = "journal-clean-will-observer"
    with tempfile.TemporaryDirectory(
        prefix="netz-mqtt-clean-will-journal-"
    ) as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        broker = start_broker(executable, port, journal, 2)
        observer = source = None
        try:
            observer = connect_client(
                port,
                observer_id,
                clean_start=False,
                session_present=False,
            )
            observer.sendall(subscribe_packet(
                1,
                CLEAN_WILL_TOPIC,
                subscription_identifier=None,
                qos=1,
            ))
            if read_packet(observer) != (0x90, b"\x00\x01\x00\x01"):
                raise AssertionError("unexpected clean Will observer SUBACK")

            baseline_size = journal.stat().st_size
            source = connect_client(
                port,
                "journal-clean-will-source",
                clean_start=True,
                session_present=False,
                session_expiry=0,
                will_topic=CLEAN_WILL_TOPIC,
                will_payload=CLEAN_WILL_PAYLOAD,
                will_delay=CLEAN_WILL_DELAY_SECONDS,
                will_qos=1,
                will_retain=True,
                will_properties=CLEAN_WILL_PROPERTIES,
            )
            wait_for_journal_growth(journal, baseline_size)
            broker.kill()
            broker.wait(timeout=5)
        finally:
            if observer is not None:
                observer.close()
            if source is not None:
                source.close()
            if broker.poll() is None:
                broker.kill()
                broker.wait()

        restored_port = free_port()
        restored = start_broker(executable, restored_port, journal, 2)
        observer = replay = None
        try:
            observer = connect_client(
                restored_port,
                observer_id,
                clean_start=False,
                session_present=True,
            )
            packet_id = _expect_clean_session_will(observer, retain=False)
            observer.sendall(ack_packet(0x40, packet_id))
            observer.sendall(packet(0xC0, b""))
            if read_packet(observer) != (0xD0, b""):
                raise AssertionError("clean Session Will was delivered twice")
            observer.sendall(packet(0xE0, b""))
            observer.close()
            observer = None

            replay = connect_client(
                restored_port,
                "journal-clean-will-replay",
                clean_start=True,
                session_present=False,
                session_expiry=0,
            )
            replay.sendall(subscribe_packet(
                1,
                CLEAN_WILL_TOPIC,
                subscription_identifier=None,
                qos=1,
            ))
            if read_packet(replay) != (0x90, b"\x00\x01\x00\x01"):
                raise AssertionError("unexpected clean Will replay SUBACK")
            packet_id = _expect_clean_session_will(replay, retain=True)
            replay.sendall(ack_packet(0x40, packet_id))
            replay.sendall(packet(0xC0, b""))
            if read_packet(replay) != (0xD0, b""):
                raise AssertionError("clean Session retained Will replayed twice")
            replay.sendall(packet(0xE0, b""))
            replay.close()
            replay = None
            stop_broker(restored)
        finally:
            if observer is not None:
                observer.close()
            if replay is not None:
                replay.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()

        final_port = free_port()
        final = start_broker(executable, final_port, journal, 1)
        observer = None
        try:
            observer = connect_client(
                final_port,
                observer_id,
                clean_start=False,
                session_present=True,
            )
            observer.sendall(packet(0xC0, b""))
            if read_packet(observer) != (0xD0, b""):
                raise AssertionError(
                    "clean Session Will was republished after recovery"
                )
            observer.sendall(packet(0xE0, b""))
            observer.close()
            observer = None
            stop_broker(final)
        finally:
            if observer is not None:
                observer.close()
            if final.poll() is None:
                final.kill()
                final.wait()


def verify_clean_session_will_cancellation_recovery(
    executable: Path,
) -> None:
    """Persist normal-DISCONNECT cancellation for a clean Session Will."""
    observer_id = "journal-clean-will-cancel-observer"
    with tempfile.TemporaryDirectory(
        prefix="netz-mqtt-clean-will-cancel-journal-"
    ) as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        broker = start_broker(executable, port, journal, 2)
        observer = source = None
        try:
            observer = connect_client(
                port,
                observer_id,
                clean_start=False,
                session_present=False,
            )
            observer.sendall(subscribe_packet(
                1,
                CLEAN_WILL_TOPIC,
                subscription_identifier=None,
                qos=1,
            ))
            if read_packet(observer) != (0x90, b"\x00\x01\x00\x01"):
                raise AssertionError(
                    "unexpected clean Will cancellation observer SUBACK"
                )

            source = connect_client(
                port,
                "journal-clean-will-cancel-source",
                clean_start=True,
                session_present=False,
                session_expiry=0,
                will_topic=CLEAN_WILL_TOPIC,
                will_payload=CLEAN_WILL_PAYLOAD,
                will_delay=CLEAN_WILL_DELAY_SECONDS,
                will_qos=1,
                will_retain=True,
                will_properties=CLEAN_WILL_PROPERTIES,
            )
            baseline_size = journal.stat().st_size
            source.sendall(packet(0xE0, b""))
            if source.recv(1) != b"":
                raise AssertionError(
                    "clean Will source remained open after DISCONNECT"
                )
            source.close()
            source = None
            wait_for_journal_growth(journal, baseline_size)
            broker.kill()
            broker.wait(timeout=5)
        finally:
            if observer is not None:
                observer.close()
            if source is not None:
                source.close()
            if broker.poll() is None:
                broker.kill()
                broker.wait()

        restored_port = free_port()
        restored = start_broker(executable, restored_port, journal, 2)
        observer = replay = None
        try:
            observer = connect_client(
                restored_port,
                observer_id,
                clean_start=False,
                session_present=True,
            )
            observer.sendall(packet(0xC0, b""))
            if read_packet(observer) != (0xD0, b""):
                raise AssertionError(
                    "normal DISCONNECT clean Will was published after recovery"
                )
            observer.sendall(packet(0xE0, b""))
            observer.close()
            observer = None

            replay = connect_client(
                restored_port,
                "journal-clean-will-cancel-replay",
                clean_start=True,
                session_present=False,
                session_expiry=0,
            )
            replay.sendall(subscribe_packet(
                1,
                CLEAN_WILL_TOPIC,
                subscription_identifier=None,
                qos=1,
            ))
            if read_packet(replay) != (0x90, b"\x00\x01\x00\x01"):
                raise AssertionError(
                    "unexpected canceled clean Will replay SUBACK"
                )
            replay.sendall(packet(0xC0, b""))
            if read_packet(replay) != (0xD0, b""):
                raise AssertionError(
                    "normal DISCONNECT clean Will became retained"
                )
            replay.sendall(packet(0xE0, b""))
            replay.close()
            replay = None
            stop_broker(restored)
        finally:
            if observer is not None:
                observer.close()
            if replay is not None:
                replay.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()


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


def verify_scheduled_will_cancellation_recovery(executable: Path) -> None:
    topic = "journal/will/canceled"
    payload = b"must-not-publish"
    observer_id = "journal-will-cancel-observer"
    source_id = "journal-will-cancel-source"
    with tempfile.TemporaryDirectory(
        prefix="netz-mqtt-will-cancel-journal-"
    ) as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        broker = start_broker(executable, port, journal, 3)
        observer = source = replacement = None
        try:
            observer = connect_client(
                port, observer_id, clean_start=False, session_present=False,
            )
            observer.sendall(subscribe_packet(
                1, topic, subscription_identifier=None, qos=0,
            ))
            if read_packet(observer) != (0x90, b"\x00\x01\x00\x00"):
                raise AssertionError("unexpected Will cancellation SUBACK")
            observer.sendall(b"\xe0\x00")
            if observer.recv(1) != b"":
                raise AssertionError("Will cancellation observer remained open")
            observer.close()
            observer = None

            source = connect_client(
                port, source_id, clean_start=False, session_present=False,
                will_topic=topic, will_payload=payload,
                will_delay=WILL_DELAY_SECONDS,
            )
            baseline_size = journal.stat().st_size
            source.close()
            source = None
            wait_for_journal_growth(journal, baseline_size)

            baseline_size = journal.stat().st_size
            replacement = connect_client(
                port, source_id, clean_start=False, session_present=True,
            )
            wait_for_journal_growth(journal, baseline_size)
            broker.kill()
            broker.wait(timeout=5)
        finally:
            if observer is not None:
                observer.close()
            if source is not None:
                source.close()
            if replacement is not None:
                replacement.close()
            if broker.poll() is None:
                broker.kill()
                broker.wait()

        restored_port = free_port()
        restored = start_broker(executable, restored_port, journal, 2)
        observer = source = None
        try:
            observer = connect_client(
                restored_port, observer_id,
                clean_start=False, session_present=True,
            )
            time.sleep(WILL_DELAY_SECONDS + 0.5)
            observer.sendall(b"\xc0\x00")
            if read_packet(observer) != (0xD0, b""):
                raise AssertionError(
                    "canceled delayed Will reappeared after journal recovery"
                )
            # Reconnecting the Will owner itself cancels a scheduled Will, so
            # verify absence first. Only then prove its Session also survived.
            source = connect_client(
                restored_port, source_id,
                clean_start=False, session_present=True,
            )
            restored.kill()
            restored.wait(timeout=5)
        finally:
            if observer is not None:
                observer.close()
            if source is not None:
                source.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()
