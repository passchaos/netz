"""Crash recovery checks for MQTT delayed Will state."""

from __future__ import annotations

from pathlib import Path
import tempfile
import time

from mqtt_commit_log_support import (
    connect_client,
    free_port,
    publish_packet,
    read_packet,
    start_broker,
    subscribe_packet,
    wait_for_journal_growth,
)


WILL_DELAY_SECONDS = 3


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
