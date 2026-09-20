"""Crash recovery checks for MQTT durable Session lifecycle state."""

from __future__ import annotations

from pathlib import Path
import tempfile

from mqtt_commit_log_support import (
    connect_client,
    free_port,
    publish_packet,
    read_packet,
    start_broker,
    subscribe_packet,
    wait_for_journal_growth,
)


def verify_active_session_expiry_recovery(executable: Path) -> None:
    """Prove deadline-driven Session deletion remains gone after SIGKILL."""
    target_id = "journal-expiring-session"
    control_id = "journal-expiry-control"
    topic = "journal/session-expiry/value"
    with tempfile.TemporaryDirectory(
        prefix="netz-mqtt-session-expiry-journal-"
    ) as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        broker = start_broker(executable, port, journal, 4)
        control = target = publisher = None
        try:
            control = connect_client(
                port, control_id, clean_start=False, session_present=False,
            )
            control.sendall(subscribe_packet(
                1, "journal/session-expiry/control",
                subscription_identifier=None, qos=0,
            ))
            if read_packet(control) != (0x90, b"\x00\x01\x00\x00"):
                raise AssertionError("unexpected expiry control SUBACK")
            control.sendall(b"\xe0\x00")
            if control.recv(1) != b"":
                raise AssertionError("expiry control remained open")
            control.close()
            control = None

            target = connect_client(
                port, target_id, clean_start=False, session_present=False,
                session_expiry=2,
            )
            target.sendall(subscribe_packet(
                1, topic, subscription_identifier=None, qos=1,
            ))
            if read_packet(target) != (0x90, b"\x00\x01\x00\x01"):
                raise AssertionError("unexpected expiring Session SUBACK")
            target.sendall(b"\xe0\x00")
            if target.recv(1) != b"":
                raise AssertionError("expiring Session remained open")
            target.close()
            target = None

            publisher = connect_client(
                port, "journal-expiry-publisher",
                clean_start=True, session_present=False, session_expiry=0,
            )
            publisher.sendall(publish_packet(
                topic, b"must-expire-with-session", 9,
            ))
            if read_packet(publisher) != (0x40, b"\x00\x09"):
                raise AssertionError(
                    "message was not queued in the expiring Session"
                )

            target = connect_client(
                port, target_id, clean_start=False, session_present=True,
                session_expiry=2,
            )
            expected_queued = publish_packet(
                topic, b"must-expire-with-session", 1,
            )
            if read_packet(target) != (
                expected_queued[0], expected_queued[2:],
            ):
                raise AssertionError(
                    "expiring Session did not own the queued message"
                )
            # Leave the delivery unacknowledged, so expiry must delete both
            # the subscription and a concrete outgoing inflight transaction.
            baseline_size = journal.stat().st_size
            target.close()
            target = None
            wait_for_journal_growth(journal, baseline_size)
            baseline_size = journal.stat().st_size
            # No further durable operation occurs while this transient
            # publisher remains connected. The next record is therefore the
            # autonomous deadline driver's atomic Session/router/queue removal.
            wait_for_journal_growth(journal, baseline_size)
            broker.kill()
            broker.wait(timeout=5)
        finally:
            if control is not None:
                control.close()
            if target is not None:
                target.close()
            if publisher is not None:
                publisher.close()
            if broker.poll() is None:
                broker.kill()
                broker.wait()

        restored_port = free_port()
        restored = start_broker(executable, restored_port, journal, 3)
        control = target = publisher = None
        try:
            control = connect_client(
                restored_port, control_id,
                clean_start=False, session_present=True,
            )
            control.sendall(b"\xc0\x00")
            if read_packet(control) != (0xD0, b""):
                raise AssertionError("control Session did not restore cleanly")

            target = connect_client(
                restored_port, target_id,
                clean_start=False, session_present=False,
            )
            # If the expired queue survived, its PUBLISH appears before this
            # barrier. Session Present alone is not sufficient evidence.
            target.sendall(b"\xc0\x00")
            if read_packet(target) != (0xD0, b""):
                raise AssertionError("expired Session queue was restored")

            publisher = connect_client(
                restored_port, "journal-expiry-probe",
                clean_start=True, session_present=False, session_expiry=0,
            )
            publisher.sendall(publish_packet(
                topic, b"must-not-route", 10,
            ))
            if read_packet(publisher) != (0x40, b"\x00\x0a\x10"):
                raise AssertionError(
                    "expired Session subscription still matched"
                )
            target.sendall(b"\xc0\x00")
            if read_packet(target) != (0xD0, b""):
                raise AssertionError("expired subscription was restored")
            restored.kill()
            restored.wait(timeout=5)
        finally:
            if control is not None:
                control.close()
            if target is not None:
                target.close()
            if publisher is not None:
                publisher.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()
