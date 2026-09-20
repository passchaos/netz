"""Crash recovery checks for MQTT broker-to-client inflight state."""

from __future__ import annotations

from pathlib import Path
import tempfile

from mqtt_commit_log_support import (
    ack_packet,
    connect_client,
    free_port,
    publish_packet,
    read_packet,
    start_broker,
    subscribe_packet,
    wait_for_journal_growth,
)


def verify_outgoing_qos1_recovery(executable: Path) -> None:
    """Require one DUP retry and durable completion after two SIGKILLs."""
    for protocol in (4, 5):
        _verify_outgoing_qos1_recovery(executable, protocol)


def _verify_outgoing_qos1_recovery(
    executable: Path, protocol: int,
) -> None:
    topic = f"journal/qos1/v{protocol}"
    payload = b"resume-with-dup"
    client_id = f"journal-qos1-subscriber-v{protocol}"
    with tempfile.TemporaryDirectory(
        prefix=f"netz-mqtt-qos1-v{protocol}-journal-"
    ) as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        broker = start_broker(executable, port, journal, 2)
        subscriber = publisher = None
        try:
            subscriber = connect_client(
                port, client_id, clean_start=False, session_present=False,
                protocol=protocol,
            )
            subscriber.sendall(subscribe_packet(
                3265, topic, subscription_identifier=None, qos=1,
                protocol=protocol,
            ))
            expected_suback_body = (
                b"\x0c\xc1\x00\x01"
                if protocol == 5 else b"\x0c\xc1\x01"
            )
            if read_packet(subscriber) != (0x90, expected_suback_body):
                raise AssertionError(
                    f"unexpected QoS 1 recovery SUBACK v{protocol}"
                )

            publisher = connect_client(
                port, f"journal-qos1-publisher-v{protocol}",
                clean_start=True, session_present=False, protocol=protocol,
                session_expiry=0,
            )
            publisher.sendall(publish_packet(
                topic, payload, 128, protocol=protocol,
            ))
            if read_packet(publisher) != (0x40, b"\x00\x80"):
                raise AssertionError(
                    f"unexpected QoS 1 publisher PUBACK v{protocol}"
                )

            expected_publish = publish_packet(
                topic, payload, 1, protocol=protocol,
            )
            if read_packet(subscriber) != (
                expected_publish[0], expected_publish[2:],
            ):
                raise AssertionError(
                    f"unexpected initial downstream PUBLISH v{protocol}"
                )
            # Delivery selection is journaled before the PUBLISH becomes
            # visible. Kill without PUBACK to preserve its inflight state.
            broker.kill()
            broker.wait(timeout=5)
        finally:
            if subscriber is not None:
                subscriber.close()
            if publisher is not None:
                publisher.close()
            if broker.poll() is None:
                broker.kill()
                broker.wait()

        restored_port = free_port()
        restored = start_broker(executable, restored_port, journal, 1)
        subscriber = None
        try:
            subscriber = connect_client(
                restored_port, client_id,
                clean_start=False, session_present=True, protocol=protocol,
            )
            expected_retry = publish_packet(
                topic, payload, 1, dup=True, protocol=protocol,
            )
            if read_packet(subscriber) != (
                expected_retry[0], expected_retry[2:],
            ):
                raise AssertionError(
                    f"QoS 1 did not resume with DUP and its original "
                    f"Packet Identifier v{protocol}"
                )
            baseline_size = journal.stat().st_size
            subscriber.sendall(ack_packet(0x40, 1))
            subscriber.sendall(b"\xc0\x00")
            if read_packet(subscriber) != (0xD0, b""):
                raise AssertionError(
                    f"unexpected post-PUBACK barrier v{protocol}"
                )
            wait_for_journal_growth(journal, baseline_size)
            restored.kill()
            restored.wait(timeout=5)
        finally:
            if subscriber is not None:
                subscriber.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()

        final_port = free_port()
        final = start_broker(executable, final_port, journal, 1)
        subscriber = None
        try:
            subscriber = connect_client(
                final_port, client_id,
                clean_start=False, session_present=True, protocol=protocol,
            )
            subscriber.sendall(b"\xc0\x00")
            if read_packet(subscriber) != (0xD0, b""):
                raise AssertionError(
                    f"completed outgoing QoS 1 transaction replayed "
                    f"v{protocol}"
                )
            final.kill()
            final.wait(timeout=5)
        finally:
            if subscriber is not None:
                subscriber.close()
            if final.poll() is None:
                final.kill()
                final.wait()


def verify_outgoing_qos2_recovery(executable: Path) -> None:
    """Resume an accepted outgoing QoS 2 transaction directly at PUBREL."""
    topic = "journal/qos2"
    payload = b"resume-at-pubrel"
    client_id = "journal-qos2-subscriber"
    with tempfile.TemporaryDirectory(prefix="netz-mqtt-qos2-journal-") as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        broker = start_broker(executable, port, journal, 2)
        subscriber = publisher = None
        try:
            subscriber = connect_client(
                port, client_id, clean_start=False, session_present=False,
            )
            subscriber.sendall(subscribe_packet(
                1, topic, subscription_identifier=None, qos=2,
            ))
            if read_packet(subscriber) != (0x90, b"\x00\x01\x00\x02"):
                raise AssertionError("unexpected QoS 2 recovery SUBACK")

            publisher = connect_client(
                port, "journal-qos2-publisher",
                clean_start=True, session_present=False, session_expiry=0,
            )
            publisher.sendall(publish_packet(
                topic, payload, 9, qos=2,
            ))
            if read_packet(publisher) != (0x50, b"\x00\x09"):
                raise AssertionError("unexpected publisher PUBREC")
            publisher.sendall(ack_packet(0x62, 9))
            if read_packet(publisher) != (0x70, b"\x00\x09"):
                raise AssertionError("unexpected publisher PUBCOMP")

            expected_publish = publish_packet(topic, payload, 1, qos=2)
            if read_packet(subscriber) != (
                expected_publish[0], expected_publish[2:],
            ):
                raise AssertionError(
                    "unexpected initial downstream QoS 2 PUBLISH"
                )
            baseline_size = journal.stat().st_size
            subscriber.sendall(ack_packet(0x50, 1))
            if read_packet(subscriber) != (0x62, b"\x00\x01"):
                raise AssertionError("unexpected initial downstream PUBREL")
            wait_for_journal_growth(journal, baseline_size)
            broker.kill()
            broker.wait(timeout=5)
        finally:
            if subscriber is not None:
                subscriber.close()
            if publisher is not None:
                publisher.close()
            if broker.poll() is None:
                broker.kill()
                broker.wait()

        restored_port = free_port()
        restored = start_broker(executable, restored_port, journal, 1)
        subscriber = None
        try:
            subscriber = connect_client(
                restored_port, client_id,
                clean_start=False, session_present=True,
            )
            # The committed transaction is already beyond PUBLISH. Recovery
            # must continue at PUBREL with the original Packet Identifier.
            if read_packet(subscriber) != (0x62, b"\x00\x01"):
                raise AssertionError(
                    "outgoing QoS 2 did not resume directly at PUBREL"
                )
            baseline_size = journal.stat().st_size
            subscriber.sendall(ack_packet(0x70, 1))
            subscriber.sendall(b"\xc0\x00")
            if read_packet(subscriber) != (0xD0, b""):
                raise AssertionError("unexpected post-PUBCOMP barrier")
            wait_for_journal_growth(journal, baseline_size)
            restored.kill()
            restored.wait(timeout=5)
        finally:
            if subscriber is not None:
                subscriber.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()

        final_port = free_port()
        final = start_broker(executable, final_port, journal, 1)
        subscriber = None
        try:
            subscriber = connect_client(
                final_port, client_id,
                clean_start=False, session_present=True,
            )
            subscriber.sendall(b"\xc0\x00")
            if read_packet(subscriber) != (0xD0, b""):
                raise AssertionError(
                    "completed outgoing QoS 2 transaction replayed"
                )
            final.kill()
            final.wait(timeout=5)
        finally:
            if subscriber is not None:
                subscriber.close()
            if final.poll() is None:
                final.kill()
                final.wait()


def verify_incoming_qos2_recovery(executable: Path) -> None:
    """Recover staged input and keep its release idempotent across crashes."""
    for protocol in (4, 5):
        _verify_incoming_qos2_recovery(executable, protocol)


def _verify_incoming_qos2_recovery(
    executable: Path, protocol: int,
) -> None:
    topic = f"journal/incoming-qos2/v{protocol}"
    payload = b"release-exactly-once"
    publisher_id = f"journal-incoming-qos2-publisher-v{protocol}"
    observer_id = f"journal-incoming-qos2-observer-v{protocol}"
    with tempfile.TemporaryDirectory(
        prefix=f"netz-mqtt-incoming-qos2-v{protocol}-journal-"
    ) as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        broker = start_broker(executable, port, journal, 2)
        observer = publisher = None
        try:
            observer = connect_client(
                port, observer_id, clean_start=False, session_present=False,
                protocol=protocol,
            )
            observer.sendall(subscribe_packet(
                1, topic, subscription_identifier=None, qos=1,
                protocol=protocol,
            ))
            expected_suback = (
                b"\x00\x01\x00\x01"
                if protocol == 5 else b"\x00\x01\x01"
            )
            if read_packet(observer) != (0x90, expected_suback):
                raise AssertionError(
                    f"unexpected incoming QoS 2 SUBACK v{protocol}"
                )

            publisher = connect_client(
                port, publisher_id, clean_start=False, session_present=False,
                protocol=protocol,
            )
            baseline_size = journal.stat().st_size
            publisher.sendall(publish_packet(
                topic, payload, 3265, qos=2, protocol=protocol,
            ))
            if read_packet(publisher) != (0x50, b"\x0c\xc1"):
                raise AssertionError(
                    f"unexpected initial inbound PUBREC v{protocol}"
                )
            wait_for_journal_growth(journal, baseline_size)
            broker.kill()
            broker.wait(timeout=5)
        finally:
            if observer is not None:
                observer.close()
            if publisher is not None:
                publisher.close()
            if broker.poll() is None:
                broker.kill()
                broker.wait()

        restored_port = free_port()
        restored = start_broker(executable, restored_port, journal, 2)
        observer = publisher = None
        try:
            observer = connect_client(
                restored_port, observer_id,
                clean_start=False, session_present=True, protocol=protocol,
            )
            publisher = connect_client(
                restored_port, publisher_id,
                clean_start=False, session_present=True, protocol=protocol,
            )
            publisher.sendall(publish_packet(
                topic, payload, 3265, qos=2, dup=True, protocol=protocol,
            ))
            if read_packet(publisher) != (0x50, b"\x0c\xc1"):
                raise AssertionError(
                    f"unexpected recovered DUP PUBREC v{protocol}"
                )
            observer.sendall(b"\xc0\x00")
            if read_packet(observer) != (0xD0, b""):
                raise AssertionError(
                    f"inbound QoS 2 routed before PUBREL v{protocol}"
                )

            publisher.sendall(ack_packet(0x62, 3265))
            if read_packet(publisher) != (0x70, b"\x0c\xc1"):
                raise AssertionError(
                    f"unexpected recovered inbound PUBCOMP v{protocol}"
                )
            expected_delivery = publish_packet(
                topic, payload, 1, qos=1, protocol=protocol,
            )
            if read_packet(observer) != (
                expected_delivery[0], expected_delivery[2:],
            ):
                raise AssertionError(
                    f"unexpected released QoS 2 delivery v{protocol}"
                )
            baseline_size = journal.stat().st_size
            observer.sendall(ack_packet(0x40, 1))
            observer.sendall(b"\xc0\x00")
            if read_packet(observer) != (0xD0, b""):
                raise AssertionError(
                    f"unexpected incoming QoS 2 completion barrier v{protocol}"
                )
            wait_for_journal_growth(journal, baseline_size)
            restored.kill()
            restored.wait(timeout=5)
        finally:
            if observer is not None:
                observer.close()
            if publisher is not None:
                publisher.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()

        final_port = free_port()
        final = start_broker(executable, final_port, journal, 2)
        observer = publisher = None
        try:
            observer = connect_client(
                final_port, observer_id,
                clean_start=False, session_present=True, protocol=protocol,
            )
            publisher = connect_client(
                final_port, publisher_id,
                clean_start=False, session_present=True, protocol=protocol,
            )
            publisher.sendall(ack_packet(0x62, 3265))
            if read_packet(publisher) != (0x70, b"\x0c\xc1"):
                raise AssertionError(
                    f"repeated PUBREL was not acknowledged v{protocol}"
                )
            observer.sendall(b"\xc0\x00")
            if read_packet(observer) != (0xD0, b""):
                raise AssertionError(
                    f"inbound QoS 2 was routed more than once v{protocol}"
                )
            final.kill()
            final.wait(timeout=5)
        finally:
            if observer is not None:
                observer.close()
            if publisher is not None:
                publisher.close()
            if final.poll() is None:
                final.kill()
                final.wait()
