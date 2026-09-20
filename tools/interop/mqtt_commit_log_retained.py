"""Crash recovery checks for MQTT retained-message mutations."""

from __future__ import annotations

from pathlib import Path
import tempfile

from mqtt_commit_log_support import (
    connect_client,
    free_port,
    qos0_publish_packet,
    read_packet,
    start_broker,
    subscribe_packet,
    wait_for_journal_growth,
)


def verify_retained_delete_recovery(executable: Path) -> None:
    """Persist two retained values, delete one, and survive both crashes."""
    for protocol in (4, 5):
        _verify_retained_delete_recovery(executable, protocol)


def _verify_retained_delete_recovery(
    executable: Path, protocol: int,
) -> None:
    topic_one = f"journal/retain/v{protocol}/one"
    topic_two = f"journal/retain/v{protocol}/two"
    filter_name = f"journal/retain/v{protocol}/#"
    payload_one = b"retained-one"
    payload_two = b"retained-two"

    with tempfile.TemporaryDirectory(
        prefix=f"netz-mqtt-retain-v{protocol}-journal-"
    ) as raw:
        journal = Path(raw) / "broker.log"
        port = free_port()
        broker = start_broker(executable, port, journal, 1)
        client = None
        try:
            client = connect_client(
                port, f"journal-retain-writer-v{protocol}",
                clean_start=True, session_present=False, protocol=protocol,
                session_expiry=0,
            )
            for topic, payload in (
                (topic_one, payload_one),
                (topic_two, payload_two),
            ):
                baseline_size = journal.stat().st_size
                client.sendall(qos0_publish_packet(
                    topic, payload, retain=True, protocol=protocol,
                ))
                client.sendall(b"\xc0\x00")
                if read_packet(client) != (0xD0, b""):
                    raise AssertionError(
                        f"unexpected retained-write barrier v{protocol}"
                    )
                wait_for_journal_growth(journal, baseline_size)
            broker.kill()
            broker.wait(timeout=5)
        finally:
            if client is not None:
                client.close()
            if broker.poll() is None:
                broker.kill()
                broker.wait()

        restored_port = free_port()
        restored = start_broker(executable, restored_port, journal, 1)
        client = None
        try:
            client = connect_client(
                restored_port, f"journal-retain-clear-v{protocol}",
                clean_start=True, session_present=False, protocol=protocol,
                session_expiry=0,
            )
            client.sendall(subscribe_packet(
                1, filter_name, subscription_identifier=None, qos=0,
                protocol=protocol,
            ))
            expected_suback = (
                b"\x00\x01\x00\x00"
                if protocol == 5 else b"\x00\x01\x00"
            )
            if read_packet(client) != (0x90, expected_suback):
                raise AssertionError(
                    f"unexpected retained recovery SUBACK v{protocol}"
                )
            expected = {
                _packet_tuple(qos0_publish_packet(
                    topic_one, payload_one, retain=True, protocol=protocol,
                )),
                _packet_tuple(qos0_publish_packet(
                    topic_two, payload_two, retain=True, protocol=protocol,
                )),
            }
            actual = {read_packet(client), read_packet(client)}
            if actual != expected:
                raise AssertionError(
                    f"unexpected retained recovery set v{protocol}: {actual!r}"
                )

            baseline_size = journal.stat().st_size
            client.sendall(qos0_publish_packet(
                topic_two, b"", retain=True, protocol=protocol,
            ))
            # A retained clear is still a live empty Application Message for
            # existing subscribers, but its RETAIN flag is cleared on route.
            if read_packet(client) != _packet_tuple(qos0_publish_packet(
                topic_two, b"", retain=False, protocol=protocol,
            )):
                raise AssertionError(
                    f"unexpected live retained-clear delivery v{protocol}"
                )
            client.sendall(b"\xc0\x00")
            if read_packet(client) != (0xD0, b""):
                raise AssertionError(
                    f"unexpected retained-clear barrier v{protocol}"
                )
            wait_for_journal_growth(journal, baseline_size)
            restored.kill()
            restored.wait(timeout=5)
        finally:
            if client is not None:
                client.close()
            if restored.poll() is None:
                restored.kill()
                restored.wait()

        final_port = free_port()
        final = start_broker(executable, final_port, journal, 1)
        client = None
        try:
            client = connect_client(
                final_port, f"journal-retain-reader-v{protocol}",
                clean_start=True, session_present=False, protocol=protocol,
                session_expiry=0,
            )
            client.sendall(subscribe_packet(
                1, filter_name, subscription_identifier=None, qos=0,
                protocol=protocol,
            ))
            expected_suback = (
                b"\x00\x01\x00\x00"
                if protocol == 5 else b"\x00\x01\x00"
            )
            if read_packet(client) != (0x90, expected_suback):
                raise AssertionError(
                    f"unexpected final retained SUBACK v{protocol}"
                )
            if read_packet(client) != _packet_tuple(qos0_publish_packet(
                topic_one, payload_one, retain=True, protocol=protocol,
            )):
                raise AssertionError(
                    f"unaffected retained sibling was not restored v{protocol}"
                )
            client.sendall(b"\xc0\x00")
            if read_packet(client) != (0xD0, b""):
                raise AssertionError(
                    f"deleted retained message reappeared v{protocol}"
                )
            final.kill()
            final.wait(timeout=5)
        finally:
            if client is not None:
                client.close()
            if final.poll() is None:
                final.kill()
                final.wait()


def _packet_tuple(encoded: bytes) -> tuple[int, bytes]:
    if encoded[1] >= 0x80:
        raise AssertionError("test packet unexpectedly uses multibyte length")
    if encoded[1] != len(encoded) - 2:
        raise AssertionError("invalid expected MQTT packet length")
    return encoded[0], encoded[2:]
