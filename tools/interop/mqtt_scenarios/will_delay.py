"""Source-locked MQTT 5 delayed Will and Session replacement process cases."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import time
from typing import Callable, Iterator

from mqtt_commit_log_support import (
    connect_client, free_port, packet, qos0_publish_packet, subscribe_packet,
)
from mqtt_broker_config_persistence_support import (
    configured_broker, expect_packet, ping,
)


_PAYLOAD = b"will delay"
_DELAY = 3


def quiet_until(sock: socket.socket, deadline: float, label: str) -> None:
    """Prove a live observer receives no byte through one monotonic deadline."""
    timeout = sock.gettimeout()
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"{label}: quiet observation deadline already passed")
        sock.settimeout(remaining)
        try:
            unexpected = sock.recv(1)
        except socket.timeout:
            return
        if not unexpected:
            raise AssertionError(f"{label}: observer closed during quiet interval")
        raise AssertionError(f"{label}: unexpected MQTT byte {unexpected.hex()}")
    finally:
        sock.settimeout(timeout)


def _close_source(sock: socket.socket, reason: int | None = None) -> float:
    started = time.monotonic()
    try:
        if reason is not None:
            sock.sendall(packet(0xE0, bytes((reason,)) if reason else b""))
        # An MQTT-ungraceful EOF is observable at the server before the next
        # CONNECT. This avoids a sleep or racing a still-live source takeover.
        sock.shutdown(socket.SHUT_WR)
        if sock.recv(1) != b"":
            raise AssertionError("unexpected MQTT bytes before source transport EOF")
    finally:
        sock.close()
    return started


@contextmanager
def _observer(
    broker: Path, directory: Path, label: str, connections: int, topic: str,
) -> Iterator[tuple[int, socket.socket]]:
    port = free_port()
    config = directory / f"{label}.conf"
    config.write_text(
        f"sys_interval 0\nallow_anonymous true\nlistener {port} 127.0.0.1\n"
        f"max_connections {connections}\nset_tcp_nodelay true\n"
    )
    with configured_broker(broker, config, connections, label):
        observer = connect_client(
            port, f"{label}-reader", clean_start=True,
            session_present=False, session_expiry=0,
        )
        try:
            observer.sendall(subscribe_packet(
                1, topic, subscription_identifier=None, qos=0,
            ))
            expect_packet(observer, packet(0x90, b"\x00\x01\x00\x00"), f"{label}: SUBACK")
            yield port, observer
            _close_source(observer, 0)
        finally:
            observer.close()


def _source(
    port: int, client_id: str, topic: str, *, clean: bool, expiry: int,
    delay: int, qos: int = 0, payload: bytes = _PAYLOAD, present: bool = False,
) -> socket.socket:
    return connect_client(
        port, client_id, clean_start=clean, session_present=present,
        session_expiry=expiry, will_topic=topic, will_payload=payload,
        will_delay=delay, will_qos=qos,
    )


def _timed_will(
    observer: socket.socket, topic: str, payload: bytes,
    started: float, delay: int, label: str,
) -> None:
    # Mosquitto's seconds clock permits [delay-1, delay+2]. For expiry-before-
    # delay this upper bound is tightened below the wrong later deadline.
    lower = max(0.0, delay - 1.0)
    upper = delay + 1.5 if delay else 2.0
    timeout = observer.gettimeout()
    observer.settimeout(upper)
    try:
        expect_packet(observer, qos0_publish_packet(topic, payload, retain=False), label)
    finally:
        observer.settimeout(timeout)
    elapsed = time.monotonic() - started
    if not lower <= elapsed < upper:
        raise AssertionError(
            f"{label}: Will arrived after {elapsed:.3f}s, expected [{lower}, {upper})"
        )
    ping(observer, f"{label}: exact one Will")


def _cleanup(
    port: int, client_id: str, observer: socket.socket,
    *, present: bool, label: str,
) -> None:
    cleanup = connect_client(
        port, client_id, clean_start=False,
        session_present=present, session_expiry=0,
    )
    _close_source(cleanup, 0)
    ping(observer, f"{label}: Session cleanup cannot replay Will")


def _delivery(
    broker: Path, directory: Path, label: str, topic: str, client_id: str,
    *, delay: int, expiry: int, clean: bool = True, reason: int | None = None,
) -> None:
    with _observer(broker, directory, label, 3, topic) as (port, observer):
        source = _source(
            port, client_id, topic, clean=clean, expiry=expiry, delay=delay, qos=2,
        )
        try:
            started = _close_source(source, reason)
            _timed_will(observer, topic, _PAYLOAD, started, min(delay, expiry), label)
            _cleanup(port, client_id, observer, present=expiry > delay, label=label)
        finally:
            source.close()


def _reconnect_without_will(broker: Path, directory: Path) -> None:
    label = "will-delay-reconnect"
    topic = "will/delay/reconnect/test"
    client_id = "will-delay-reconnect-helper"
    with _observer(broker, directory, label, 4, topic) as (port, observer):
        source = _source(port, client_id, topic, clean=False, expiry=60, delay=_DELAY)
        replacement: socket.socket | None = None
        try:
            started = _close_source(source)
            replacement = connect_client(
                port, client_id, clean_start=False,
                session_present=True, session_expiry=0,
            )
            quiet_until(
                observer, started + _DELAY + 1,
                f"{label}: resumed Session cancels old Will",
            )
            ping(observer, f"{label}: no old Will after its deadline")
            _close_source(replacement)
            ping(observer, f"{label}: ending resumed Session cannot resurrect old Will")
            _cleanup(port, client_id, observer, present=False, label=label)
        finally:
            source.close()
            if replacement is not None:
                replacement.close()


def _recovery(
    broker: Path, directory: Path, clean: bool,
    *, replacement_payload: bytes = _PAYLOAD,
) -> None:
    variant = "upstream" if replacement_payload == _PAYLOAD else "owned"
    label = f"will-delay-recover-{int(clean)}-{variant}"
    topic = "will/delay/recovery/test"
    client_id = "will-delay-recovery-helper"
    with _observer(broker, directory, label, 4, topic) as (port, observer):
        source = _source(port, client_id, topic, clean=clean, expiry=30, delay=_DELAY)
        replacement: socket.socket | None = None
        try:
            started = _close_source(source)
            replacement_started = time.monotonic()
            replacement = _source(
                port, client_id, topic, clean=clean, expiry=30, delay=_DELAY,
                present=not clean, payload=replacement_payload,
            )
            if clean:
                _timed_will(
                    observer, topic, _PAYLOAD, replacement_started, 0,
                    f"{label}: Clean Start ends old Session",
                )
            quiet_until(
                observer, started + _DELAY + 1,
                f"{label}: live replacement has no premature or duplicate Will",
            )
            ping(observer, f"{label}: old deadline passed")
            replacement_closed = _close_source(replacement)
            _timed_will(
                observer, topic, replacement_payload, replacement_closed, _DELAY,
                f"{label}: replacement owns its new Will",
            )
            _cleanup(port, client_id, observer, present=True, label=label)
        finally:
            source.close()
            if replacement is not None:
                replacement.close()


def _normal_disconnect(broker: Path, directory: Path) -> None:
    label = "will-delay-normal-disconnect"
    topic = "will/delay/normal/test"
    client_id = "will-delay-normal-helper"
    with _observer(broker, directory, label, 3, topic) as (port, observer):
        source = _source(port, client_id, topic, clean=False, expiry=60, delay=_DELAY)
        try:
            started = _close_source(source, 0)
            quiet_until(
                observer, started + _DELAY + 1,
                f"{label}: normal DISCONNECT removes delayed Will",
            )
            ping(observer, f"{label}: no Will after its original deadline")
            _cleanup(port, client_id, observer, present=True, label=label)
        finally:
            source.close()


def run_will_delay_cases(broker: Path, directory: Path) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []

    def run(case: str, source: str | None, operation: Callable[[], None], **profile: object) -> None:
        started = time.monotonic_ns()
        operation()
        results.append({
            "case": case, "source": source, "protocol": 5,
            "elapsed_ns": time.monotonic_ns() - started,
            "complete": True, **profile,
        })

    for clean in (True, False):
        run(
            f"delay-clean-{int(clean)}", "broker/07-will-delay.py",
            lambda: _delivery(
                broker, directory, f"will-delay-{int(clean)}",
                "will/delay/test", "will-delay-helper",
                delay=3, expiry=60, clean=clean,
            ),
            clean_start=clean, will_delay=3, session_expiry=60,
        )
    for case, source, topic, client_id, delay, expiry in (
        ("expiry-before-delay", "07-will-delay-session-expiry.py",
         "will/session-expiry/test", "will-session-exp-helper", 4, 2),
        ("delay-before-expiry", "07-will-delay-session-expiry2.py",
         "will/session/expiry2/test", "will-session-exp2-helper", 2, 4),
        ("immediate-expiry", "07-will-delay-session-expiry-0.py",
         "will/session-expiry/test", "will-session-exp-helper", 60, 0),
    ):
        run(
            case, f"broker/{source}",
            lambda: _delivery(
                broker, directory, case, topic, client_id,
                delay=delay, expiry=expiry,
            ),
            clean_start=True, will_delay=delay, session_expiry=expiry,
        )
    run(
        "reconnect-without-will", "broker/07-will-delay-reconnect.py",
        lambda: _reconnect_without_will(broker, directory),
        clean_start=False, will_delay=3, session_expiry=60,
        replacement_has_will=False, replacement_session_expiry=0,
    )
    for clean in (True, False):
        run(
            f"recover-clean-{int(clean)}", "broker/07-will-delay-recover.py",
            lambda: _recovery(broker, directory, clean),
            clean_start=clean, will_delay=3, session_expiry=30,
            replacement_has_will=True,
        )
    run(
        "disconnect-with-will", "broker/07-will-disconnect-with-will.py",
        lambda: _delivery(
            broker, directory, "will-disconnect-with-will",
            "will/with/disconnect/test", "will-with-disconnect-helper",
            delay=0, expiry=0, reason=4,
        ),
        clean_start=True, will_delay=0, session_expiry=0, disconnect_reason=4,
    )
    # Extra cause and ownership phases beyond the nine upstream scenarios.
    run(
        "delayed-disconnect-with-will", None,
        lambda: _delivery(
            broker, directory, "will-delay-disconnect-with-will",
            "will/with/disconnect/test", "will-with-disconnect-helper",
            delay=3, expiry=60, reason=4,
        ),
        clean_start=True, will_delay=3, session_expiry=60, disconnect_reason=4,
    )
    run(
        "normal-disconnect", None,
        lambda: _normal_disconnect(broker, directory),
        clean_start=False, will_delay=3, session_expiry=60, disconnect_reason=0,
    )
    run(
        "replacement-payload-ownership", None,
        lambda: _recovery(
            broker, directory, True,
            replacement_payload=b"replacement owns this Will",
        ),
        clean_start=True, will_delay=3, session_expiry=30,
        replacement_has_will=True, distinct_replacement_payload=True,
    )
    return results
