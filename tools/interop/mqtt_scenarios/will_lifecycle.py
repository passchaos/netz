"""Mosquitto Will QoS0 and publication-time ACL process scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import signal
import socket
import subprocess
from typing import Iterator

from mqtt_commit_log_support import (
    connect_client, free_port, packet, qos0_publish_packet,
    subscribe_packet,
)
from mqtt_broker_config_persistence_support import (
    configured_broker, expect_packet, ping,
)
from mqtt_scenarios.process import wait_process_line


_TOPIC = "will/qos0/test"
_PAYLOAD = b"will-message"


def _disconnect(sock: socket.socket, *, with_will: bool = False) -> None:
    try:
        sock.sendall(packet(0xE0, b"\x04" if with_will else b""))
        sock.shutdown(socket.SHUT_WR)
        if sock.recv(1) != b"":
            raise AssertionError("unexpected bytes after client DISCONNECT")
    finally:
        sock.close()


def _subscribe(sock: socket.socket, protocol: int, topic: str, mid: int) -> None:
    sock.sendall(subscribe_packet(
        mid, topic, subscription_identifier=None, qos=0, protocol=protocol,
    ))
    expect_packet(
        sock,
        packet(0x90, mid.to_bytes(2, "big") + (b"\x00" if protocol == 5 else b"") + b"\x00"),
        f"MQTT {protocol} Will SUBACK {topic}",
    )


def _upstream_case(broker: Path, directory: Path, protocol: int, clean: bool, per_listener: bool) -> None:
    port = free_port()
    label = f"will-qos0-{protocol}-{int(clean)}-{int(per_listener)}"
    config = directory / f"{label}.conf"
    config.write_text(
        "sys_interval 0\n"
        + ("per_listener_settings true\n" if per_listener else "allow_anonymous true\n")
        + f"listener {port} 127.0.0.1\n"
        + ("allow_anonymous true\n" if per_listener else "")
        + "max_connections 3\n"
    )
    with configured_broker(broker, config, 3, label):
        observer = connect_client(
            port, "will-qos0-test", clean_start=True,
            session_present=False, protocol=protocol, session_expiry=0,
        )
        source_id = "test-helper" if per_listener else "will-qos0-helper"
        source: socket.socket | None = None
        cleanup: socket.socket | None = None
        try:
            _subscribe(observer, protocol, _TOPIC, 53)
            source = connect_client(
                port, source_id, clean_start=clean, session_present=False,
                protocol=protocol, session_expiry=60,
                will_topic=_TOPIC, will_payload=_PAYLOAD,
            )
            source.close()  # The exact upstream ungraceful network close.
            source = None
            expect_packet(observer, qos0_publish_packet(
                _TOPIC, _PAYLOAD, retain=False, protocol=protocol,
            ), label)
            ping(observer, f"{label}: one Will and no trailing delivery")
            # Keep the observer alive through Session cleanup, strengthening
            # the upstream reconnect phase with a duplicate-Will barrier.
            cleanup = connect_client(
                port, source_id, clean_start=True, session_present=False,
                protocol=protocol, session_expiry=0,
            )
            _disconnect(cleanup)
            cleanup = None
            ping(observer, f"{label}: Session cleanup cannot replay Will")
            _disconnect(observer)
        finally:
            observer.close()
            if source is not None:
                source.close()
            if cleanup is not None:
                cleanup.close()


@contextmanager
def _reload_broker(broker: Path, config: Path, label: str) -> Iterator[subprocess.Popen[str]]:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True,
    )
    assert process.stdout is not None
    try:
        wait_process_line(process, "configured 1 listeners for 4 clients", label)
        wait_process_line(process, "mqtt ", f"{label}: listener")
        yield process
        if process.wait(timeout=5) != 0:
            raise AssertionError(f"{label}: broker failed: {process.stdout.read()}")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process.stdout.close()


def _reload_case(broker: Path, directory: Path, per_listener: bool) -> None:
    port = free_port()
    label = f"will-acl-reload-{int(per_listener)}"
    acl = directory / f"{label}.acl"
    config = directory / f"{label}.conf"
    allow = "topic read will/#\ntopic write will/#\n"
    deny = "topic read will/#\ntopic write will/allowed\n"
    acl.write_text(allow)
    policy = f"allow_anonymous true\nacl_file {acl}\n"
    config.write_text(
        "sys_interval 0\n"
        + ("per_listener_settings true\n" if per_listener else policy)
        + f"listener {port} 127.0.0.1\n"
        + (policy if per_listener else "")
        + "max_connections 4\n"
    )
    with _reload_broker(broker, config, label) as process:
        observer = connect_client(
            port, "will-reload-reader", clean_start=True,
            session_present=False, session_expiry=0,
        )
        clients = [observer]
        try:
            _subscribe(observer, 5, "will/#", 53)
            sources = {}
            for topic in ("allowed", "blocked"):
                source = connect_client(
                    port, f"will-reload-{topic}", clean_start=True,
                    session_present=False, session_expiry=60,
                    will_topic=f"will/{topic}",
                    will_payload=f"{topic}-will".encode(), will_retain=True,
                )
                sources[topic] = source
                clients.append(source)
            acl.write_text(deny)
            process.send_signal(signal.SIGHUP)
            wait_process_line(process, "security reload completed", f"{label}: deny reload")
            for source in sources.values():
                ping(source, f"{label}: source survives ACL reload")
            _disconnect(sources["blocked"], with_will=True)
            _disconnect(sources["allowed"], with_will=True)
            expect_packet(observer, qos0_publish_packet(
                "will/allowed", b"allowed-will", retain=False,
            ), f"{label}: currently allowed Will")
            ping(observer, f"{label}: denied Will was not routed")
            acl.write_text(allow)
            process.send_signal(signal.SIGHUP)
            wait_process_line(process, "security reload completed", f"{label}: allow reload")
            ping(observer, f"{label}: denied Will cannot resurrect")
            _subscribe(observer, 5, "will/blocked", 54)
            ping(observer, f"{label}: denied Will did not create retained state")
            _subscribe(observer, 5, "will/allowed", 55)
            expect_packet(observer, qos0_publish_packet(
                "will/allowed", b"allowed-will", retain=True,
            ), f"{label}: allowed retained Will survives source teardown")
            cleanup = connect_client(
                port, "will-reload-blocked", clean_start=True,
                session_present=False, session_expiry=0,
            )
            clients.append(cleanup)
            _disconnect(cleanup)
            ping(observer, f"{label}: source Session cleanup cannot replay denied Will")
            _disconnect(observer)
        finally:
            for client in clients:
                client.close()


def run_will_lifecycle_case(broker: Path, directory: Path) -> None:
    for per_listener in (False, True):
        for protocol in (4, 5):
            for clean in (True, False):
                _upstream_case(broker, directory, protocol, clean, per_listener)
        _reload_case(broker, directory, per_listener)
