"""Mosquitto-derived outbound bridge queue persistence scenario."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import subprocess

from mqtt_broker_config_bridge import (
    _connect_client,
    _distinct_ports,
    _expect_bridge_state,
    _publish_message,
    _read_packet,
    _read_publish_and_ack,
    _start_broker,
    _stop,
    _subscribe_client,
    _wait_for_log,
    _wait_for_log_count,
)
from mqtt_commit_log_support import (
    connect_client as connect_persistent_client,
    read_packet as read_mqtt_packet,
    subscribe_packet,
)


_MESSAGE_COUNT = 16
_STATE_TOPIC = "bridge/persistent-queue/state"
_LOCAL_TOPIC = "local/sensors/queue"
_REMOTE_TOPIC = "remote/sensors/queue"


def _checkpoint(
    process: subprocess.Popen[bytes],
    log: Path,
    label: str,
) -> None:
    os.kill(process.pid, signal.SIGUSR1)
    _wait_for_log_count(
        process,
        log,
        "persistence checkpoint completed: source=SIGUSR1",
        1,
    )
    if process.poll() is not None:
        raise RuntimeError(f"{label} exited during persistence checkpoint")


def _connect_target_subscriber(
    port: int,
    session_present: bool,
) -> socket.socket:
    subscriber = connect_persistent_client(
        port,
        "persistent-queue-target-subscriber",
        clean_start=False,
        session_present=session_present,
        protocol=5,
        session_expiry=3600,
    )
    if not session_present:
        subscriber.sendall(subscribe_packet(
            1,
            "remote/sensors/#",
            subscription_identifier=None,
            qos=1,
            protocol=5,
        ))
        if read_mqtt_packet(subscriber) != (
            0x90,
            b"\x00\x01\x00\x01",
        ):
            subscriber.close()
            raise AssertionError(
                "persistent bridge target subscriber SUBACK mismatch"
            )
    return subscriber


def _disconnect_persistent(client: socket.socket, label: str) -> None:
    client.sendall(b"\xe0\x00")
    if client.recv(1) != b"":
        raise AssertionError(f"{label} remained open after DISCONNECT")
    client.close()


def run_outbound_bridge_persistent_queue_case(
    broker: Path,
    directory: Path,
) -> None:
    """Drain a target-offline QoS 1 queue after both brokers restart."""
    remote_port, local_port = _distinct_ports(2)
    remote_config = directory / "persistent-queue-remote.conf"
    remote_snapshot = directory / "persistent-queue-remote.db"
    remote_config.write_text(
        "persistence true\n"
        f"persistence_location {directory}\n"
        f"persistence_file {remote_snapshot.name}\n"
        "autosave_interval 0\n"
        f"listener {remote_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 8\n"
    )
    local_config = directory / "persistent-queue-local.conf"
    local_snapshot = directory / "persistent-queue-local.db"
    local_config.write_text(
        "persistence true\n"
        f"persistence_location {directory}\n"
        f"persistence_file {local_snapshot.name}\n"
        "autosave_interval 0\n"
        f"listener {local_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 8\n"
        "max_queued_messages 32\n"
        "connection persistent-queue\n"
        f"address 127.0.0.1:{remote_port}\n"
        "topic sensors/# out 1 local/ remote/\n"
        "cleansession false\n"
        "bridge_protocol_version mqttv50\n"
        "bridge_session_expiry_interval 3600\n"
        "remote_clientid configured-persistent-queue\n"
        "start_type lazy\n"
        "threshold 1\n"
        "idle_timeout 1\n"
        f"notification_topic {_STATE_TOPIC}\n"
        "restart_timeout 1\n"
    )
    remote_log = directory / "persistent-queue-remote.log"
    local_log = directory / "persistent-queue-local.log"
    remote = local = None
    remote_output = local_output = None
    subscriber = local_observer = publisher = None
    try:
        remote, remote_output = _start_broker(
            broker,
            remote_config,
            remote_log,
            finite=False,
        )
        _wait_for_log(remote, remote_log, "configured 1 listeners")
        subscriber = _connect_target_subscriber(remote_port, False)

        local, local_output = _start_broker(
            broker,
            local_config,
            local_log,
            finite=False,
        )
        _wait_for_log(local, local_log, "bridge persistent-queue remote=")
        local_observer = _connect_client(
            local_port,
            "persistent-queue-local-observer",
        )
        _subscribe_client(local_observer, 1, _STATE_TOPIC, 1)
        publisher = _connect_client(
            local_port,
            "persistent-queue-local-publisher",
        )

        _publish_message(
            publisher,
            1,
            b"warmup",
            1,
            topic=_LOCAL_TOPIC,
        )
        _expect_bridge_state(local_observer, _STATE_TOPIC, b"1")
        topic, payload = _read_publish_and_ack(subscriber)
        if (topic, payload) != (_REMOTE_TOPIC, b"warmup"):
            raise AssertionError(
                f"persistent bridge warmup mismatch: {(topic, payload)!r}"
            )
        _expect_bridge_state(local_observer, _STATE_TOPIC, b"0")

        _disconnect_persistent(subscriber, "bridge target subscriber")
        subscriber = None
        _checkpoint(remote, remote_log, "bridge target broker")
        remote.kill()
        remote.wait(timeout=5)
        remote_output.close()
        remote = remote_output = None

        for index in range(_MESSAGE_COUNT):
            _publish_message(
                publisher,
                index + 10,
                f"queued-{index:03}".encode(),
                1,
                topic=_LOCAL_TOPIC,
            )
        publisher.sendall(b"\xc0\x00")
        if _read_packet(publisher) != b"\xd0\x00":
            raise AssertionError("local queued publisher PINGRESP mismatch")
        _checkpoint(local, local_log, "local bridge broker")
        local.kill()
        local.wait(timeout=5)
        local_output.close()
        local = local_output = None
        publisher.close()
        publisher = None
        local_observer.close()
        local_observer = None

        remote, remote_output = _start_broker(
            broker,
            remote_config,
            remote_log,
            finite=False,
        )
        _wait_for_log(remote, remote_log, "configured 1 listeners")
        subscriber = _connect_target_subscriber(remote_port, True)
        subscriber.sendall(b"\xc0\x00")
        if read_mqtt_packet(subscriber) != (0xD0, b""):
            raise AssertionError("target Session had stale pre-bridge delivery")

        local, local_output = _start_broker(
            broker,
            local_config,
            local_log,
            finite=False,
        )
        _wait_for_log(local, local_log, "bridge persistent-queue remote=")
        local_observer = _connect_client(
            local_port,
            "persistent-queue-local-observer-restored",
        )
        _subscribe_client(local_observer, 1, _STATE_TOPIC, 1)
        _expect_bridge_state(local_observer, _STATE_TOPIC, b"1")
        for index in range(_MESSAGE_COUNT):
            topic, payload = _read_publish_and_ack(subscriber)
            expected = f"queued-{index:03}".encode()
            if (topic, payload) != (_REMOTE_TOPIC, expected):
                raise AssertionError(
                    "persistent bridge queue order mismatch: "
                    f"expected {expected!r}, got {(topic, payload)!r}"
                )
        _expect_bridge_state(local_observer, _STATE_TOPIC, b"0")
        subscriber.sendall(b"\xc0\x00")
        if _read_packet(subscriber) != b"\xd0\x00":
            raise AssertionError("persistent bridge queue delivered duplicates")

        _checkpoint(local, local_log, "drained local bridge broker")
        local.kill()
        local.wait(timeout=5)
        local_output.close()
        local = local_output = None
        local_observer.close()
        local_observer = None

        local, local_output = _start_broker(
            broker,
            local_config,
            local_log,
            finite=False,
        )
        _wait_for_log(local, local_log, "bridge persistent-queue remote=")
        local_observer = _connect_client(
            local_port,
            "persistent-queue-local-observer-final",
        )
        _subscribe_client(local_observer, 1, _STATE_TOPIC, 1)
        _expect_bridge_state(local_observer, _STATE_TOPIC, b"0")
        subscriber.sendall(b"\xc0\x00")
        if _read_packet(subscriber) != b"\xd0\x00":
            raise AssertionError(
                "drained persistent bridge queue revived after restart"
            )
        subscriber.sendall(b"\xe0\x00")
        subscriber.close()
        subscriber = None
    finally:
        if publisher is not None:
            publisher.close()
        if subscriber is not None:
            subscriber.close()
        if local_observer is not None:
            local_observer.close()
        if local is not None and local_output is not None:
            _stop(local, local_output)
        if remote is not None and remote_output is not None:
            _stop(remote, remote_output)
