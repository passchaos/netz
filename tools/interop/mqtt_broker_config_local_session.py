"""Configured outbound-bridge local Session lifecycle checks."""

from pathlib import Path
import socket

from mqtt_broker_config_bridge import (
    _connect_client,
    _distinct_ports,
    _expect_bridge_state,
    _packet,
    _read_publish_and_ack,
    _start_broker,
    _stop,
    _subscribe_client,
    _utf8,
    _wait_for_log,
)


def _publish_qos0(client: socket.socket, payload: bytes) -> None:
    client.sendall(
        _packet(0x30, _utf8("local/session/value") + b"\x00" + payload)
    )


def run_local_clean_session_case(broker: Path, directory: Path) -> None:
    remote_port, local_port = _distinct_ports(2)
    remote_config = directory / "local-clean-remote.conf"
    remote_config.write_text(
        f"listener {remote_port} 127.0.0.1\nallow_anonymous true\n"
        "max_connections 4\n"
    )
    local_config = directory / "local-clean.conf"
    local_config.write_text(
        f"persistence true\npersistence_location {directory}\n"
        "persistence_file local-clean.db\nqueue_qos0_messages true\n"
        f"listener {local_port} 127.0.0.1\nallow_anonymous true\n"
        "max_connections 4\nconnection local-clean\n"
        f"address 127.0.0.1:{remote_port}\n"
        "topic session/# out 0 local/ remote/\n"
        "cleansession false\nlocal_cleansession true\n"
        "local_clientid configured-local-source\n"
        "bridge_protocol_version mqttv50\n"
        "bridge_session_expiry_interval 0xFFFFFFFF\n"
        "remote_clientid configured-local-clean\n"
        "notification_topic bridge/local-clean/state\nrestart_timeout 1\n"
    )
    remote_log = directory / "local-clean-remote.log"
    local_log = directory / "local-clean.log"
    notification = "bridge/local-clean/state"
    remote = remote_output = local = local_output = None
    subscriber = publisher = local_observer = None
    try:
        remote, remote_output = _start_broker(
            broker, remote_config, remote_log, finite=False
        )
        _wait_for_log(remote, remote_log, "configured 1 listeners")
        subscriber = _connect_client(remote_port, "local-clean-observer")
        _subscribe_client(subscriber, 1, notification, 1)
        _subscribe_client(subscriber, 2, "remote/session/#", 0)
        local, local_output = _start_broker(
            broker, local_config, local_log, finite=False
        )
        _wait_for_log(local, local_log, "bridge local-clean remote=")
        _expect_bridge_state(subscriber, notification, b"1")
        publisher = _connect_client(local_port, "local-clean-publisher")
        local_observer = _connect_client(local_port, "local-clean-local-observer")
        _subscribe_client(local_observer, 1, notification, 1)
        _expect_bridge_state(local_observer, notification, b"1")

        subscriber.close()
        subscriber = None
        _stop(remote, remote_output)
        remote = remote_output = None
        _expect_bridge_state(local_observer, notification, b"0")
        _publish_qos0(publisher, b"stale-before-restart")
        _stop(local, local_output)
        local = local_output = None
        publisher.close()
        publisher = None
        local_observer.close()
        local_observer = None

        remote, remote_output = _start_broker(
            broker, remote_config, remote_log, finite=False
        )
        _wait_for_log(remote, remote_log, "configured 1 listeners")
        subscriber = _connect_client(remote_port, "local-clean-observer-after")
        _subscribe_client(subscriber, 1, notification, 1)
        _subscribe_client(subscriber, 2, "remote/session/#", 0)
        local, local_output = _start_broker(
            broker, local_config, local_log, finite=False
        )
        _wait_for_log(local, local_log, "bridge local-clean remote=")
        _expect_bridge_state(subscriber, notification, b"1")
        subscriber.settimeout(0.3)
        try:
            stale = _read_publish_and_ack(subscriber)
        except socket.timeout:
            pass
        else:
            raise AssertionError(
                f"local clean Session replayed stale delivery: {stale!r}"
            )
        finally:
            subscriber.settimeout(10)

        publisher = _connect_client(local_port, "local-clean-publisher-after")
        _publish_qos0(publisher, b"fresh-after-restart")
        topic, payload = _read_publish_and_ack(subscriber)
        if (topic, payload) != (
            "remote/session/value",
            b"fresh-after-restart",
        ):
            raise AssertionError(
                f"local clean Session lost fresh delivery: {(topic, payload)!r}"
            )
    finally:
        if publisher is not None:
            publisher.close()
        if local_observer is not None:
            local_observer.close()
        if subscriber is not None:
            subscriber.close()
        if local is not None:
            _stop(local, local_output)
        if remote is not None:
            _stop(remote, remote_output)
