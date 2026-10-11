"""Production outbound configuration, local consumer and coordinator restart."""

from pathlib import Path
import socket
import time

from mqtt_broker_config_bridge import (
    _distinct_ports, _start_broker, _stop, _wait_for_log,
    _connect_client, _subscribe_client, _expect_bridge_state,
    _read_publish_and_ack, _packet, _utf8, _read_packet,
    _create_tls_material, _connect_tls_client, _expect_startup_rejection,
    _openssl,
)


def run_outbound_bridge_case(broker: Path, directory: Path, *, tls: bool = False) -> None:
    remote_port, local_port, unavailable_port = _distinct_ports(3)
    remote_tls = local_tls = ""
    if tls:
        ca, cert, key, client_cert, client_key = _create_tls_material(directory)
        server_ca_path = directory / "outbound-server-capath"
        server_ca_path.mkdir()
        (server_ca_path / "server-root.pem").write_bytes(ca.read_bytes())
        _openssl("rehash", server_ca_path)
        if not any(entry.is_symlink() for entry in server_ca_path.iterdir()):
            raise AssertionError("openssl rehash did not create bridge_capath links")
        encrypted_key = directory / "outbound-client-encrypted.pem"
        key_password = directory / "outbound-client.password"
        key_password.write_text("outbound-secret\n")
        _openssl("pkcs8", "-topk8", "-in", client_key, "-out", encrypted_key,
                 "-v2", "aes-256-cbc", "-iter", 2048, "-passout", "pass:outbound-secret")
        remote_tls = f"certfile {cert}\nkeyfile {key}\ncafile {ca}\nrequire_certificate true\n"
        local_tls = (f"bridge_capath {server_ca_path}\nbridge_certfile {client_cert}\n"
                     f"bridge_keyfile {encrypted_key}\nbridge_keyfile_password_file {key_password}\n"
                     "bridge_alpn mqtt\nbridge_tls_version tlsv1.3\n")
    remote_config = directory / "outbound-remote.conf"
    remote_config.write_text(
        f"listener {remote_port} 127.0.0.1\n{remote_tls}allow_anonymous true\n"
        "max_connections 4\n"
    )
    local_config = directory / "outbound-local.conf"
    local_config.write_text(
        f"persistence true\npersistence_location {directory}\n"
        "persistence_file outbound-local.db\n"
        f"listener {local_port} 127.0.0.1\nallow_anonymous true\n"
        "max_connections 4\nconnection outbound\n"
        f"address localhost:{unavailable_port} localhost:{remote_port}\n"
        "round_robin true\n"
        "topic sensors/# out 2 local/ remote/\n"
        "cleansession false\nbridge_protocol_version mqttv50\n"
        "bridge_session_expiry_interval 0xFFFFFFFF\n"
        f"remote_clientid configured-outbound\nrestart_timeout 1\n{local_tls}"
    )
    remote_log = directory / "outbound-remote.log"
    local_log = directory / "outbound-local.log"
    remote, remote_output = _start_broker(broker, remote_config, remote_log)
    local = local_output = subscriber = publisher = None
    try:
        _wait_for_log(remote, remote_log, "configured 1 listeners")
        local, local_output = _start_broker(broker, local_config, local_log)
        _wait_for_log(local, local_log, "bridge outbound remote=")
        subscriber = (_connect_tls_client(remote_port, "outbound-observer", ca, client_cert, client_key)
                      if tls else _connect_client(remote_port, "outbound-observer"))
        notification = "$SYS/broker/connection/configured-outbound/state"
        _subscribe_client(subscriber, 1, notification, 1)
        _expect_bridge_state(subscriber, notification, b"1")
        _subscribe_client(subscriber, 2, "remote/sensors/#", 2)
        publisher = _connect_client(local_port, "outbound-publisher")

        def publish(qos: int, packet_id: int, payload: bytes) -> None:
            body = _utf8("local/sensors/room")
            if qos:
                body += packet_id.to_bytes(2, "big")
            publisher.sendall(_packet(0x31 | qos << 1, body + b"\x00" + payload))
            if qos:
                ack = _read_packet(publisher)
                expected_type = 0x40 if qos == 1 else 0x50
                if ack[0] != expected_type or ack[2:4] != packet_id.to_bytes(2, "big"):
                    raise AssertionError(f"local publish ACK mismatch: {ack.hex()}")
                if qos == 2:
                    publisher.sendall(_packet(0x62, packet_id.to_bytes(2, "big")))
                    if _read_packet(publisher)[0] != 0x70:
                        raise AssertionError("local publish PUBCOMP missing")

        for qos in (0, 1, 2):
            payload = f"before-restart-qos{qos}".encode()
            publish(qos, qos + 10, payload)
            topic, actual = _read_publish_and_ack(subscriber)
            if (topic, actual) != ("remote/sensors/room", payload):
                raise AssertionError(f"outbound mapping mismatch: {(topic, actual)!r}")
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None
        local.kill()
        local.wait(timeout=5)
        local_output.close()
        local = local_output = None
        _expect_bridge_state(subscriber, notification, b"0")
        local, local_output = _start_broker(broker, local_config, local_log)
        _wait_for_log(local, local_log, "bridge outbound remote=")
        _expect_bridge_state(subscriber, notification, b"1")
        publisher = _connect_client(local_port, "outbound-publisher-after")
        publish(2, 20, b"after-restart")
        topic, payload = _read_publish_and_ack(subscriber)
        if (topic, payload) != ("remote/sensors/room", b"after-restart"):
            raise AssertionError("outbound journal restart lost mapping or payload")
        subscriber.sendall(b"\xc0\x00")
        if _read_packet(subscriber) != b"\xd0\x00":
            raise AssertionError("duplicate outbound delivery after restart")
    finally:
        if publisher is not None: publisher.close()
        if subscriber is not None: subscriber.close()
        if local is not None: _stop(local, local_output)
        _stop(remote, remote_output)
    if tls:
        empty_ca_path = directory / "empty-outbound-server-capath"
        empty_ca_path.mkdir()
        invalid_port = _distinct_ports(1)[0]
        invalid_config = directory / "empty-outbound-capath.conf"
        invalid_config.write_text(
            f"listener {invalid_port} 127.0.0.1\nallow_anonymous true\n"
            "connection empty-capath\naddress localhost:1\n"
            "topic # in 0\n"
            f"bridge_capath {empty_ca_path}\n"
        )
        _expect_startup_rejection(
            broker,
            invalid_config,
            invalid_port,
            "EmptyCertificateDirectory",
        )


def run_lazy_outbound_bridge_case(broker: Path, directory: Path) -> None:
    remote_port, local_port = _distinct_ports(2)
    remote_config = directory / "lazy-outbound-remote.conf"
    remote_config.write_text(
        f"listener {remote_port} 127.0.0.1\nallow_anonymous true\n"
        "max_connections 4\n"
    )
    local_config = directory / "lazy-outbound-local.conf"
    local_config.write_text(
        f"persistence true\npersistence_location {directory}\n"
        "persistence_file lazy-outbound.db\n"
        f"listener {local_port} 127.0.0.1\nallow_anonymous true\n"
        "max_connections 4\nconnection lazy-out\n"
        f"address 127.0.0.1:{remote_port}\n"
        "topic sensors/# out 2 local/ remote/\n"
        "cleansession false\nbridge_protocol_version mqttv50\n"
        "bridge_session_expiry_interval 0xFFFFFFFF\n"
        "remote_clientid configured-lazy-outbound\n"
        "start_type lazy\nthreshold 2\nidle_timeout 1\n"
        "notification_topic bridge/lazy/state\nrestart_timeout 1\n"
    )
    remote_log = directory / "lazy-outbound-remote.log"
    local_log = directory / "lazy-outbound-local.log"
    remote, remote_output = _start_broker(
        broker,
        remote_config,
        remote_log,
        finite=False,
    )
    local = local_output = subscriber = publisher = local_observer = None

    def publish(payload: bytes, packet_id: int) -> None:
        assert publisher is not None
        body = _utf8("local/sensors/lazy") + packet_id.to_bytes(2, "big")
        publisher.sendall(_packet(0x32, body + b"\x00" + payload))
        ack = _read_packet(publisher)
        if ack[0] != 0x40 or ack[2:4] != packet_id.to_bytes(2, "big"):
            raise AssertionError(f"lazy local PUBACK mismatch: {ack.hex()}")

    def expect_quiet() -> None:
        assert subscriber is not None
        subscriber.settimeout(0.3)
        try:
            packet = _read_packet(subscriber)
        except socket.timeout:
            return
        finally:
            subscriber.settimeout(10)
        raise AssertionError(f"lazy bridge connected below threshold: {packet.hex()}")

    def connect_after_restart(client_id: str) -> socket.socket:
        assert local is not None
        deadline = time.monotonic() + 3
        while True:
            try:
                return _connect_client(local_port, client_id)
            except (OSError, EOFError) as error:
                if local.poll() is not None:
                    raise RuntimeError(
                        "lazy broker exited during restart: "
                        + local_log.read_text(errors="replace")
                    ) from error
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        "lazy broker did not accept a stable post-restart "
                        "connection: "
                        + local_log.read_text(errors="replace")
                    ) from error
                time.sleep(0.02)

    try:
        _wait_for_log(remote, remote_log, "configured 1 listeners")
        local, local_output = _start_broker(
            broker,
            local_config,
            local_log,
            finite=False,
        )
        _wait_for_log(local, local_log, "bridge lazy-out remote=")
        subscriber = _connect_client(remote_port, "lazy-outbound-observer")
        _subscribe_client(subscriber, 1, "bridge/lazy/state", 1)
        _subscribe_client(subscriber, 2, "remote/#", 1)
        expect_quiet()

        publisher = _connect_client(local_port, "lazy-outbound-publisher")
        local_observer = _connect_client(local_port, "lazy-state-observer")
        _subscribe_client(local_observer, 1, "bridge/lazy/state", 1)
        publish(b"first", 1)
        expect_quiet()
        publish(b"second", 2)
        _expect_bridge_state(subscriber, "bridge/lazy/state", b"1")
        _expect_bridge_state(local_observer, "bridge/lazy/state", b"1")
        for expected in (b"first", b"second"):
            topic, payload = _read_publish_and_ack(subscriber)
            if (topic, payload) != ("remote/sensors/lazy", expected):
                raise AssertionError(
                    f"lazy outbound delivery mismatch: {(topic, payload)!r}"
                )
        _expect_bridge_state(subscriber, "bridge/lazy/state", b"0")
        _expect_bridge_state(local_observer, "bridge/lazy/state", b"0")

        publish(b"persisted-below-threshold", 3)
        expect_quiet()
        publisher.close()
        publisher = None
        local_observer.close()
        local_observer = None
        local.kill()
        local.wait(timeout=5)
        local_output.close()
        local = local_output = None

        local, local_output = _start_broker(
            broker,
            local_config,
            local_log,
            finite=False,
        )
        _wait_for_log(local, local_log, "bridge lazy-out remote=")
        local_observer = connect_after_restart("lazy-state-observer-after")
        _subscribe_client(local_observer, 1, "bridge/lazy/state", 1)
        _expect_bridge_state(local_observer, "bridge/lazy/state", b"0")
        expect_quiet()
        publisher = _connect_client(local_port, "lazy-outbound-publisher-after")
        publish(b"threshold-after-restart", 4)
        _expect_bridge_state(subscriber, "bridge/lazy/state", b"1")
        _expect_bridge_state(local_observer, "bridge/lazy/state", b"1")
        for expected in (b"persisted-below-threshold", b"threshold-after-restart"):
            topic, payload = _read_publish_and_ack(subscriber)
            if (topic, payload) != ("remote/sensors/lazy", expected):
                raise AssertionError(
                    f"lazy restart delivery mismatch: {(topic, payload)!r}"
                )
    finally:
        if publisher is not None:
            publisher.close()
        if subscriber is not None:
            subscriber.close()
        if local_observer is not None:
            local_observer.close()
        if local is not None and local_output is not None:
            _stop(local, local_output)
        _stop(remote, remote_output)
