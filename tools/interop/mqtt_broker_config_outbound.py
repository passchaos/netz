"""Production outbound configuration, local consumer and coordinator restart."""

from pathlib import Path
import socket

from mqtt_broker_config_bridge import (
    _distinct_ports, _start_broker, _stop, _wait_for_log,
    _connect_client, _subscribe_client, _expect_bridge_state,
    _read_publish_and_ack, _packet, _utf8, _read_packet,
    _create_tls_material, _connect_tls_client, _openssl,
)


def run_outbound_bridge_case(broker: Path, directory: Path, *, tls: bool = False) -> None:
    remote_port, local_port, unavailable_port = _distinct_ports(3)
    remote_tls = local_tls = ""
    if tls:
        ca, cert, key, client_cert, client_key = _create_tls_material(directory)
        encrypted_key = directory / "outbound-client-encrypted.pem"
        key_password = directory / "outbound-client.password"
        key_password.write_text("outbound-secret\n")
        _openssl("pkcs8", "-topk8", "-in", client_key, "-out", encrypted_key,
                 "-v2", "aes-256-cbc", "-iter", 2048, "-passout", "pass:outbound-secret")
        remote_tls = f"certfile {cert}\nkeyfile {key}\ncafile {ca}\nrequire_certificate true\n"
        local_tls = (f"bridge_cafile {ca}\nbridge_certfile {client_cert}\n"
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
