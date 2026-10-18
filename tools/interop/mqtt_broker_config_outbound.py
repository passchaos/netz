"""Production outbound configuration, local consumer and coordinator restart."""

from pathlib import Path
import shutil
import socket
import ssl
import sys
import time

from mqtt_broker_config_bridge import (
    _distinct_ports, _start_broker, _stop, _wait_for_log,
    _connect_client, _subscribe_client, _expect_bridge_state,
    _read_publish_and_ack, _packet, _utf8, _read_packet, _decode_varint,
    _create_tls_material, _connect_tls_client, _expect_startup_rejection,
    _openssl, _connect_limits,
)


def _publish_contents(packet: bytes, protocol_level: int) -> tuple[str, bytes]:
    if packet[0] >> 4 != 3:
        raise AssertionError(f"expected bridge PUBLISH: {packet.hex()}")
    remaining, cursor = _decode_varint(packet, 1)
    end = cursor + remaining
    topic_size = int.from_bytes(packet[cursor:cursor + 2], "big")
    cursor += 2
    topic = packet[cursor:cursor + topic_size].decode()
    cursor += topic_size
    qos = (packet[0] >> 1) & 0x03
    if qos:
        cursor += 2
    if protocol_level == 5:
        property_size, cursor = _decode_varint(packet, cursor)
        cursor += property_size
    return topic, packet[cursor:end]


def _connect_shape(packet: bytes) -> tuple[int, bool, int, bool]:
    if packet[0] != 0x10:
        raise AssertionError(f"expected bridge CONNECT: {packet.hex()}")
    _, cursor = _decode_varint(packet, 1)
    protocol_name_size = int.from_bytes(packet[cursor:cursor + 2], "big")
    cursor += 2 + protocol_name_size
    protocol_byte = packet[cursor]
    protocol_level = protocol_byte & 0x7F
    private_bridge = protocol_byte & 0x80 != 0
    flags = packet[cursor + 1]
    if flags & 0x04 == 0:
        raise AssertionError(f"bridge CONNECT omitted notification Will: {packet.hex()}")
    return (
        protocol_level,
        private_bridge,
        (flags >> 3) & 0x03,
        flags & 0x20 != 0,
    )


def _unsubscribe_filters(
    packet: bytes, protocol_level: int
) -> tuple[int, list[str]]:
    if packet[0] != 0xA2:
        raise AssertionError(f"expected bridge UNSUBSCRIBE: {packet.hex()}")
    remaining, cursor = _decode_varint(packet, 1)
    end = cursor + remaining
    packet_id = int.from_bytes(packet[cursor:cursor + 2], "big")
    cursor += 2
    if protocol_level == 5:
        property_size, cursor = _decode_varint(packet, cursor)
        cursor += property_size
    filters: list[str] = []
    while cursor < end:
        size = int.from_bytes(packet[cursor:cursor + 2], "big")
        cursor += 2
        filters.append(packet[cursor:cursor + size].decode())
        cursor += size
    if cursor != end:
        raise AssertionError(f"malformed bridge UNSUBSCRIBE: {packet.hex()}")
    return packet_id, filters


def _expect_tcp_user_timeout_trace(trace: Path, expected_ms: int) -> None:
    expected = f"TCP_USER_TIMEOUT, [{expected_ms}], 4) = 0"
    calls = [
        line
        for line in trace.read_text(errors="replace").splitlines()
        if "TCP_USER_TIMEOUT" in line
    ]
    if not any(expected in call for call in calls):
        raise AssertionError(
            f"bridge did not apply {expected_ms}ms TCP_USER_TIMEOUT: {calls!r}"
        )


def _expect_tcp_keepalive_trace(
    trace: Path,
    idle_seconds: int,
    interval_seconds: int,
    probe_count: int,
) -> None:
    content = trace.read_text(errors="replace")
    expected = (
        "SO_KEEPALIVE, [1], 4) = 0",
        f"TCP_KEEPIDLE, [{idle_seconds}], 4) = 0",
        f"TCP_KEEPINTVL, [{interval_seconds}], 4) = 0",
        f"TCP_KEEPCNT, [{probe_count}], 4) = 0",
    )
    missing = [fragment for fragment in expected if fragment not in content]
    if missing:
        raise AssertionError(
            f"bridge did not apply complete TCP keepalive policy: {missing!r}"
        )


def _private_bridge_connect(
    port: int, client_id: str, protocol_level: int
) -> socket.socket:
    client = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        client.settimeout(10)
        protocol_name = "MQIsdp" if protocol_level == 3 else "MQTT"
        body = (
            _utf8(protocol_name)
            + bytes((protocol_level | 0x80, 0x02))
            + (30).to_bytes(2, "big")
            + _utf8(client_id)
        )
        client.sendall(_packet(0x10, body))
        if _read_packet(client) != b"\x20\x02\x00\x00":
            raise AssertionError("private bridge CONNECT was not accepted")
        return client
    except BaseException:
        client.close()
        raise


def run_private_bridge_server_case(broker: Path, directory: Path) -> None:
    for protocol_level in (3, 4):
        port = _distinct_ports(1)[0]
        config = directory / f"private-bridge-server-v{protocol_level}.conf"
        config.write_text(
            f"listener {port} 127.0.0.1\n"
            "listener_allow_anonymous true\nmax_connections 3\n"
        )
        log = directory / f"private-bridge-server-v{protocol_level}.log"
        process, output = _start_broker(broker, config, log)
        private = publisher = None
        try:
            _wait_for_log(process, log, "configured 1 listeners")
            private = _private_bridge_connect(
                port, f"private-bridge-peer-v{protocol_level}", protocol_level
            )
            private.sendall(
                _packet(0x82, b"\x00\x01" + _utf8("bridge/#") + b"\x00")
            )
            if _read_packet(private) != b"\x90\x03\x00\x01\x00":
                raise AssertionError("private bridge SUBSCRIBE was not accepted")

            private.sendall(_packet(0x31, _utf8("bridge/self") + b"self"))
            private.settimeout(0.2)
            try:
                unexpected = _read_packet(private)
            except socket.timeout:
                unexpected = None
            if unexpected is not None:
                raise AssertionError(
                    "private bridge no-local policy echoed its own publish: "
                    + unexpected.hex()
                )

            private.settimeout(10)
            publisher = _connect_client(
                port, f"private-bridge-publisher-v{protocol_level}"
            )
            publisher.sendall(
                _packet(0x31, _utf8("bridge/peer") + b"\x00" + b"retained")
            )
            forwarded = _read_packet(private)
            if forwarded[0] & 0x01 == 0:
                raise AssertionError(
                    "private bridge subscription did not preserve RETAIN: "
                    + forwarded.hex()
                )
            if _publish_contents(forwarded, protocol_level) != (
                "bridge/peer",
                b"retained",
            ):
                raise AssertionError("private bridge received the wrong publication")
        finally:
            if publisher is not None:
                publisher.close()
            if private is not None:
                private.close()
            _stop(process, output)


def run_bridge_cipher_suite_case(broker: Path, directory: Path) -> None:
    remote_port, local_port = _distinct_ports(2)
    ca, certificate, key, _, _ = _create_tls_material(directory)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certificate, key)
    context.set_alpn_protocols(["mqtt"])
    required_cipher = "TLS_CHACHA20_POLY1305_SHA256"
    if required_cipher not in {
        cipher["name"] for cipher in context.get_ciphers()
    }:
        raise AssertionError(f"OpenSSL does not support {required_cipher}")

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", remote_port))
    listener.listen(1)
    listener.settimeout(10)
    config = directory / "bridge-cipher-suite.conf"
    config.write_text(
        f"listener {local_port} 127.0.0.1\nlistener_allow_anonymous true\n"
        "max_connections 1\nconnection cipher-suite\n"
        f"address localhost:{remote_port}\ntopic # in 0\n"
        "bridge_protocol_version mqttv50\nnotifications false\n"
        f"bridge_cafile {ca}\nbridge_alpn mqtt\n"
        f"bridge_ciphers_tls1.3 {required_cipher}\n"
    )
    log = directory / "bridge-cipher-suite.log"
    process = output = raw = peer = None
    try:
        process, output = _start_broker(broker, config, log)
        raw, _ = listener.accept()
        raw.settimeout(10)
        peer = context.wrap_socket(raw, server_side=True)
        raw = None
        if peer.selected_alpn_protocol() != "mqtt":
            raise AssertionError("bridge cipher test did not negotiate mqtt ALPN")
        if peer.cipher()[0] != required_cipher:
            raise AssertionError(
                f"bridge negotiated {peer.cipher()[0]}, expected {required_cipher}"
            )
        _connect_limits(_read_packet(peer), 5)
        peer.sendall(_packet(0x20, b"\x00\x00\x00"))
        _wait_for_log(process, log, "bridge cipher-suite remote=")
    finally:
        if peer is not None:
            peer.close()
        if raw is not None:
            raw.close()
        listener.close()
        if process is not None:
            _stop(process, output)


def run_bridge_connack_capability_case(
    broker: Path,
    directory: Path,
) -> None:
    remote_port, local_port = _distinct_ports(2)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", remote_port))
    listener.listen(4)
    listener.settimeout(10)
    config = directory / "bridge-connack-capabilities.conf"
    config.write_text(
        f"listener {local_port} 127.0.0.1\n"
        "listener_allow_anonymous true\nmax_connections 1\n"
        "connection connack-capabilities\n"
        f"address 127.0.0.1:{remote_port}\n"
        "topic # out 0\ncleansession false\n"
        "bridge_protocol_version mqttv50\n"
        "bridge_session_expiry_interval 0xFFFFFFFF\n"
        "remote_clientid configured-capability-bridge\n"
        "notification_topic bridge/capability/state\n"
        "bridge_attempt_unsubscribe false\nrestart_timeout 1\n"
    )
    log = directory / "bridge-connack-capabilities.log"
    process = output = peer = None
    try:
        process, output = _start_broker(
            broker,
            config,
            log,
            finite=False,
        )

        expected = (
            ((5, False, 1, True), b"\x00\x9b\x02\x24\x00"),
            ((5, False, 0, True), b"\x00\x9a\x02\x25\x00"),
            ((5, False, 0, False), b"\x00\x84\x00"),
            ((4, True, 0, False), b"\x00\x00"),
        )
        for index, (will_shape, connack_body) in enumerate(expected):
            peer, _ = listener.accept()
            peer.settimeout(10)
            connect = _read_packet(peer)
            actual_shape = _connect_shape(connect)
            if actual_shape != will_shape:
                raise AssertionError(
                    f"bridge Will attempt {index + 1} mismatch: "
                    f"{actual_shape!r} != {will_shape!r}"
                )
            peer.sendall(_packet(0x20, connack_body))
            if index != len(expected) - 1:
                peer.close()
                peer = None

        state = _read_packet(peer)
        if _publish_contents(state, 4) != (
            "bridge/capability/state",
            b"1",
        ):
            raise AssertionError(
                f"bridge capability state mismatch: {state.hex()}"
            )
        _wait_for_log(
            process,
            log,
            "bridge connack-capabilities remote=",
        )
    finally:
        if peer is not None:
            peer.close()
        listener.close()
        if process is not None and output is not None:
            _stop(process, output)


def run_outbound_bridge_protocol_limits_case(
    broker: Path, directory: Path
) -> None:
    # The retain matrix is ported from Mosquitto 5cd254651159's
    # 06-bridge-outgoing-retain.py and extended with MQTT 5 bridge limits.
    for protocol_level, protocol_name in ((4, "mqttv311"), (5, "mqttv50")):
        for outgoing_retain in (True, False):
            remote_port, local_port = _distinct_ports(2)
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", remote_port))
            listener.listen(1)
            listener.settimeout(10)
            case_name = (
                f"limits-{protocol_level}-"
                f"{'retain' if outgoing_retain else 'no-retain'}"
            )
            session_expiry = (
                "bridge_session_expiry_interval 0xFFFFFFFF\n"
                if protocol_level == 5
                else ""
            )
            attempt_unsubscribe = outgoing_retain
            config = directory / f"{case_name}.conf"
            config.write_text(
                f"persistence true\npersistence_location {directory}\n"
                f"persistence_file {case_name}.db\n"
                f"listener {local_port} 127.0.0.1\nlistener_allow_anonymous true\n"
                "max_connections 3\n"
                f"connection {case_name}\naddress 127.0.0.1:{remote_port}\n"
                "topic sensors/# out 2 local/ remote/\ncleansession false\n"
                f"bridge_protocol_version {protocol_name}\n"
                f"{session_expiry}"
                "bridge_receive_maximum 7\nbridge_max_topic_alias 3\n"
                "bridge_max_packet_size 96\n"
                f"bridge_outgoing_retain {str(outgoing_retain).lower()}\n"
                "bridge_attempt_unsubscribe "
                f"{str(attempt_unsubscribe).lower()}\n"
                "bridge_bind_address 127.0.0.2\n"
                "notifications false\nrestart_timeout 1\n"
            )
            log = directory / f"{case_name}.log"
            process = output = bridge = publisher = None
            try:
                process, output = _start_broker(broker, config, log)
                bridge, peer = listener.accept()
                bridge.settimeout(10)
                if peer[0] != "127.0.0.2":
                    raise AssertionError(
                        f"bridge_bind_address mismatch: {peer!r}"
                    )
                connect = _read_packet(bridge)
                limits = _connect_limits(
                    connect,
                    protocol_level,
                    private_bridge=protocol_level == 4,
                )
                if protocol_level == 4 and not outgoing_retain:
                    bridge.sendall(_packet(0x20, b"\x00\x01"))
                    bridge.close()
                    bridge = None
                    bridge, peer = listener.accept()
                    bridge.settimeout(10)
                    if peer[0] != "127.0.0.2":
                        raise AssertionError(
                            f"fallback bridge_bind_address mismatch: {peer!r}"
                        )
                    connect = _read_packet(bridge)
                    limits = _connect_limits(
                        connect,
                        protocol_level,
                        private_bridge=False,
                    )
                if protocol_level == 5:
                    if limits.get(0x21) != 7 or limits.get(0x22) != 3:
                        raise AssertionError(
                            f"configured bridge CONNECT limits mismatch: {limits!r}"
                        )
                    if limits.get(0x27, 0) <= 96:
                        raise AssertionError(
                            "bridge_max_packet_size was incorrectly advertised "
                            "as the local receive limit"
                        )
                    connack_properties = (
                        b"\x21\x00\x05"  # Receive Maximum
                        b"\x22\x00\x02"  # Topic Alias Maximum
                        b"\x27\x00\x00\x00\x50"  # Maximum Packet Size 80
                        b"\x25\x01"  # Retain Available
                    )
                    bridge.sendall(
                        _packet(
                            0x20,
                            b"\x00\x00"
                            + bytes((len(connack_properties),))
                            + connack_properties,
                        )
                    )
                else:
                    bridge.sendall(_packet(0x20, b"\x00\x00"))

                if attempt_unsubscribe:
                    unsubscribe = _read_packet(bridge)
                    packet_id, filters = _unsubscribe_filters(
                        unsubscribe, protocol_level
                    )
                    if filters != ["remote/sensors/#"]:
                        raise AssertionError(
                            f"bridge cleanup filters mismatch: {filters!r}"
                        )
                    bridge.sendall(
                        _packet(
                            0x30,
                            _utf8("remote/sensors/stale")
                            + (b"\x00" if protocol_level == 5 else b"")
                            + b"ignored",
                        )
                    )
                    bridge.sendall(
                        _packet(
                            0xB0,
                            packet_id.to_bytes(2, "big")
                            + (b"\x00\x11" if protocol_level == 5 else b""),
                        )
                    )

                _wait_for_log(process, log, f"bridge {case_name} remote=")
                publisher = _connect_client(local_port, f"publisher-{case_name}")
                payload = b"retain-policy"
                publisher.sendall(
                    _packet(
                        0x31,
                        _utf8("local/sensors/retain/test")
                        + b"\x00"
                        + payload,
                    )
                )
                forwarded = _read_packet(bridge)
                if bool(forwarded[0] & 0x01) != outgoing_retain:
                    raise AssertionError(
                        "bridge_outgoing_retain mismatch: " + forwarded.hex()
                    )
                if len(forwarded) > 80:
                    raise AssertionError(
                        f"bridge exceeded negotiated packet limit: {len(forwarded)}"
                    )
                topic, actual = _publish_contents(forwarded, protocol_level)
                if (topic, actual) != ("remote/sensors/retain/test", payload):
                    raise AssertionError(
                        f"bridge protocol-limit publish mismatch: {(topic, actual)!r}"
                    )

                oversized_payload = b"x" * (61 if protocol_level == 5 else 80)
                publisher.sendall(
                    _packet(
                        0x34,
                        _utf8("local/sensors/oversize")
                        + b"\x00\x01"
                        + b"\x00"
                        + oversized_payload,
                    )
                )
                pubrec = _read_packet(publisher)
                if pubrec[0] != 0x50 or pubrec[2:4] != b"\x00\x01":
                    raise AssertionError(
                        f"local oversized QoS 2 PUBREC mismatch: {pubrec.hex()}"
                    )
                publisher.sendall(_packet(0x62, b"\x00\x01"))
                pubcomp = _read_packet(publisher)
                if pubcomp[0] != 0x70 or pubcomp[2:4] != b"\x00\x01":
                    raise AssertionError(
                        f"local oversized QoS 2 PUBCOMP mismatch: {pubcomp.hex()}"
                    )
                publisher.sendall(
                    _packet(
                        0x30,
                        _utf8("local/sensors/after-limit")
                        + b"\x00"
                        + b"alive",
                    )
                )
                after_limit = _read_packet(bridge)
                topic, actual = _publish_contents(after_limit, protocol_level)
                if (topic, actual) != ("remote/sensors/after-limit", b"alive"):
                    raise AssertionError(
                        "oversized bridge PUBLISH was not dropped before "
                        f"the next message: {(topic, actual)!r}"
                    )
            finally:
                if publisher is not None:
                    publisher.close()
                if bridge is not None:
                    bridge.close()
                listener.close()
                if process is not None:
                    _stop(process, output)


def run_outbound_bridge_case(broker: Path, directory: Path, *, tls: bool = False) -> None:
    remote_port, local_port, unavailable_port = _distinct_ports(3)
    tcp_user_timeout_ms = 4321
    tcp_keepalive = (31, 11, 7)
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
                     "bridge_alpn mqtt\n"
                     "bridge_ciphers_tls1.3 TLS_AES_256_GCM_SHA384\n"
                     "bridge_tls_version tlsv1.3\n")
    remote_config = directory / "outbound-remote.conf"
    remote_config.write_text(
        f"listener {remote_port} 127.0.0.1\n{remote_tls}listener_allow_anonymous true\n"
        "max_connections 4\n"
    )
    local_config = directory / "outbound-local.conf"
    local_config.write_text(
        f"persistence true\npersistence_location {directory}\n"
        "persistence_file outbound-local.db\n"
        f"listener {local_port} 127.0.0.1\nlistener_allow_anonymous true\n"
        "max_connections 4\nconnection outbound\n"
        f"address localhost:{unavailable_port} localhost:{remote_port}\n"
        "round_robin true\n"
        "topic sensors/# out 2 local/ remote/\n"
        "cleansession false\nbridge_protocol_version mqttv50\n"
        "bridge_session_expiry_interval 0xFFFFFFFF\n"
        "bridge_bind_address 127.0.0.2\n"
        f"bridge_tcp_keepalive {' '.join(map(str, tcp_keepalive))}\n"
        f"bridge_tcp_user_timeout {tcp_user_timeout_ms}\n"
        f"remote_clientid configured-outbound\nrestart_timeout 1\n{local_tls}"
    )
    remote_log = directory / "outbound-remote.log"
    local_log = directory / "outbound-local.log"
    socket_trace = directory / (
        "outbound-local-tls.socket.trace"
        if tls
        else "outbound-local-cleartext.socket.trace"
    )
    trace_socket_options = (
        socket_trace
        if sys.platform.startswith("linux") and shutil.which("strace")
        else None
    )
    remote, remote_output = _start_broker(broker, remote_config, remote_log)
    local = local_output = subscriber = publisher = None
    try:
        _wait_for_log(remote, remote_log, "configured 1 listeners")
        local, local_output = _start_broker(
            broker,
            local_config,
            local_log,
            trace_socket_options=trace_socket_options,
        )
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
        local, local_output = _start_broker(
            broker,
            local_config,
            local_log,
            trace_socket_options=trace_socket_options,
        )
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
    if trace_socket_options is not None:
        _expect_tcp_keepalive_trace(socket_trace, *tcp_keepalive)
        _expect_tcp_user_timeout_trace(socket_trace, tcp_user_timeout_ms)
    if tls:
        empty_ca_path = directory / "empty-outbound-server-capath"
        empty_ca_path.mkdir()
        invalid_port = _distinct_ports(1)[0]
        invalid_config = directory / "empty-outbound-capath.conf"
        invalid_config.write_text(
            f"listener {invalid_port} 127.0.0.1\nlistener_allow_anonymous true\n"
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
        f"listener {remote_port} 127.0.0.1\nlistener_allow_anonymous true\n"
        "max_connections 4\n"
    )
    local_config = directory / "lazy-outbound-local.conf"
    local_config.write_text(
        f"persistence true\npersistence_location {directory}\n"
        "persistence_file lazy-outbound.db\n"
        f"listener {local_port} 127.0.0.1\nlistener_allow_anonymous true\n"
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
