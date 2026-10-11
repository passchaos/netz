"""End-to-end inbound bridge coverage for the production config runner."""

from __future__ import annotations

import os
from pathlib import Path
import socket
import ssl
import subprocess
import time


FINITE_TEST_ENV = "NETZ_MQTT_CONFIG_FINITE_TEST"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _distinct_ports(count: int) -> list[int]:
    ports: set[int] = set()
    while len(ports) != count:
        ports.add(_free_port())
    return list(ports)


def _varint(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        result.append(byte)
        if not value:
            return bytes(result)


def _utf8(value: str) -> bytes:
    encoded = value.encode()
    return len(encoded).to_bytes(2, "big") + encoded


def _packet(first: int, body: bytes) -> bytes:
    return bytes((first,)) + _varint(len(body)) + body


def _connect(client_id: str) -> bytes:
    variable = _utf8("MQTT") + bytes((5, 2)) + (30).to_bytes(2, "big")
    return _packet(0x10, variable + b"\x00" + _utf8(client_id))


def _subscribe(packet_id: int, topic: str, qos: int) -> bytes:
    body = packet_id.to_bytes(2, "big") + b"\x00" + _utf8(topic) + bytes((qos,))
    return _packet(0x82, body)


def _publish(packet_id: int, topic: str, payload: bytes, qos: int) -> bytes:
    body = _utf8(topic) + packet_id.to_bytes(2, "big") + b"\x00" + payload
    return _packet(0x31 | (qos << 1), body)


def _read_exact(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) != length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise EOFError("MQTT peer closed the connection")
        result.extend(chunk)
    return bytes(result)


def _read_varint_socket(sock: socket.socket) -> tuple[int, bytes]:
    value = 0
    multiplier = 1
    encoded = bytearray()
    for _ in range(4):
        byte = _read_exact(sock, 1)[0]
        encoded.append(byte)
        value += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            return value, bytes(encoded)
        multiplier *= 128
    raise AssertionError("overlong MQTT Remaining Length")


def _read_packet(sock: socket.socket) -> bytes:
    first = _read_exact(sock, 1)
    remaining, encoded = _read_varint_socket(sock)
    return first + encoded + _read_exact(sock, remaining)


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    multiplier = 1
    for _ in range(4):
        if offset >= len(data):
            raise AssertionError("truncated MQTT variable integer")
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            return value, offset
        multiplier *= 128
    raise AssertionError("overlong MQTT variable integer")


def _connect_limits(
    packet: bytes,
    protocol_level: int,
    *,
    private_bridge: bool = False,
) -> dict[int, int]:
    if packet[0] != 0x10:
        raise AssertionError(f"expected bridge CONNECT: {packet.hex()}")
    _, cursor = _decode_varint(packet, 1)
    protocol_name_size = int.from_bytes(packet[cursor:cursor + 2], "big")
    cursor += 2
    protocol_name = packet[cursor:cursor + protocol_name_size]
    cursor += protocol_name_size
    expected_level = protocol_level | (0x80 if private_bridge else 0)
    if protocol_name != b"MQTT" or packet[cursor] != expected_level:
        raise AssertionError(f"unexpected bridge protocol: {packet.hex()}")
    cursor += 4  # protocol level, flags, and Keep Alive
    if protocol_level == 4:
        return {}

    property_size, cursor = _decode_varint(packet, cursor)
    property_end = cursor + property_size
    properties: dict[int, int] = {}
    widths = {0x11: 4, 0x21: 2, 0x22: 2, 0x27: 4}
    while cursor < property_end:
        identifier = packet[cursor]
        cursor += 1
        width = widths.get(identifier)
        if width is None or cursor + width > property_end:
            raise AssertionError(
                f"unexpected bridge CONNECT property: {packet.hex()}"
            )
        properties[identifier] = int.from_bytes(
            packet[cursor:cursor + width], "big"
        )
        cursor += width
    if cursor != property_end:
        raise AssertionError(f"malformed bridge CONNECT properties: {packet.hex()}")
    return properties


def _finish_connect(client: socket.socket, client_id: str) -> socket.socket:
    client.settimeout(10)
    client.sendall(_connect(client_id))
    connack = _read_packet(client)
    _, body = _decode_varint(connack, 1)
    if connack[0] != 0x20 or body + 2 > len(connack) or connack[body + 1] != 0:
        client.close()
        raise AssertionError(f"bridge test CONNECT failed: {connack.hex()}")
    return client


def _connect_client(port: int, client_id: str) -> socket.socket:
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        return _finish_connect(raw, client_id)
    except BaseException:
        raw.close()
        raise


def _connect_tls_client(
    port: int,
    client_id: str,
    ca_certificate: Path,
    client_certificate: Path,
    client_key: Path,
) -> socket.socket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=ca_certificate)
    context.load_cert_chain(client_certificate, client_key)
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        return _finish_connect(
            context.wrap_socket(raw, server_hostname="localhost"),
            client_id,
        )
    except BaseException:
        raw.close()
        raise


def _publish_message(
    client: socket.socket,
    packet_id: int,
    payload: bytes,
    qos: int,
    topic: str = "remote/sensors/temperature",
) -> None:
    client.sendall(_publish(packet_id, topic, payload, qos))
    acknowledgement = _read_packet(client)
    expected_type = 0x40 if qos == 1 else 0x50
    if (
        acknowledgement[0] != expected_type
        or packet_id.to_bytes(2, "big") not in acknowledgement
    ):
        raise AssertionError(
            f"bridge publisher expected QoS {qos} acknowledgement: "
            f"{acknowledgement.hex()}"
        )
    if qos == 2:
        client.sendall(_packet(0x62, packet_id.to_bytes(2, "big")))
        pubcomp = _read_packet(client)
        if pubcomp[0] != 0x70 or packet_id.to_bytes(2, "big") not in pubcomp:
            raise AssertionError(
                f"bridge publisher expected PUBCOMP: {pubcomp.hex()}"
            )


def _read_publish_and_ack(client: socket.socket) -> tuple[str, bytes]:
    packet = _read_packet(client)
    if packet[0] >> 4 != 3:
        raise AssertionError(f"expected bridged PUBLISH: {packet.hex()}")
    remaining, cursor = _decode_varint(packet, 1)
    end = cursor + remaining
    topic_length = int.from_bytes(packet[cursor : cursor + 2], "big")
    cursor += 2
    topic = packet[cursor : cursor + topic_length].decode()
    cursor += topic_length
    qos = (packet[0] >> 1) & 0x03
    packet_id = None
    if qos != 0:
        packet_id = int.from_bytes(packet[cursor : cursor + 2], "big")
        cursor += 2
    property_length, cursor = _decode_varint(packet, cursor)
    cursor += property_length
    payload = packet[cursor:end]
    if packet_id is not None:
        if qos == 1:
            client.sendall(_packet(0x40, packet_id.to_bytes(2, "big")))
        elif qos == 2:
            client.sendall(_packet(0x50, packet_id.to_bytes(2, "big")))
            pubrel = _read_packet(client)
            if pubrel[0] != 0x62 or packet_id.to_bytes(2, "big") not in pubrel:
                raise AssertionError(
                    f"bridge subscriber expected PUBREL: {pubrel.hex()}"
                )
            client.sendall(_packet(0x70, packet_id.to_bytes(2, "big")))
        else:
            raise AssertionError(f"invalid bridged PUBLISH QoS {qos}")
    return topic, payload


def _expect_mapped_publish(
    client: socket.socket,
    payload: bytes,
    expected_topic: str = "local/sensors/temperature",
) -> None:
    topic, actual_payload = _read_publish_and_ack(client)
    if topic != expected_topic or actual_payload != payload:
        raise AssertionError(
            f"unexpected bridge mapping topic={topic!r} payload={actual_payload!r}"
        )


def _subscribe_client(
    client: socket.socket, packet_id: int, topic: str, qos: int
) -> None:
    client.sendall(_subscribe(packet_id, topic, qos))
    suback = _read_packet(client)
    if suback[0] != 0x90 or suback[-1] != qos:
        raise AssertionError(f"bridge subscriber expected SUBACK: {suback.hex()}")


def _expect_bridge_state(
    client: socket.socket, topic: str, expected: bytes
) -> None:
    for _ in range(3):
        actual_topic, payload = _read_publish_and_ack(client)
        if actual_topic != topic:
            raise AssertionError(
                f"unexpected notification topic {actual_topic!r}, expected {topic!r}"
            )
        if payload == expected:
            return
        if payload != b"0":
            raise AssertionError(f"unexpected bridge state payload {payload!r}")
    raise AssertionError(f"bridge state did not reach {expected!r}")


def _wait_for_log(process: subprocess.Popen[bytes], log: Path, marker: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        content = log.read_text(errors="replace") if log.exists() else ""
        if marker in content:
            return
        if process.poll() is not None:
            raise RuntimeError(f"broker exited before {marker!r}: {content}")
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for {marker!r}: {log.read_text()}")


def _start_broker(
    binary: Path,
    config: Path,
    log: Path,
    *,
    finite: bool = True,
    trace_socket_options: Path | None = None,
) -> tuple[subprocess.Popen[bytes], object]:
    output = log.open("wb")
    environment = os.environ.copy()
    if finite:
        environment[FINITE_TEST_ENV] = "1"
    else:
        environment.pop(FINITE_TEST_ENV, None)
    command = [str(binary), f"--config={config}"]
    if trace_socket_options is not None:
        command = [
            "strace",
            "--follow-forks",
            "--kill-on-exit",
            "--trace=setsockopt",
            f"--output={trace_socket_options}",
            *command,
        ]
    process = subprocess.Popen(
        command,
        stdout=output,
        stderr=subprocess.STDOUT,
        env=environment,
    )
    return process, output


def _stop(process: subprocess.Popen[bytes], output: object) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    output.close()  # type: ignore[attr-defined]


def _wait_clean(
    process: subprocess.Popen[bytes], output: object, log: Path, label: str
) -> None:
    try:
        code = process.wait(timeout=10)
    finally:
        output.close()  # type: ignore[attr-defined]
    if code != 0:
        raise RuntimeError(f"{label} exited {code}: {log.read_text(errors='replace')}")


def _expect_startup_rejection(
    broker: Path, config: Path, port: int, expected_error: str
) -> None:
    environment = os.environ.copy()
    environment[FINITE_TEST_ENV] = "1"
    try:
        result = subprocess.run(
            [str(broker), f"--config={config}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError("invalid TLS bridge configuration started") from exc
    if result.returncode == 0 or expected_error not in result.stdout:
        raise AssertionError(
            f"expected {expected_error} startup rejection: {result.stdout}"
        )
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            raise AssertionError("listener bound before bridge TLS validation")


def _openssl(*arguments: object) -> None:
    subprocess.run(
        ["openssl", *(str(argument) for argument in arguments)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=True,
    )


def _create_tls_material(directory: Path) -> tuple[Path, Path, Path, Path, Path]:
    ca_key = directory / "bridge-ca.key"
    ca_certificate = directory / "bridge-ca.pem"
    server_key = directory / "bridge-server.key"
    server_request = directory / "bridge-server.csr"
    server_certificate = directory / "bridge-server.pem"
    server_extensions = directory / "bridge-server.ext"
    client_key = directory / "bridge-client.key"
    client_request = directory / "bridge-client.csr"
    client_certificate = directory / "bridge-client.pem"
    client_extensions = directory / "bridge-client.ext"

    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", ca_key)
    _openssl(
        "req",
        "-new",
        "-x509",
        "-key",
        ca_key,
        "-sha256",
        "-days",
        "1",
        "-subj",
        "/CN=Netz bridge test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-out",
        ca_certificate,
    )
    server_extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost\n"
    )
    client_extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth\n"
    )
    for key, request, certificate, common_name, extensions, serial in (
        (
            server_key,
            server_request,
            server_certificate,
            "localhost",
            server_extensions,
            101,
        ),
        (
            client_key,
            client_request,
            client_certificate,
            "netz-bridge-client",
            client_extensions,
            102,
        ),
    ):
        _openssl(
            "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key
        )
        _openssl("req", "-new", "-key", key, "-subj", f"/CN={common_name}", "-out", request)
        _openssl(
            "x509",
            "-req",
            "-in",
            request,
            "-CA",
            ca_certificate,
            "-CAkey",
            ca_key,
            "-set_serial",
            serial,
            "-days",
            "1",
            "-sha256",
            "-extfile",
            extensions,
            "-out",
            certificate,
        )
    return (
        ca_certificate,
        server_certificate,
        server_key,
        client_certificate,
        client_key,
    )


def run_inbound_bridge_case(broker: Path, directory: Path) -> None:
    upstream_port, local_port, unavailable_port = _distinct_ports(3)
    upstream_config = directory / "bridge-upstream.conf"
    upstream_config.write_text(
        f"listener {upstream_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 2\n"
    )
    local_config = directory / "bridge-local.conf"
    local_config.write_text(
        "persistence true\n"
        f"persistence_location {directory}\n"
        "persistence_file bridge-local.db\n"
        f"listener {local_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        "connection upstream\n"
        f"address 127.0.0.1:{unavailable_port} 127.0.0.1:{upstream_port}\n"
        "round_robin true\n"
        "topic sensors/# in 2 local/ remote/\n"
        "cleansession false\n"
        "bridge_protocol_version mqttv50\n"
        "bridge_session_expiry_interval 0xFFFFFFFF\n"
        "remote_clientid configured-inbound-bridge\n"
        "restart_timeout 1 2 1\n"
    )
    upstream_log = directory / "bridge-upstream.log"
    local_log = directory / "bridge-local.log"
    upstream, upstream_output = _start_broker(
        broker, upstream_config, upstream_log
    )
    local = None
    local_output = None
    subscriber = None
    publisher = None
    try:
        _wait_for_log(upstream, upstream_log, "configured 1 listeners")
        local, local_output = _start_broker(broker, local_config, local_log)
        _wait_for_log(local, local_log, "bridge upstream remote=")

        subscriber = _connect_client(local_port, "configured-bridge-subscriber")
        notification_topic = (
            "$SYS/broker/connection/configured-inbound-bridge/state"
        )
        _subscribe_client(subscriber, 1, notification_topic, 1)
        _expect_bridge_state(subscriber, notification_topic, b"1")
        _subscribe_client(subscriber, 2, "local/#", 2)

        publisher = _connect_client(upstream_port, "configured-bridge-publisher-1")
        _subscribe_client(publisher, 1, notification_topic, 1)
        _expect_bridge_state(publisher, notification_topic, b"1")
        _publish_message(publisher, 1, b"before-restart", 1)
        _expect_mapped_publish(subscriber, b"before-restart")
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None

        upstream.kill()
        upstream.wait(timeout=5)
        upstream_output.close()
        upstream_output = None
        _expect_bridge_state(subscriber, notification_topic, b"0")
        if local.poll() is not None:
            raise RuntimeError(
                "configured bridge stopped its local broker after upstream loss: "
                + local_log.read_text(errors="replace")
            )

        upstream, upstream_output = _start_broker(
            broker, upstream_config, upstream_log
        )
        _wait_for_log(upstream, upstream_log, "configured 1 listeners")
        publisher = _connect_client(upstream_port, "configured-bridge-publisher-2")
        _expect_bridge_state(subscriber, notification_topic, b"1")
        _subscribe_client(publisher, 1, notification_topic, 1)
        _expect_bridge_state(publisher, notification_topic, b"1")
        _publish_message(publisher, 2, b"after-restart", 2)
        _expect_mapped_publish(subscriber, b"after-restart")

        subscriber.sendall(b"\xe0\x00")
        subscriber.close()
        subscriber = None
        _wait_clean(local, local_output, local_log, "local bridge broker")
        local = None
        local_output = None
        _expect_bridge_state(publisher, notification_topic, b"0")
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None
        _wait_clean(upstream, upstream_output, upstream_log, "upstream broker")
        upstream_output = None
    finally:
        if publisher is not None:
            publisher.close()
        if subscriber is not None:
            subscriber.close()
        if local is not None and local_output is not None:
            _stop(local, local_output)
        if upstream_output is not None:
            _stop(upstream, upstream_output)


def run_primary_failback_case(broker: Path, directory: Path) -> None:
    primary_port, secondary_port, local_port = _distinct_ports(3)
    primary_config = directory / "bridge-primary.conf"
    secondary_config = directory / "bridge-secondary.conf"
    for config, port in (
        (primary_config, primary_port),
        (secondary_config, secondary_port),
    ):
        config.write_text(
            f"listener {port} 127.0.0.1\n"
            "allow_anonymous true\n"
            "max_connections 2\n"
        )
    local_config = directory / "bridge-primary-failback-local.conf"
    local_config.write_text(
        f"listener {local_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        "connection primary-preferred\n"
        f"address 127.0.0.1:{primary_port} 127.0.0.1:{secondary_port}\n"
        "topic sensors/# in 1 local/ remote/\n"
        "cleansession false\n"
        "remote_clientid configured-primary-failback\n"
        "restart_timeout 1\n"
    )
    primary_log = directory / "bridge-primary.log"
    secondary_log = directory / "bridge-secondary.log"
    local_log = directory / "bridge-primary-failback-local.log"
    secondary, secondary_output = _start_broker(
        broker, secondary_config, secondary_log
    )
    primary = None
    primary_output = None
    local = None
    local_output = None
    subscriber = None
    publisher = None
    try:
        _wait_for_log(secondary, secondary_log, "configured 1 listeners")
        local, local_output = _start_broker(broker, local_config, local_log)
        _wait_for_log(local, local_log, "bridge primary-preferred remote=")
        subscriber = _connect_client(local_port, "primary-failback-subscriber")
        subscriber.sendall(_subscribe(1, "local/#", 1))
        suback = _read_packet(subscriber)
        if suback[0] != 0x90 or suback[-1] != 1:
            raise AssertionError(
                f"primary failback subscriber expected SUBACK: {suback.hex()}"
            )

        publisher = _connect_client(secondary_port, "secondary-publisher")
        _publish_message(publisher, 1, b"from-secondary", 1)
        _expect_mapped_publish(subscriber, b"from-secondary")
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None

        primary, primary_output = _start_broker(
            broker, primary_config, primary_log
        )
        _wait_for_log(primary, primary_log, "configured 1 listeners")
        publisher = _connect_client(primary_port, "primary-publisher")
        _publish_message(publisher, 2, b"from-primary", 1)
        _expect_mapped_publish(subscriber, b"from-primary")
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None

        subscriber.sendall(b"\xe0\x00")
        subscriber.close()
        subscriber = None
        _wait_clean(local, local_output, local_log, "primary failback broker")
        local = None
        local_output = None
        _wait_clean(primary, primary_output, primary_log, "primary broker")
        primary = None
        primary_output = None
        _wait_clean(
            secondary,
            secondary_output,
            secondary_log,
            "secondary broker",
        )
        secondary_output = None
    finally:
        if publisher is not None:
            publisher.close()
        if subscriber is not None:
            subscriber.close()
        if local is not None and local_output is not None:
            _stop(local, local_output)
        if primary is not None and primary_output is not None:
            _stop(primary, primary_output)
        if secondary_output is not None:
            _stop(secondary, secondary_output)


def run_once_bridge_case(broker: Path, directory: Path) -> None:
    upstream_port, local_port = _distinct_ports(2)
    upstream_config = directory / "bridge-once-upstream.conf"
    upstream_config.write_text(
        f"listener {upstream_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 2\n"
    )
    restart_config = directory / "bridge-once-upstream-restart.conf"
    restart_config.write_text(
        f"listener {upstream_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
    )
    local_config = directory / "bridge-once-local.conf"
    local_config.write_text(
        f"listener {local_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        "connection one-shot\n"
        f"address 127.0.0.1:{upstream_port}\n"
        "topic sensors/# in 1 local/ remote/\n"
        "start_type once\n"
        "notifications false\n"
    )
    upstream_log = directory / "bridge-once-upstream.log"
    restart_log = directory / "bridge-once-upstream-restart.log"
    local_log = directory / "bridge-once-local.log"
    upstream, upstream_output = _start_broker(
        broker, upstream_config, upstream_log
    )
    restarted = None
    restarted_output = None
    local = None
    local_output = None
    subscriber = None
    publisher = None
    try:
        _wait_for_log(upstream, upstream_log, "configured 1 listeners")
        local, local_output = _start_broker(broker, local_config, local_log)
        _wait_for_log(local, local_log, "bridge one-shot remote=")
        subscriber = _connect_client(local_port, "once-bridge-subscriber")
        subscriber.sendall(_subscribe(1, "local/#", 1))
        suback = _read_packet(subscriber)
        if suback[0] != 0x90 or suback[-1] != 1:
            raise AssertionError(f"once bridge expected SUBACK: {suback.hex()}")

        publisher = _connect_client(upstream_port, "once-publisher-before")
        _publish_message(publisher, 1, b"once-before", 1)
        _expect_mapped_publish(subscriber, b"once-before")
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None

        upstream.kill()
        upstream.wait(timeout=5)
        upstream_output.close()
        upstream_output = None
        _wait_for_log(local, local_log, "completed start_type=once")
        if local.poll() is not None:
            raise RuntimeError(
                "start_type=once stopped the local broker: "
                + local_log.read_text(errors="replace")
            )

        restarted, restarted_output = _start_broker(
            broker, restart_config, restart_log
        )
        _wait_for_log(restarted, restart_log, "configured 1 listeners")
        publisher = _connect_client(upstream_port, "once-publisher-after")
        _publish_message(publisher, 2, b"once-after", 1)
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None
        _wait_clean(
            restarted,
            restarted_output,
            restart_log,
            "restarted once upstream",
        )
        restarted = None
        restarted_output = None

        subscriber.settimeout(2)
        try:
            unexpected = _read_packet(subscriber)
        except socket.timeout:
            pass
        else:
            raise AssertionError(
                "start_type=once reconnected after upstream restart: "
                + unexpected.hex()
            )
        subscriber.sendall(b"\xe0\x00")
        subscriber.close()
        subscriber = None
        _wait_clean(local, local_output, local_log, "once bridge broker")
        local = None
        local_output = None
    finally:
        if publisher is not None:
            publisher.close()
        if subscriber is not None:
            subscriber.close()
        if local is not None and local_output is not None:
            _stop(local, local_output)
        if restarted is not None and restarted_output is not None:
            _stop(restarted, restarted_output)
        if upstream_output is not None:
            _stop(upstream, upstream_output)


def run_tls_inbound_bridge_case(broker: Path, directory: Path) -> None:
    (
        ca_certificate,
        server_certificate,
        server_key,
        client_certificate,
        client_key,
    ) = _create_tls_material(directory)
    encrypted_client_key = directory / "bridge-client-encrypted.pem"
    client_key_password = directory / "bridge-client-key.password"
    client_key_password.write_text("bridge-key-secret\n")
    _openssl(
        "pkcs8",
        "-topk8",
        "-in",
        client_key,
        "-out",
        encrypted_client_key,
        "-v2",
        "aes-256-cbc",
        "-iter",
        2048,
        "-passout",
        "pass:bridge-key-secret",
    )
    upstream_port, local_port = _distinct_ports(2)
    upstream_config = directory / "bridge-tls-upstream.conf"
    upstream_config.write_text(
        f"listener {upstream_port} 127.0.0.1\n"
        f"certfile {server_certificate}\n"
        f"keyfile {server_key}\n"
        f"cafile {ca_certificate}\n"
        "require_certificate true\n"
        "allow_anonymous true\n"
        "max_connections 2\n"
    )
    local_config = directory / "bridge-tls-local.conf"
    local_config.write_text(
        f"listener {local_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "max_connections 1\n"
        "connection secure-upstream\n"
        f"address localhost:{upstream_port}\n"
        "topic sensors/# in 1 tls-local/ tls-remote/\n"
        "bridge_protocol_version mqttv50\n"
        "cleansession false\n"
        "bridge_session_expiry_interval 60\n"
        f"bridge_cafile {ca_certificate}\n"
        f"bridge_certfile {client_certificate}\n"
        f"bridge_keyfile {encrypted_client_key}\n"
        f"bridge_keyfile_password_file {client_key_password}\n"
        "bridge_insecure false\n"
        "bridge_tls_version tlsv1.3\n"
        "restart_timeout 1\n"
    )
    upstream_log = directory / "bridge-tls-upstream.log"
    local_log = directory / "bridge-tls-local.log"
    upstream, upstream_output = _start_broker(
        broker, upstream_config, upstream_log
    )
    local = None
    local_output = None
    subscriber = None
    publisher = None
    try:
        _wait_for_log(upstream, upstream_log, "configured 1 listeners")
        local, local_output = _start_broker(broker, local_config, local_log)
        _wait_for_log(local, local_log, "bridge secure-upstream remote=")

        subscriber = _connect_client(local_port, "tls-bridge-subscriber")
        subscriber.sendall(_subscribe(1, "tls-local/#", 1))
        suback = _read_packet(subscriber)
        if suback[0] != 0x90 or suback[-1] != 1:
            raise AssertionError(
                f"TLS bridge subscriber expected SUBACK: {suback.hex()}"
            )

        publisher = _connect_tls_client(
            upstream_port,
            "tls-bridge-publisher",
            ca_certificate,
            client_certificate,
            client_key,
        )
        _publish_message(
            publisher,
            1,
            b"vail-mtls",
            1,
            "tls-remote/sensors/temperature",
        )
        _expect_mapped_publish(
            subscriber,
            b"vail-mtls",
            "tls-local/sensors/temperature",
        )
        publisher.sendall(b"\xe0\x00")
        publisher.close()
        publisher = None
        subscriber.sendall(b"\xe0\x00")
        subscriber.close()
        subscriber = None
        _wait_clean(local, local_output, local_log, "local TLS bridge broker")
        local = None
        local_output = None
        _wait_clean(upstream, upstream_output, upstream_log, "TLS upstream broker")
        upstream_output = None
    except BaseException as exc:
        raise RuntimeError(
            "configured TLS bridge failed:\nlocal:\n"
            + (local_log.read_text(errors="replace") if local_log.exists() else "")
            + "\nupstream:\n"
            + (
                upstream_log.read_text(errors="replace")
                if upstream_log.exists()
                else ""
            )
        ) from exc
    finally:
        if publisher is not None:
            publisher.close()
        if subscriber is not None:
            subscriber.close()
        if local is not None and local_output is not None:
            _stop(local, local_output)
        if upstream_output is not None:
            _stop(upstream, upstream_output)

    empty_ca = directory / "bridge-empty-ca.pem"
    empty_ca.write_bytes(b"")
    invalid_ca_port = _free_port()
    invalid_ca_config = directory / "bridge-invalid-ca.conf"
    invalid_ca_config.write_text(
        f"listener {invalid_ca_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "connection invalid-ca\n"
        "address localhost:1\n"
        "topic # in 0\n"
        f"bridge_cafile {empty_ca}\n"
        "bridge_tls_version tlsv1.3\n"
    )
    _expect_startup_rejection(
        broker,
        invalid_ca_config,
        invalid_ca_port,
        "EmptyBridgeCaFile",
    )

    wrong_password = directory / "bridge-client-key-wrong.password"
    wrong_password.write_text("wrong-secret\n")
    invalid_key_port = _free_port()
    invalid_key_config = directory / "bridge-invalid-key-password.conf"
    invalid_key_config.write_text(
        f"listener {invalid_key_port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "connection invalid-key-password\n"
        "address localhost:1\n"
        "topic # in 0\n"
        f"bridge_cafile {ca_certificate}\n"
        f"bridge_certfile {client_certificate}\n"
        f"bridge_keyfile {encrypted_client_key}\n"
        f"bridge_keyfile_password_file {wrong_password}\n"
        "bridge_tls_version tlsv1.3\n"
    )
    _expect_startup_rejection(
        broker,
        invalid_key_config,
        invalid_key_port,
        "InvalidPasswordOrCiphertext",
    )
