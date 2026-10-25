"""Production include_dir startup, file ordering, and atomic reload evidence."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import signal
import socket
import subprocess


def connack_policy(packet: bytes) -> dict[int, int | str]:
    """Decode policy values at property boundaries, including duplicate checks."""
    from mqtt_broker_config import connack_properties, connack_reason

    if connack_reason(packet) != 0:
        raise AssertionError(f"unsuccessful CONNECT: {packet.hex()}")
    properties = connack_properties(packet)
    widths = {0x11: 4, 0x13: 2, 0x21: 2, 0x22: 2, 0x24: 1,
              0x25: 1, 0x27: 4, 0x28: 1, 0x29: 1, 0x2A: 1}
    strings = {0x12, 0x15, 0x1A, 0x1C, 0x1F}
    values: dict[int, int | str] = {}
    offset = 0
    while offset < len(properties):
        identifier = properties[offset]
        offset += 1
        if identifier in values:
            raise AssertionError(f"duplicate CONNACK property {identifier:#x}")
        if identifier in widths:
            width = widths[identifier]
            if offset + width > len(properties):
                raise AssertionError("truncated CONNACK property")
            value = int.from_bytes(properties[offset:offset + width], "big")
            offset += width
        elif identifier in strings:
            if offset + 2 > len(properties):
                raise AssertionError("truncated CONNACK string length")
            width = int.from_bytes(properties[offset:offset + 2], "big")
            offset += 2
            if offset + width > len(properties):
                raise AssertionError("truncated CONNACK string")
            value = properties[offset:offset + width].decode("utf-8")
            offset += width
        else:
            raise AssertionError(f"unexpected CONNACK property {identifier:#x}")
        values[identifier] = value
    return values


def _stop(process: subprocess.Popen[str], *, require_success: bool = False) -> None:
    running = process.poll() is None
    if running:
        process.terminate()
    try:
        code = process.wait(timeout=5)
        if (running or require_success) and code not in (0, -signal.SIGTERM):
            raise AssertionError(f"configured broker exited with {code}")
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise AssertionError("configured broker did not terminate")
    finally:
        if process.stdout is not None:
            process.stdout.close()


def run_include_directory_reload_case(broker: Path, directory: Path) -> None:
    from mqtt_broker_config import (
        connect_packet, connack_reason, free_port, read_mqtt_packet,
        publish_packet, subscribe_packet, wait_process_line,
    )

    root = directory / "include reload"
    root.mkdir()
    first = root / "first fragments"
    second = root / "second fragments"
    first.mkdir()
    second.mkdir()
    ports: list[int] = []
    while len(ports) < 3:
        port = free_port()
        if port not in ports:
            ports.append(port)
    password_token = directory / "include-users.pw"
    salt = b"include-salt"
    digest = hashlib.sha512(b"correct" + salt).digest()
    password_token.write_text(
        "included-user:$6$" + base64.b64encode(salt).decode() + "$"
        + base64.b64encode(digest).decode() + "\n"
    )
    fragments = (first / "A.conf", first / "a.conf", second / "00.conf")
    # Ignored extensions and subdirectories must not affect the config set.
    (first / "ignored.txt").write_text("unknown_option true\n")
    (first / "ignored.CONF").write_text("unknown_option true\n")
    nested = first / "nested"
    nested.mkdir()
    (nested / "ignored.conf").write_text("unknown_option true\n")
    main = root / "main.conf"
    main.write_text(
        "per_listener_settings true\nsys_interval 0\n"
        f"include_dir {first}\ninclude_dir {second}\n"
    )
    original_main = main.read_bytes()

    def write_fragments(phase: str) -> None:
        for index, fragment in enumerate(fragments):
            qos = 0 if index == 1 and phase in ("initial", "recovered") else 1
            alias = 1 + index if phase == "initial" else 5 + index
            anonymous = index != 0 or phase in ("initial", "recovered")
            fragment.write_text(
                f"listener {ports[index]} 127.0.0.1\n"
                f"password_file {password_token}\n"
                f"allow_anonymous {str(anonymous).lower()}\n"
                f"listener_auto_id_prefix {phase}-{index}-\n"
                f"maximum_qos {qos}\nmax_topic_alias {alias}\n"
                "max_keepalive 30\nmax_connections 32\n"
            )

    write_fragments("initial")
    env = os.environ.copy()
    env.pop("NETZ_MQTT_CONFIG_FINITE_TEST", None)
    process = subprocess.Popen(
        [str(broker), f"--config={main}"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    clients: list[socket.socket] = []
    completed = False

    def expect(sock: socket.socket, packet: bytes, label: str) -> None:
        actual = read_mqtt_packet(sock)
        if actual != packet:
            raise AssertionError(
                f"{label}: expected {packet.hex()}, got {actual.hex()}"
            )

    def ping(sock: socket.socket) -> None:
        sock.sendall(b"\xc0\x00")
        expect(sock, b"\xd0\x00", "live connection PING")

    def connect(index: int, identifier: str, version: int = 5,
                authenticated: bool = False, reason: int = 0) -> tuple[socket.socket, bytes]:
        sock = socket.create_connection(("127.0.0.1", ports[index]), timeout=5)
        clients.append(sock)
        sock.settimeout(5)
        sock.sendall(connect_packet(
            identifier, proto_ver=version,
            keep_alive=20 if version == 4 else 60,
            username="included-user" if authenticated else None,
            password="correct" if authenticated else None,
        ))
        ack = read_mqtt_packet(sock)
        if connack_reason(ack) != reason:
            raise AssertionError(f"{identifier}: unexpected CONNACK {ack.hex()}")
        return sock, ack

    def probe(phase: str) -> None:
        for index in range(3):
            sock, ack = connect(index, "")
            values = connack_policy(ack)
            expected = {
                0x24: 0 if index == 1 and phase in ("initial", "recovered") else 1,
                0x22: (1 if phase == "initial" else 5) + index,
                0x13: 30,
            }
            for key, value in expected.items():
                if values.get(key) != value:
                    raise AssertionError(f"{phase} listener {index}: property {key:#x} {values!r}")
            assigned = values.get(0x12)
            if not isinstance(assigned, str) or not assigned.startswith(f"{phase}-{index}-"):
                raise AssertionError(f"{phase} listener {index}: assigned ID {assigned!r}")
            sock.sendall(subscribe_packet(1, "include/probe", qos=1))
            expect(sock, bytes((0x90, 4, 0, 1, 0, expected[0x24])), "policy SUBACK")
            ping(sock)
            sock.sendall(b"\xe0\x00")
            sock.close()

    def check_changed() -> None:
        denied, ack = connect(0, "denied", reason=0x87)
        denied.close()
        for index in range(3):
            sock, ack = connect(index, "", authenticated=True)
            values = connack_policy(ack)
            if values.get(0x24) != 1 or values.get(0x22) != 5 + index or values.get(0x13) != 30:
                raise AssertionError(f"changed listener {index}: {values!r}")
            assigned = values.get(0x12)
            if not isinstance(assigned, str) or not assigned.startswith(f"changed-{index}-"):
                raise AssertionError(f"changed listener {index}: assigned ID {assigned!r}")
            ping(sock)
            sock.sendall(b"\xe0\x00")
            sock.close()

    def reload(marker: str) -> None:
        if main.read_bytes() != original_main:
            raise AssertionError("include scenario changed the root config")
        process.send_signal(signal.SIGHUP)
        wait_process_line(process, marker, "included-file reload")

    try:
        wait_process_line(process, "configured 3 listeners global_max_connections=", "included startup")
        for port in ports:
            wait_process_line(process, f"127.0.0.1:{port} ", "included filename order")
        probe("initial")
        # Preserve authenticated and v3.1.1 connections across every reload.
        subscriber, _ = connect(0, "live-subscriber", authenticated=True)
        publisher, _ = connect(0, "live-publisher", authenticated=True)
        legacy, _ = connect(2, "live-v311", version=4, authenticated=True)
        subscriber.sendall(subscribe_packet(1, "include/live", qos=0))
        expect(subscriber, b"\x90\x04\x00\x01\x00\x00", "live SUBACK")

        def delivery(payload: bytes, mid: int, rejected: bool = False) -> None:
            publisher.sendall(publish_packet("include/live", payload, qos=1, packet_id=mid))
            expect(publisher, b"\x40" + bytes((3 if rejected else 2,))
                   + mid.to_bytes(2, "big") + (b"\x83" if rejected else b""), "payload PUBACK")
            if not rejected:
                expect(subscriber, publish_packet("include/live", payload), "live PUBLISH")
            ping(subscriber)
            ping(legacy)

        delivery(b"before", 1)
        write_fragments("changed")
        reload("Client ID prefix reload completed: length=0")
        check_changed()
        delivery(b"after", 2)

        # A valid earlier fragment must not apply if a later source is invalid.
        write_fragments("recovered")
        invalid = second / "99-invalid.conf"
        invalid.write_text("unknown_option true\n")
        reload("configuration reload failed: error=UnsupportedDirective")
        check_changed()
        delivery(b"rollback", 3)
        invalid.unlink()
        reload("Client ID prefix reload completed: length=0")
        probe("recovered")
        delivery(b"recovered", 4)

        # Security dependencies are prepared before any earlier policy changes
        # commit, even when the missing path lives in the last include source.
        write_fragments("changed")
        fragments[2].write_text(fragments[2].read_text().replace(
            str(password_token), str(directory / "missing-included-users.pw"),
        ))
        reload("security reload failed: error=FileNotFound")
        probe("recovered")
        delivery(b"security rollback", 8)
        write_fragments("recovered")
        reload("Client ID prefix reload completed: length=0")
        probe("recovered")

        # Adding/deleting a fragment must update runtime policy on live clients.
        extra = second / "90-payload.conf"
        extra.write_text("message_size_limit 1\n")
        reload("runtime delivery reload completed: message_size_limit=1 ")
        delivery(b"AB", 5, rejected=True)
        delivery(b"A", 6)
        extra.unlink()
        reload("runtime delivery reload completed: message_size_limit=0 ")
        delivery(b"AB", 7)
        for sock in (subscriber, publisher, legacy):
            ping(sock)
            sock.sendall(b"\xe0\x00")
        completed = True
    finally:
        for sock in clients:
            sock.close()
        _stop(process, require_success=completed)


def run_include_directory_case(broker: Path, directory: Path) -> None:
    from mqtt_broker_config import (
        free_port, connect_packet, connack_reason, read_mqtt_packet,
        wait_process_line,
    )

    include_directory = directory / "listeners.d"
    include_directory.mkdir()
    first_port = free_port()
    second_port = free_port()
    while second_port == first_port:
        second_port = free_port()
    (include_directory / "ignored.txt").write_text("unsupported value\n")
    (include_directory / "a.conf").write_text(
        f"listener {second_port} 127.0.0.1\n"
        "listener_allow_anonymous true\n"
        "max_connections 1\n"
    )
    (include_directory / "A.conf").write_text(
        f"listener {first_port} 127.0.0.1\n"
        "listener_allow_anonymous true\n"
        "max_connections 1\n"
    )
    config = directory / "include-main.conf"
    config.write_text(f"include_dir {include_directory}\n")
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_process_line(process, "configured 2 listeners for 2 clients", "include startup")
        for port in (first_port, second_port):
            wait_process_line(process, f"127.0.0.1:{port} ", "include filename order")
        for index, port in enumerate((first_port, second_port)):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.settimeout(5)
                client.sendall(connect_packet(f"include-dir-{index}"))
                if connack_reason(read_mqtt_packet(client)) != 0:
                    raise AssertionError("include_dir listener rejected CONNECT")
                client.sendall(bytes.fromhex("e000"))
        if process.wait(timeout=5) != 0:
            raise RuntimeError("include_dir broker exited with an error")
    finally:
        _stop(process)

    invalid_port = free_port()
    invalid_directory = directory / "invalid-listeners.d"
    invalid_directory.mkdir()
    (invalid_directory / "10-listener.conf").write_text(
        f"listener {free_port()} 127.0.0.1\nlistener_allow_anonymous true\n"
    )
    (invalid_directory / "20-invalid.conf").write_text(
        "unsupported_directive true\n"
    )
    invalid_config = directory / "invalid-include-main.conf"
    invalid_config.write_text(
        f"listener {invalid_port} 127.0.0.1\n"
        "listener_allow_anonymous true\n"
        f"include_dir {invalid_directory}\n"
    )
    def invalid_startup(expected: str) -> None:
        result = subprocess.run(
            [str(broker), f"--config={invalid_config}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=5, check=False,
        )
        if result.returncode == 0 or expected not in result.stdout:
            raise AssertionError(f"included config did not reject {expected}: {result.stdout}")
        if "configured" in result.stdout or "  mqtt " in result.stdout:
            raise AssertionError("included config failure occurred after binding listeners")
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(("127.0.0.1", invalid_port)) == 0:
                raise AssertionError("listener bound before include validation")

    invalid_startup("UnsupportedDirective")
    invalid_file = invalid_directory / "20-invalid.conf"
    invalid_file.write_text("password_file missing-included-security.pw\n")
    invalid_startup("FileNotFound")
    invalid_file.unlink()
    invalid_file.symlink_to(invalid_directory / "10-listener.conf")
    invalid_startup("InvalidIncludeFile")
    invalid_file.unlink()
    invalid_file.write_text(f"include_dir {include_directory}\n")
    invalid_startup("NestedIncludeDirectory")
