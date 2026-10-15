"""Atomic SIGHUP reload scenarios for broker delivery and Session policy."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import socket
import subprocess
import time

from mqtt_commit_log_support import (
    connect_client,
    free_port,
    packet,
    publish_packet,
    qos0_publish_packet,
    read_packet,
    subscribe_packet,
)


def _expect(sock: socket.socket, expected: bytes, label: str) -> None:
    first, body = read_packet(sock)
    actual = packet(first, body)
    if actual != expected:
        raise AssertionError(
            f"{label}: expected {expected.hex()}, got {actual.hex()}"
        )


def _ping(sock: socket.socket, label: str) -> None:
    sock.sendall(packet(0xC0, b""))
    _expect(sock, packet(0xD0, b""), label)


def _disconnect(sock: socket.socket) -> None:
    sock.sendall(packet(0xE0, b""))
    sock.close()


def _wait_for_output(
    process: subprocess.Popen[str], expected: str, label: str
) -> None:
    assert process.stdout is not None
    os.set_blocking(process.stdout.fileno(), False)
    deadline = time.monotonic() + 5
    observed: list[str] = []
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if not line:
            if process.poll() is not None:
                break
            time.sleep(0.01)
            continue
        observed.append(line.rstrip())
        if expected in line:
            return
    raise RuntimeError(
        f"{label}: missing {expected!r}; observed={observed!r}"
    )


def run_runtime_delivery_policy_reload_case(
    broker: Path,
    directory: Path,
) -> None:
    port = free_port()
    config = directory / "runtime-delivery-policy-reload.conf"

    def write_config(
        message_size_limit: int,
        queue_qos0: bool,
        upgrade_qos: bool,
        persistent_expiry: int,
        extra_global: str = "",
    ) -> None:
        config.write_text(
            f"message_size_limit {message_size_limit}\n"
            f"queue_qos0_messages {str(queue_qos0).lower()}\n"
            f"upgrade_outgoing_qos {str(upgrade_qos).lower()}\n"
            f"persistent_client_expiration {persistent_expiry}s\n"
            "sys_interval 0\n"
            + extra_global
            + f"listener {port} 127.0.0.1\n"
            "allow_anonymous true\n"
            "max_connections 5\n"
        )

    write_config(1, False, False, 10)
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if "configured 1 listeners for 5 clients" not in ready:
        raise RuntimeError(f"runtime delivery broker failed to start: {ready}")

    clients: list[socket.socket] = []
    try:
        offline = connect_client(
            port,
            "runtime-policy-offline",
            clean_start=False,
            session_present=False,
            session_expiry=60,
        )
        offline.sendall(
            subscribe_packet(
                1,
                "policy/offline",
                subscription_identifier=None,
                qos=1,
                protocol=5,
            )
        )
        _expect(offline, packet(0x90, b"\x00\x01\x00\x01"), "offline SUBACK")
        _disconnect(offline)

        live = connect_client(
            port,
            "runtime-policy-live",
            clean_start=True,
            session_present=False,
            session_expiry=0,
        )
        clients.append(live)
        live.sendall(
            subscribe_packet(
                1,
                "policy/live",
                subscription_identifier=None,
                qos=1,
                protocol=5,
            )
        )
        _expect(live, packet(0x90, b"\x00\x01\x00\x01"), "live SUBACK")

        publisher = connect_client(
            port,
            "runtime-policy-publisher",
            clean_start=True,
            session_present=False,
            session_expiry=0,
        )
        clients.append(publisher)

        publisher.sendall(publish_packet("policy/live", b"AB", 1, qos=1))
        _expect(
            publisher,
            packet(0x40, b"\x00\x01\x83"),
            "initial payload rejection",
        )
        _ping(live, "live barrier after payload rejection")

        publisher.sendall(
            qos0_publish_packet(
                "policy/live",
                b"A",
                retain=False,
                protocol=5,
            )
        )
        _expect(
            live,
            qos0_publish_packet(
                "policy/live",
                b"A",
                retain=False,
                protocol=5,
            ),
            "initial non-upgraded delivery",
        )
        publisher.sendall(
            qos0_publish_packet(
                "policy/offline",
                b"drop",
                retain=False,
                protocol=5,
            )
        )
        _ping(publisher, "initial offline-drop barrier")

        write_config(0, True, True, 1)
        os.kill(process.pid, signal.SIGHUP)
        _wait_for_output(
            process,
            "runtime delivery reload completed: message_size_limit=0 "
            "queue_qos0_messages=true upgrade_outgoing_qos=true "
            "persistent_client_expiration=1",
            "runtime delivery policy reload",
        )

        write_config(
            1,
            False,
            False,
            10,
            extra_global="max_packet_size 100\n",
        )
        os.kill(process.pid, signal.SIGHUP)
        _wait_for_output(
            process,
            "configuration reload failed: "
            "error=GlobalConfigurationRequiresRestart",
            "runtime delivery cross-policy rollback",
        )

        publisher.sendall(
            qos0_publish_packet(
                "policy/live",
                b"AB",
                retain=False,
                protocol=5,
            )
        )
        _expect(
            live,
            publish_packet("policy/live", b"AB", 1, qos=1),
            "reloaded payload and QoS policy",
        )
        live.sendall(packet(0x40, b"\x00\x01"))

        publisher.sendall(
            qos0_publish_packet(
                "policy/offline",
                b"queued",
                retain=False,
                protocol=5,
            )
        )
        _ping(publisher, "reloaded offline-queue barrier")

        resumed = connect_client(
            port,
            "runtime-policy-offline",
            clean_start=False,
            session_present=True,
            session_expiry=60,
        )
        _expect(
            resumed,
            publish_packet("policy/offline", b"queued", 1, qos=1),
            "reloaded queued QoS 0 delivery",
        )
        resumed.sendall(packet(0x40, b"\x00\x01"))
        _ping(resumed, "dropped QoS 0 remained absent")
        _disconnect(resumed)

        time.sleep(1.2)
        expired = connect_client(
            port,
            "runtime-policy-offline",
            clean_start=False,
            session_present=False,
            session_expiry=60,
        )
        clients.append(expired)
        _disconnect(expired)
        clients.pop()
        _disconnect(publisher)
        clients.remove(publisher)
        _disconnect(live)
        clients.remove(live)

        if process.wait(timeout=5) != 0:
            raise RuntimeError(
                "runtime delivery broker failed: " + process.stdout.read()
            )
    finally:
        for client in clients:
            client.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
