"""Mosquitto-style periodic $SYS configuration scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import os
import signal
import socket
import subprocess
import time
from typing import Iterator

from mqtt_commit_log_support import (
    connect_client,
    free_port,
    packet,
    qos0_publish_packet,
    read_packet,
    subscribe_packet,
)


@contextmanager
def _configured_broker(
    broker: Path, config: Path
) -> Iterator[subprocess.Popen[str]]:
    process = subprocess.Popen(
        [str(broker), f"--config={config}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    try:
        ready = process.stdout.readline().strip()
        if "configured 1 listeners for 1 clients" not in ready:
            raise RuntimeError(f"sys-interval broker failed to start: {ready}")
        yield process
        if process.wait(timeout=5) != 0:
            raise RuntimeError(
                "sys-interval broker failed: " + process.stdout.read()
            )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def _expect(sock: socket.socket, expected: bytes, label: str) -> None:
    first, body = read_packet(sock)
    actual = bytes((first,)) + bytes((len(body),)) + body
    if actual != expected:
        raise AssertionError(
            f"{label}: expected {expected.hex()}, got {actual.hex()}"
        )


def _expect_no_packet(sock: socket.socket, timeout: float, label: str) -> None:
    sock.settimeout(timeout)
    try:
        first, body = read_packet(sock)
    except TimeoutError:
        return
    finally:
        sock.settimeout(5)
    raise AssertionError(
        f"{label}: unexpected packet "
        + (bytes((first,)) + body).hex()
    )


def _ping_barrier(sock: socket.socket, label: str) -> None:
    sock.sendall(packet(0xC0, b""))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        first, body = read_packet(sock)
        if first == 0xD0 and body == b"":
            return
        if first >> 4 != 3:
            raise AssertionError(
                f"{label}: expected PUBLISH or PINGRESP, "
                f"got {(bytes((first,)) + body).hex()}"
            )
    raise TimeoutError(f"{label}: timed out waiting for PINGRESP")


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


def _disconnect(sock: socket.socket) -> None:
    sock.sendall(packet(0xE0, b""))
    try:
        if sock.recv(1):
            raise AssertionError("broker wrote bytes after DISCONNECT")
    except ConnectionResetError:
        pass
    finally:
        sock.close()


def _subscribe(port: int, client_id: str) -> socket.socket:
    client = connect_client(
        port,
        client_id,
        clean_start=True,
        session_present=False,
        protocol=5,
        session_expiry=0,
    )
    client.sendall(
        subscribe_packet(
            1,
            "$SYS/broker/clients/connected",
            subscription_identifier=None,
            qos=0,
            protocol=5,
        )
    )
    _expect(client, packet(0x90, b"\x00\x01\x00\x00"), "system SUBACK")
    return client


def run_system_interval_case(broker: Path, directory: Path) -> None:
    port = free_port()
    config = directory / "sys-interval-reload.conf"

    def write_config(
        sys_interval: str,
        retain_minutes: int = 0,
        extra_global: str = "",
    ) -> None:
        retained = (
            f"retain_expiry_interval {retain_minutes}\n"
            if retain_minutes
            else ""
        )
        config.write_text(
            f"sys_interval {sys_interval}\n"
            + retained
            + extra_global
            + f"listener {port} 127.0.0.1\n"
            + "max_topic_alias_broker 0\n"
            + "listener_allow_anonymous true\n"
            + "max_connections 1\n"
        )

    def reload(
        process: subprocess.Popen[str],
        sys_interval: str,
        retain_minutes: int = 0,
        extra_global: str = "",
    ) -> None:
        write_config(sys_interval, retain_minutes, extra_global)
        os.kill(process.pid, signal.SIGHUP)

    write_config("0")
    with _configured_broker(broker, config) as process:
        client = _subscribe(port, "sys-interval-reload")
        try:
            _expect_no_packet(client, 1.2, "disabled system interval")

            reload(process, "1")
            _wait_for_output(
                process,
                "runtime scheduling reload completed: sys_interval=1 "
                "retain_expiry_interval=0",
                "enable system interval reload",
            )
            _expect(
                client,
                qos0_publish_packet(
                    "$SYS/broker/clients/connected",
                    b"1",
                    retain=False,
                    protocol=5,
                ),
                "enabled periodic system statistic",
            )

            reload(
                process,
                "0",
                extra_global="max_packet_size 100\n",
            )
            _wait_for_output(
                process,
                "configuration reload failed: "
                "error=GlobalConfigurationRequiresRestart",
                "restart-required global rollback",
            )
            _expect(
                client,
                qos0_publish_packet(
                    "$SYS/broker/clients/connected",
                    b"1",
                    retain=False,
                    protocol=5,
                ),
                "system interval after rejected global reload",
            )

            reload(process, "invalid")
            _wait_for_output(
                process,
                "configuration reload failed: error=InvalidInteger",
                "invalid scheduling rollback",
            )
            _expect(
                client,
                qos0_publish_packet(
                    "$SYS/broker/clients/connected",
                    b"1",
                    retain=False,
                    protocol=5,
                ),
                "system interval after failed reload",
            )

            reload(process, "10", retain_minutes=1)
            _wait_for_output(
                process,
                "runtime scheduling reload completed: sys_interval=10 "
                "retain_expiry_interval=60",
                "long scheduling interval reload",
            )
            reload(process, "1")
            _wait_for_output(
                process,
                "runtime scheduling reload completed: sys_interval=1 "
                "retain_expiry_interval=0",
                "shortened scheduling interval reload",
            )
            _expect(
                client,
                qos0_publish_packet(
                    "$SYS/broker/clients/connected",
                    b"1",
                    retain=False,
                    protocol=5,
                ),
                "shortened periodic system statistic",
            )

            reload(process, "0")
            _wait_for_output(
                process,
                "runtime scheduling reload completed: sys_interval=0 "
                "retain_expiry_interval=0",
                "disable scheduling interval reload",
            )
            _ping_barrier(client, "disabled scheduling barrier")
            _expect_no_packet(
                client,
                1.2,
                "disabled system interval after reload",
            )
            _disconnect(client)
        finally:
            client.close()
