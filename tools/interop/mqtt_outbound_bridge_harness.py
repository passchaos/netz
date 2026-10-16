"""Shared process and socket harness for outbound-bridge interop cases."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import BinaryIO

from mqtt_outbound_bridge_support import read_packet


@dataclass(frozen=True)
class Case:
    name: str
    source_protocol: int
    target_protocol: int
    qos: int
    retain: bool

    @property
    def source_label(self) -> str:
        return "v311" if self.source_protocol == 4 else "v5"

    @property
    def target_label(self) -> str:
        return "v311" if self.target_protocol == 4 else "v5"


@dataclass
class ManagedProcess:
    label: str
    process: subprocess.Popen[bytes]
    output: BinaryIO
    log: Path

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if not self.output.closed:
            self.output.close()

    def wait_clean(self) -> None:
        try:
            return_code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{self.label} did not stop gracefully") from exc
        if not self.output.closed:
            self.output.close()
        if return_code != 0:
            raise RuntimeError(
                f"{self.label} exited {return_code}: "
                + self.log.read_text(errors="replace")
            )

    def crash(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        if not self.output.closed:
            self.output.close()

    def wait_failure(self, expected: str) -> None:
        try:
            return_code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"{self.label} did not fail as expected"
            ) from exc
        if not self.output.closed:
            self.output.close()
        content = self.log.read_text(errors="replace")
        if return_code == 0 or expected not in content:
            raise RuntimeError(
                f"{self.label} did not fail with {expected}: " + content
            )


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def distinct_ports(count: int) -> list[int]:
    ports: set[int] = set()
    while len(ports) != count:
        ports.add(free_port())
    return list(ports)


def connect_client(
    port: int, mqtt_packets, client_id: str, protocol: int
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(mqtt_packets.gen_connect(client_id, proto_ver=protocol))
    connack = read_packet(sock)
    if connack[0] != 0x20 or len(connack) < 4 or connack[3] >= 0x80:
        sock.close()
        raise AssertionError(f"invalid CONNACK: {connack.hex()}")
    return sock


def subscribe(
    sock: socket.socket, mqtt_packets, protocol: int, topic: str, qos: int
) -> None:
    sock.sendall(mqtt_packets.gen_subscribe(1, topic, qos, proto_ver=protocol))
    packet = read_packet(sock)
    if packet[0] != 0x90:
        raise AssertionError(f"expected SUBACK, received {packet.hex()}")
    expected = mqtt_packets.gen_suback(1, qos, proto_ver=protocol)
    if packet != expected:
        raise AssertionError(
            f"SUBACK mismatch: expected {expected.hex()}, got {packet.hex()}"
        )


def wait_for_log(
    process: subprocess.Popen[bytes], path: Path, marker: str, label: str
) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        content = path.read_text(errors="replace") if path.exists() else ""
        if marker in content:
            return
        code = process.poll()
        if code is not None:
            raise RuntimeError(f"{label} exited {code}: {content}")
        time.sleep(0.02)
    raise RuntimeError(f"timed out waiting for {label}: {path.read_text()}")


def assert_log_absent(path: Path, marker: str, duration: float) -> None:
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        if marker in path.read_text(errors="replace"):
            raise AssertionError(f"unexpected log marker before recovery: {marker}")
        time.sleep(0.02)


def start_broker(
    executable: Path, port: int, directory: Path, label: str,
    extra_config: str = "",
) -> ManagedProcess:
    config = directory / f"{label}.conf"
    log = directory / f"{label}.log"
    config.write_text(
        f"listener {port} 127.0.0.1\n"
        "listener_allow_anonymous true\n"
        "persistence false\n"
        "log_type all\n"
        + extra_config,
        encoding="ascii",
    )
    output = log.open("wb")
    managed = ManagedProcess(
        label,
        subprocess.Popen(
            [str(executable), "-c", str(config), "-v"],
            stdout=output,
            stderr=subprocess.STDOUT,
        ),
        output,
        log,
    )
    try:
        wait_for_log(managed.process, log, " running", label)
    except BaseException:
        managed.stop()
        raise
    return managed


def launch_bridge(
    executable: Path, source_port: int, target_port: int,
    control_port: int, case: Case, directory: Path,
    coordinator_mode: str | None = None,
) -> ManagedProcess:
    log = directory / (
        "bridge.log" if coordinator_mode is None
        else f"bridge-{coordinator_mode}.log"
    )
    output = log.open("wb")
    command = [
        str(executable), str(source_port), str(target_port),
        str(control_port), case.source_label, case.target_label,
        str(case.qos), case.name,
    ]
    if coordinator_mode is not None:
        command.extend((str(directory), coordinator_mode))
    return ManagedProcess(
        "bridge",
        subprocess.Popen(
            command,
            stdout=output,
            stderr=subprocess.STDOUT,
        ),
        output,
        log,
    )


def start_bridge(
    executable: Path, source_port: int, target_port: int,
    control_port: int, case: Case, directory: Path,
    coordinator_mode: str | None = None,
) -> ManagedProcess:
    managed = launch_bridge(
        executable, source_port, target_port, control_port, case, directory,
        coordinator_mode,
    )
    try:
        wait_for_log(
            managed.process, managed.log, "outbound bridge ready",
            managed.label,
        )
    except BaseException:
        managed.stop()
        raise
    return managed


def cleanup_case(
    clients: list[socket.socket],
    processes: list[ManagedProcess],
    failed: bool,
) -> None:
    for client in clients:
        try:
            client.close()
        except OSError:
            pass
    for managed in reversed(processes):
        managed.stop()
    if failed:
        for managed in processes:
            print(f"===== {managed.label} log =====", file=sys.stderr)
            if managed.log.exists():
                print(
                    managed.log.read_text(errors="replace"),
                    file=sys.stderr,
                )
