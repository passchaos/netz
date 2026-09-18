#!/usr/bin/env python3
"""Exercise netz OutboundBridge between two real Mosquitto brokers."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import BinaryIO


RUNTIME = (
    "bridge_io=zio-std-io source_broker_io=mosquitto-event-loop "
    "target_broker_io=mosquitto-event-loop"
)


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


CASES = (
    Case("v311-to-v5-qos0", 4, 5, 0, False),
    Case("v5-to-v311-qos1-retain", 5, 4, 1, True),
)


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


class AckDropProxy:
    def __init__(self, listen_port: int, target_port: int, payload: bytes):
        self.target_port = target_port
        self.payload = payload
        self.allow_replay = threading.Event()
        self.retry_held = threading.Event()
        self.replay_complete = threading.Event()
        self.stop_requested = threading.Event()
        self.error: BaseException | None = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", listen_port))
        self.listener.listen(2)
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self._run, name="mqtt-ack-drop")
        self.thread.start()

    def _accept(self) -> socket.socket:
        while not self.stop_requested.is_set():
            try:
                client, _ = self.listener.accept()
                client.settimeout(5)
                return client
            except socket.timeout:
                continue
        raise RuntimeError("proxy stopped before bridge reconnect")

    def _connect_session(
        self, client: socket.socket, *, session_present: bool
    ) -> socket.socket:
        target = socket.create_connection(
            ("127.0.0.1", self.target_port), timeout=5
        )
        target.settimeout(5)
        connect_packet = read_packet(client)
        if connect_packet[0] >> 4 != 1:
            raise AssertionError(
                f"proxy expected CONNECT, received {connect_packet.hex()}"
            )
        target.sendall(connect_packet)
        connack = read_packet(target)
        _, cursor = decode_remaining_length(connack)
        if connack[0] >> 4 != 2 or bool(connack[cursor] & 0x01) != session_present:
            raise AssertionError(
                f"target Session Present mismatch: {connack.hex()}"
            )
        client.sendall(connack)
        return target

    def _read_publish(self, client: socket.socket) -> tuple[bytes, int]:
        packet = read_packet(client)
        packet_id = assert_publish(
            packet, 5, qos=1, retain=True, payload=self.payload
        )
        if packet_id is None:
            raise AssertionError("proxied QoS 1 PUBLISH has no packet id")
        return packet, packet_id

    @staticmethod
    def _expect_puback(packet: bytes, packet_id: int) -> None:
        _, cursor = decode_remaining_length(packet)
        if packet[0] >> 4 != 4 or int.from_bytes(
            packet[cursor : cursor + 2], "big"
        ) != packet_id:
            raise AssertionError(f"target PUBACK mismatch: {packet.hex()}")

    def _run_fallible(self) -> None:
        with self._accept() as first:
            with self._connect_session(first, session_present=False) as target:
                original, packet_id = self._read_publish(first)
                if original[0] & 0x08:
                    raise AssertionError("initial target PUBLISH unexpectedly set DUP")
                target.sendall(original)
                puback = read_packet(target)
                self._expect_puback(puback, packet_id)
                # Deliberately discard this PUBACK and close the bridge-facing
                # transport. Mosquitto has completed its QoS 1 transaction.

        with self._accept() as resumed:
            with self._connect_session(resumed, session_present=True) as target:
                retry, retry_packet_id = self._read_publish(resumed)
                if retry[0] & 0x08 == 0:
                    raise AssertionError("resumed target PUBLISH omitted DUP")
                if retry_packet_id != packet_id:
                    raise AssertionError(
                        "resumed target PUBLISH changed Packet Identifier"
                    )
                self.retry_held.set()
                if not self.allow_replay.wait(timeout=5):
                    raise RuntimeError("timed out waiting to release retry")
                target.sendall(retry)
                puback = read_packet(target)
                self._expect_puback(puback, packet_id)
                resumed.sendall(puback)
                self.replay_complete.set()

                while not self.stop_requested.is_set():
                    try:
                        packet = read_packet(resumed)
                    except socket.timeout:
                        continue
                    target.sendall(packet)
                    if packet[0] >> 4 == 14:
                        return
                    response = read_packet(target)
                    resumed.sendall(response)

    def _run(self) -> None:
        try:
            self._run_fallible()
        except BaseException as exc:
            if not self.stop_requested.is_set():
                self.error = exc
        finally:
            self.retry_held.set()
            self.replay_complete.set()

    def wait(self, event: threading.Event, label: str) -> None:
        if not event.wait(timeout=10):
            raise RuntimeError(f"timed out waiting for {label}")
        if self.error is not None:
            raise self.error

    def finish(self) -> None:
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("ACK-drop proxy did not stop")
        if self.error is not None:
            raise self.error

    def stop(self) -> None:
        self.stop_requested.set()
        self.allow_replay.set()
        self.listener.close()
        self.thread.join(timeout=6)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("bridge", type=Path)
    parser.add_argument("mosquitto", type=Path)
    parser.add_argument(
        "--mosquitto-test-root",
        type=Path,
        default=Path.home() / "Work/mosquitto/test",
    )
    return parser.parse_args()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def distinct_ports(count: int) -> list[int]:
    ports: set[int] = set()
    while len(ports) != count:
        ports.add(free_port())
    return list(ports)


def recv_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise AssertionError("peer closed before complete MQTT packet")
        result.extend(part)
    return bytes(result)


def decode_remaining_length(data: bytes, offset: int = 1) -> tuple[int, int]:
    value = 0
    multiplier = 1
    for index in range(4):
        encoded = data[offset + index]
        value += (encoded & 0x7F) * multiplier
        if encoded & 0x80 == 0:
            return value, offset + index + 1
        multiplier *= 128
    raise AssertionError("malformed MQTT Remaining Length")


def read_packet(sock: socket.socket) -> bytes:
    packet = bytearray(recv_exact(sock, 1))
    remaining = 0
    multiplier = 1
    for _ in range(4):
        encoded = recv_exact(sock, 1)[0]
        packet.append(encoded)
        remaining += (encoded & 0x7F) * multiplier
        if encoded & 0x80 == 0:
            packet.extend(recv_exact(sock, remaining))
            return bytes(packet)
        multiplier *= 128
    raise AssertionError("malformed MQTT Remaining Length")


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


def parse_publish(packet: bytes, protocol: int) -> dict[str, object]:
    if packet[0] >> 4 != 3:
        raise AssertionError(f"expected PUBLISH, received {packet.hex()}")
    remaining, cursor = decode_remaining_length(packet)
    if cursor + remaining != len(packet):
        raise AssertionError("PUBLISH length mismatch")
    topic_len = int.from_bytes(packet[cursor : cursor + 2], "big")
    cursor += 2
    topic = packet[cursor : cursor + topic_len].decode("utf-8")
    cursor += topic_len
    qos = (packet[0] >> 1) & 0x03
    packet_id = None
    if qos != 0:
        packet_id = int.from_bytes(packet[cursor : cursor + 2], "big")
        cursor += 2
    if protocol == 5:
        properties_len, properties_start = decode_remaining_length(
            packet, cursor
        )
        cursor = properties_start + properties_len
    return {
        "topic": topic,
        "payload": packet[cursor:],
        "qos": qos,
        "retain": bool(packet[0] & 0x01),
        "packet_id": packet_id,
    }


def assert_publish(
    packet: bytes, protocol: int, *, qos: int, retain: bool, payload: bytes
) -> int | None:
    publish = parse_publish(packet, protocol)
    if publish["topic"] != "remote/sensors/room":
        raise AssertionError(f"wrong remapped topic: {publish['topic']}")
    if publish["payload"] != payload:
        raise AssertionError(f"wrong bridged payload: {publish['payload']!r}")
    if publish["qos"] != qos:
        raise AssertionError(f"wrong bridged QoS: {publish['qos']}")
    if publish["retain"] != retain:
        raise AssertionError(f"wrong RETAIN bit: {publish['retain']}")
    return publish["packet_id"]  # type: ignore[return-value]


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
    executable: Path, port: int, directory: Path, label: str
) -> ManagedProcess:
    config = directory / f"{label}.conf"
    log = directory / f"{label}.log"
    config.write_text(
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "persistence false\n"
        "log_type all\n",
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


def start_bridge(
    executable: Path, source_port: int, target_port: int,
    control_port: int, case: Case, directory: Path,
) -> ManagedProcess:
    log = directory / "bridge.log"
    output = log.open("wb")
    managed = ManagedProcess(
        "bridge",
        subprocess.Popen(
            [
                str(executable), str(source_port), str(target_port),
                str(control_port), case.source_label, case.target_label,
                str(case.qos), case.name,
            ],
            stdout=output,
            stderr=subprocess.STDOUT,
        ),
        output,
        log,
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


def run_case(
    bridge_executable: Path, mosquitto: Path, mqtt_packets, case: Case
) -> None:
    source_port, target_port, control_port = distinct_ports(3)
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        processes: list[ManagedProcess] = []
        clients: list[socket.socket] = []
        try:
            source = start_broker(
                mosquitto, source_port, directory, "source"
            )
            processes.append(source)
            target = start_broker(
                mosquitto, target_port, directory, "target"
            )
            processes.append(target)
            bridge = start_bridge(
                bridge_executable, source_port, target_port, control_port,
                case, directory,
            )
            processes.append(bridge)
            subscriber = connect_client(
                target_port, mqtt_packets, f"target-{case.name}",
                case.target_protocol,
            )
            clients.append(subscriber)
            subscribe(
                subscriber, mqtt_packets, case.target_protocol,
                "remote/sensors/#", case.qos,
            )
            publisher = connect_client(
                source_port, mqtt_packets, f"source-{case.name}",
                case.source_protocol,
            )
            clients.append(publisher)
            payload = f"outbound-{case.name}".encode("ascii")
            publisher.sendall(
                mqtt_packets.gen_publish(
                    "local/sensors/room", qos=case.qos, mid=7,
                    retain=case.retain, payload=payload,
                    proto_ver=case.source_protocol,
                )
            )
            if case.qos == 1:
                expected_ack = mqtt_packets.gen_puback(
                    7, proto_ver=case.source_protocol
                )
                actual_ack = read_packet(publisher)
                if actual_ack != expected_ack:
                    raise AssertionError(
                        f"source PUBACK mismatch: {actual_ack.hex()}"
                    )
            target_packet_id = assert_publish(
                read_packet(subscriber), case.target_protocol, qos=case.qos,
                retain=False, payload=payload,
            )
            if target_packet_id is not None:
                subscriber.sendall(
                    mqtt_packets.gen_puback(
                        target_packet_id, proto_ver=case.target_protocol
                    )
                )
            subscriber.sendall(
                mqtt_packets.gen_disconnect(proto_ver=case.target_protocol)
            )
            subscriber.close()
            clients.remove(subscriber)

            if case.retain:
                retained = connect_client(
                    target_port, mqtt_packets, f"retained-{case.name}",
                    case.target_protocol,
                )
                clients.append(retained)
                subscribe(
                    retained, mqtt_packets, case.target_protocol,
                    "remote/sensors/room", case.qos,
                )
                retained_packet_id = assert_publish(
                    read_packet(retained), case.target_protocol, qos=case.qos,
                    retain=True, payload=payload,
                )
                if retained_packet_id is not None:
                    retained.sendall(
                        mqtt_packets.gen_puback(
                            retained_packet_id, proto_ver=case.target_protocol
                        )
                    )

            publisher.sendall(
                mqtt_packets.gen_disconnect(proto_ver=case.source_protocol)
            )
            with socket.create_connection(
                ("127.0.0.1", control_port), timeout=5
            ) as control:
                control.sendall(b"\x01")
            bridge.wait_clean()
        finally:
            cleanup_case(clients, processes, sys.exc_info()[0] is not None)


def run_fresh_target_reconnect(
    bridge_executable: Path, mosquitto: Path, mqtt_packets
) -> None:
    case = Case("fresh-target-reconnect", 5, 5, 1, True)
    source_port, target_port, control_port = distinct_ports(3)
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        processes: list[ManagedProcess] = []
        clients: list[socket.socket] = []
        try:
            source = start_broker(
                mosquitto, source_port, directory, "source"
            )
            processes.append(source)
            target = start_broker(
                mosquitto, target_port, directory, "target"
            )
            processes.append(target)
            bridge = start_bridge(
                bridge_executable, source_port, target_port, control_port,
                case, directory,
            )
            processes.append(bridge)

            target.stop()

            publisher = connect_client(
                source_port, mqtt_packets, "fresh-target-publisher", 5
            )
            clients.append(publisher)
            payload = b"retained-across-fresh-target"
            publisher.sendall(
                mqtt_packets.gen_publish(
                    "local/sensors/room", qos=1, mid=7, retain=True,
                    payload=payload, proto_ver=5,
                )
            )
            expected_ack = mqtt_packets.gen_puback(7, proto_ver=5)
            actual_ack = read_packet(publisher)
            if actual_ack != expected_ack:
                raise AssertionError(
                    f"source publisher PUBACK mismatch: {actual_ack.hex()}"
                )

            bridge_source_id = "netz-outbound-source-fresh-target-reconnect"
            bridge_target_id = "netz-outbound-target-fresh-target-reconnect"
            wait_for_log(
                source.process, source.log,
                f"Sending PUBLISH to {bridge_source_id}",
                "source bridge delivery",
            )
            assert_log_absent(
                source.log, f"Received PUBACK from {bridge_source_id}", 0.3
            )

            restarted = start_broker(
                mosquitto, target_port, directory, "target-restarted"
            )
            processes.append(restarted)
            wait_for_log(
                restarted.process, restarted.log,
                f"Received PUBLISH from {bridge_target_id} "
                "(d0, q1, r1,",
                "fresh target bridge publish",
            )
            wait_for_log(
                source.process, source.log,
                f"Received PUBACK from {bridge_source_id}",
                "source bridge acknowledgement",
            )

            retained = connect_client(
                target_port, mqtt_packets, "fresh-target-retained", 5
            )
            clients.append(retained)
            subscribe(retained, mqtt_packets, 5, "remote/sensors/room", 1)
            retained_packet_id = assert_publish(
                read_packet(retained), 5, qos=1, retain=True, payload=payload
            )
            if retained_packet_id is None:
                raise AssertionError("retained QoS 1 message has no packet id")
            retained.sendall(mqtt_packets.gen_puback(retained_packet_id, proto_ver=5))
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

            with socket.create_connection(
                ("127.0.0.1", control_port), timeout=5
            ) as control:
                control.sendall(b"\x01")
            bridge.wait_clean()
        finally:
            cleanup_case(clients, processes, sys.exc_info()[0] is not None)


def run_resumed_target_reconnect(
    bridge_executable: Path, mosquitto: Path, mqtt_packets
) -> None:
    case = Case("resumed-target-reconnect", 5, 5, 1, True)
    source_port, target_port, proxy_port, control_port = distinct_ports(4)
    payload = b"retained-across-resumed-target"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        processes: list[ManagedProcess] = []
        clients: list[socket.socket] = []
        proxy: AckDropProxy | None = None
        try:
            source = start_broker(
                mosquitto, source_port, directory, "source"
            )
            processes.append(source)
            target = start_broker(
                mosquitto, target_port, directory, "target"
            )
            processes.append(target)
            proxy = AckDropProxy(proxy_port, target_port, payload)
            bridge = start_bridge(
                bridge_executable, source_port, proxy_port, control_port,
                case, directory,
            )
            processes.append(bridge)

            publisher = connect_client(
                source_port, mqtt_packets, "resumed-target-publisher", 5
            )
            clients.append(publisher)
            publisher.sendall(
                mqtt_packets.gen_publish(
                    "local/sensors/room", qos=1, mid=7, retain=True,
                    payload=payload, proto_ver=5,
                )
            )
            expected_ack = mqtt_packets.gen_puback(7, proto_ver=5)
            actual_ack = read_packet(publisher)
            if actual_ack != expected_ack:
                raise AssertionError(
                    f"source publisher PUBACK mismatch: {actual_ack.hex()}"
                )

            proxy.wait(proxy.retry_held, "held resumed target PUBLISH")
            bridge_source_id = "netz-outbound-source-resumed-target-reconnect"
            assert_log_absent(
                source.log, f"Received PUBACK from {bridge_source_id}", 0.3
            )
            proxy.allow_replay.set()
            proxy.wait(proxy.replay_complete, "resumed target PUBACK")
            wait_for_log(
                source.process, source.log,
                f"Received PUBACK from {bridge_source_id}",
                "source bridge acknowledgement",
            )

            retained = connect_client(
                target_port, mqtt_packets, "resumed-target-retained", 5
            )
            clients.append(retained)
            subscribe(retained, mqtt_packets, 5, "remote/sensors/room", 1)
            retained_packet_id = assert_publish(
                read_packet(retained), 5, qos=1, retain=True, payload=payload
            )
            if retained_packet_id is None:
                raise AssertionError("retained QoS 1 message has no packet id")
            retained.sendall(mqtt_packets.gen_puback(retained_packet_id, proto_ver=5))
            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

            with socket.create_connection(
                ("127.0.0.1", control_port), timeout=5
            ) as control:
                control.sendall(b"\x01")
            bridge.wait_clean()
            proxy.finish()
        finally:
            if proxy is not None:
                proxy.stop()
            cleanup_case(clients, processes, sys.exc_info()[0] is not None)


def main() -> None:
    args = parse_args()
    sys.path.insert(0, str(args.mosquitto_test_root))
    import mqtt_packets  # type: ignore

    for case in CASES:
        run_case(args.bridge, args.mosquitto, mqtt_packets, case)
    run_fresh_target_reconnect(args.bridge, args.mosquitto, mqtt_packets)
    run_resumed_target_reconnect(args.bridge, args.mosquitto, mqtt_packets)
    print(
        "MQTT OutboundBridge two-Mosquitto interop passed: "
        "v3.1.1->v5 QoS0, v5->v3.1.1 QoS1 retained, "
        "fresh-target republish, resumed-target same-ID DUP replay, "
        "delayed bridge ACK, topic remap "
        + RUNTIME
    )


if __name__ == "__main__":
    main()
