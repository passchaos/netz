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
import time
from typing import BinaryIO

from mqtt_outbound_bridge_support import (
    AckDropProxy,
    Qos2PubcompDropProxy,
    assert_publish,
    read_packet,
)


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
    Case("v5-to-v5-qos2", 5, 5, 2, False),
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

    def crash(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        if not self.output.closed:
            self.output.close()


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
    managed = ManagedProcess(
        "bridge",
        subprocess.Popen(
            command,
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
                "create" if case.qos == 2 else None,
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
            elif case.qos == 2:
                pubrec = read_packet(publisher)
                if pubrec != mqtt_packets.gen_pubrec(
                    7, proto_ver=case.source_protocol
                ):
                    raise AssertionError(
                        f"source PUBREC mismatch: {pubrec.hex()}"
                    )
                publisher.sendall(
                    mqtt_packets.gen_pubrel(
                        7, proto_ver=case.source_protocol
                    )
                )
                pubcomp = read_packet(publisher)
                if pubcomp != mqtt_packets.gen_pubcomp(
                    7, proto_ver=case.source_protocol
                ):
                    raise AssertionError(
                        f"source PUBCOMP mismatch: {pubcomp.hex()}"
                    )
            target_packet_id = assert_publish(
                read_packet(subscriber), case.target_protocol, qos=case.qos,
                retain=False, payload=payload,
            )
            if target_packet_id is not None:
                if case.qos == 2:
                    subscriber.sendall(
                        mqtt_packets.gen_pubrec(
                            target_packet_id, proto_ver=case.target_protocol
                        )
                    )
                    target_pubrel = read_packet(subscriber)
                    if target_pubrel != mqtt_packets.gen_pubrel(
                        target_packet_id, proto_ver=case.target_protocol
                    ):
                        raise AssertionError(
                            f"subscriber PUBREL mismatch: {target_pubrel.hex()}"
                        )
                    subscriber.sendall(
                        mqtt_packets.gen_pubcomp(
                            target_packet_id, proto_ver=case.target_protocol
                        )
                    )
                else:
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


def run_qos2_pubcomp_restart(
    bridge_executable: Path, mosquitto: Path, mqtt_packets
) -> None:
    case = Case("qos2-pubcomp-restart", 5, 5, 2, False)
    source_port, target_port, proxy_port, first_control_port, second_control_port = (
        distinct_ports(5)
    )
    payload = b"qos2-target-once-across-bridge-restart"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        processes: list[ManagedProcess] = []
        clients: list[socket.socket] = []
        proxy: Qos2PubcompDropProxy | None = None
        try:
            source = start_broker(
                mosquitto, source_port, directory, "source"
            )
            processes.append(source)
            target = start_broker(
                mosquitto, target_port, directory, "target"
            )
            processes.append(target)
            proxy = Qos2PubcompDropProxy(proxy_port, target_port, payload)
            first_bridge = start_bridge(
                bridge_executable, source_port, proxy_port,
                first_control_port, case, directory, "create",
            )
            processes.append(first_bridge)

            subscriber = connect_client(
                target_port, mqtt_packets, "qos2-restart-subscriber", 5
            )
            clients.append(subscriber)
            subscribe(subscriber, mqtt_packets, 5, "remote/sensors/#", 2)
            publisher = connect_client(
                source_port, mqtt_packets, "qos2-restart-publisher", 5
            )
            clients.append(publisher)
            publisher.sendall(
                mqtt_packets.gen_publish(
                    "local/sensors/room", qos=2, mid=7,
                    retain=False, payload=payload, proto_ver=5,
                )
            )
            source_pubrec = read_packet(publisher)
            if source_pubrec != mqtt_packets.gen_pubrec(7, proto_ver=5):
                raise AssertionError(
                    f"publisher PUBREC mismatch: {source_pubrec.hex()}"
                )
            publisher.sendall(mqtt_packets.gen_pubrel(7, proto_ver=5))
            source_pubcomp = read_packet(publisher)
            if source_pubcomp != mqtt_packets.gen_pubcomp(7, proto_ver=5):
                raise AssertionError(
                    f"publisher PUBCOMP mismatch: {source_pubcomp.hex()}"
                )

            delivered_packet_id = assert_publish(
                read_packet(subscriber), 5, qos=2, retain=False,
                payload=payload,
            )
            if delivered_packet_id is None:
                raise AssertionError("subscriber QoS 2 PUBLISH has no packet id")
            subscriber.sendall(
                mqtt_packets.gen_pubrec(delivered_packet_id, proto_ver=5)
            )
            subscriber_pubrel = read_packet(subscriber)
            if subscriber_pubrel != mqtt_packets.gen_pubrel(
                delivered_packet_id, proto_ver=5
            ):
                raise AssertionError(
                    f"subscriber PUBREL mismatch: {subscriber_pubrel.hex()}"
                )
            subscriber.sendall(
                mqtt_packets.gen_pubcomp(delivered_packet_id, proto_ver=5)
            )

            proxy.wait(
                proxy.first_pubcomp_dropped,
                "first target PUBCOMP drop",
            )
            bridge_source_id = (
                "netz-outbound-source-qos2-pubcomp-restart"
            )
            assert_log_absent(
                source.log,
                f"Received PUBREC from {bridge_source_id}",
                0.3,
            )
            first_bridge.crash()
            proxy.wait(
                proxy.ready_for_recovery,
                "first bridge transport closure",
            )
            restored_bridge = start_bridge(
                bridge_executable, source_port, proxy_port,
                second_control_port, case, directory, "restore",
            )
            processes.append(restored_bridge)
            proxy.wait(
                proxy.recovery_pubrel_seen,
                "restored target PUBREL",
            )
            wait_for_log(
                source.process, source.log,
                f"Received PUBREC from {bridge_source_id}",
                "restored source PUBREC",
            )
            wait_for_log(
                source.process, source.log,
                f"Received PUBCOMP from {bridge_source_id}",
                "restored source PUBCOMP",
            )
            if proxy.publish_count != 1:
                raise AssertionError(
                    f"target observed {proxy.publish_count} bridge PUBLISH packets"
                )
            subscriber.settimeout(0.3)
            try:
                duplicate = read_packet(subscriber)
            except socket.timeout:
                duplicate = None
            if duplicate is not None:
                raise AssertionError(
                    "subscriber received a second Application Message: "
                    + duplicate.hex()
                )

            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            with socket.create_connection(
                ("127.0.0.1", second_control_port), timeout=5
            ) as control:
                control.sendall(b"\x01")
            restored_bridge.wait_clean()
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
    run_qos2_pubcomp_restart(args.bridge, args.mosquitto, mqtt_packets)
    print(
        "MQTT OutboundBridge two-Mosquitto interop passed: "
        "v3.1.1->v5 QoS0, v5->v3.1.1 QoS1 retained, v5 QoS2, "
        "fresh-target republish, resumed-target same-ID DUP replay, "
        "durable QoS2 PUBCOMP-loss process restart without target republish, "
        "delayed bridge ACK, topic remap "
        + RUNTIME
    )


if __name__ == "__main__":
    main()
