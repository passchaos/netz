"""Negative-PUBREC propagation gate for the outbound QoS 2 bridge."""

from __future__ import annotations

from pathlib import Path
import socket
import sys
import tempfile
import threading

from mqtt_outbound_bridge_harness import (
    Case,
    ManagedProcess,
    cleanup_case,
    connect_client,
    distinct_ports,
    start_bridge,
    start_broker,
)
from mqtt_outbound_bridge_support import (
    SessionProxy,
    assert_ack,
    assert_publish,
    assert_publish_on_topic,
    read_packet,
)


REJECTION = 0x87


class SourceNegativeObserver(SessionProxy):
    def __init__(self, listen_port: int, source_port: int, payload: bytes):
        self.payload = payload
        self.rejection_seen = threading.Event()
        self.packet_id: int | None = None
        self.publish_count = 0
        super().__init__(listen_port, source_port, "mqtt-source-negative")

    def _run_fallible(self) -> None:
        with self._accept() as bridge:
            with self._connect_session(bridge, session_present=False) as source:
                subscribe = read_packet(bridge)
                if subscribe[0] >> 4 != 8:
                    raise AssertionError(
                        f"expected bridge SUBSCRIBE, got {subscribe.hex()}"
                    )
                source.sendall(subscribe)
                bridge.sendall(read_packet(source))
                publish = read_packet(source)
                packet_id = assert_publish_on_topic(
                    publish, 5, topic="local/sensors/room", qos=2,
                    retain=False, payload=self.payload,
                )
                if packet_id is None:
                    raise AssertionError("source PUBLISH omitted Packet Identifier")
                self.packet_id = packet_id
                self.publish_count += 1
                bridge.sendall(publish)
                pubrec = read_packet(bridge)
                assert_ack(pubrec, 5, packet_id, REJECTION)
                source.sendall(pubrec)
                self.rejection_seen.set()
                self._forward_until_disconnect(bridge, source)

    def _forward_until_disconnect(
        self, bridge: socket.socket, source: socket.socket
    ) -> None:
        while not self.stop_requested.is_set():
            try:
                packet = read_packet(bridge)
            except socket.timeout:
                continue
            source.sendall(packet)
            if packet[0] >> 4 == 14:
                return
            bridge.sendall(read_packet(source))

    def _wake_waiters(self) -> None:
        self.rejection_seen.set()


class TargetNegativeObserver(SessionProxy):
    def __init__(self, listen_port: int, target_port: int, payload: bytes):
        self.payload = payload
        self.rejection_sent = threading.Event()
        self.publish_count = 0
        self.pubrel_count = 0
        super().__init__(listen_port, target_port, "mqtt-target-negative")

    def _run_fallible(self) -> None:
        with self._accept() as bridge:
            with self._connect_session(bridge, session_present=False) as target:
                publish = read_packet(bridge)
                packet_id = assert_publish(
                    publish, 5, qos=2, retain=False, payload=self.payload
                )
                if packet_id is None:
                    raise AssertionError("target PUBLISH omitted Packet Identifier")
                self.publish_count += 1
                target.sendall(publish)
                pubrec = read_packet(target)
                assert_ack(pubrec, 5, packet_id, REJECTION)
                bridge.sendall(pubrec)
                self.rejection_sent.set()
                while not self.stop_requested.is_set():
                    try:
                        packet = read_packet(bridge)
                    except socket.timeout:
                        continue
                    if packet[0] >> 4 == 6:
                        self.pubrel_count += 1
                        raise AssertionError(
                            "bridge sent PUBREL after negative target PUBREC"
                        )
                    target.sendall(packet)
                    if packet[0] >> 4 == 14:
                        return
                    bridge.sendall(read_packet(target))

    def _wake_waiters(self) -> None:
        self.rejection_sent.set()


def run_negative_pubrec_case(
    bridge_executable: Path, mosquitto: Path, mqtt_packets
) -> None:
    case = Case("qos2-negative-pubrec", 5, 5, 2, False)
    source_port, source_proxy_port, target_port, target_proxy_port, control_port, (
        restored_control_port
    ) = distinct_ports(6)
    payload = b"qos2-negative-pubrec"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        processes: list[ManagedProcess] = []
        clients: list[socket.socket] = []
        source_proxy: SourceNegativeObserver | None = None
        target_proxy: TargetNegativeObserver | None = None
        try:
            source = start_broker(
                mosquitto, source_port, directory, "source"
            )
            processes.append(source)
            target_acl = directory / "target.acl"
            target_acl.write_text(
                "topic read remote/sensors/#\n", encoding="ascii"
            )
            target_acl.chmod(0o600)
            target = start_broker(
                mosquitto, target_port, directory, "target",
                f"acl_file {target_acl}\n",
            )
            processes.append(target)
            source_proxy = SourceNegativeObserver(
                source_proxy_port, source_port, payload
            )
            target_proxy = TargetNegativeObserver(
                target_proxy_port, target_port, payload
            )
            bridge = start_bridge(
                bridge_executable, source_proxy_port, target_proxy_port,
                control_port, case, directory, "create",
            )
            processes.append(bridge)

            subscriber = connect_client(
                target_port, mqtt_packets, "negative-target-subscriber", 5
            )
            clients.append(subscriber)
            subscriber.sendall(
                mqtt_packets.gen_subscribe(
                    1, "remote/sensors/#", 2, proto_ver=5
                )
            )
            if read_packet(subscriber)[0] != 0x90:
                raise AssertionError("negative target subscriber SUBACK missing")
            publisher = connect_client(
                source_port, mqtt_packets, "negative-source-publisher", 5
            )
            clients.append(publisher)
            publisher.sendall(
                mqtt_packets.gen_publish(
                    "local/sensors/room", qos=2, mid=7, retain=False,
                    payload=payload, proto_ver=5,
                )
            )
            assert_ack(read_packet(publisher), 5, 7, 0)
            publisher.sendall(mqtt_packets.gen_pubrel(7, proto_ver=5))
            assert_ack(read_packet(publisher), 7, 7, 0)

            target_proxy.wait(target_proxy.rejection_sent, "negative PUBREC send")
            source_proxy.wait(source_proxy.rejection_seen, "negative PUBREC propagation")
            if target_proxy.publish_count != 1 or target_proxy.pubrel_count != 0:
                raise AssertionError("invalid target negative-PUBREC wire sequence")
            if source_proxy.publish_count != 1:
                raise AssertionError("source delivery count changed")
            target_marker = (
                f"Denied PUBLISH from netz-outbound-target-{case.name}"
            )
            if target.log.read_text(errors="replace").count(target_marker) != 1:
                raise AssertionError(
                    "target Mosquitto did not reject exactly one PUBLISH"
                )
            subscriber.settimeout(0.3)
            try:
                unexpected = read_packet(subscriber)
            except socket.timeout:
                unexpected = None
            if unexpected is not None:
                raise AssertionError(
                    "subscriber received rejected Application Message: "
                    + unexpected.hex()
                )

            publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            with socket.create_connection(
                ("127.0.0.1", control_port), timeout=5
            ) as control:
                control.sendall(b"\x01")
            bridge.wait_clean()

            restored = start_bridge(
                bridge_executable, source_port, target_port,
                restored_control_port, case, directory, "restore",
            )
            processes.append(restored)
            if target.log.read_text(errors="replace").count(target_marker) != 1:
                raise AssertionError(
                    "empty coordinator replayed the rejected PUBLISH"
                )
            if source_proxy.publish_count != 1 or target_proxy.publish_count != 1:
                raise AssertionError("empty coordinator replayed rejected delivery")
            with socket.create_connection(
                ("127.0.0.1", restored_control_port), timeout=5
            ) as control:
                control.sendall(b"\x01")
            restored.wait_clean()
        finally:
            failed = sys.exc_info()[0] is not None
            cleanup_case(clients, processes, failed)
            proxy_error: BaseException | None = None
            for proxy in (source_proxy, target_proxy):
                if proxy is None:
                    continue
                try:
                    proxy.stop()
                except BaseException as exc:
                    proxy_error = proxy_error or exc
            if not failed and proxy_error is not None:
                raise proxy_error
