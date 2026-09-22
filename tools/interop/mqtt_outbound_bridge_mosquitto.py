#!/usr/bin/env python3
"""Exercise netz OutboundBridge between two real Mosquitto brokers."""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import sys
import tempfile

from mqtt_outbound_bridge_harness import (
    Case,
    ManagedProcess,
    assert_log_absent,
    cleanup_case,
    connect_client,
    distinct_ports,
    start_bridge,
    start_broker,
    subscribe,
    wait_for_log,
)
from mqtt_outbound_bridge_support import (
    AckDropProxy,
    Qos2PubcompDropProxy,
    SourcePubcompDropProxy,
    TargetPublishDropProxy,
    assert_publish,
    read_packet,
)
from mqtt_outbound_bridge_session_loss import run_session_loss_cases
from mqtt_outbound_bridge_negative import run_negative_pubrec_case


RUNTIME = (
    "bridge_io=zio-std-io source_broker_io=mosquitto-event-loop "
    "target_broker_io=mosquitto-event-loop"
)


CASES = (
    Case("v311-to-v5-qos0", 4, 5, 0, False),
    Case("v5-to-v311-qos1-retain", 5, 4, 1, True),
    Case("v5-to-v5-qos2", 5, 5, 2, False),
)


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
            publisher_pubcomp = read_packet(publisher)
            if publisher_pubcomp != mqtt_packets.gen_pubcomp(7, proto_ver=5):
                raise AssertionError(
                    f"publisher PUBCOMP mismatch: {publisher_pubcomp.hex()}"
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


def run_qos2_pre_target_wire_restart(
    bridge_executable: Path, mosquitto: Path, mqtt_packets
) -> None:
    case = Case("qos2-pre-target-wire-restart", 5, 5, 2, False)
    source_port, target_port, proxy_port, first_control_port, second_control_port = (
        distinct_ports(5)
    )
    payload = b"qos2-journal-before-target-wire"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        processes: list[ManagedProcess] = []
        clients: list[socket.socket] = []
        proxy: TargetPublishDropProxy | None = None
        try:
            source = start_broker(
                mosquitto, source_port, directory, "source"
            )
            processes.append(source)
            target = start_broker(
                mosquitto, target_port, directory, "target"
            )
            processes.append(target)
            proxy = TargetPublishDropProxy(proxy_port, target_port, payload)
            first_bridge = start_bridge(
                bridge_executable, source_port, proxy_port,
                first_control_port, case, directory, "create",
            )
            processes.append(first_bridge)

            subscriber = connect_client(
                target_port, mqtt_packets, "qos2-pre-wire-subscriber", 5
            )
            clients.append(subscriber)
            subscribe(subscriber, mqtt_packets, 5, "remote/sensors/#", 2)
            publisher = connect_client(
                source_port, mqtt_packets, "qos2-pre-wire-publisher", 5
            )
            clients.append(publisher)
            publisher.sendall(
                mqtt_packets.gen_publish(
                    "local/sensors/room", qos=2, mid=7,
                    retain=False, payload=payload, proto_ver=5,
                )
            )
            publisher_pubrec = read_packet(publisher)
            if publisher_pubrec != mqtt_packets.gen_pubrec(7, proto_ver=5):
                raise AssertionError(
                    f"publisher PUBREC mismatch: {publisher_pubrec.hex()}"
                )
            publisher.sendall(mqtt_packets.gen_pubrel(7, proto_ver=5))
            publisher_pubcomp = read_packet(publisher)
            if publisher_pubcomp != mqtt_packets.gen_pubcomp(7, proto_ver=5):
                raise AssertionError(
                    f"publisher PUBCOMP mismatch: {publisher_pubcomp.hex()}"
                )

            proxy.wait(
                proxy.first_publish_dropped,
                "first target PUBLISH drop",
            )
            bridge_source_id = (
                "netz-outbound-source-qos2-pre-target-wire-restart"
            )
            bridge_target_id = (
                "netz-outbound-target-qos2-pre-target-wire-restart"
            )
            assert_log_absent(
                source.log,
                f"Received PUBREC from {bridge_source_id}",
                0.3,
            )
            if f"Received PUBLISH from {bridge_target_id}" in (
                target.log.read_text(errors="replace")
            ):
                raise AssertionError(
                    "target broker observed the dropped pre-crash PUBLISH"
                )
            first_bridge.crash()
            proxy.wait(
                proxy.ready_for_recovery,
                "first target bridge transport closure",
            )
            restored_bridge = start_bridge(
                bridge_executable, source_port, proxy_port,
                second_control_port, case, directory, "restore",
            )
            processes.append(restored_bridge)
            proxy.wait(proxy.replay_complete, "restored target QoS 2 flow")
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
            if proxy.bridge_publish_count != 2:
                raise AssertionError(
                    "bridge did not emit exactly one initial and one restored PUBLISH"
                )
            if proxy.forwarded_publish_count != 1:
                raise AssertionError(
                    "target broker did not receive exactly one PUBLISH"
                )
            target_log = target.log.read_text(errors="replace")
            marker = f"Received PUBLISH from {bridge_target_id}"
            if target_log.count(marker) != 1:
                raise AssertionError(
                    "target broker did not log exactly one bridge PUBLISH"
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


def run_qos2_source_pubcomp_restart(
    bridge_executable: Path, mosquitto: Path, mqtt_packets
) -> None:
    case = Case("qos2-source-pubcomp-restart", 5, 5, 2, False)
    source_port, source_proxy_port, target_port, first_control_port, (
        second_control_port
    ) = distinct_ports(5)
    payload = b"qos2-final-clear-before-source-pubcomp"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        processes: list[ManagedProcess] = []
        clients: list[socket.socket] = []
        proxy: SourcePubcompDropProxy | None = None
        try:
            source = start_broker(
                mosquitto, source_port, directory, "source"
            )
            processes.append(source)
            target = start_broker(
                mosquitto, target_port, directory, "target"
            )
            processes.append(target)
            proxy = SourcePubcompDropProxy(
                source_proxy_port, source_port, payload
            )
            first_bridge = start_bridge(
                bridge_executable, source_proxy_port, target_port,
                first_control_port, case, directory, "create",
            )
            processes.append(first_bridge)

            subscriber = connect_client(
                target_port, mqtt_packets, "qos2-source-clear-subscriber", 5
            )
            clients.append(subscriber)
            subscribe(subscriber, mqtt_packets, 5, "remote/sensors/#", 2)
            publisher = connect_client(
                source_port, mqtt_packets, "qos2-source-clear-publisher", 5
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
            publisher_pubcomp = read_packet(publisher)
            if publisher_pubcomp != mqtt_packets.gen_pubcomp(7, proto_ver=5):
                raise AssertionError(
                    f"publisher PUBCOMP mismatch: {publisher_pubcomp.hex()}"
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
                "first source PUBCOMP drop",
            )
            bridge_source_id = (
                "netz-outbound-source-qos2-source-pubcomp-restart"
            )
            assert_log_absent(
                source.log,
                f"Received PUBCOMP from {bridge_source_id}",
                0.3,
            )
            first_bridge.crash()
            proxy.wait(
                proxy.ready_for_recovery,
                "first source bridge transport closure",
            )
            restored_bridge = start_bridge(
                bridge_executable, source_proxy_port, target_port,
                second_control_port, case, directory, "restore",
            )
            processes.append(restored_bridge)
            proxy.wait(
                proxy.recovery_pubcomp_seen,
                "restored source PUBCOMP",
            )
            wait_for_log(
                source.process, source.log,
                f"Received PUBCOMP from {bridge_source_id}",
                "restored source broker completion",
            )
            if proxy.publish_count != 1:
                raise AssertionError(
                    f"source observed {proxy.publish_count} bridge deliveries"
                )
            bridge_target_id = (
                "netz-outbound-target-qos2-source-pubcomp-restart"
            )
            target_log = target.log.read_text(errors="replace")
            marker = f"Received PUBLISH from {bridge_target_id}"
            if target_log.count(marker) != 1:
                raise AssertionError(
                    "target broker did not observe exactly one bridge PUBLISH"
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
    run_qos2_pre_target_wire_restart(args.bridge, args.mosquitto, mqtt_packets)
    run_qos2_pubcomp_restart(args.bridge, args.mosquitto, mqtt_packets)
    run_qos2_source_pubcomp_restart(args.bridge, args.mosquitto, mqtt_packets)
    run_session_loss_cases(args.bridge, args.mosquitto, mqtt_packets)
    run_negative_pubrec_case(args.bridge, args.mosquitto, mqtt_packets)
    print(
        "MQTT OutboundBridge two-Mosquitto interop passed: "
        "v3.1.1->v5 QoS0, v5->v3.1.1 QoS1 retained, v5 QoS2, "
        "fresh-target republish, resumed-target same-ID DUP replay, "
        "durable pre-target-wire restart with same-ID DUP PUBLISH, "
        "durable QoS2 PUBCOMP-loss process restart without target republish, "
        "durable source-PUBCOMP-loss restart after journal clear, "
        "source/target Session-loss fail-closed recovery, "
        "negative PUBREC propagation without target delivery, "
        "delayed bridge ACK, topic remap "
        + RUNTIME
    )


if __name__ == "__main__":
    main()
