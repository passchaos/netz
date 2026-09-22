"""Real-Mosquitto fail-closed checks for lost bridge Sessions."""

from __future__ import annotations

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
    launch_bridge,
    start_bridge,
    start_broker,
)
from mqtt_outbound_bridge_support import TargetPublishDropProxy, read_packet


def run_session_loss_cases(
    bridge_executable: Path, mosquitto: Path, mqtt_packets
) -> None:
    _run_session_loss(
        bridge_executable, mosquitto, mqtt_packets, lost_side="source"
    )
    _run_session_loss(
        bridge_executable, mosquitto, mqtt_packets, lost_side="target"
    )


def _run_session_loss(
    bridge_executable: Path, mosquitto: Path, mqtt_packets, *, lost_side: str
) -> None:
    case = Case(f"qos2-{lost_side}-session-loss", 5, 5, 2, False)
    source_port, target_port, proxy_port, first_control_port, second_control_port = (
        distinct_ports(5)
    )
    payload = f"qos2-{lost_side}-session-loss".encode("ascii")
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
            proxy = TargetPublishDropProxy(
                proxy_port, target_port, payload,
                recovery_session_present=lost_side != "target",
            )
            first_bridge = start_bridge(
                bridge_executable, source_port, proxy_port,
                first_control_port, case, directory, "create",
            )
            processes.append(first_bridge)

            publisher = connect_client(
                source_port, mqtt_packets, f"{lost_side}-loss-publisher", 5
            )
            clients.append(publisher)
            publisher.sendall(
                mqtt_packets.gen_publish(
                    "local/sensors/room", qos=2, mid=7, retain=False,
                    payload=payload, proto_ver=5,
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

            proxy.wait(proxy.first_publish_dropped, "staged target PUBLISH")
            bridge_source_id = f"netz-outbound-source-{case.name}"
            assert_log_absent(
                source.log,
                f"Received PUBREC from {bridge_source_id}",
                0.3,
            )
            first_bridge.crash()
            proxy.wait(proxy.ready_for_recovery, "first bridge closure")

            if lost_side == "source":
                source.stop()
                restarted = start_broker(
                    mosquitto, source_port, directory, "source-restarted"
                )
            else:
                target.stop()
                restarted = start_broker(
                    mosquitto, target_port, directory, "target-restarted"
                )
            processes.append(restarted)

            restored_bridge = launch_bridge(
                bridge_executable, source_port, proxy_port,
                second_control_port, case, directory, "restore",
            )
            processes.append(restored_bridge)
            expected = (
                "SourceSessionLost"
                if lost_side == "source"
                else "TargetSessionLost"
            )
            restored_bridge.wait_failure(expected)

            if lost_side == "source":
                if proxy.accepted_connection_count != 1:
                    raise AssertionError(
                        "source-first recovery connected target after source loss"
                    )
            else:
                proxy.wait(proxy.recovery_connected, "fresh target Session")
                if proxy.accepted_connection_count != 2:
                    raise AssertionError(
                        "target-loss recovery did not make exactly one reconnect"
                    )
            if proxy.bridge_publish_count != 1:
                raise AssertionError(
                    "bridge emitted a target PUBLISH after Session loss"
                )
            if proxy.forwarded_publish_count != 0:
                raise AssertionError(
                    "target broker received a PUBLISH after Session loss"
                )
            target_marker = (
                f"Received PUBLISH from netz-outbound-target-{case.name}"
            )
            for target_process in (target, restarted):
                if target_marker in target_process.log.read_text(
                    errors="replace"
                ):
                    raise AssertionError(
                        "target broker observed delivery despite Session loss"
                    )
        finally:
            if proxy is not None:
                proxy.stop()
            cleanup_case(clients, processes, sys.exc_info()[0] is not None)
