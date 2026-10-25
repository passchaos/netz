"""Message expiry across a bridge crash must not replay target publications."""
from __future__ import annotations

from pathlib import Path
import socket
import sys
import tempfile
import time

from mqtt_outbound_bridge_harness import (
    Case, ManagedProcess, assert_log_absent, cleanup_case, connect_client,
    distinct_ports, start_bridge, start_broker, subscribe, wait_for_log,
)
from mqtt_outbound_bridge_support import TargetPublishDropProxy, assert_ack, read_packet


def run_message_expiry(bridge_executable: Path, mosquitto: Path, packets) -> None:
    import mqtt5_props

    case = Case("qos2-message-expiry-restart", 5, 5, 2, False)
    source_port, target_port, proxy_port, control_port, restored_port = distinct_ports(5)
    payload = b"expired-before-target-acceptance"
    source_id = f"netz-outbound-source-{case.name}"
    target_id = f"netz-outbound-target-{case.name}"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        processes: list[ManagedProcess] = []
        clients: list[socket.socket] = []
        proxy = None
        try:
            source = start_broker(mosquitto, source_port, directory, "source")
            processes.append(source)
            target = start_broker(mosquitto, target_port, directory, "target")
            processes.append(target)
            proxy = TargetPublishDropProxy(proxy_port, target_port, payload, expire_before_recovery=True)
            bridge = start_bridge(bridge_executable, source_port, proxy_port,
                                  control_port, case, directory, "create")
            processes.append(bridge)
            subscriber = connect_client(target_port, packets, "expiry-observer", 5)
            clients.append(subscriber)
            subscribe(subscriber, packets, 5, "remote/sensors/#", 2)
            publisher = connect_client(source_port, packets, "expiry-publisher", 5)
            clients.append(publisher)
            publisher.sendall(packets.gen_publish(
                "local/sensors/room", qos=2, mid=7, payload=payload, proto_ver=5,
                properties=mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 1),
            ))
            assert_ack(read_packet(publisher), 5, 7)
            publisher.sendall(packets.gen_pubrel(7, proto_ver=5))
            assert_ack(read_packet(publisher), 7, 7)
            proxy.wait(proxy.first_publish_dropped, "first expirable target PUBLISH")
            assert_log_absent(source.log, f"Received PUBREC from {source_id}", 0.1)
            bridge.crash()
            proxy.wait(proxy.ready_for_recovery, "first bridge closure")
            time.sleep(1.2)
            restored = start_bridge(bridge_executable, source_port, proxy_port,
                                    restored_port, case, directory, "restore")
            processes.append(restored)
            proxy.wait(proxy.recovery_connected, "preserved target Session")
            wait_for_log(source.process, source.log, f"Received PUBCOMP from {source_id}", "expired source transaction completion")
            subscriber.sendall(packets.gen_pingreq())
            if read_packet(subscriber) != packets.gen_pingresp():
                raise AssertionError("subscriber received expired target message")
            subscriber.settimeout(0.2)
            try:
                extra = read_packet(subscriber)
            except socket.timeout:
                pass
            else:
                raise AssertionError(f"unexpected target packet after Message Expiry: {extra.hex()}")
            with socket.create_connection(("127.0.0.1", restored_port), timeout=5) as control:
                control.sendall(b"\x01")
            restored.wait_clean()
            if proxy.bridge_publish_count != 1 or proxy.forwarded_publish_count != 0:
                raise AssertionError("Message Expiry replayed the target PUBLISH")
            if f"Received PUBLISH from {target_id}" in target.log.read_text(errors="replace"):
                raise AssertionError("target broker received the expired message")
        finally:
            if proxy is not None:
                proxy.stop()
            cleanup_case(clients, processes, sys.exc_info()[0] is not None)
