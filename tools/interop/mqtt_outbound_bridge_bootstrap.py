"""A new coordinator must consume messages from pre-existing broker Sessions."""

from __future__ import annotations

from pathlib import Path
import socket
import sys
import tempfile

from mqtt_outbound_bridge_harness import (
    Case, ManagedProcess, cleanup_case, connect_client, distinct_ports,
    start_bridge, start_broker, subscribe, wait_for_log,
)
from mqtt_outbound_bridge_support import (
    assert_ack, assert_publish, decode_remaining_length, read_packet,
)


def seed_session(port, packets, client_id, protocol, source):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.sendall(packets.gen_connect(
            client_id, proto_ver=protocol, clean_session=False,
            session_expiry=60 if protocol == 5 else -1,
        ))
        connack = read_packet(client)
        _, cursor = decode_remaining_length(connack)
        if connack[0] != 0x20 or connack[cursor:cursor + 2] != b"\x00\x00":
            raise AssertionError(f"seed Session CONNACK mismatch: {connack.hex()}")
        if source:
            subscribe(client, packets, protocol, "local/sensors/#", 2)
        client.sendall(packets.gen_disconnect(proto_ver=protocol))


def stop_bridge(bridge, control_port):
    with socket.create_connection(("127.0.0.1", control_port), timeout=5) as control:
        control.sendall(b"\x01")
    bridge.wait_clean()


def run_bootstrap_cases(bridge_executable: Path, mosquitto: Path, packets) -> None:
    for source_protocol in (4, 5):
        for target_protocol in (4, 5):
            for target_present in (False, True):
                run_case(bridge_executable, mosquitto, packets, Case(
                    f"bootstrap-{source_protocol}-{target_protocol}-{int(target_present)}",
                    source_protocol, target_protocol, 2, False,
                ), target_present)


def run_case(executable, mosquitto, packets, case, target_present):
    source_port, target_port, control_port, restore_port = distinct_ports(4)
    source_id = f"netz-outbound-source-{case.name}"
    target_id = f"netz-outbound-target-{case.name}"
    payload = case.name.encode("ascii")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        processes: list[ManagedProcess] = []
        clients: list[socket.socket] = []
        try:
            source = start_broker(mosquitto, source_port, directory, "source")
            processes.append(source)
            processes.append(start_broker(mosquitto, target_port, directory, "target"))
            seed_session(source_port, packets, source_id, case.source_protocol, True)
            if target_present:
                seed_session(target_port, packets, target_id, case.target_protocol, False)
            subscriber = connect_client(target_port, packets, "bootstrap-observer", case.target_protocol)
            clients.append(subscriber)
            subscribe(subscriber, packets, case.target_protocol, "remote/sensors/#", 2)
            publisher = connect_client(source_port, packets, "bootstrap-publisher", case.source_protocol)
            clients.append(publisher)
            # Queue a QoS 2 message in the offline, persistent source Session
            # before a coordinator or target publication exists.
            publisher.sendall(packets.gen_publish(
                "local/sensors/room", qos=2, mid=7, payload=payload,
                proto_ver=case.source_protocol,
            ))
            assert_ack(read_packet(publisher), 5, 7)
            publisher.sendall(packets.gen_pubrel(7, proto_ver=case.source_protocol))
            assert_ack(read_packet(publisher), 7, 7)
            bridge = start_bridge(executable, source_port, target_port, control_port,
                                  case, directory, "create", session_present=(True, target_present))
            processes.append(bridge)
            mid = assert_publish(read_packet(subscriber), case.target_protocol,
                                 qos=2, retain=False, payload=payload)
            if mid is None:
                raise AssertionError("QoS 2 target publication has no Packet Identifier")
            subscriber.sendall(packets.gen_pubrec(mid, proto_ver=case.target_protocol))
            assert_ack(read_packet(subscriber), 6, mid)
            subscriber.sendall(packets.gen_pubcomp(mid, proto_ver=case.target_protocol))
            wait_for_log(source.process, source.log, f"Received PUBCOMP from {source_id}", "bootstrap source completion")
            stop_bridge(bridge, control_port)
            restored = start_bridge(executable, source_port, target_port, restore_port,
                                    case, directory, "restore")
            processes.append(restored)
            # A clear, restored coordinator cannot redeliver the completed
            # Application Message to this existing subscriber.
            subscriber.sendall(packets.gen_pingreq())
            if read_packet(subscriber) != packets.gen_pingresp():
                raise AssertionError("unexpected target delivery after coordinator restart")
            subscriber.settimeout(0.2)
            try:
                extra = read_packet(subscriber)
            except socket.timeout:
                pass
            else:
                raise AssertionError(f"extra target packet after coordinator restart: {extra.hex()}")
            stop_bridge(restored, restore_port)
            log = source.log.read_text(errors="replace")
            for kind in ("PUBREC", "PUBCOMP"):
                if log.count(f"Received {kind} from {source_id}") != 1:
                    raise AssertionError(f"bootstrap source {kind} did not complete exactly once")
        finally:
            cleanup_case(clients, processes, sys.exc_info()[0] is not None)
