#!/usr/bin/env python3
"""Run complete portable Mosquitto packet-sequence JSON files against netz.

The upstream broker harness mixes raw packet conformance with Mosquitto CLI,
configuration, plugin, and log assertions. This adapter deliberately handles
only its portable packet files and preserves their group/test inheritance,
payload DSL, and standard MQTT helper-publisher actions. Add a file to
SEQUENCE_FILES only when every action is portable without weakening or
rewriting individual expectations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import sys

from mqtt_mosquitto_vectors import (
    NetzBroker,
    connect_client,
    expect_packet,
    recv_exact,
)


SEQUENCE_FILES = {
    "FORBIDDEN.json":
        "9ef4419f01bb7edb907b8846de498883fbd58eebc5fbd41bf2782e0fb14c83ad",
    "FLOW.json":
        "b77b707ca927b593c02b74ebc894c76fafc31327543dc3c04ae3f3f4da7b37ea",
    "PINGREQ.json":
        "85c5d707c54065157f2ded972bac72d1a2fccf24ff4a65e7775ed61759a77408",
    "PINGRESP.json":
        "7926b2eb3f80ec57e5a01f2e3dd937bd10881331a70d728c06e8599fc598f0fb",
    "PUBACK.json":
        "58bee064eebc419cd2da58b84786010523e996445a337b5414cb5ec3c00e4546",
    "PUBREC.json":
        "f230937d9eebe3df2e0bd5cc269d3e17002df64f976b261a4c07fa3201a49f8a",
    "REGRESSION.json":
        "bf6a7b5f6c03faf31f2e825ba6853943b7b9cc6fa4bf07706fb54ecd9703e73f",
    "PUBCOMP.json":
        "097a9d2b5e3690295dedde21665a82a97baf0e5f8a0258a6deed35c9f848943f",
    "SUBACK.json":
        "1894d26a0f79718055ea1135cdeed5632a470ce6968dc9ef2810cfb83e15d3ae",
    "UNSUBACK.json":
        "593719885cb1fa474c252449c11f2f1183fa432ee389737dca45beca225ac1a0",
}
EXPECTED_SEQUENCE_COUNT = 663
MQTT_PACKETS_SHA256 = (
    "0024fcebd421a3286cea021ed64083f906d9b457004786b05f8a74abae5bfb37"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("broker", type=Path)
    parser.add_argument(
        "--mosquitto-test-root",
        type=Path,
        default=Path.home() / "Work/mosquitto/test",
    )
    return parser.parse_args()


def parse_message(message: str) -> bytes:
    """Parse Mosquitto broker/msg_sequence_test.py's packet DSL exactly."""
    result = bytearray()
    parts = message.split(" ")
    index = 0
    while index < len(parts):
        part = parts[index]
        index += 1
        if not part:
            continue
        if part[0] == "i":
            result.extend(int(part[1:]).to_bytes(1, "big"))
        elif part[0] in ("H", "k", "m", "s"):
            result.extend(int(part[1:]).to_bytes(2, "big"))
        elif part[0] == "L":
            result.extend(int(part[1:]).to_bytes(4, "big"))
        elif part[0] == "'":
            value = part[1:]
            while not value.endswith("'") and index < len(parts):
                value += " " + parts[index]
                index += 1
            if not value.endswith("'"):
                raise ValueError(f"incomplete string in packet DSL: {message}")
            result.extend(value[:-1].encode("utf-8"))
        elif part[0] in ("v", "r"):
            value = int(part[1:])
            while True:
                byte = value % 128
                value //= 128
                if value > 0:
                    byte |= 0x80
                result.append(byte)
                if value == 0:
                    break
        else:
            result.extend(bytes.fromhex(part))
    return bytes(result)


def load_sequences(
    data_root: Path, selected_files: dict[str, str] = SEQUENCE_FILES
) -> list[dict]:
    sequences: list[dict] = []
    for filename, expected_hash in selected_files.items():
        path = data_root / filename
        source = path.read_bytes()
        verify_source_hash(path, expected_hash)
        groups = json.loads(source)
        for group in groups:
            if group.get("disable", False):
                continue
            group_protocol = group.get("ver", 4)
            group_connect = group.get("connect", True)
            group_disconnect = group.get("expect_disconnect", True)
            for test in group["tests"]:
                actions = test.get("msgs", [])
                action_types = {action["type"] for action in actions}
                if not action_types <= {"send", "recv", "external_publish"}:
                    raise ValueError(
                        f"{filename} {test['name']} is not a portable raw sequence"
                    )
                sequences.append({
                    "source": filename,
                    "name": f"{group['group']} {test['name']}",
                    "protocol": test.get("ver", group_protocol),
                    "connect": test.get("connect", group_connect),
                    "expect_disconnect": test.get(
                        "expect_disconnect", group_disconnect
                    ),
                    "actions": actions,
                })
    return sequences


def verify_source_hash(path: Path, expected_hash: str) -> None:
    actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError(
            f"{path.name} source hash mismatch: expected {expected_hash}, "
            f"found {actual_hash}"
        )


def expect_closed(
    sock: socket.socket,
    label: str,
    *,
    optional_v5_diagnostic: bool,
) -> None:
    try:
        trailing = sock.recv(1)
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
        return
    except socket.timeout as exc:
        raise AssertionError(f"{label}: broker kept connection open") from exc
    if not trailing:
        return
    if not optional_v5_diagnostic or trailing != b"\xe0":
        raise AssertionError(
            f"{label}: expected close, received trailing byte {trailing.hex()}"
        )

    # The upstream sequence omitted an exact terminal packet and therefore
    # requires only a close. MQTT 5 section 4.13 additionally recommends a
    # representable Malformed Packet / Protocol Error DISCONNECT. Accept that
    # stricter diagnostic only when it is one exact packet, then still require
    # the upstream EOF. Explicit recv actions never take this compatibility
    # path and remain byte-for-byte assertions.
    remaining = recv_exact(sock, 2)
    diagnostic = trailing + remaining
    if diagnostic not in (b"\xe0\x01\x81", b"\xe0\x01\x82"):
        raise AssertionError(
            f"{label}: unexpected terminal MQTT 5 diagnostic {diagnostic.hex()}"
        )
    expect_closed(sock, label, optional_v5_diagnostic=False)


def expect_sequence_packet(
    sock: socket.socket, expected: bytes, label: str
) -> None:
    try:
        expect_packet(sock, expected, label)
    except AssertionError as exc:
        raise AssertionError(f"{label}: {exc}") from exc


def external_publish(
    broker: NetzBroker,
    action: dict,
    mqtt_packets,
    label: str,
) -> None:
    """Perform Mosquitto's standard MQTT 3.1.1 helper publication."""
    qos = action["qos"]
    if qos not in (0, 1, 2):
        raise ValueError(f"{label}: invalid helper QoS {qos}")
    with broker.connect() as helper:
        connect_client(helper, mqtt_packets, "helper", 4)
        helper.sendall(
            mqtt_packets.gen_publish(
                topic=action["topic"],
                qos=qos,
                payload=action["payload"],
                retain=action.get("retain", False),
                mid=1 if qos else 0,
            )
        )
        if qos == 1:
            expect_sequence_packet(
                helper, mqtt_packets.gen_puback(mid=1), f"{label} PUBACK"
            )
        elif qos == 2:
            expect_sequence_packet(
                helper, mqtt_packets.gen_pubrec(mid=1), f"{label} PUBREC"
            )
            helper.sendall(mqtt_packets.gen_pubrel(mid=1))
            expect_sequence_packet(
                helper, mqtt_packets.gen_pubcomp(mid=1), f"{label} PUBCOMP"
            )


def run_sequence(
    broker: NetzBroker,
    sequence: dict,
    index: int,
    mqtt_packets,
) -> None:
    proto_ver = sequence["protocol"]
    if proto_ver not in (4, 5):
        raise AssertionError(
            f"{sequence['name']}: unsupported portable protocol {proto_ver}"
        )
    label = f"{sequence['source']}::{sequence['name']}"
    with broker.connect() as sock:
        if sequence["connect"]:
            connect_client(
                sock, mqtt_packets, f"packet-sequence-{index}", proto_ver
            )

        for action_index, action in enumerate(sequence["actions"]):
            action_label = f"{label} action {action_index}"
            if action["type"] == "external_publish":
                external_publish(broker, action, mqtt_packets, action_label)
                continue
            packet = parse_message(action["payload"])
            if action["type"] == "send":
                sock.sendall(packet)
            else:
                expect_sequence_packet(sock, packet, action_label)

        if sequence["expect_disconnect"]:
            has_explicit_receive = any(
                action["type"] == "recv"
                for action in sequence["actions"]
            )
            expect_closed(
                sock,
                label,
                optional_v5_diagnostic=(
                    proto_ver == 5
                    and sequence["connect"]
                    and not has_explicit_receive
                ),
            )
        else:
            sock.sendall(mqtt_packets.gen_pingreq())
            expect_sequence_packet(
                sock, mqtt_packets.gen_pingresp(), f"{label} liveness"
            )
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=proto_ver))


def main() -> None:
    args = parse_args()
    verify_source_hash(
        args.mosquitto_test_root / "mqtt_packets.py",
        MQTT_PACKETS_SHA256,
    )
    sys.path.insert(0, str(args.mosquitto_test_root))
    import mqtt_packets  # type: ignore

    sequences = load_sequences(args.mosquitto_test_root / "broker" / "data")
    if len(sequences) != EXPECTED_SEQUENCE_COUNT:
        raise AssertionError(
            f"expected {EXPECTED_SEQUENCE_COUNT} upstream packet sequences, "
            f"found {len(sequences)}"
        )

    helper_connections = sum(
        action["type"] == "external_publish"
        for sequence in sequences
        for action in sequence["actions"]
    )
    with NetzBroker(
        args.broker,
        connections=len(sequences) + helper_connections + 1,
        ignore_errors=True,
    ) as broker:
        for index, sequence in enumerate(sequences):
            run_sequence(
                broker, sequence, index, mqtt_packets
            )

        with broker.connect() as healthy:
            connect_client(
                healthy, mqtt_packets, "after-packet-sequences", 5
            )
            healthy.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                healthy, mqtt_packets.gen_pingresp(), "final healthy PINGRESP"
            )
            healthy.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

    print(
        "Mosquitto packet-sequence JSON gate passed: 663 upstream scenarios "
        "from FLOW.json, FORBIDDEN.json, PINGREQ.json, PINGRESP.json, "
        "PUBACK.json, PUBCOMP.json, PUBREC.json, REGRESSION.json, "
        "SUBACK.json, and UNSUBACK.json"
    )


if __name__ == "__main__":
    main()
