#!/usr/bin/env python3
"""Run complete files and audited Mosquitto packet-sequence subsets.

The upstream broker harness mixes raw packet conformance with Mosquitto CLI,
configuration, plugin, and log assertions. This adapter deliberately handles
only its portable packet files and preserves their group/test inheritance,
payload DSL, and standard MQTT helper-publisher actions. Add a file to
SEQUENCE_FILES only when every action is portable without weakening or
rewriting individual expectations. Subsets lock the whole source file and name
every exclusion with a documented reason so fixture drift fails closed.
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
    "OTHER.json":
        "a5a5b28b3baf530ec1cd6b8c778a1988be35d931798cfced3e247452de9fb30b",
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
SEQUENCE_SUBSET_FILES = {
    "PUBLISH.json":
        "a3b6a5d5b2cd44b70550ce17a03ff5607cc76e4f165ae1f1f6deb68eb7013f86",
    "SUBSCRIBE.json":
        "f3feba6c933d43dc7be5397a42afd616e5f4a21824cf5289c986166ec6c0e60c",
    "UNSUBSCRIBE.json":
        "32a8618e6f74fb02df944bc528e9b4ff258e5e920473b7d7ea81ac107374b825",
}

# Each exclusion is an audited divergence from the selected upstream fixture,
# not a wildcard skip. The full-file hash plus exact group/test identity makes
# an upstream addition, rename, or content change fail closed.
EXCLUSION_REASONS = {
    "mosquitto_qos2_reuse_limit": (
        "Mosquitto disconnects after its second pre-PUBREL non-DUP reuse; "
        "MQTT 5 section 4.3.3 requires PUBREC for every same-identifier "
        "PUBLISH until PUBREL, without replacing the first message"
    ),
    "optional_utf8_control_policy": (
        "MQTT permits receivers to reject U+0001/U+001F/U+007F/U+009F, "
        "while netz intentionally accepts these valid UTF-8 code points"
    ),
    "mosquitto_fixture_configuration": (
        "the expected bytes depend on Mosquitto's advertised packet-size or "
        "topic-alias limits rather than portable MQTT behavior"
    ),
}
SEQUENCE_EXCLUSIONS = {
    "PUBLISH.json": {
        ("v3.1.1 PUBLISH", "34 QoS 2 Dup flow*3"):
            "mosquitto_qos2_reuse_limit",
        ("v5.0   PUBLISH", "34 QoS 2 Dup flow*3"):
            "mosquitto_qos2_reuse_limit",
        ("v5.0   PUBLISH ALLOWED PROPERTIES", "maximum packet size"):
            "mosquitto_fixture_configuration",
        (
            "v5.0   PUBLISH ALLOWED PROPERTIES",
            "topic alias > max topic alias",
        ): "mosquitto_fixture_configuration",
        ("v3.1.1 PUBLISH", "30 topic with U+0001"):
            "optional_utf8_control_policy",
        ("v3.1.1 PUBLISH", "30 topic with U+001F"):
            "optional_utf8_control_policy",
        ("v3.1.1 PUBLISH", "30 topic with U+007F"):
            "optional_utf8_control_policy",
        ("v3.1.1 PUBLISH", "30 topic with U+009F"):
            "optional_utf8_control_policy",
        ("v5.0   PUBLISH", "30 topic with U+0001"):
            "optional_utf8_control_policy",
        ("v5.0   PUBLISH", "30 topic with U+001F"):
            "optional_utf8_control_policy",
        ("v5.0   PUBLISH", "30 topic with U+007F"):
            "optional_utf8_control_policy",
        ("v5.0   PUBLISH", "30 topic with U+009F"):
            "optional_utf8_control_policy",
    },
    "SUBSCRIBE.json": {
        ("v3.1.1 SUBSCRIBE", "82 topic with U+0001"):
            "optional_utf8_control_policy",
        ("v3.1.1 SUBSCRIBE", "82 topic with U+001F"):
            "optional_utf8_control_policy",
        ("v3.1.1 SUBSCRIBE", "82 topic with U+007F"):
            "optional_utf8_control_policy",
        ("v3.1.1 SUBSCRIBE", "82 topic with U+009F"):
            "optional_utf8_control_policy",
    },
    "UNSUBSCRIBE.json": {
        ("v3.1.1 UNSUBSCRIBE", "A2 topic with U+0001"):
            "optional_utf8_control_policy",
        ("v3.1.1 UNSUBSCRIBE", "A2 topic with U+001F"):
            "optional_utf8_control_policy",
        ("v3.1.1 UNSUBSCRIBE", "A2 topic with U+007F"):
            "optional_utf8_control_policy",
        ("v3.1.1 UNSUBSCRIBE", "A2 topic with U+009F"):
            "optional_utf8_control_policy",
        ("v5.0   UNSUBSCRIBE", "A2 topic with U+0001"):
            "optional_utf8_control_policy",
        ("v5.0   UNSUBSCRIBE", "A2 topic with U+001F"):
            "optional_utf8_control_policy",
        ("v5.0   UNSUBSCRIBE", "A2 topic with U+007F"):
            "optional_utf8_control_policy",
        ("v5.0   UNSUBSCRIBE", "A2 topic with U+009F"):
            "optional_utf8_control_policy",
    },
}

# MQTT 5 section 2.2.2.2 requires a known Property Identifier used in a
# Control Packet where it is not valid to be reported as Malformed Packet
# 0x81. Mosquitto's selected fixtures expect Protocol Error 0x82 instead.
# These finite names retain the upstream scenario and replace only its exact
# source-locked recv action; a fixture rename or byte change fails closed.
ACK_DISALLOWED_PROPERTY_CASES = (
    "payload-format-indicator (byte)",
    "request-problem-information (byte)",
    "maximum-qos (byte)",
    "retain-available (byte)",
    "wildcard-subscription-available (byte)",
    "subscription-identifier-available (byte)",
    "shared-subscription-available (byte)",
    "message-expiry-interval (four byte integer)",
    "session-expiry-interval (four byte integer)",
    "will-delay-interval (four byte integer)",
    "maximum-packet-size (four byte integer)",
    "content-type (UTF-8 string)",
    "response-topic (UTF-8 string)",
    "assigned-client-identifier (UTF-8 string)",
    "authentication-method (UTF-8 string)",
    "response-information (UTF-8 string)",
    "server-reference (UTF-8 string)",
    "correlation-data (binary data)",
    "authentication-data (binary data)",
    "subscription-identifier (variable byte integer)",
    "server-keep-alive (two byte integer)",
    "receive-maximum (two byte integer)",
    "topic-alias-maximum (two byte integer)",
    "topic-alias (two byte integer)",
)
PUBLISH_DISALLOWED_PROPERTY_CASES = (
    "reason-string property",
    "request-problem-information (byte)",
    "maximum-qos (byte)",
    "retain-available (byte)",
    "wildcard-subscription-available (byte)",
    "subscription-identifier-available (byte)",
    "shared-subscription-available (byte)",
    "session-expiry-interval (four byte integer)",
    "will-delay-interval (four byte integer)",
    "maximum-packet-size (four byte integer)",
    "assigned-client-identifier (UTF-8 string)",
    "authentication-method (UTF-8 string)",
    "response-information (UTF-8 string)",
    "server-reference (UTF-8 string)",
    "authentication-data (binary data)",
    "server-keep-alive (two byte integer)",
    "receive-maximum (two byte integer)",
    "topic-alias-maximum (two byte integer)",
)
STANDARD_OVERRIDE_REASONS = {
    "mqtt5_property_context_malformed": (
        "MQTT 5 section 2.2.2.2 requires 0x81 when a known Property "
        "Identifier is not valid for its Control Packet type"
    ),
    "mqtt5_publish_protocol_error": (
        "MQTT 5 classifies a parsed invalid Topic Name as Protocol Error "
        "0x82 rather than Mosquitto's Malformed Packet 0x81"
    ),
    "mqtt5_subscribe_protocol_error": (
        "MQTT 5 explicitly classifies the parsed SUBSCRIBE semantic fault "
        "as Protocol Error 0x82 rather than Malformed Packet 0x81"
    ),
    "mqtt5_unsubscribe_protocol_error": (
        "MQTT 5 classifies the parsed UNSUBSCRIBE semantic fault as "
        "Protocol Error 0x82 rather than Mosquitto's Malformed Packet 0x81"
    ),
}


def expectation_override(
    source: str, expected: str, reason: str
) -> tuple[str, str, str]:
    return source, expected, reason


STANDARD_EXPECTATION_OVERRIDES = {
    filename: {
        (f"v5.0   {packet} DISALLOWED PROPERTIES",
         f"{prefix} with {case}", 1): expectation_override(
            "E0 r1 82", "E0 r1 81",
            "mqtt5_property_context_malformed",
        )
        for case in ACK_DISALLOWED_PROPERTY_CASES
    }
    for filename, packet, prefix in (
        ("PUBACK.json", "PUBACK", "40"),
        ("PUBREC.json", "PUBREC", "50"),
        ("PUBCOMP.json", "PUBCOMP", "70"),
    )
}
STANDARD_EXPECTATION_OVERRIDES["PUBLISH.json"] = {
    ("v5.0   PUBLISH DISALLOWED PROPERTIES", case, 1):
        expectation_override(
            "E0 r1 82", "E0 r1 81",
            "mqtt5_property_context_malformed",
        )
    for case in PUBLISH_DISALLOWED_PROPERTY_CASES
}
STANDARD_EXPECTATION_OVERRIDES["PUBLISH.json"].update({
    ("v5.0   PUBLISH", "30 topic 0", 1): expectation_override(
        "E0 r1 81", "E0 r1 82", "mqtt5_publish_protocol_error",
    ),
    ("v5.0   PUBLISH", "30 topic with + [MQTT-3.3.2-2]", 1):
        expectation_override(
            "E0 r1 81", "E0 r1 82", "mqtt5_publish_protocol_error",
        ),
    ("v5.0   PUBLISH", "30 topic with # [MQTT-3.3.2-2]", 1):
        expectation_override(
            "E0 r1 81", "E0 r1 82", "mqtt5_publish_protocol_error",
        ),
})
STANDARD_EXPECTATION_OVERRIDES["SUBSCRIBE.json"] = {
    (group, test, 1): expectation_override(
        "E0 r1 81", "E0 r1 82", "mqtt5_subscribe_protocol_error",
    )
    for group, test in (
        ("v5.0   SUBSCRIBE",
         "82 QoS 3 [MQTT-3-8.3-2] (no topic or qos)"),
        ("v5.0   SUBSCRIBE", "82 QoS 3 [MQTT-3-8.3-4]"),
        ("v5.0   SUBSCRIBE",
         "82 QoS 0 retain handling=3 0x30 [MQTT-3-8.3-4]"),
        ("v5.0   SUBSCRIBE", "82 short 3"),
        ("v5.0   SUBSCRIBE", "82 single topic len 0"),
        ("v5.0   SUBSCRIBE", "82 multiple topic 1 len 0"),
        ("v5.0   SUBSCRIBE", "82 multiple topic 2 len 0"),
        ("v5.0   SUBSCRIBE", "82 multiple topic 1,2 len 0"),
        ("v5.0   SUBSCRIBE", "82 mid 0"),
    )
}
STANDARD_EXPECTATION_OVERRIDES["UNSUBSCRIBE.json"] = {
    ("v5.0   UNSUBSCRIBE", test, 1): expectation_override(
        "E0 r1 81", "E0 r1 82", "mqtt5_unsubscribe_protocol_error",
    )
    for test in (
        "A2 multiple zero 1st",
        "A2 multiple zero 2nd",
        "A2 short 3 [MQTT-3.10.3-2]",
        "A2 zero mid",
    )
}
EXPECTED_COMPLETE_SEQUENCE_COUNT = 683
EXPECTED_SUBSET_SEQUENCE_COUNTS = {
    "PUBLISH.json": 148,
    "SUBSCRIBE.json": 151,
    "UNSUBSCRIBE.json": 100,
}
EXPECTED_SUBSET_SEQUENCE_COUNT = sum(EXPECTED_SUBSET_SEQUENCE_COUNTS.values())
EXPECTED_SEQUENCE_COUNT = (
    EXPECTED_COMPLETE_SEQUENCE_COUNT + EXPECTED_SUBSET_SEQUENCE_COUNT
)
EXPECTED_STANDARD_OVERRIDE_COUNT = 106
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
    data_root: Path,
    selected_files: dict[str, str] | None = None,
    excluded_tests: dict[str, dict[tuple[str, str], str]] | None = None,
    expectation_overrides: dict[
        str, dict[tuple[str, str, int], tuple[str, str, str]]
    ] | None = None,
) -> list[dict]:
    if selected_files is None:
        selected_files = SEQUENCE_FILES | SEQUENCE_SUBSET_FILES
        excluded_tests = SEQUENCE_EXCLUSIONS
        expectation_overrides = STANDARD_EXPECTATION_OVERRIDES
    elif excluded_tests is None:
        excluded_tests = {}
    if expectation_overrides is None:
        expectation_overrides = {}
    unknown_exclusion_files = set(excluded_tests) - set(selected_files)
    if unknown_exclusion_files:
        raise ValueError(
            f"exclusions name unselected files: "
            f"{sorted(unknown_exclusion_files)}"
        )
    unknown_override_files = set(expectation_overrides) - set(selected_files)
    if unknown_override_files:
        raise ValueError(
            f"expectation overrides name unselected files: "
            f"{sorted(unknown_override_files)}"
        )
    sequences: list[dict] = []
    for filename, expected_hash in selected_files.items():
        path = data_root / filename
        source = path.read_bytes()
        verify_source_hash(path, expected_hash)
        groups = json.loads(source)
        file_exclusions = excluded_tests.get(filename, {})
        file_overrides = expectation_overrides.get(filename, {})
        found_exclusions: set[tuple[str, str]] = set()
        found_overrides: set[tuple[str, str, int]] = set()
        for group in groups:
            if group.get("disable", False):
                continue
            group_protocol = group.get("ver", 4)
            group_connect = group.get("connect", True)
            group_disconnect = group.get("expect_disconnect", True)
            for test in group["tests"]:
                identity = (group["group"], test["name"])
                if identity in file_exclusions:
                    reason = file_exclusions[identity]
                    if reason not in EXCLUSION_REASONS:
                        raise ValueError(
                            f"{filename} {identity} has unknown exclusion "
                            f"reason: {reason}"
                        )
                    found_exclusions.add(identity)
                    continue
                actions = [dict(action) for action in test.get("msgs", [])]
                action_types = {action["type"] for action in actions}
                if not action_types <= {"send", "recv", "external_publish"}:
                    raise ValueError(
                        f"{filename} {test['name']} is not a portable raw sequence"
                    )
                for action_index, action in enumerate(actions):
                    override_identity = (
                        group["group"], test["name"], action_index,
                    )
                    override = file_overrides.get(override_identity)
                    if override is None:
                        continue
                    source_payload, expected_payload, reason = override
                    if reason not in STANDARD_OVERRIDE_REASONS:
                        raise ValueError(
                            f"{filename} {override_identity} has unknown "
                            f"override reason: {reason}"
                        )
                    if (
                        action["type"] != "recv"
                        or action["payload"] != source_payload
                    ):
                        raise ValueError(
                            f"{filename} override source drift for "
                            f"{override_identity}: expected recv "
                            f"{source_payload!r}, found {action!r}"
                        )
                    action["payload"] = expected_payload
                    found_overrides.add(override_identity)
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
        expected_exclusions = set(file_exclusions)
        if found_exclusions != expected_exclusions:
            missing = sorted(expected_exclusions - found_exclusions)
            raise ValueError(
                f"{filename} exclusions not found in source: {missing}"
            )
        expected_overrides = set(file_overrides)
        if found_overrides != expected_overrides:
            missing = sorted(expected_overrides - found_overrides)
            raise ValueError(
                f"{filename} expectation overrides not found in source: "
                f"{missing}"
            )
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
    except (AssertionError, TimeoutError) as exc:
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
    if set(SEQUENCE_EXCLUSIONS) != set(SEQUENCE_SUBSET_FILES):
        raise AssertionError(
            "every audited subset file must have one exclusion manifest"
        )
    selected_files = set(SEQUENCE_FILES) | set(SEQUENCE_SUBSET_FILES)
    if not set(STANDARD_EXPECTATION_OVERRIDES) <= selected_files:
        raise AssertionError(
            "standard expectation overrides must name selected files"
        )
    override_count = sum(
        len(overrides)
        for overrides in STANDARD_EXPECTATION_OVERRIDES.values()
    )
    if override_count != EXPECTED_STANDARD_OVERRIDE_COUNT:
        raise AssertionError(
            f"expected {EXPECTED_STANDARD_OVERRIDE_COUNT} standard "
            f"expectation overrides, found {override_count}"
        )
    verify_source_hash(
        args.mosquitto_test_root / "mqtt_packets.py",
        MQTT_PACKETS_SHA256,
    )
    sys.path.insert(0, str(args.mosquitto_test_root))
    import mqtt_packets  # type: ignore

    data_root = args.mosquitto_test_root / "broker" / "data"
    complete_overrides = {
        filename: STANDARD_EXPECTATION_OVERRIDES[filename]
        for filename in SEQUENCE_FILES
        if filename in STANDARD_EXPECTATION_OVERRIDES
    }
    complete_sequences = load_sequences(
        data_root,
        SEQUENCE_FILES,
        expectation_overrides=complete_overrides,
    )
    if len(complete_sequences) != EXPECTED_COMPLETE_SEQUENCE_COUNT:
        raise AssertionError(
            f"expected {EXPECTED_COMPLETE_SEQUENCE_COUNT} complete-file "
            f"sequences, found {len(complete_sequences)}"
        )
    subset_overrides = {
        filename: STANDARD_EXPECTATION_OVERRIDES[filename]
        for filename in SEQUENCE_SUBSET_FILES
        if filename in STANDARD_EXPECTATION_OVERRIDES
    }
    subset_sequences = load_sequences(
        data_root,
        SEQUENCE_SUBSET_FILES,
        SEQUENCE_EXCLUSIONS,
        subset_overrides,
    )
    if len(subset_sequences) != EXPECTED_SUBSET_SEQUENCE_COUNT:
        raise AssertionError(
            f"expected {EXPECTED_SUBSET_SEQUENCE_COUNT} audited-subset "
            f"sequences, found {len(subset_sequences)}"
        )
    subset_counts = {
        filename: sum(
            sequence["source"] == filename
            for sequence in subset_sequences
        )
        for filename in SEQUENCE_SUBSET_FILES
    }
    if subset_counts != EXPECTED_SUBSET_SEQUENCE_COUNTS:
        raise AssertionError(
            f"expected audited-subset counts "
            f"{EXPECTED_SUBSET_SEQUENCE_COUNTS}, found {subset_counts}"
        )
    sequences = complete_sequences + subset_sequences
    if len(sequences) != EXPECTED_SEQUENCE_COUNT:
        raise AssertionError(
            f"expected {EXPECTED_SEQUENCE_COUNT} total upstream sequences, "
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

    filenames = ", ".join(sorted(SEQUENCE_FILES))
    subset_summary = ", ".join(
        f"{filename}={EXPECTED_SUBSET_SEQUENCE_COUNTS[filename]}"
        for filename in sorted(SEQUENCE_SUBSET_FILES)
    )
    print(
        f"Mosquitto packet-sequence JSON gate passed: "
        f"{EXPECTED_SEQUENCE_COUNT} upstream scenarios "
        f"({EXPECTED_COMPLETE_SEQUENCE_COUNT} from complete files "
        f"{filenames}; {EXPECTED_SUBSET_SEQUENCE_COUNT} from audited "
        f"subsets {subset_summary}; "
        f"{EXPECTED_STANDARD_OVERRIDE_COUNT} exact standard expectation "
        f"overrides)"
    )


if __name__ == "__main__":
    main()
