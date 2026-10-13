#!/usr/bin/env python3
"""Run complete files and audited Mosquitto packet-sequence subsets.

The upstream broker harness mixes raw packet conformance with Mosquitto CLI,
configuration, plugin, and log assertions. This adapter deliberately handles
only its portable packet files and preserves their group/test inheritance,
payload DSL, and standard MQTT helper-publisher actions. Standards-correcting
replays lock the complete original action sequence before substituting it. Add
a file to SEQUENCE_FILES only when every action is portable without weakening
individual expectations. Subsets lock the whole source file and name every
exclusion with a documented reason so fixture drift fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import sys
from typing import NamedTuple

from mqtt_mosquitto_vectors import (
    NetzBroker,
    connect_client,
    expect_packet,
    recv_exact,
)


SEQUENCE_FILES = {
    "AUTH.json":
        "e9591dd6236144f9d913d9cf2a167e2ed0aacc45f9e8ec1adb6a96031958b1a4",
    "CONNECT.json":
        "22dc51ebccb0d9938bb1e5111988ab02a061671dec15beab8aa4410e948158ac",
    "CONNACK.json":
        "307445b4773e219f4377b880e19678791ee70379f85a43c729b45af548fb9108",
    "DISCONNECT.json":
        "7572c864a8aea807ab8122a28fa6721292ee367b19e6cbb2a6e76ccb2d21f3bd",
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
    "PUBLISH.json":
        "a3b6a5d5b2cd44b70550ce17a03ff5607cc76e4f165ae1f1f6deb68eb7013f86",
    "PUBREL.json":
        "5edf48213e6a9c85254b6255618fa5c67b47bfe59bf84b3b09307b8691cea225",
    "SUBACK.json":
        "1894d26a0f79718055ea1135cdeed5632a470ce6968dc9ef2810cfb83e15d3ae",
    "SUBSCRIBE.json":
        "f3feba6c933d43dc7be5397a42afd616e5f4a21824cf5289c986166ec6c0e60c",
    "UNSUBACK.json":
        "593719885cb1fa474c252449c11f2f1183fa432ee389737dca45beca225ac1a0",
    "UNSUBSCRIBE.json":
        "32a8618e6f74fb02df944bc528e9b4ff258e5e920473b7d7ea81ac107374b825",
}
SEQUENCE_SUBSET_FILES: dict[str, str] = {}

# Each exclusion is an audited divergence from the selected upstream fixture,
# not a wildcard skip. The full-file hash plus exact group/test identity makes
# an upstream addition, rename, or content change fail closed.
EXCLUSION_REASONS: dict[str, str] = {}
SEQUENCE_EXCLUSIONS: dict[str, dict[tuple[str, str], str]] = {}

# Mosquitto's two "QoS 2 Dup flow*3" cases impose its implementation's
# finite tolerance for repeated non-DUP PUBLISH packets. MQTT 3.1.1/5 instead
# require the receiver to repeat PUBREC until PUBREL. These full-sequence
# replays preserve all three source PUBLISH packets, assert each PUBREC, finish
# the transaction, and leave the connection live. The complete source action
# list and inherited terminal policy are checked before substitution.
SEQUENCE_REPLAY_REASONS = {
    "mqtt_qos2_repeat_pubrec": (
        "MQTT 3.1.1/5 require PUBREC for every same-identifier PUBLISH "
        "received before PUBREL, without replacing the first transaction"
    ),
}


class SequenceReplay(NamedTuple):
    source_actions: tuple[tuple[str, str], ...]
    actions: tuple[tuple[str, str], ...]
    source_expect_disconnect: bool
    expect_disconnect: bool
    reason: str


SEQUENCE_REPLAYS = {
    "PUBLISH.json": {
        ("v3.1.1 PUBLISH", "34 QoS 2 Dup flow*3", 0): SequenceReplay(
            source_actions=(
                ("send", "34 r16 s5 'topic' m1234 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "34 r16 s5 'topic' m1234 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "34 r16 s5 'topic' m1234 'payload'"),
            ),
            actions=(
                ("send", "34 r16 s5 'topic' m1234 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "34 r16 s5 'topic' m1234 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "34 r16 s5 'topic' m1234 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "62 r2 m1234"),
                ("recv", "70 r2 m1234"),
            ),
            source_expect_disconnect=True,
            expect_disconnect=False,
            reason="mqtt_qos2_repeat_pubrec",
        ),
        ("v5.0   PUBLISH", "34 QoS 2 Dup flow*3", 0): SequenceReplay(
            source_actions=(
                ("send", "34 r17 s5 'topic' m1234 v0 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "34 r17 s5 'topic' m1234 v0 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "34 r17 s5 'topic' m1234 v0 'payload'"),
                ("recv", "E0 r1 82"),
            ),
            actions=(
                ("send", "34 r17 s5 'topic' m1234 v0 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "34 r17 s5 'topic' m1234 v0 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "34 r17 s5 'topic' m1234 v0 'payload'"),
                ("recv", "50 r2 m1234"),
                ("send", "62 r2 m1234"),
                ("recv", "70 r2 m1234"),
            ),
            source_expect_disconnect=True,
            expect_disconnect=False,
            reason="mqtt_qos2_repeat_pubrec",
        ),
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
EXPECTATION_OVERRIDE_REASONS = {
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
    "mqtt5_fixed_header_flags_malformed": (
        "MQTT 5 section 2.1.3 requires invalid reserved Fixed Header flags "
        "to be reported as Malformed Packet 0x81"
    ),
    "mqtt5_truncated_variable_header_malformed": (
        "MQTT 5 classifies a truncated variable header as Malformed Packet "
        "0x81 rather than Protocol Error 0x82"
    ),
    "mqtt5_invalid_utf8_malformed": (
        "MQTT 5 classifies malformed or forbidden UTF-8 in a CONNECT "
        "field as Malformed Packet 0x81 rather than Client Identifier not "
        "valid 0x85"
    ),
    "equivalent_connack_property_order": (
        "the configured CONNACK contains the same properties and values as "
        "the fixture but emits them in netz's deterministic property order"
    ),
}


def expectation_override(
    source: str, expected: str, reason: str
) -> tuple[str, str, str]:
    return source, expected, reason


EXPECTATION_OVERRIDES = {
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
        ("PUBREL.json", "PUBREL", "62"),
        ("PUBCOMP.json", "PUBCOMP", "70"),
    )
}
EXPECTATION_OVERRIDES["AUTH.json"] = {
    ("v5.0   AUTH", "F0 long", 1): expectation_override(
        "E0 r1 82", "E0 r1 81",
        "mqtt5_truncated_variable_header_malformed",
    ),
    **{
        ("v5.0   AUTH", header, 1): expectation_override(
            "E0 r1 82", "E0 r1 81",
            "mqtt5_fixed_header_flags_malformed",
        )
        for header in ("F1", "F2", "F4", "F8")
    },
}
EXPECTATION_OVERRIDES["CONNACK.json"] = {
    ("v5.0   CONNACK", test, 1): expectation_override(
        "E0 r1 82", "E0 r1 81", "mqtt5_fixed_header_flags_malformed",
    )
    for test in (
        "21",
        "22",
        "24",
        "28",
        "issue 2163 v5",
    )
}
CONNECT_SUCCESS_CASES = (
    ("v5.0   CONNECT", "10 ok ", 0),
    ("v5.0   CONNECT", "10 Username flag 1 ok", 0),
    ("v5.0   CONNECT", "10 Will flag 1 ok", 0),
    ("v5.0   CONNECT", "10 Will flag 1 ok", 1),
    *{
        ("v5.0   CONNECT ALLOWED PROPERTIES", test, 0)
        for test in (
            "session-expiry-interval (four byte integer)",
            "receive-maximum (two byte integer)",
            "maximum-packet-size (four byte integer)",
            "maximum-packet-size (four byte integer) FFFFFFFF value",
            "topic-alias-maximum (two byte integer)",
            "topic-alias-maximum (two byte integer) 0 value",
            "request-response-information (byte)",
            "request-problem-information (byte)",
            "user-property",
            "2*user-property",
            "user-property empty key",
            "user-property empty value",
            "user-property empty key,value",
        )
    },
    *{
        ("v5.0   WILL ALLOWED PROPERTIES", test, 0)
        for test in (
            "payload-format-indicator (byte)",
            "message-expiry-interval (four byte integer)",
            "will-delay-interval (four byte integer)",
            "content-type (UTF-8 string)",
            "content-type (UTF-8 string) empty",
            "response-topic (UTF-8 string)",
            "correlation-data (binary)",
            "correlation-data (binary) empty",
            "user-property",
            "2*user-property",
            "user-property empty key",
            "user-property empty value",
            "user-property empty key,value",
        )
    },
)
CONNECT_DISALLOWED_PROPERTY_CASES = (
    "payload-format-indicator (byte)",
    "maximum-qos (byte)",
    "retain-available (byte)",
    "wildcard-subscription-available (byte)",
    "subscription-identifier-available (byte)",
    "shared-subscription-available (byte)",
    "message-expiry-interval (four byte integer)",
    "message-expiry-interval (four byte integer) 0 value",
    "message-expiry-interval (four byte integer) FFFFFFFF value",
    "will-delay-interval (four byte integer)",
    "will-delay-interval (four byte integer) 0 value",
    "will-delay-interval (four byte integer) FFFFFFFF value",
    "server-keep-alive (two byte integer)",
    "topic-alias (two byte integer)",
    "content-type (UTF-8 string)",
    "content-type (UTF-8 string) empty",
    "response-topic (UTF-8 string)",
    "assigned-client-identifier (UTF-8 string)",
    "assigned-client-identifier (UTF-8 string) empty",
    "response-information (UTF-8 string)",
    "response-information (UTF-8 string) empty",
    "correlation-data (binary)",
    "correlation-data (binary) empty",
    "subscription-identifier (variable byte integer)",
)
WILL_DISALLOWED_PROPERTY_CASES = (
    "request-problem-information (byte)",
    "request-response-information (byte)",
    "maximum-qos (byte)",
    "retain-available (byte)",
    "wildcard-subscription-available (byte)",
    "subscription-identifier-available (byte)",
    "shared-subscription-available (byte)",
    "server-keep-alive (two byte integer)",
    "receive-maximum (two byte integer)",
    "topic-alias-maximum (two byte integer)",
    "topic-alias (two byte integer)",
    "session-expiry-interval (four byte integer)",
    "maximum-packet-size (four byte integer)",
    "assigned-client-identifier (UTF-8 string)",
    "assigned-client-identifier (UTF-8 string) empty",
    "authentication-method (UTF-8 string)",
    "authentication-method (UTF-8 string) empty",
    "response-information (UTF-8 string)",
    "response-information (UTF-8 string) empty",
    "server-reference (UTF-8 string)",
    "server-reference (UTF-8 string) empty",
    "reason-string (UTF-8 string)",
    "reason-string (UTF-8 string) empty",
    "authentication-data (binary)",
    "authentication-data (binary) empty",
    "subscription-identifier (variable byte integer)",
)
EXPECTATION_OVERRIDES["CONNECT.json"] = {
    **{
        (group, test, occurrence, 1): expectation_override(
            "20 r14 00000B 22 H10 27 L2000000 21 H20",
            "20 r14 00000B 21 H20 27 L2000000 22 H10",
            "equivalent_connack_property_order",
        )
        for group, test, occurrence in CONNECT_SUCCESS_CASES
    },
    **{
        (group, test, 0, 1): expectation_override(
            "20 r3 00 82 00", "20 r3 00 81 00",
            "mqtt5_property_context_malformed",
        )
        for group, cases in (
            ("v5.0   CONNECT DISALLOWED PROPERTIES",
             CONNECT_DISALLOWED_PROPERTY_CASES),
            ("v5.0   WILL DISALLOWED PROPERTIES",
             WILL_DISALLOWED_PROPERTY_CASES),
        )
        for test in cases
    },
    **{
        ("v5.0   CONNECT", test, 0, 1): expectation_override(
            "20 r3 00 85 00", "20 r3 00 81 00",
            "mqtt5_invalid_utf8_malformed",
        )
        for test in (
            "10 Client ID with 0x0000",
            "10 Client ID with U+D800",
            "10 Client ID with U+0001",
            "10 Client ID with U+001F",
            "10 Client ID with U+007F",
            "10 Client ID with U+009F",
            "10 Client ID with U+FFFF",
        )
    },
}
EXPECTATION_OVERRIDES["PUBREL.json"].update({
    ("v5.0   PUBREL", f"{header} unsolicited", 1): expectation_override(
        "E0 r1 82", "E0 r1 81", "mqtt5_fixed_header_flags_malformed",
    )
    for header in ("63", "64", "66", "6A")
})
EXPECTATION_OVERRIDES["PUBLISH.json"] = {
    ("v5.0   PUBLISH DISALLOWED PROPERTIES", case, 1):
        expectation_override(
            "E0 r1 82", "E0 r1 81",
            "mqtt5_property_context_malformed",
        )
    for case in PUBLISH_DISALLOWED_PROPERTY_CASES
}
EXPECTATION_OVERRIDES["PUBLISH.json"].update({
    (
        "v5.0   PUBLISH ALLOWED PROPERTIES",
        "maximum packet size",
        1,
    ): expectation_override(
        "20 r14 00000b 22 H10 27 H30 84 80 21 00 14",
        "20 r14 00000B 21 H20 27 L2000000 22 H10",
        "equivalent_connack_property_order",
    ),
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
EXPECTATION_OVERRIDES["SUBSCRIBE.json"] = {
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
EXPECTATION_OVERRIDES["UNSUBSCRIBE.json"] = {
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
DISCONNECT_DISALLOWED_PROPERTY_CASES = tuple(
    case
    for case in ACK_DISALLOWED_PROPERTY_CASES
    if case not in {
        "session-expiry-interval (four byte integer)",
        "server-reference (UTF-8 string)",
    }
)
EXPECTATION_OVERRIDES["DISCONNECT.json"] = {
    (
        "v5.0   DISCONNECT DISALLOWED PROPERTIES",
        f"E0 with {case}",
        1,
    ): expectation_override(
        "E0 r1 82", "E0 r1 81", "mqtt5_property_context_malformed",
    )
    for case in DISCONNECT_DISALLOWED_PROPERTY_CASES
}
EXPECTATION_OVERRIDES["DISCONNECT.json"].update({
    (
        "v5.0   DISCONNECT",
        "E0 non-zero session expiry",
        1,
    ): expectation_override(
        "20 r14 00000B 22 H10 27 L2000000 21 H20",
        "20 r14 00000B 21 H20 27 L2000000 22 H10",
        "equivalent_connack_property_order",
    ),
    **{
        (
            "v5.0   DISCONNECT",
            f"{header} [MQTT-3.14.1-1]",
            1,
        ): expectation_override(
            "E0 r1 82", "E0 r1 81",
            "mqtt5_fixed_header_flags_malformed",
        )
        for header in ("E1", "E2", "E4", "E8")
    },
})
EXPECTED_COMPLETE_SEQUENCE_COUNT = 1825
EXPECTED_SUBSET_SEQUENCE_COUNTS: dict[str, int] = {}
EXPECTED_SUBSET_SEQUENCE_COUNT = sum(EXPECTED_SUBSET_SEQUENCE_COUNTS.values())
EXPECTED_SEQUENCE_COUNT = 1825
EXPECTED_EXPECTATION_OVERRIDE_COUNT = 259
EXPECTED_SEQUENCE_REPLAY_COUNT = 2
CONNECT_REFUSAL_DIAGNOSTICS = {
    ("CONNECT.json", group, test): bytes.fromhex("20 03 00 81 00")
    for group, test in (
        ("v3.1.1 CONNECT", "10 incorrect command flags"),
        ("v3.1.1 CONNECT", "10 missing keepalive"),
        ("v5.0   CONNECT",
         "10 Will flag 1 Will Qos 3 [MQTT-3.1.2-14]"),
        ("v5.0   CONNECT", "10 [MQTT-3.1.2-17]"),
        ("v5.0   CONNECT", "10 Username with 0x0000"),
        ("v5.0   CONNECT", "10 Username with 0xD800"),
        ("v5.0   CONNECT", "10 Username with 0x0001"),
        ("v5.0   CONNECT", "10 Username with 0x001F"),
        ("v5.0   CONNECT", "10 Username with 0x007F"),
        ("v5.0   CONNECT", "10 Username with 0x009F"),
        ("v5.0   CONNECT", "10 Username with 0xFFFF"),
        ("v5.0   CONNECT", "10 [MQTT-3.1.2-19]"),
    )
}
EXPECTED_CONNECT_REFUSAL_DIAGNOSTIC_COUNT = 12
PACKET_SEQUENCE_BROKER_ARGS = (
    "--max-outgoing-inflight=20",
    "--max-packet-size=2000000",
    "--topic-alias-maximum=10",
    "--strict-utf8",
)
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
    sequence_replays: dict[
        str, dict[tuple[str, str, int], SequenceReplay]
    ] | None = None,
) -> list[dict]:
    if selected_files is None:
        selected_files = SEQUENCE_FILES | SEQUENCE_SUBSET_FILES
        excluded_tests = SEQUENCE_EXCLUSIONS
        expectation_overrides = EXPECTATION_OVERRIDES
        sequence_replays = SEQUENCE_REPLAYS
    elif excluded_tests is None:
        excluded_tests = {}
    if expectation_overrides is None:
        expectation_overrides = {}
    if sequence_replays is None:
        sequence_replays = {}
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
    unknown_replay_files = set(sequence_replays) - set(selected_files)
    if unknown_replay_files:
        raise ValueError(
            f"sequence replays name unselected files: "
            f"{sorted(unknown_replay_files)}"
        )
    sequences: list[dict] = []
    for filename, expected_hash in selected_files.items():
        path = data_root / filename
        source = path.read_bytes()
        verify_source_hash(path, expected_hash)
        groups = json.loads(source)
        file_exclusions = excluded_tests.get(filename, {})
        file_overrides = expectation_overrides.get(filename, {})
        file_replays = sequence_replays.get(filename, {})
        found_exclusions: set[tuple[str, str]] = set()
        found_overrides: set[tuple] = set()
        found_replays: set[tuple[str, str, int]] = set()
        for group in groups:
            if group.get("disable", False):
                continue
            group_protocol = group.get("ver", 4)
            group_connect = group.get("connect", True)
            group_disconnect = group.get("expect_disconnect", True)
            identity_counts = {
                test["name"]: sum(
                    candidate["name"] == test["name"]
                    for candidate in group["tests"]
                    if not candidate.get("disable", False)
                )
                for test in group["tests"]
            }
            identity_occurrences: dict[str, int] = {}
            for test in group["tests"]:
                identity = (group["group"], test["name"])
                occurrence = identity_occurrences.get(test["name"], 0)
                identity_occurrences[test["name"]] = occurrence + 1
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
                replay_identity = (group["group"], test["name"], occurrence)
                replay = file_replays.get(replay_identity)
                source_expect_disconnect = test.get(
                    "expect_disconnect", group_disconnect
                )
                if replay is not None:
                    reason = replay.reason
                    if reason not in SEQUENCE_REPLAY_REASONS:
                        raise ValueError(
                            f"{filename} {replay_identity} has unknown "
                            f"sequence replay reason: {reason}"
                        )
                    source_actions = tuple(
                        (action["type"], action["payload"])
                        for action in actions
                    )
                    if source_actions != replay.source_actions:
                        raise ValueError(
                            f"{filename} sequence replay source drift for "
                            f"{replay_identity}: expected "
                            f"{replay.source_actions!r}, found "
                            f"{source_actions!r}"
                        )
                    if source_expect_disconnect != replay.source_expect_disconnect:
                        raise ValueError(
                            f"{filename} sequence replay terminal-policy "
                            f"drift for {replay_identity}"
                        )
                    actions = [
                        {"type": kind, "payload": payload}
                        for kind, payload in replay.actions
                    ]
                    replay_action_types = {
                        action["type"] for action in actions
                    }
                    if not replay_action_types <= {"send", "recv"}:
                        raise ValueError(
                            f"{filename} {replay_identity} has invalid "
                            f"sequence replay action type"
                        )
                    source_expect_disconnect = replay.expect_disconnect
                    found_replays.add(replay_identity)
                for action_index, action in enumerate(actions):
                    exact_override_identity = (
                        group["group"], test["name"], occurrence,
                        action_index,
                    )
                    legacy_override_identity = (
                        group["group"], test["name"], action_index,
                    )
                    override_identity = exact_override_identity
                    override = file_overrides.get(exact_override_identity)
                    if (override is None and
                            identity_counts[test["name"]] == 1):
                        override_identity = legacy_override_identity
                        override = file_overrides.get(legacy_override_identity)
                    if override is None:
                        continue
                    source_payload, expected_payload, reason = override
                    if reason not in EXPECTATION_OVERRIDE_REASONS:
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
                    "group": group["group"],
                    "test": test["name"],
                    "name": f"{group['group']} {test['name']}",
                    "protocol": test.get("ver", group_protocol),
                    "connect": test.get("connect", group_connect),
                    "expect_disconnect": source_expect_disconnect,
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
        expected_replays = set(file_replays)
        if found_replays != expected_replays:
            missing = sorted(expected_replays - found_replays)
            raise ValueError(
                f"{filename} sequence replays not found in source: {missing}"
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
    optional_connack_diagnostic: bytes | None = None,
) -> None:
    try:
        trailing = sock.recv(1)
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
        return
    except socket.timeout as exc:
        raise AssertionError(f"{label}: broker kept connection open") from exc
    if not trailing:
        return
    if optional_connack_diagnostic is not None and trailing == b"\x20":
        diagnostic = trailing + recv_exact(
            sock, len(optional_connack_diagnostic) - 1
        )
        if diagnostic != optional_connack_diagnostic:
            raise AssertionError(
                f"{label}: unexpected CONNECT refusal {diagnostic.hex()}"
            )
        expect_closed(sock, label, optional_v5_diagnostic=False)
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
    if proto_ver not in (3, 4, 5):
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
                optional_connack_diagnostic=CONNECT_REFUSAL_DIAGNOSTICS.get((
                    sequence["source"], sequence["group"], sequence["test"],
                )),
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
    if not set(EXPECTATION_OVERRIDES) <= selected_files:
        raise AssertionError(
            "expectation overrides must name selected files"
        )
    if not set(SEQUENCE_REPLAYS) <= selected_files:
        raise AssertionError(
            "sequence replays must name selected files"
        )
    override_count = sum(
        len(overrides)
        for overrides in EXPECTATION_OVERRIDES.values()
    )
    if override_count != EXPECTED_EXPECTATION_OVERRIDE_COUNT:
        raise AssertionError(
            f"expected {EXPECTED_EXPECTATION_OVERRIDE_COUNT} audited "
            f"expectation overrides, found {override_count}"
        )
    replay_count = sum(
        len(replays) for replays in SEQUENCE_REPLAYS.values()
    )
    if replay_count != EXPECTED_SEQUENCE_REPLAY_COUNT:
        raise AssertionError(
            f"expected {EXPECTED_SEQUENCE_REPLAY_COUNT} audited sequence "
            f"replays, found {replay_count}"
        )
    if (len(CONNECT_REFUSAL_DIAGNOSTICS) !=
            EXPECTED_CONNECT_REFUSAL_DIAGNOSTIC_COUNT):
        raise AssertionError(
            f"expected {EXPECTED_CONNECT_REFUSAL_DIAGNOSTIC_COUNT} exact "
            f"CONNECT refusal diagnostics, found "
            f"{len(CONNECT_REFUSAL_DIAGNOSTICS)}"
        )
    verify_source_hash(
        args.mosquitto_test_root / "mqtt_packets.py",
        MQTT_PACKETS_SHA256,
    )
    sys.path.insert(0, str(args.mosquitto_test_root))
    import mqtt_packets  # type: ignore

    data_root = args.mosquitto_test_root / "broker" / "data"
    complete_overrides = {
        filename: EXPECTATION_OVERRIDES[filename]
        for filename in SEQUENCE_FILES
        if filename in EXPECTATION_OVERRIDES
    }
    complete_replays = {
        filename: SEQUENCE_REPLAYS[filename]
        for filename in SEQUENCE_FILES
        if filename in SEQUENCE_REPLAYS
    }
    complete_sequences = load_sequences(
        data_root,
        SEQUENCE_FILES,
        expectation_overrides=complete_overrides,
        sequence_replays=complete_replays,
    )
    if len(complete_sequences) != EXPECTED_COMPLETE_SEQUENCE_COUNT:
        raise AssertionError(
            f"expected {EXPECTED_COMPLETE_SEQUENCE_COUNT} complete-file "
            f"sequences, found {len(complete_sequences)}"
        )
    subset_overrides = {
        filename: EXPECTATION_OVERRIDES[filename]
        for filename in SEQUENCE_SUBSET_FILES
        if filename in EXPECTATION_OVERRIDES
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

    # The upstream harness launches a fresh broker for every JSON test. Most
    # selected cases use unique Client IDs or clean Sessions and can share one
    # bounded process here. MQTT 3.1's source fixtures deliberately reuse the
    # persistent Client ID "p", so isolate those nine cases to preserve their
    # byte-exact Session Present expectations without rewriting the fixtures.
    mqtt31_sequences = [
        sequence for sequence in sequences if sequence["protocol"] == 3
    ]
    shared_sequences = [
        sequence for sequence in sequences if sequence["protocol"] != 3
    ]

    for index, sequence in enumerate(mqtt31_sequences):
        helper_connections = sum(
            action["type"] == "external_publish"
            for action in sequence["actions"]
        )
        with NetzBroker(
            args.broker,
            connections=1 + helper_connections,
            ignore_errors=True,
            extra_args=PACKET_SEQUENCE_BROKER_ARGS + (
                "--mqtt31-session-present-extension",
            ),
        ) as broker:
            run_sequence(broker, sequence, index, mqtt_packets)

    helper_connections = sum(
        action["type"] == "external_publish"
        for sequence in shared_sequences
        for action in sequence["actions"]
    )
    with NetzBroker(
        args.broker,
        connections=len(shared_sequences) + helper_connections + 1,
        ignore_errors=True,
        extra_args=PACKET_SEQUENCE_BROKER_ARGS,
    ) as broker:
        for index, sequence in enumerate(
            shared_sequences,
            start=len(mqtt31_sequences),
        ):
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
    subset_clause = (
        f"; {EXPECTED_SUBSET_SEQUENCE_COUNT} from audited subsets "
        f"{subset_summary}"
        if EXPECTED_SUBSET_SEQUENCE_COUNT != 0 else ""
    )
    print(
        f"Mosquitto packet-sequence JSON gate passed: "
        f"{EXPECTED_SEQUENCE_COUNT} upstream scenarios "
        f"({EXPECTED_COMPLETE_SEQUENCE_COUNT} from complete files "
        f"{filenames}{subset_clause}; "
        f"{EXPECTED_EXPECTATION_OVERRIDE_COUNT} exact audited expectation "
        f"overrides; {EXPECTED_SEQUENCE_REPLAY_COUNT} exact audited "
        f"standards replays; {EXPECTED_CONNECT_REFUSAL_DIAGNOSTIC_COUNT} exact "
        f"optional CONNECT refusal diagnostics)"
    )


if __name__ == "__main__":
    main()
