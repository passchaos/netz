"""Maximum-length MQTT Topic Filter hierarchy scenarios."""

from __future__ import annotations

from typing import Callable


MAXIMUM_TOPIC_BYTES = 65_535
PROTOCOL_VERSIONS = (4, 5)
SCENARIO_COUNT = 2 + len(PROTOCOL_VERSIONS)


def encode_remaining_length(value: int) -> bytes:
    if not 0 <= value <= 268_435_455:
        raise ValueError("invalid MQTT Remaining Length")
    encoded = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


def unsubscribe_packet(packet_identifier: int, topic_filter: str, proto_ver: int) -> bytes:
    topic = topic_filter.encode("utf-8")
    variable_header = packet_identifier.to_bytes(2, "big")
    if proto_ver == 5:
        variable_header += b"\x00"
    payload = len(topic).to_bytes(2, "big") + topic
    return b"\xa2" + encode_remaining_length(
        len(variable_header) + len(payload)
    ) + variable_header + payload


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Mosquitto 02-subpub-qos0-long-topic.py accepts 200 hierarchy levels and
    # rejects 201 as an implementation guard. MQTT has no such shallower cap,
    # so first prove a 201-level filter remains routable.
    deep_topic = "/" * 201
    with broker_type(executable) as broker:
        with broker.connect() as sock:
            mqtt_version = 4
            sock.sendall(mqtt_packets.gen_connect(
                "deep-topic-levels", proto_ver=mqtt_version
            ))
            expect_packet(
                sock, mqtt_packets.gen_connack(proto_ver=mqtt_version),
                "201-level topic CONNACK",
            )
            sock.sendall(mqtt_packets.gen_subscribe(
                53, deep_topic, 0, proto_ver=mqtt_version
            ))
            expect_packet(
                sock, mqtt_packets.gen_suback(53, 0, proto_ver=mqtt_version),
                "201-level topic SUBACK",
            )
            publish = mqtt_packets.gen_publish(
                deep_topic, qos=0, payload="message",
                proto_ver=mqtt_version,
            )
            sock.sendall(publish)
            expect_packet(sock, publish, "201-level topic PUBLISH")
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=mqtt_version))

    # A flat value isolates the two-byte UTF-8 field boundary from hierarchy
    # depth and complements Mosquitto 03-publish-long-topic.py.
    maximum_flat_topic = "t" * MAXIMUM_TOPIC_BYTES
    with broker_type(
        executable, extra_args=("--max-packet-size=131072",)
    ) as broker:
        with broker.connect() as sock:
            connect_packet = mqtt_packets.gen_connect(
                "maximum-topic-length", proto_ver=5
            )
            sock.sendall(connect_packet)
            expect_packet(
                sock,
                expected_connack(
                    mqtt_packets, mqtt5_props,
                    maximum_packet_size=131_072,
                ),
                "65,535-byte flat topic CONNACK",
            )
            sock.sendall(mqtt_packets.gen_subscribe(
                54, maximum_flat_topic, 0, proto_ver=5
            ))
            expect_packet(
                sock, mqtt_packets.gen_suback(54, 0, proto_ver=5),
                "65,535-byte flat topic SUBACK",
            )
            publish = mqtt_packets.gen_publish(
                maximum_flat_topic, qos=0, payload="maximum", proto_ver=5
            )
            sock.sendall(publish)
            expect_packet(sock, publish, "65,535-byte flat topic PUBLISH")
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

    # Mosquitto's issue-1412 guards reject a Topic Filter or Topic Name made
    # from 65,535 slash-separated empty levels. MQTT itself limits the UTF-8
    # field to 65,535 bytes and does not impose Mosquitto's 200-level cap.
    # Exercise the standards-valid maximum against netz in both supported
    # protocol versions, including route removal and connection reuse.
    topic = "/" * MAXIMUM_TOPIC_BYTES
    for proto_ver in PROTOCOL_VERSIONS:
        connack = (
            expected_connack(
                mqtt_packets, mqtt5_props, maximum_packet_size=131_072
            )
            if proto_ver == 5
            else mqtt_packets.gen_connack(proto_ver=proto_ver)
        )
        with broker_type(
            executable, extra_args=("--max-packet-size=131072",)
        ) as broker:
            with broker.connect() as sock:
                label = f"maximum topic hierarchy v{proto_ver}"
                sock.sendall(mqtt_packets.gen_connect(
                    f"maximum-topic-hierarchy-v{proto_ver}",
                    proto_ver=proto_ver,
                ))
                expect_packet(sock, connack, f"{label} CONNACK")

                sock.sendall(mqtt_packets.gen_subscribe(
                    55, topic, 0, proto_ver=proto_ver
                ))
                expect_packet(
                    sock,
                    mqtt_packets.gen_suback(55, 0, proto_ver=proto_ver),
                    f"{label} SUBACK",
                )

                publish = mqtt_packets.gen_publish(
                    topic, qos=0, payload="maximum", proto_ver=proto_ver
                )
                sock.sendall(publish)
                expect_packet(sock, publish, f"{label} PUBLISH")

                sock.sendall(unsubscribe_packet(56, topic, proto_ver))
                expect_packet(
                    sock,
                    mqtt_packets.gen_unsuback(56, proto_ver=proto_ver),
                    f"{label} UNSUBACK",
                )
                sock.sendall(mqtt_packets.gen_publish(
                    topic, qos=1, mid=57, payload="removed",
                    proto_ver=proto_ver,
                ))
                expect_packet(
                    sock,
                    mqtt_packets.gen_puback(
                        57, proto_ver=proto_ver,
                        reason_code=0x10 if proto_ver == 5 else 0,
                    ),
                    f"{label} removed PUBACK",
                )
                sock.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    sock, mqtt_packets.gen_pingresp(),
                    f"{label} route removal PINGRESP",
                )
                sock.sendall(mqtt_packets.gen_disconnect(
                    proto_ver=proto_ver
                ))
