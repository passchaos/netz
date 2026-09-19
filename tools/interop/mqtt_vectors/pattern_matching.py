"""Mosquitto-derived live and retained topic-filter matching scenarios."""

from __future__ import annotations

from typing import Callable


PATTERN_CASES = (
    ("#", "test/topic"),
    ("#", "/test/topic"),
    ("foo/#", "foo/bar/baz"),
    ("foo/+/baz", "foo/bar/baz"),
    ("foo/+/baz/#", "foo/bar/baz"),
    ("foo/+/baz/#", "foo/bar/baz/bar"),
    ("foo/foo/baz/#", "foo/foo/baz/bar"),
    ("foo/#", "foo"),
    ("foo/#", "foo/"),
    ("/#", "/foo"),
    ("test/topic/", "test/topic/"),
    ("test/topic/+", "test/topic/"),
    (
        "+/+/+/+/+/+/+/+/+/+/test",
        "one/two/three/four/five/six/seven/eight/nine/ten/test",
    ),
    ("#", "test////a//topic"),
    ("#", "/test////a//topic"),
    ("foo/#", "foo//bar///baz"),
    ("foo/+/baz", "foo//baz"),
    ("foo/+/baz//", "foo//baz//"),
    ("foo/+/baz/#", "foo//baz"),
    ("foo/+/baz/#", "foo//baz/bar"),
    ("foo//baz/#", "foo//baz/bar"),
    ("foo/foo/baz/#", "foo/foo/baz/bar"),
    ("/#", "////foo///bar"),
)
SCENARIO_COUNT = len(PATTERN_CASES) * 2


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Strengthened port of Mosquitto 03-pattern-matching.py. Every source
    # filter/topic pair runs against both supported protocol versions. Besides
    # the upstream live and retained checks, the PING barrier proves an
    # intervening UNSUBSCRIBE suppresses delivery and the retained tombstone is
    # checked as an ordinary live message before it removes stored state.
    for proto_ver in (4, 5):
        if proto_ver == 5:
            connack = expected_connack(mqtt_packets, mqtt5_props)
        else:
            connack = mqtt_packets.gen_connack(proto_ver=proto_ver)

        with broker_type(
            executable, connections=len(PATTERN_CASES)
        ) as broker:
            for index, (topic_filter, topic) in enumerate(PATTERN_CASES):
                label = f"pattern {index + 1} v{proto_ver}"
                with broker.connect() as sock:
                    sock.sendall(mqtt_packets.gen_connect(
                        f"pattern-sub-v{proto_ver}-{index + 1}",
                        proto_ver=proto_ver,
                    ))
                    expect_packet(sock, connack, f"{label} CONNACK")

                    subscribe = mqtt_packets.gen_subscribe(
                        312, topic_filter, 0, proto_ver=proto_ver
                    )
                    suback = mqtt_packets.gen_suback(
                        312, 0, proto_ver=proto_ver
                    )
                    sock.sendall(subscribe)
                    expect_packet(sock, suback, f"{label} initial SUBACK")

                    sock.sendall(mqtt_packets.gen_publish(
                        topic, qos=0, retain=True, payload="message",
                        proto_ver=proto_ver,
                    ))
                    expect_packet(
                        sock,
                        mqtt_packets.gen_publish(
                            topic, qos=0, retain=False, payload="message",
                            proto_ver=proto_ver,
                        ),
                        f"{label} live retained-source PUBLISH",
                    )

                    sock.sendall(mqtt_packets.gen_unsubscribe(
                        234, topic_filter, proto_ver=proto_ver
                    ))
                    expect_packet(
                        sock,
                        mqtt_packets.gen_unsuback(
                            234, proto_ver=proto_ver
                        ),
                        f"{label} UNSUBACK",
                    )
                    sock.sendall(mqtt_packets.gen_publish(
                        topic, qos=1, mid=313, payload="unsubscribed",
                        proto_ver=proto_ver,
                    ))
                    expect_packet(
                        sock,
                        mqtt_packets.gen_puback(
                            313, proto_ver=proto_ver,
                            reason_code=0x10 if proto_ver == 5 else 0,
                        ),
                        f"{label} unsubscribed PUBACK",
                    )
                    sock.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        sock, mqtt_packets.gen_pingresp(),
                        f"{label} unsubscribed route barrier",
                    )

                    sock.sendall(subscribe)
                    expect_packet(sock, suback, f"{label} replay SUBACK")
                    expect_packet(
                        sock,
                        mqtt_packets.gen_publish(
                            topic, qos=0, retain=True, payload="message",
                            proto_ver=proto_ver,
                        ),
                        f"{label} retained replay",
                    )

                    sock.sendall(mqtt_packets.gen_publish(
                        topic, qos=0, retain=True, payload="",
                        proto_ver=proto_ver,
                    ))
                    expect_packet(
                        sock,
                        mqtt_packets.gen_publish(
                            topic, qos=0, retain=False, payload="",
                            proto_ver=proto_ver,
                        ),
                        f"{label} retained tombstone live delivery",
                    )

                    sock.sendall(mqtt_packets.gen_unsubscribe(
                        235, topic_filter, proto_ver=proto_ver
                    ))
                    expect_packet(
                        sock,
                        mqtt_packets.gen_unsuback(
                            235, proto_ver=proto_ver
                        ),
                        f"{label} tombstone UNSUBACK",
                    )
                    sock.sendall(mqtt_packets.gen_subscribe(
                        313, topic_filter, 0, proto_ver=proto_ver
                    ))
                    expect_packet(
                        sock,
                        mqtt_packets.gen_suback(313, 0, proto_ver=proto_ver),
                        f"{label} tombstone SUBACK",
                    )
                    sock.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        sock, mqtt_packets.gen_pingresp(),
                        f"{label} tombstone replay barrier",
                    )
                    sock.sendall(mqtt_packets.gen_disconnect(
                        proto_ver=proto_ver
                    ))
