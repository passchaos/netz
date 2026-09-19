"""Mosquitto-derived subscription hierarchy removal scenarios."""

from __future__ import annotations

from typing import Callable


SCENARIO_COUNT = 2


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Strengthened wire port of Mosquitto 02-subhier-crash.py (issue #505).
    # Each round builds sibling leaves, removes topic/a, and proves both that
    # topic/a no longer routes and that topic/b still does. Repeating the full
    # round proves removing the first tree did not corrupt later insertion.
    for proto_ver in (4, 5):
        if proto_ver == 5:
            connack = expected_connack(mqtt_packets, mqtt5_props)
        else:
            connack = mqtt_packets.gen_connack(proto_ver=proto_ver)

        with broker_type(executable, connections=4) as broker:
            for round_index in (1, 2):
                with broker.connect() as subscriber:
                    subscriber.sendall(mqtt_packets.gen_connect(
                        f"subhier-crash-v{proto_ver}-{round_index}",
                        proto_ver=proto_ver,
                    ))
                    expect_packet(
                        subscriber, connack,
                        f"subscription hierarchy CONNACK "
                        f"v{proto_ver}/{round_index}",
                    )
                    subscriber.sendall(mqtt_packets.gen_subscribe(
                        1, "topic/a", 0, proto_ver=proto_ver
                    ))
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_suback(1, 0, proto_ver=proto_ver),
                        f"subscription hierarchy topic/a SUBACK "
                        f"v{proto_ver}/{round_index}",
                    )
                    subscriber.sendall(mqtt_packets.gen_subscribe(
                        2, "topic/b", 0, proto_ver=proto_ver
                    ))
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_suback(2, 0, proto_ver=proto_ver),
                        f"subscription hierarchy topic/b SUBACK "
                        f"v{proto_ver}/{round_index}",
                    )
                    subscriber.sendall(mqtt_packets.gen_unsubscribe(
                        3, "topic/a", proto_ver=proto_ver
                    ))
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_unsuback(3, proto_ver=proto_ver),
                        f"subscription hierarchy topic/a UNSUBACK "
                        f"v{proto_ver}/{round_index}",
                    )

                    with broker.connect() as publisher:
                        publisher.sendall(mqtt_packets.gen_connect(
                            f"subhier-publisher-v{proto_ver}-{round_index}",
                            proto_ver=proto_ver,
                        ))
                        expect_packet(
                            publisher, connack,
                            f"subscription hierarchy publisher CONNACK "
                            f"v{proto_ver}/{round_index}",
                        )
                        publisher.sendall(mqtt_packets.gen_publish(
                            "topic/a", qos=1, mid=10, payload="removed",
                            proto_ver=proto_ver,
                        ))
                        expect_packet(
                            publisher,
                            mqtt_packets.gen_puback(
                                10, proto_ver=proto_ver,
                                reason_code=0x10 if proto_ver == 5 else 0,
                            ),
                            f"subscription hierarchy removed PUBACK "
                            f"v{proto_ver}/{round_index}",
                        )

                        # The PUBACK synchronizes routing of topic/a. PINGRESP
                        # must therefore be next; a stale PUBLISH would fail
                        # this exact comparison.
                        subscriber.sendall(mqtt_packets.gen_pingreq())
                        expect_packet(
                            subscriber, mqtt_packets.gen_pingresp(),
                            f"subscription hierarchy removed route "
                            f"v{proto_ver}/{round_index}",
                        )

                        publisher.sendall(mqtt_packets.gen_publish(
                            "topic/b", qos=1, mid=11, payload="kept",
                            proto_ver=proto_ver,
                        ))
                        expect_packet(
                            publisher,
                            mqtt_packets.gen_puback(11, proto_ver=proto_ver),
                            f"subscription hierarchy kept PUBACK "
                            f"v{proto_ver}/{round_index}",
                        )
                        expect_packet(
                            subscriber,
                            mqtt_packets.gen_publish(
                                "topic/b", qos=0, payload="kept",
                                proto_ver=proto_ver,
                            ),
                            f"subscription hierarchy kept route "
                            f"v{proto_ver}/{round_index}",
                        )
                        publisher.sendall(mqtt_packets.gen_disconnect(
                            proto_ver=proto_ver
                        ))

                    subscriber.sendall(mqtt_packets.gen_disconnect(
                        proto_ver=proto_ver
                    ))
