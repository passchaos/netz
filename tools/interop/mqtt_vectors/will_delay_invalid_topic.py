"""Mosquitto issue 573191 invalid delayed-Will regression vector."""

from __future__ import annotations

import time
from typing import Callable


CLIENT_ID = "will-573191-test"
WILL_DELAY_SECONDS = 3
SCENARIO_COUNT = 1


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Direct process-level port of Mosquitto 07-will-delay-invalid-573191.py.
    # The empty Will Topic is invalid even though its Will properties parsed
    # successfully. Strengthen the upstream clean Session into a persistent
    # request: waiting past the delay and reconnecting with the same Client ID
    # proves that rejection installed neither a delayed Will nor a Session and
    # left the listener healthy.
    will_delay = mqtt5_props.gen_uint32_prop(
        mqtt5_props.WILL_DELAY_INTERVAL, WILL_DELAY_SECONDS
    )
    invalid_connect = mqtt_packets.gen_connect(
        CLIENT_ID,
        clean_session=False,
        proto_ver=5,
        session_expiry=60,
        will_topic="",
        will_properties=will_delay,
    )

    with broker_type(
        executable, connections=3, ignore_errors=True
    ) as broker:
        with broker.connect() as observer:
            observer.sendall(mqtt_packets.gen_connect(
                "will-573191-observer", proto_ver=5
            ))
            expect_packet(
                observer, expected_connack(mqtt_packets, mqtt5_props),
                "invalid delayed-Will observer CONNACK",
            )
            observer.sendall(mqtt_packets.gen_subscribe(
                1, "#", 0, proto_ver=5
            ))
            expect_packet(
                observer, mqtt_packets.gen_suback(1, 0, proto_ver=5),
                "invalid delayed-Will observer SUBACK",
            )

            with broker.connect() as rejected:
                rejected.sendall(invalid_connect)
                expect_packet(
                    rejected,
                    bytes.fromhex("20 03 00 90 00"),
                    "empty delayed-Will Topic CONNACK",
                )

            time.sleep(WILL_DELAY_SECONDS + 0.1)
            observer.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                observer, mqtt_packets.gen_pingresp(),
                "no publication after invalid delayed Will",
            )
            with broker.connect() as healthy:
                healthy.sendall(mqtt_packets.gen_connect(
                    CLIENT_ID,
                    clean_session=False,
                    proto_ver=5,
                    session_expiry=60,
                ))
                expect_packet(
                    healthy,
                    expected_connack(mqtt_packets, mqtt5_props),
                    "healthy CONNACK after invalid delayed Will",
                )
                healthy.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    healthy, mqtt_packets.gen_pingresp(),
                    "healthy PINGRESP after invalid delayed Will",
                )
                healthy.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
            observer.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
