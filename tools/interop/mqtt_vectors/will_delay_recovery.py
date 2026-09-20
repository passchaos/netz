"""Mosquitto-derived delayed-Will Session replacement scenarios."""

from __future__ import annotations

import time
from typing import Callable


WILL_DELAY_SECONDS = 3
RECONNECT_DELAY_SECONDS = 1
CLEAN_START_VALUES = (True, False)
SCENARIO_COUNT = len(CLEAN_START_VALUES)


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    connect_v5: Callable,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Direct wire port of both branches in Mosquitto
    # 07-will-delay-recover.py. Resuming the durable Session before the Will
    # deadline cancels the old Will. Replacing it with Clean Start ends the old
    # Session and publishes that Will, while installing a fresh connection.
    topic = "will/delay/recovery/test"
    client_id = "will-delay-recovery-helper"
    session_expiry = mqtt5_props.gen_uint32_prop(
        mqtt5_props.SESSION_EXPIRY_INTERVAL, 30
    )
    will_delay = mqtt5_props.gen_uint32_prop(
        mqtt5_props.WILL_DELAY_INTERVAL, WILL_DELAY_SECONDS
    )

    for clean_start in CLEAN_START_VALUES:
        with broker_type(executable, connections=3) as broker:
            with broker.connect() as observer:
                connect_v5(
                    observer, mqtt_packets,
                    f"will-delay-recovery-observer-{int(clean_start)}",
                )
                observer.sendall(mqtt_packets.gen_subscribe(
                    1, topic, 0, proto_ver=5
                ))
                expect_packet(
                    observer, mqtt_packets.gen_suback(1, 0, proto_ver=5),
                    f"Will Delay recovery SUBACK clean={clean_start}",
                )

                source_connect = mqtt_packets.gen_connect(
                    client_id,
                    proto_ver=5,
                    clean_session=False,
                    properties=session_expiry,
                    will_topic=topic,
                    will_payload=b"will delay",
                    will_properties=will_delay,
                )
                with broker.connect() as source:
                    source.sendall(source_connect)
                    expect_packet(
                        source, expected_connack(mqtt_packets, mqtt5_props),
                        f"Will Delay source CONNACK clean={clean_start}",
                    )

                time.sleep(RECONNECT_DELAY_SECONDS)
                with broker.connect() as replacement:
                    replacement.sendall(mqtt_packets.gen_connect(
                        client_id,
                        proto_ver=5,
                        clean_session=clean_start,
                        session_expiry=0 if clean_start else 30,
                        will_topic=topic,
                        will_payload=b"will delay",
                        will_properties=will_delay,
                    ))
                    expect_packet(
                        replacement,
                        expected_connack(
                            mqtt_packets, mqtt5_props,
                            session_present=not clean_start,
                        ),
                        f"Will Delay replacement CONNACK clean={clean_start}",
                    )

                    if clean_start:
                        expect_packet(
                            observer, mqtt_packets.gen_publish(
                                topic, qos=0, payload="will delay",
                                proto_ver=5,
                            ),
                            "Will from clean-start Session replacement",
                        )
                    time.sleep(WILL_DELAY_SECONDS + 0.1)
                    observer.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        observer, mqtt_packets.gen_pingresp(),
                        f"Will Delay recovery barrier clean={clean_start}",
                    )
                    replacement.sendall(
                        mqtt_packets.gen_disconnect(proto_ver=5)
                    )
                observer.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
