"""Mosquitto MQTT 5 clean-DISCONNECT encoding lifecycle vectors."""

from __future__ import annotations

from typing import Callable


SCENARIO_COUNT = 4
TOPIC = "disconnect/forms/failure"


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    """Require every legal MQTT 5 DISCONNECT form to cancel the Will."""
    user_property = mqtt5_props.gen_string_pair_prop(
        mqtt5_props.USER_PROPERTY, "key", "value"
    )
    cases = (
        ("remaining-length-0", mqtt_packets.gen_disconnect(proto_ver=5)),
        (
            "reason-code-only",
            mqtt_packets.gen_disconnect(proto_ver=5, reason_code=0),
        ),
        (
            "empty-properties",
            mqtt_packets.gen_disconnect(
                proto_ver=5, reason_code=0, properties=""
            ),
        ),
        (
            "user-property",
            mqtt_packets.gen_disconnect(
                proto_ver=5,
                reason_code=0,
                properties=user_property,
            ),
        ),
    )

    # Direct complete port of Mosquitto 01-connect-disconnect-v5.py. Each
    # legal encoding closes a Will-bearing connection normally. A subscriber
    # PING barrier must therefore see PINGRESP rather than the forbidden Will.
    with broker_type(executable, connections=2 * len(cases)) as broker:
        for index, (label, disconnect) in enumerate(cases, start=1):
            with broker.connect() as observer:
                observer.sendall(mqtt_packets.gen_connect(
                    f"disconnect-form-observer-{index}", proto_ver=5
                ))
                expect_packet(
                    observer,
                    expected_connack(mqtt_packets, mqtt5_props),
                    f"{label} observer CONNACK",
                )
                observer.sendall(mqtt_packets.gen_subscribe(
                    1, TOPIC, 0, proto_ver=5
                ))
                expect_packet(
                    observer,
                    mqtt_packets.gen_suback(1, 0, proto_ver=5),
                    f"{label} observer SUBACK",
                )

                source = broker.connect()
                try:
                    source.sendall(mqtt_packets.gen_connect(
                        f"disconnect-form-source-{index}",
                        proto_ver=5,
                        will_topic=TOPIC,
                        will_payload=b"failure",
                    ))
                    expect_packet(
                        source,
                        expected_connack(mqtt_packets, mqtt5_props),
                        f"{label} source CONNACK",
                    )
                    source.sendall(disconnect)
                finally:
                    source.close()

                observer.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    observer,
                    mqtt_packets.gen_pingresp(),
                    f"{label} clean DISCONNECT suppressed Will",
                )
                observer.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
