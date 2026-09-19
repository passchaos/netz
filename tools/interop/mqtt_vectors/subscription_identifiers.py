"""Mosquitto-derived Subscription Identifier replacement scenario."""

from __future__ import annotations

from typing import Callable


INITIAL_SUBSCRIPTIONS = (
    (1, "02/subpub/subid/id1", 1),
    (2, "02/subpub/subid/+/id2", 14),
    (3, "02/subpub/subid/noid", None),
)
INITIAL_PUBLISHES = (
    ("02/subpub/subid/noid", "message3", None),
    ("02/subpub/subid/test/id2", "message2", 14),
    ("02/subpub/subid/id1", "message1", 1),
)
UPDATED_SUBSCRIPTIONS = (
    (4, "02/subpub/subid/id1", None),
    (5, "02/subpub/subid/+/id2", 19),
    (6, "02/subpub/subid/noid", 21),
)
UPDATED_PUBLISHES = (
    ("02/subpub/subid/test/id2", "message2", 19),
    ("02/subpub/subid/noid", "message3", 21),
    ("02/subpub/subid/id1", "message1", None),
)
SCENARIO_COUNT = 1


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Direct wire port of Mosquitto 02-subpub-qos0-subscription-id.py. The
    # second subscription for each filter replaces its complete options, so
    # this exercises identifier removal, replacement, and addition.
    with broker_type(executable) as broker:
        with broker.connect() as sock:
            sock.sendall(mqtt_packets.gen_connect(
                "02-subpub-subid", proto_ver=5
            ))
            expect_packet(
                sock, expected_connack(mqtt_packets, mqtt5_props),
                "subscription identifier CONNACK",
            )

            def subscribe_all(subscriptions) -> None:
                for packet_id, topic_filter, identifier in subscriptions:
                    properties = (
                        mqtt5_props.gen_varint_prop(
                            mqtt5_props.SUBSCRIPTION_IDENTIFIER, identifier
                        )
                        if identifier is not None
                        else b""
                    )
                    sock.sendall(mqtt_packets.gen_subscribe(
                        packet_id, topic_filter, 0, proto_ver=5,
                        properties=properties,
                    ))
                    expect_packet(
                        sock,
                        mqtt_packets.gen_suback(packet_id, 0, proto_ver=5),
                        f"subscription identifier SUBACK {packet_id}",
                    )

            def publish_all(publishes, phase: str) -> None:
                for topic, payload, identifier in publishes:
                    sock.sendall(mqtt_packets.gen_publish(
                        topic, qos=0, payload=payload, proto_ver=5
                    ))
                    properties = (
                        mqtt5_props.gen_varint_prop(
                            mqtt5_props.SUBSCRIPTION_IDENTIFIER, identifier
                        )
                        if identifier is not None
                        else b""
                    )
                    expect_packet(
                        sock,
                        mqtt_packets.gen_publish(
                            topic, qos=0, payload=payload, proto_ver=5,
                            properties=properties,
                        ),
                        f"subscription identifier {phase} PUBLISH {topic}",
                    )

            subscribe_all(INITIAL_SUBSCRIPTIONS)
            publish_all(INITIAL_PUBLISHES, "initial")
            subscribe_all(UPDATED_SUBSCRIPTIONS)
            publish_all(UPDATED_PUBLISHES, "updated")
            sock.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                sock, mqtt_packets.gen_pingresp(),
                "subscription identifier duplicate barrier",
            )
            sock.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
