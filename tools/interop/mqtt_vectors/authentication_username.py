"""Mosquitto-derived Enhanced Authentication username/ACL scenarios."""

from __future__ import annotations


METHOD = "change"
AUTHENTICATED_USERNAME = "new_username"
TOPIC = "topic/one"
PAYLOAD = "message"
CLIENT_IDS = ("client-params-test1", "client-params-test2")
SCENARIO_COUNT = len(CLIENT_IDS)


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    mqtt5_rc,
    broker_type,
    expected_connack,
    expect_packet,
    expect_packets_unordered,
) -> None:
    method_property = mqtt5_props.gen_string_prop(
        mqtt5_props.AUTHENTICATION_METHOD,
        METHOD,
    )
    subscribe = mqtt_packets.gen_subscribe(1, TOPIC, 1, proto_ver=5)
    suback = mqtt_packets.gen_suback(1, 1, proto_ver=5)
    publish = mqtt_packets.gen_publish(
        TOPIC,
        qos=1,
        mid=2,
        payload=PAYLOAD,
        proto_ver=5,
    )

    # Portable identity/ACL core of 09-extended-auth-change-username.py. The
    # upstream repeats this under global and per-listener configuration; Netz's
    # config matrix covers that scoping separately, so these two distinct wire
    # cases execute once rather than duplicating identical single-listener I/O.
    with broker_type(
        executable,
        connections=2,
        extra_args=(
            "--interop-test-authentication",
            "--interop-authenticated-username-acl",
        ),
    ) as broker:
        with broker.connect() as anonymous:
            anonymous.sendall(mqtt_packets.gen_connect(
                CLIENT_IDS[0],
                proto_ver=5,
            ))
            expect_packet(
                anonymous,
                expected_connack(mqtt_packets, mqtt5_props),
                "anonymous identity CONNACK",
            )
            anonymous.sendall(subscribe)
            expect_packet(anonymous, suback, "anonymous identity SUBACK")
            anonymous.sendall(publish)
            expect_packet(
                anonymous,
                mqtt_packets.gen_puback(
                    2,
                    proto_ver=5,
                    reason_code=mqtt5_rc.NOT_AUTHORIZED,
                ),
                "anonymous identity PUBACK",
            )
            anonymous.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                anonymous,
                mqtt_packets.gen_pingresp(),
                "anonymous identity delivery barrier",
            )
            anonymous.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

        with broker.connect() as authenticated:
            authenticated.sendall(mqtt_packets.gen_connect(
                CLIENT_IDS[1],
                proto_ver=5,
                properties=method_property,
            ))
            expect_packet(
                authenticated,
                expected_connack(
                    mqtt_packets,
                    mqtt5_props,
                    leading_properties=method_property,
                ),
                "authenticated identity CONNACK",
            )
            authenticated.sendall(subscribe)
            expect_packet(
                authenticated,
                suback,
                "authenticated identity SUBACK",
            )
            authenticated.sendall(publish)
            expect_packets_unordered(
                authenticated,
                [
                    mqtt_packets.gen_puback(2, proto_ver=5),
                    mqtt_packets.gen_publish(
                        TOPIC,
                        qos=1,
                        mid=1,
                        payload=PAYLOAD,
                        proto_ver=5,
                    ),
                ],
                "authenticated identity publish and delivery",
            )
            authenticated.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                authenticated,
                mqtt_packets.gen_pingresp(),
                "authenticated identity delivery barrier",
            )
            authenticated.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
