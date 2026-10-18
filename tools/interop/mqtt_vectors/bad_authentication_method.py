"""Mosquitto-derived unsupported MQTT 5 Authentication Method scenario."""

from __future__ import annotations


AUTHENTICATION_METHOD = "basic"
CLIENT_ID = "connect-test"
SCENARIO_COUNT = 1


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    mqtt5_rc,
    broker_type,
    expect_packet,
) -> None:
    properties = mqtt5_props.gen_string_prop(
        mqtt5_props.AUTHENTICATION_METHOD,
        AUTHENTICATION_METHOD,
    )
    request = mqtt_packets.gen_connect(
        CLIENT_ID,
        proto_ver=5,
        properties=properties,
    )
    expected = mqtt_packets.gen_connack(
        rc=mqtt5_rc.BAD_AUTHENTICATION_METHOD,
        proto_ver=5,
        properties=None,
    )
    with broker_type(executable, connections=1) as broker:
        with broker.connect() as client:
            client.sendall(request)
            expect_packet(
                client,
                expected,
                "unsupported CONNECT Authentication Method",
            )
