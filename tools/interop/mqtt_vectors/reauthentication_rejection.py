"""Mosquitto-derived MQTT 5 failed re-authentication scenario."""

from __future__ import annotations


METHOD = "repeat"
AUTHENTICATION_DATA = "repeat"
CLIENT_ID = "client-params-test"
SCENARIO_COUNT = 1


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    mqtt5_rc,
    broker_type,
    expected_connack,
    expect_packet,
) -> None:
    properties = mqtt5_props.gen_string_prop(
        mqtt5_props.AUTHENTICATION_METHOD,
        METHOD,
    )
    properties += mqtt5_props.gen_string_prop(
        mqtt5_props.AUTHENTICATION_DATA,
        AUTHENTICATION_DATA,
    )
    method_property = mqtt5_props.gen_string_prop(
        mqtt5_props.AUTHENTICATION_METHOD,
        METHOD,
    )
    connect = mqtt_packets.gen_connect(
        CLIENT_ID,
        proto_ver=5,
        properties=properties,
    )
    connack = expected_connack(
        mqtt_packets,
        mqtt5_props,
        leading_properties=method_property,
    )
    reauthenticate = mqtt_packets.gen_auth(
        reason_code=mqtt5_rc.REAUTHENTICATE,
        properties=properties,
    )
    rejected = mqtt_packets.gen_disconnect(
        reason_code=mqtt5_rc.NOT_AUTHORIZED,
        proto_ver=5,
    )

    # Complete production-process port of 09-extended-auth-reauth.py. The
    # successful initial CONNACK additionally retains Netz's normal bounded
    # receive/packet/topic-alias capability advertisements.
    with broker_type(
        executable,
        connections=1,
        extra_args=("--interop-test-authentication",),
    ) as broker:
        with broker.connect() as client:
            client.sendall(connect)
            expect_packet(client, connack, "repeat authentication CONNACK")
            client.sendall(reauthenticate)
            expect_packet(
                client,
                rejected,
                "re-authentication Not Authorized DISCONNECT",
            )
