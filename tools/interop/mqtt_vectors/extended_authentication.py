"""Mosquitto-derived MQTT 5 multi-step and re-authentication scenario."""

from __future__ import annotations


METHOD = "mirror"
INITIAL_DATA = "step1"
SERVER_CHALLENGE = "1pets"
CLIENT_RESPONSE = "supercalifragilisticexpialidocious"
BAD_METHOD = "badmethod"
CLIENT_ID = "client-params-test"
SCENARIO_COUNT = 1


def authentication_properties(mqtt5_props, method, data=None):
    properties = mqtt5_props.gen_string_prop(
        mqtt5_props.AUTHENTICATION_METHOD,
        method,
    )
    if data is not None:
        properties += mqtt5_props.gen_string_prop(
            mqtt5_props.AUTHENTICATION_DATA,
            data,
        )
    return properties


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    mqtt5_rc,
    broker_type,
    expected_connack,
    expect_packet,
) -> None:
    initial_properties = authentication_properties(
        mqtt5_props,
        METHOD,
        INITIAL_DATA,
    )
    server_challenge_properties = authentication_properties(
        mqtt5_props,
        METHOD,
        SERVER_CHALLENGE,
    )
    client_response_properties = authentication_properties(
        mqtt5_props,
        METHOD,
        CLIENT_RESPONSE,
    )
    method_properties = authentication_properties(mqtt5_props, METHOD)

    connect = mqtt_packets.gen_connect(
        CLIENT_ID,
        proto_ver=5,
        properties=initial_properties,
    )
    server_challenge = mqtt_packets.gen_auth(
        reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION,
        properties=server_challenge_properties,
    )
    client_response = mqtt_packets.gen_auth(
        reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION,
        properties=client_response_properties,
    )
    connack = expected_connack(
        mqtt_packets,
        mqtt5_props,
        leading_properties=method_properties,
    )
    reauthenticate = mqtt_packets.gen_auth(
        reason_code=mqtt5_rc.REAUTHENTICATE,
        properties=initial_properties,
    )
    authentication_success = mqtt_packets.gen_auth(
        reason_code=0,
        properties=method_properties,
    )
    bad_method = mqtt_packets.gen_auth(
        reason_code=mqtt5_rc.REAUTHENTICATE,
        properties=authentication_properties(
            mqtt5_props,
            BAD_METHOD,
            INITIAL_DATA,
        ),
    )
    protocol_error = mqtt_packets.gen_disconnect(
        reason_code=mqtt5_rc.PROTOCOL_ERROR,
        proto_ver=5,
    )

    # Complete production-process port of
    # 09-extended-auth-multistep-reauth.py. Netz additionally advertises its
    # normal bounded receive/packet/topic-alias capabilities in CONNACK.
    with broker_type(
        executable,
        connections=1,
        ignore_errors=True,
        extra_args=("--interop-test-authentication",),
    ) as broker:
        with broker.connect() as client:
            client.sendall(connect)
            expect_packet(client, server_challenge, "initial AUTH challenge")
            client.sendall(client_response)
            expect_packet(client, connack, "authenticated CONNACK")
            client.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                client,
                mqtt_packets.gen_pingresp(),
                "PINGRESP after initial authentication",
            )

            client.sendall(reauthenticate)
            expect_packet(client, server_challenge, "re-authentication challenge")
            client.sendall(client_response)
            expect_packet(
                client,
                authentication_success,
                "re-authentication success",
            )
            client.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                client,
                mqtt_packets.gen_pingresp(),
                "PINGRESP after re-authentication",
            )

            client.sendall(bad_method)
            expect_packet(
                client,
                protocol_error,
                "changed re-authentication method",
            )
