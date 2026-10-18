"""Mosquitto-derived MQTT 5 single-step authentication result matrix."""

from __future__ import annotations


METHODS = ("error", "non-matching", "single", "single", "mirror")
CLIENT_IDS = (
    "client-params-test1",
    "client-params-test2",
    "client-params-test3",
    "client-params-test5",
    "client-params-test6",
)
SCENARIO_COUNT = len(METHODS)


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


def expect_closed(sock, label: str) -> None:
    try:
        unexpected = sock.recv(1)
    except (BrokenPipeError, ConnectionResetError):
        return
    if unexpected:
        raise AssertionError(
            f"{label}: expected connection close, received {unexpected.hex()}"
        )


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    mqtt5_rc,
    broker_type,
    expected_connack,
    expect_packet,
) -> None:
    method_only = {
        method: authentication_properties(mqtt5_props, method)
        for method in ("single", "mirror")
    }
    cases = (
        (
            CLIENT_IDS[0],
            authentication_properties(mqtt5_props, METHODS[0]),
            None,
        ),
        (
            CLIENT_IDS[1],
            authentication_properties(mqtt5_props, METHODS[1]),
            mqtt_packets.gen_connack(
                rc=mqtt5_rc.BAD_AUTHENTICATION_METHOD,
                proto_ver=5,
                properties=None,
            ),
        ),
        (
            CLIENT_IDS[2],
            authentication_properties(mqtt5_props, METHODS[2], "baddata"),
            mqtt_packets.gen_connack(
                rc=mqtt5_rc.NOT_AUTHORIZED,
                proto_ver=5,
                properties=None,
            ),
        ),
        (
            CLIENT_IDS[3],
            authentication_properties(mqtt5_props, METHODS[3], "data"),
            expected_connack(
                mqtt_packets,
                mqtt5_props,
                leading_properties=method_only["single"],
            ),
        ),
        (
            CLIENT_IDS[4],
            authentication_properties(mqtt5_props, METHODS[4], "somedata"),
            expected_connack(
                mqtt_packets,
                mqtt5_props,
                leading_properties=(
                    method_only["mirror"]
                    + mqtt5_props.gen_string_prop(
                        mqtt5_props.AUTHENTICATION_DATA,
                        "atademos",
                    )
                ),
            ),
        ),
    )

    # Complete production-process port of 09-extended-auth-single.py. The
    # successful CONNACKs additionally retain Netz's normal bounded
    # receive/packet/topic-alias capability advertisements.
    with broker_type(
        executable,
        connections=len(cases),
        ignore_errors=True,
        extra_args=("--interop-test-authentication",),
    ) as broker:
        for index, (client_id, properties, expected) in enumerate(cases):
            with broker.connect() as client:
                client.sendall(mqtt_packets.gen_connect(
                    client_id,
                    proto_ver=5,
                    properties=properties,
                ))
                label = f"single-step authentication case {index + 1}"
                if expected is None:
                    expect_closed(client, label)
                else:
                    expect_packet(client, expected, label)
                    if expected[3] == 0:
                        client.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
