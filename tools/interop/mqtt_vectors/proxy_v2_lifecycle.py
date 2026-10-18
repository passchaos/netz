"""Mosquitto-derived PROXY v2 LOCAL and truncated-peer lifecycle cases."""

from __future__ import annotations


MAGIC = b"\x0d\x0a\x0d\x0a\x00\x0d\x0aQUIT\x0a"
LOCAL_HEADER = MAGIC + b"\x20\x00\x00\x00"
TRUNCATED_IPV4_HEADER = (
    MAGIC
    + b"\x21\x11\x00\x0f"
    + b"\x00\x00\x00\x00"
    + b"\x00\x00\x00\x00"
    + b"\x00\x00\x00\x00"
)
HEALTHY_IPV4_HEADER = (
    MAGIC
    + b"\x21\x11\x00\x0c"
    + b"\xc0\x00\x02\x05"
    + b"\x7f\x00\x00\x01"
    + b"\x18\x83\x07\x5b"
)
SCENARIO_COUNT = 2


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack,
    expect_packet,
) -> None:
    # Mosquitto's 21-proxy-v2-local.py currently closes this connection.
    # HAProxy PROXY v2 instead requires LOCAL to be accepted while its address
    # block is ignored; strengthen the locked source with an MQTT/PING exchange
    # that proves Netz retains the real transport peer and consumes the header.
    with broker_type(
        executable,
        connections=1,
        extra_args=("--proxy-protocol=2",),
    ) as broker:
        with broker.connect() as local:
            local.sendall(
                LOCAL_HEADER
                + mqtt_packets.gen_connect("proxy-v2-local", proto_ver=5)
            )
            expect_packet(
                local,
                expected_connack(mqtt_packets, mqtt5_props),
                "PROXY v2 LOCAL CONNACK",
            )
            local.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                local,
                mqtt_packets.gen_pingresp(),
                "PROXY v2 LOCAL PINGRESP",
            )
            local.sendall(mqtt_packets.gen_disconnect(proto_ver=5))

    # Complete the sanitizer-only 21-proxy-v2-lost-connection.py shape, then
    # add a valid peer so an EOF inside the declared address block must retire
    # only that connection and leave the production listener usable.
    with broker_type(
        executable,
        connections=2,
        ignore_errors=True,
        extra_args=("--proxy-protocol=2",),
    ) as broker:
        truncated = broker.connect()
        truncated.sendall(TRUNCATED_IPV4_HEADER)
        truncated.close()

        with broker.connect() as healthy:
            healthy.sendall(
                HEALTHY_IPV4_HEADER
                + mqtt_packets.gen_connect(
                    "proxy-v2-after-truncated",
                    proto_ver=5,
                )
            )
            expect_packet(
                healthy,
                expected_connack(mqtt_packets, mqtt5_props),
                "PROXY v2 healthy CONNACK after truncated peer",
            )
            healthy.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                healthy,
                mqtt_packets.gen_pingresp(),
                "PROXY v2 healthy PINGRESP after truncated peer",
            )
            healthy.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
