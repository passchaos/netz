"""Complete wire port of Mosquitto's private bridge No Local matrix."""

from __future__ import annotations


SCENARIOS = ((128 + 3, 3, 0), (128 + 4, 4, 0), (5, 5, 4))
SCENARIO_COUNT = len(SCENARIOS)
TOPIC = "loop/test"


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack,
    expect_packet,
) -> None:
    # 06-bridge-no-local.py uses the private CONNECT protocol marker for
    # MQTT 3.1/3.1.1 and the explicit No Local subscription option for MQTT 5.
    # Preserve all three wire shapes rather than translating them to MQTT 5.
    for connect_version, message_version, options in SCENARIOS:
        with broker_type(executable, connections=2) as broker:
            with broker.connect() as bridge:
                bridge.sendall(mqtt_packets.gen_connect(
                    "bridge-test", proto_ver=connect_version,
                ))
                connack = (
                    expected_connack(mqtt_packets, mqtt5_props)
                    if message_version == 5 else
                    mqtt_packets.gen_connack(rc=0, proto_ver=message_version)
                )
                expect_packet(bridge, connack, "bridge No Local CONNACK")
                bridge.sendall(mqtt_packets.gen_subscribe(
                    1, TOPIC, options, proto_ver=message_version,
                ))
                expect_packet(
                    bridge,
                    mqtt_packets.gen_suback(1, 0, proto_ver=message_version),
                    "bridge No Local SUBACK",
                )
                bridge.sendall(mqtt_packets.gen_publish(
                    TOPIC, qos=0, payload="message", proto_ver=message_version,
                ))
                bridge.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    bridge, mqtt_packets.gen_pingresp(),
                    "bridge No Local self-publication barrier",
                )

                # A separate publisher proves the subscription still routes.
                # Its PING barrier makes this positive control independent of
                # scheduling delays and rejects delayed self-message leakage.
                with broker.connect() as peer:
                    peer.sendall(mqtt_packets.gen_connect(
                        "bridge-peer", proto_ver=message_version,
                    ))
                    expect_packet(peer, connack, "bridge peer CONNACK")
                    publication = mqtt_packets.gen_publish(
                        TOPIC, qos=0, payload="peer-message",
                        proto_ver=message_version,
                    )
                    peer.sendall(publication + mqtt_packets.gen_pingreq())
                    expect_packet(
                        peer, mqtt_packets.gen_pingresp(),
                        "bridge peer publication barrier",
                    )
                    expect_packet(bridge, publication, "bridge peer delivery")
                    bridge.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        bridge, mqtt_packets.gen_pingresp(),
                        "bridge No Local final delivery barrier",
                    )
                    peer.sendall(mqtt_packets.gen_disconnect(
                        proto_ver=message_version,
                    ))
                bridge.sendall(mqtt_packets.gen_disconnect(
                    proto_ver=message_version,
                ))
