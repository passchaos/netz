"""Mosquitto-derived outgoing QoS 2 Receive Maximum scenarios."""

from __future__ import annotations

import socket
from typing import Callable


RECEIVE_MAXIMUMS = (1, 2)
MESSAGE_COUNT = 3
SCENARIO_COUNT = len(RECEIVE_MAXIMUMS)


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Strengthened ports of Mosquitto's
    # 02-subpub-qos2-receive-maximum-{1,2}.py. All three upstream messages
    # run at both window sizes. A slot remains occupied after PUBREC/PUBREL
    # and releases only after PUBCOMP, as required for outgoing QoS 2.
    for receive_maximum in RECEIVE_MAXIMUMS:
        topic = f"subpub/qos2/receive/maximum{receive_maximum}"
        receive_maximum_property = mqtt5_props.gen_uint16_prop(
            mqtt5_props.RECEIVE_MAXIMUM, receive_maximum
        )
        with broker_type(executable, connections=2) as broker:
            with broker.connect() as subscriber, broker.connect() as publisher:
                subscriber.sendall(mqtt_packets.gen_connect(
                    f"subpub-qos2-receive-max{receive_maximum}",
                    proto_ver=5,
                    properties=receive_maximum_property,
                ))
                expect_packet(
                    subscriber, expected_connack(mqtt_packets, mqtt5_props),
                    f"Receive Maximum {receive_maximum} subscriber CONNACK",
                )
                subscriber.sendall(mqtt_packets.gen_subscribe(
                    1, topic, 2, proto_ver=5
                ))
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(1, 2, proto_ver=5),
                    f"Receive Maximum {receive_maximum} SUBACK",
                )

                publisher.sendall(mqtt_packets.gen_connect(
                    f"subpub-qos2-recv-max{receive_maximum}-helper",
                    proto_ver=5,
                ))
                expect_packet(
                    publisher, expected_connack(mqtt_packets, mqtt5_props),
                    f"Receive Maximum {receive_maximum} publisher CONNACK",
                )
                for packet_id in range(1, MESSAGE_COUNT + 1):
                    publisher.sendall(mqtt_packets.gen_publish(
                        topic, qos=2, mid=packet_id,
                        payload=f"message{packet_id}", proto_ver=5,
                    ))
                    expect_packet(
                        publisher,
                        mqtt_packets.gen_pubrec(packet_id, proto_ver=5),
                        f"Receive Maximum {receive_maximum} publisher "
                        f"PUBREC {packet_id}",
                    )
                    publisher.sendall(mqtt_packets.gen_pubrel(
                        packet_id, proto_ver=5
                    ))
                    expect_packet(
                        publisher,
                        mqtt_packets.gen_pubcomp(packet_id, proto_ver=5),
                        f"Receive Maximum {receive_maximum} publisher "
                        f"PUBCOMP {packet_id}",
                    )

                for packet_id in range(1, receive_maximum + 1):
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_publish(
                            topic, qos=2, mid=packet_id,
                            payload=f"message{packet_id}", proto_ver=5,
                        ),
                        f"Receive Maximum {receive_maximum} downstream "
                        f"PUBLISH {packet_id}",
                    )
                _expect_silence(
                    subscriber,
                    f"Receive Maximum {receive_maximum} initial window",
                )

                for packet_id in range(1, MESSAGE_COUNT + 1):
                    subscriber.sendall(mqtt_packets.gen_pubrec(
                        packet_id, proto_ver=5
                    ))
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_pubrel(packet_id, proto_ver=5),
                        f"Receive Maximum {receive_maximum} downstream "
                        f"PUBREL {packet_id}",
                    )
                    _expect_silence(
                        subscriber,
                        f"Receive Maximum {receive_maximum} pre-PUBCOMP "
                        f"{packet_id}",
                    )
                    subscriber.sendall(mqtt_packets.gen_pubcomp(
                        packet_id, proto_ver=5
                    ))
                    next_packet_id = packet_id + receive_maximum
                    if next_packet_id <= MESSAGE_COUNT:
                        expect_packet(
                            subscriber,
                            mqtt_packets.gen_publish(
                                topic, qos=2, mid=next_packet_id,
                                payload=f"message{next_packet_id}",
                                proto_ver=5,
                            ),
                            f"Receive Maximum {receive_maximum} downstream "
                            f"PUBLISH {next_packet_id}",
                        )

                subscriber.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    subscriber, mqtt_packets.gen_pingresp(),
                    f"Receive Maximum {receive_maximum} completion barrier",
                )
                publisher.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
                subscriber.sendall(mqtt_packets.gen_disconnect(proto_ver=5))


def _expect_silence(sock, label: str) -> None:
    sock.settimeout(0.1)
    try:
        unexpected = sock.recv(1)
        if unexpected:
            raise AssertionError(
                f"{label} leaked queued PUBLISH: {unexpected.hex()}"
            )
    except socket.timeout:
        pass
    finally:
        sock.settimeout(5)
