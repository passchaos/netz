"""Mosquitto-derived live QoS 0 queue-limit isolation scenarios."""

from __future__ import annotations

from typing import Callable


TOPIC = "subpub/qos0/queued/bytes"
PAYLOAD = "message"
QUEUED_PAYLOAD_BYTE_LIMIT = 1
SCENARIO_COUNT = 2


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Strengthened port of Mosquitto 02-subpub-qos0-queued-bytes.py. The
    # upstream one-megabyte queue limit is much larger than its payload and
    # therefore does not prove scope isolation. Use a one-byte durable queue
    # budget here: the seven-byte QoS 0 payload must still reach an online,
    # transient subscriber because no durable Session copy is involved.
    for proto_ver in (4, 5):
        if proto_ver == 5:
            connack = expected_connack(mqtt_packets, mqtt5_props)
        else:
            connack = mqtt_packets.gen_connack(proto_ver=proto_ver)

        with broker_type(
            executable,
            connections=2,
            extra_args=(
                f"--max-session-queued-payload-bytes="
                f"{QUEUED_PAYLOAD_BYTE_LIMIT}",
            ),
        ) as broker:
            with broker.connect() as subscriber, broker.connect() as publisher:
                subscriber.sendall(mqtt_packets.gen_connect(
                    f"subpub-qos0-bytes-v{proto_ver}",
                    proto_ver=proto_ver,
                ))
                expect_packet(
                    subscriber, connack,
                    f"live QoS0 queue scope subscriber CONNACK v{proto_ver}",
                )
                subscriber.sendall(mqtt_packets.gen_subscribe(
                    1, TOPIC, 1, proto_ver=proto_ver
                ))
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(1, 1, proto_ver=proto_ver),
                    f"live QoS0 queue scope SUBACK v{proto_ver}",
                )

                publisher.sendall(mqtt_packets.gen_connect(
                    f"qos0-bytes-helper-v{proto_ver}",
                    proto_ver=proto_ver,
                ))
                expect_packet(
                    publisher, connack,
                    f"live QoS0 queue scope publisher CONNACK v{proto_ver}",
                )
                publisher.sendall(mqtt_packets.gen_publish(
                    TOPIC, qos=0, payload=PAYLOAD, proto_ver=proto_ver
                ))
                publisher.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    publisher, mqtt_packets.gen_pingresp(),
                    f"live QoS0 queue scope publisher PINGRESP v{proto_ver}",
                )

                expect_packet(
                    subscriber,
                    mqtt_packets.gen_publish(
                        TOPIC, qos=0, payload=PAYLOAD, proto_ver=proto_ver
                    ),
                    f"live QoS0 queue scope PUBLISH v{proto_ver}",
                )
                subscriber.sendall(mqtt_packets.gen_pingreq())
                expect_packet(
                    subscriber, mqtt_packets.gen_pingresp(),
                    f"live QoS0 queue scope duplicate barrier v{proto_ver}",
                )
                publisher.sendall(mqtt_packets.gen_disconnect(
                    proto_ver=proto_ver
                ))
                subscriber.sendall(mqtt_packets.gen_disconnect(
                    proto_ver=proto_ver
                ))
