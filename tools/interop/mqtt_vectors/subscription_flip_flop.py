"""Mosquitto-derived persistent/clean subscription transition scenarios."""

from __future__ import annotations

from typing import Callable


SCENARIO_COUNT = 2


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Direct wire port of Mosquitto 02-subscribe-persistence-flipflop.py
    # (issue #874). A clean connection must discard the previous durable
    # Session, but a later persistent connection must still be able to create
    # a fresh subscription and receive a routed QoS 1 message. MQTT 5 needs an
    # explicit non-zero Session Expiry Interval to express persistence.
    topic = "flipflop/test"
    payload = "message"
    for proto_ver in (4, 5):
        persistent_connect = mqtt_packets.gen_connect(
            "flipflop-test",
            clean_session=False,
            proto_ver=proto_ver,
            session_expiry=60 if proto_ver == 5 else None,
        )
        clean_connect = mqtt_packets.gen_connect(
            "flipflop-test",
            clean_session=True,
            proto_ver=proto_ver,
            session_expiry=0 if proto_ver == 5 else None,
        )

        def connack(session_present: bool) -> bytes:
            if proto_ver == 5:
                return expected_connack(
                    mqtt_packets,
                    mqtt5_props,
                    session_present=session_present,
                )
            return mqtt_packets.gen_connack(
                flags=int(session_present), rc=0, proto_ver=proto_ver
            )

        subscribe = mqtt_packets.gen_subscribe(
            1, topic, 1, proto_ver=proto_ver
        )
        suback = mqtt_packets.gen_suback(1, 1, proto_ver=proto_ver)
        publish = mqtt_packets.gen_publish(
            topic, qos=1, mid=1, payload=payload, proto_ver=proto_ver
        )
        puback = mqtt_packets.gen_puback(1, proto_ver=proto_ver)

        with broker_type(executable, connections=5) as broker:
            with broker.connect() as first:
                first.sendall(persistent_connect)
                expect_packet(
                    first, connack(False),
                    f"flip-flop initial persistent CONNACK v{proto_ver}",
                )
                first.sendall(subscribe)
                expect_packet(
                    first, suback,
                    f"flip-flop initial persistent SUBACK v{proto_ver}",
                )

            with broker.connect() as clean:
                clean.sendall(clean_connect)
                expect_packet(
                    clean, connack(False),
                    f"flip-flop clean CONNACK v{proto_ver}",
                )
                clean.sendall(subscribe)
                expect_packet(
                    clean, suback,
                    f"flip-flop clean SUBACK v{proto_ver}",
                )

            with broker.connect() as persistent:
                persistent.sendall(persistent_connect)
                expect_packet(
                    persistent, connack(False),
                    f"flip-flop fresh persistent CONNACK v{proto_ver}",
                )
                persistent.sendall(subscribe)
                expect_packet(
                    persistent, suback,
                    f"flip-flop fresh persistent SUBACK v{proto_ver}",
                )

                with broker.connect() as publisher:
                    publisher.sendall(mqtt_packets.gen_connect(
                        "flipflop-test-pub", proto_ver=proto_ver
                    ))
                    expect_packet(
                        publisher, connack(False),
                        f"flip-flop publisher CONNACK v{proto_ver}",
                    )
                    publisher.sendall(publish)
                    expect_packet(
                        publisher, puback,
                        f"flip-flop publisher PUBACK v{proto_ver}",
                    )
                    publisher.sendall(mqtt_packets.gen_disconnect(
                        proto_ver=proto_ver
                    ))

                expect_packet(
                    persistent, publish,
                    f"flip-flop routed PUBLISH v{proto_ver}",
                )
                persistent.sendall(puback)
                persistent.sendall(mqtt_packets.gen_disconnect(
                    proto_ver=proto_ver
                ))

            with broker.connect() as final_clean:
                final_clean.sendall(clean_connect)
                expect_packet(
                    final_clean, connack(False),
                    f"flip-flop final clean CONNACK v{proto_ver}",
                )
                final_clean.sendall(mqtt_packets.gen_disconnect(
                    proto_ver=proto_ver
                ))
