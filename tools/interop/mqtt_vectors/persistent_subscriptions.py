"""Mosquitto-derived persistent subscription recovery scenarios."""

from __future__ import annotations

from typing import Callable


SCENARIO_COUNT = 2


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    connect_client: Callable,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    # Direct wire port of Mosquitto 02-subpub-recover-subscriptions.py. The
    # ordinary subscription is restored for both supported protocol versions;
    # MQTT 5 additionally verifies restoration of the shared subscription. No
    # SUBSCRIBE is sent after reconnect, so delivery proves broker-side state.
    ordinary_topic = "not-shared/sub"
    shared_topic = "shared/sub"
    for proto_ver in (4, 5):
        client_id = f"subpub-recover-v{proto_ver}"
        persistent_connect = mqtt_packets.gen_connect(
            client_id,
            clean_session=False,
            proto_ver=proto_ver,
            session_expiry=60 if proto_ver == 5 else None,
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

        def publish_pair(broker, phase: str) -> None:
            with broker.connect() as publisher:
                connect_client(
                    publisher, mqtt_packets,
                    f"subpub-recover-helper-v{proto_ver}-{phase}", 4,
                )
                publisher.sendall(mqtt_packets.gen_publish(
                    ordinary_topic, qos=0, payload="message1", proto_ver=4
                ))
                publisher.sendall(mqtt_packets.gen_publish(
                    shared_topic, qos=0, payload="message2", proto_ver=4
                ))

        with broker_type(executable, connections=4) as broker:
            subscriber = broker.connect()
            try:
                subscriber.sendall(persistent_connect)
                expect_packet(
                    subscriber, connack(False),
                    f"subscription recovery initial CONNACK v{proto_ver}",
                )
                subscriber.sendall(mqtt_packets.gen_subscribe(
                    1, ordinary_topic, 0, proto_ver=proto_ver
                ))
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(1, 0, proto_ver=proto_ver),
                    f"subscription recovery ordinary SUBACK v{proto_ver}",
                )
                subscriber.sendall(mqtt_packets.gen_subscribe(
                    2, f"$share/name/{shared_topic}", 0,
                    proto_ver=proto_ver,
                ))
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_suback(2, 0, proto_ver=proto_ver),
                    f"subscription recovery shared SUBACK v{proto_ver}",
                )
                publish_pair(broker, "initial")
                expect_packet(
                    subscriber,
                    mqtt_packets.gen_publish(
                        ordinary_topic, qos=0, payload="message1",
                        proto_ver=proto_ver,
                    ),
                    f"subscription recovery initial ordinary v{proto_ver}",
                )
                if proto_ver == 5:
                    expect_packet(
                        subscriber,
                        mqtt_packets.gen_publish(
                            shared_topic, qos=0, payload="message2",
                            proto_ver=proto_ver,
                        ),
                        f"subscription recovery initial shared v{proto_ver}",
                    )
            finally:
                subscriber.close()

            with broker.connect() as resumed:
                resumed.sendall(persistent_connect)
                expect_packet(
                    resumed, connack(True),
                    f"subscription recovery resumed CONNACK v{proto_ver}",
                )
                publish_pair(broker, "resumed")
                expect_packet(
                    resumed,
                    mqtt_packets.gen_publish(
                        ordinary_topic, qos=0, payload="message1",
                        proto_ver=proto_ver,
                    ),
                    f"subscription recovery resumed ordinary v{proto_ver}",
                )
                if proto_ver == 5:
                    expect_packet(
                        resumed,
                        mqtt_packets.gen_publish(
                            shared_topic, qos=0, payload="message2",
                            proto_ver=proto_ver,
                        ),
                        f"subscription recovery resumed shared v{proto_ver}",
                    )
                resumed.sendall(mqtt_packets.gen_disconnect(
                    proto_ver=proto_ver
                ))
