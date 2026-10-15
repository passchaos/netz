"""Mosquitto-derived inbound QoS 2 persistence restart scenarios."""

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Callable


SCENARIO_COUNT = 2
TOPIC = "client-msg-in/2"


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    """Resume two staged inbound QoS 2 messages after process restart."""
    for proto_ver in (4, 5):
        publisher_id = f"persist-client-msg-in-v{proto_ver}"
        helper_id = f"persist-client-msg-in-helper-v{proto_ver}"
        connect = mqtt_packets.gen_connect(
            publisher_id,
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

        publishes = tuple(
            mqtt_packets.gen_publish(
                topic=TOPIC,
                qos=2,
                payload=f"message{packet_id}",
                mid=packet_id,
                proto_ver=proto_ver,
            )
            for packet_id in (1, 2)
        )

        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "broker.db"
            persistence_arg = f"--persistence={snapshot}"

            # Complete port of the pre-restart half of Mosquitto's
            # 15-persist-client-msg-in-v3-1-1.py and v5-0.py. The publisher
            # closes after PUBREC, leaving both Application Messages awaiting
            # PUBREL in its durable Session. Finite broker shutdown writes the
            # same coherent restart boundary as Mosquitto's persistence save.
            with broker_type(
                executable,
                connections=1,
                extra_args=(persistence_arg,),
            ) as broker:
                with broker.connect() as publisher:
                    publisher.sendall(connect)
                    expect_packet(
                        publisher,
                        connack(False),
                        f"inbound QoS2 initial CONNACK v{proto_ver}",
                    )
                    for packet_id, publish in enumerate(publishes, start=1):
                        publisher.sendall(publish)
                        expect_packet(
                            publisher,
                            mqtt_packets.gen_pubrec(
                                packet_id, proto_ver=proto_ver
                            ),
                            f"inbound QoS2 pre-restart PUBREC "
                            f"{packet_id} v{proto_ver}",
                        )

            if not snapshot.is_file() or snapshot.stat().st_size == 0:
                raise AssertionError(
                    f"inbound QoS2 snapshot missing v{proto_ver}"
                )

            with broker_type(
                executable,
                connections=2,
                restore=True,
                extra_args=(persistence_arg,),
            ) as broker:
                with broker.connect() as helper, broker.connect() as publisher:
                    helper.sendall(mqtt_packets.gen_connect(
                        helper_id, proto_ver=proto_ver
                    ))
                    expect_packet(
                        helper,
                        connack(False),
                        f"inbound QoS2 helper CONNACK v{proto_ver}",
                    )
                    helper.sendall(mqtt_packets.gen_subscribe(
                        2, TOPIC, 2, proto_ver=proto_ver
                    ))
                    expect_packet(
                        helper,
                        mqtt_packets.gen_suback(
                            2, 2, proto_ver=proto_ver
                        ),
                        f"inbound QoS2 helper SUBACK v{proto_ver}",
                    )

                    publisher.sendall(connect)
                    expect_packet(
                        publisher,
                        connack(True),
                        f"inbound QoS2 resumed CONNACK v{proto_ver}",
                    )
                    for packet_id in (1, 2):
                        publisher.sendall(mqtt_packets.gen_pubrel(
                            packet_id, proto_ver=proto_ver
                        ))
                        expect_packet(
                            publisher,
                            mqtt_packets.gen_pubcomp(
                                packet_id, proto_ver=proto_ver
                            ),
                            f"inbound QoS2 resumed PUBCOMP "
                            f"{packet_id} v{proto_ver}",
                        )

                    for packet_id, publish in enumerate(publishes, start=1):
                        expect_packet(
                            helper,
                            publish,
                            f"inbound QoS2 post-restart PUBLISH "
                            f"{packet_id} v{proto_ver}",
                        )
                    for packet_id in (1, 2):
                        helper.sendall(mqtt_packets.gen_pubrec(
                            packet_id, proto_ver=proto_ver
                        ))
                        expect_packet(
                            helper,
                            mqtt_packets.gen_pubrel(
                                packet_id, proto_ver=proto_ver
                            ),
                            f"inbound QoS2 downstream PUBREL "
                            f"{packet_id} v{proto_ver}",
                        )
                        helper.sendall(mqtt_packets.gen_pubcomp(
                            packet_id, proto_ver=proto_ver
                        ))

                    helper.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        helper,
                        mqtt_packets.gen_pingresp(),
                        f"inbound QoS2 completion barrier v{proto_ver}",
                    )
                    publisher.sendall(mqtt_packets.gen_disconnect(
                        proto_ver=proto_ver
                    ))
                    helper.sendall(mqtt_packets.gen_disconnect(
                        proto_ver=proto_ver
                    ))
