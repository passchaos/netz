"""Mosquitto-derived persistent self-subscription process restart matrix."""

from __future__ import annotations

from pathlib import Path
import tempfile


SCENARIO_COUNT = 4
TOPIC = "subpub/qos1"
CLIENT_ID = "persistent-subscription-test"


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack,
    expect_packet,
    expect_packets_unordered,
) -> None:
    # Complete MQTT 3.1.1/5 port of 11-persistent-subscription.py. The first
    # process saves a subscription; the second must restore and use it without
    # another SUBSCRIBE, including delivery back to the publishing Client ID.
    # Journal companions kill an active subscribed peer after durable SUBACK,
    # so no disconnect or orderly final snapshot can supply missing state.
    for version, storage in (
        (4, "snapshot"), (5, "snapshot"),
        (4, "journal"), (5, "journal"),
    ):
        connect = mqtt_packets.gen_connect(
            CLIENT_ID, clean_session=False, proto_ver=version,
            session_expiry=60 if version == 5 else None,
        )

        def connack(present: bool) -> bytes:
            return (
                expected_connack(
                    mqtt_packets, mqtt5_props, session_present=present,
                ) if version == 5 else
                mqtt_packets.gen_connack(flags=int(present), rc=0, proto_ver=version)
            )

        with tempfile.TemporaryDirectory(prefix="netz-subscription-restart-") as raw:
            snapshot = Path(raw) / "broker.db"
            persistence = (
                f"--persistence={snapshot}" if storage == "snapshot" else
                f"--commit-log={snapshot}"
            )
            with broker_type(
                executable, restore=storage == "journal",
                extra_args=(persistence,),
            ) as broker:
                with broker.connect() as client:
                    client.sendall(connect)
                    expect_packet(client, connack(False), "restart initial CONNACK")
                    client.sendall(mqtt_packets.gen_subscribe(
                        530, TOPIC, 1, proto_ver=version,
                    ))
                    expect_packet(
                        client, mqtt_packets.gen_suback(530, 1, proto_ver=version),
                        "restart durable SUBACK",
                    )
                    if storage == "journal":
                        broker.crash()
            if not snapshot.is_file() or snapshot.stat().st_size == 0:
                raise AssertionError("persistent subscription storage missing")

            with broker_type(
                executable, restore=True, extra_args=(persistence,),
            ) as broker:
                with broker.connect() as client:
                    client.sendall(connect)
                    expect_packet(client, connack(True), "restart resumed CONNACK")
                    client.sendall(mqtt_packets.gen_publish(
                        TOPIC, qos=1, mid=300, payload="message", proto_ver=version,
                    ))
                    expect_packets_unordered(
                        client,
                        [
                            mqtt_packets.gen_puback(300, proto_ver=version),
                            mqtt_packets.gen_publish(
                                TOPIC, qos=1, mid=1, payload="message",
                                proto_ver=version,
                            ),
                        ],
                        "restart self-publication and PUBACK",
                    )
                    client.sendall(mqtt_packets.gen_puback(1, proto_ver=version))
                    client.sendall(mqtt_packets.gen_pingreq())
                    expect_packet(
                        client, mqtt_packets.gen_pingresp(),
                        "restart self-delivery completion barrier",
                    )
                    client.sendall(mqtt_packets.gen_disconnect(proto_ver=version))
