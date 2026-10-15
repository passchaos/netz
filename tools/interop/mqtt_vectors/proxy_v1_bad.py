"""Mosquitto PROXY v1 malformed-header process vectors."""

from __future__ import annotations

import socket
from typing import Callable


SCENARIO_COUNT = 22

BAD_HEADERS = (
    # Basic framing/family failures.
    b"PROXY TCP3 192.0.2.5 127.0.0.1 6275 1234\r\n",
    b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1234"
    + b" " * 67
    + b"\r\n",
    # TCP4 missing fields, invalid ports, and invalid addresses.
    b"PROXY TCP4 192.0.2.5 127.0.0.1 6275\r\n",
    b"PROXY TCP4 192.0.2.5 127.0.0.1\r\n",
    b"PROXY TCP4 192.0.2.5\r\n",
    b"PROXY TCP4 \r\n",
    b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 0\r\n",
    b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 65536\r\n",
    b"PROXY TCP4 192.0.2.5 127.0.0.1 0 1234\r\n",
    b"PROXY TCP4 192.0.2.5 127.0.0.1 65536 1234\r\n",
    b"PROXY TCP4 192.0.2.5 127.0.0.256 6275 1234\r\n",
    b"PROXY TCP4 192.0.2.256 127.0.0.1 6275 1234\r\n",
    # The upstream TCP6 cases deliberately retain IPv4-looking addresses in
    # addition to their missing/range faults. Family validation must reject
    # all of them rather than accepting the textual address independently.
    b"PROXY TCP6 192.0.2.5 127.0.0.1 6275\r\n",
    b"PROXY TCP6 192.0.2.5 127.0.0.1\r\n",
    b"PROXY TCP6 192.0.2.5\r\n",
    b"PROXY TCP6 \r\n",
    b"PROXY TCP6 192.0.2.5 127.0.0.1 6275 0\r\n",
    b"PROXY TCP6 192.0.2.5 127.0.0.1 6275 65536\r\n",
    b"PROXY TCP6 192.0.2.5 127.0.0.1 0 1234\r\n",
    b"PROXY TCP6 192.0.2.5 127.0.0.1 65536 1234\r\n",
    b"PROXY TCP6 192.0.2.5 127.0.0.256 6275 1234\r\n",
    b"PROXY TCP6 192.0.2.256 127.0.0.1 6275 1234\r\n",
)


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    """Reject every upstream malformed preface and retain listener health."""
    # Complete process-level port of Mosquitto 21-proxy-v1-bad.py. The final
    # valid connection is an added recovery assertion: malformed trusted-proxy
    # input must retire only that peer, not the finite listener worker.
    with broker_type(
        executable,
        connections=len(BAD_HEADERS) + 1,
        ignore_errors=True,
        extra_args=("--proxy-protocol=1",),
    ) as broker:
        for index, header in enumerate(BAD_HEADERS, start=1):
            with broker.connect() as sock:
                sock.sendall(header)
                try:
                    unexpected = sock.recv(1)
                except (ConnectionResetError, BrokenPipeError):
                    unexpected = b""
                except socket.timeout as exc:
                    raise AssertionError(
                        f"PROXY v1 bad case {index} remained open"
                    ) from exc
                if unexpected:
                    raise AssertionError(
                        f"PROXY v1 bad case {index} returned bytes: "
                        f"{unexpected.hex()}"
                    )

        with broker.connect() as healthy:
            healthy.sendall(
                b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1883\r\n"
                + mqtt_packets.gen_connect(
                    "proxy-v1-after-malformed", proto_ver=5
                )
            )
            expect_packet(
                healthy,
                expected_connack(mqtt_packets, mqtt5_props),
                "PROXY v1 healthy CONNACK after malformed matrix",
            )
            healthy.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                healthy,
                mqtt_packets.gen_pingresp(),
                "PROXY v1 healthy PINGRESP after malformed matrix",
            )
            healthy.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
