"""Mosquitto PROXY v2 malformed-header process vectors."""

from __future__ import annotations

import socket
from typing import Callable


SCENARIO_COUNT = 12
MAGIC = b"\x0d\x0a\x0d\x0a\x00\x0d\x0aQUIT\x0a"
ZERO_ADDRESS = b"\x00" * 12

SSL_VALUE = (
    b"\x05\x00\x00\x00\x00"
    + b"\x21\x00\x07TLSv1.3"
    + b"\x23\x00\x08pqrstuv"
)

BAD_HEADERS = (
    # Signature, version, command, and family/protocol faults.
    MAGIC[:-1] + b"\x0b\x21\x01\x00\x0c" + ZERO_ADDRESS,
    MAGIC + b"\x31\x01\x00\x0c" + ZERO_ADDRESS,
    MAGIC + b"\x23\x01\x00\x0c" + ZERO_ADDRESS,
    MAGIC + b"\x21\x00\x00\x0c" + ZERO_ADDRESS,
    # Address-family payload lengths must cover the complete fixed address.
    MAGIC + b"\x21\x11\x00\x0b" + ZERO_ADDRESS,
    MAGIC + b"\x21\x11\x00\x00" + ZERO_ADDRESS,
    MAGIC + b"\x21\x21\x00\x0b" + ZERO_ADDRESS,
    MAGIC + b"\x21\x21\x00\x00" + ZERO_ADDRESS,
    MAGIC + b"\x21\x31\x00\x00" + ZERO_ADDRESS,
    # Truncated outer SSL TLV and inconsistent nested lengths.
    MAGIC
    + b"\x21\x11\x00\x10"
    + ZERO_ADDRESS
    + b"\x20\x00\x01\x21\x00",
    MAGIC
    + b"\x21\x11\x00\x10"
    + b"\xc0\x00\x02\x05\x00\x00\x00\x00\x18\x83\x00\x00"
    + b"\x20\x00\x19"
    + SSL_VALUE,
    MAGIC
    + b"\x21\x11\x00\x28"
    + b"\xc0\x00\x02\x05\x00\x00\x00\x00\x18\x83\x00\x00"
    + b"\x20\x00\x19"
    + b"\x05\x00\x00\x00\x00"
    + b"\x21\x00\x07TLSv1.3"
    + b"\x23\x00\x0apqrstuv",
)

HEALTHY_HEADER = (
    MAGIC
    + b"\x21\x11\x00\x0c"
    + b"\xc0\x00\x02\x05"
    + b"\x7f\x00\x00\x01"
    + b"\x18\x83\x07\x5b"
)


def run(
    executable,
    mqtt_packets,
    mqtt5_props,
    broker_type,
    expected_connack: Callable,
    expect_packet: Callable,
) -> None:
    """Reject every malformed v2 preface and retain listener health."""
    # Complete process-level port of Mosquitto 21-proxy-v2-bad-header.py. The
    # final valid connection strengthens the source by proving all parser
    # failures retire only their peer and preserve the finite listener worker.
    with broker_type(
        executable,
        connections=len(BAD_HEADERS) + 1,
        ignore_errors=True,
        extra_args=("--proxy-protocol=2",),
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
                        f"PROXY v2 bad case {index} remained open"
                    ) from exc
                if unexpected:
                    raise AssertionError(
                        f"PROXY v2 bad case {index} returned bytes: "
                        f"{unexpected.hex()}"
                    )

        with broker.connect() as healthy:
            healthy.sendall(
                HEALTHY_HEADER
                + mqtt_packets.gen_connect(
                    "proxy-v2-after-malformed", proto_ver=5
                )
            )
            expect_packet(
                healthy,
                expected_connack(mqtt_packets, mqtt5_props),
                "PROXY v2 healthy CONNACK after malformed matrix",
            )
            healthy.sendall(mqtt_packets.gen_pingreq())
            expect_packet(
                healthy,
                mqtt_packets.gen_pingresp(),
                "PROXY v2 healthy PINGRESP after malformed matrix",
            )
            healthy.sendall(mqtt_packets.gen_disconnect(proto_ver=5))
