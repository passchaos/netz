"""Fail-closed source identities for imported Mosquitto wire vectors."""

from __future__ import annotations

import hashlib
from pathlib import Path


MOSQUITTO_HELPER_SHA256 = {
    "mqtt_packets.py":
        "0024fcebd421a3286cea021ed64083f906d9b457004786b05f8a74abae5bfb37",
    "mqtt5_props.py":
        "133b5edb1f2a57c459411dc479ff3c24e3a000d7fcb3eb4b0e96c197241ef1b9",
    "mqtt5_rc.py":
        "9e27a9994b4622466c5e4babd20ecf8a493a8c8796bbba379125a8a3bc23ca0e",
    "mqtt5_opts.py":
        "00a1a30e29092938eeed59240358810914a4120d1b6df08376d3fa3085304576",
}
MOSQUITTO_SOURCE_SHA256 = {
    "broker/02-subhier-crash.py":
        "9cf95f158aabeff60e96c2dcff2f33c48415507725b383201e143ef832620966",
    "broker/02-subpub-recover-subscriptions.py":
        "2f6289be6000de501a7329b635ea1659f81abb06fbf6f597144a160371e8a271",
    "broker/02-subscribe-persistence-flipflop.py":
        "a505ba09fbeea473296914d9bc7704c88ef99e2db0a5c952c220ab7104b8dffe",
}


def verify_source_hash(path: Path, expected: str) -> None:
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError(
            f"unexpected SHA-256 for {path}: expected {expected}, got {actual}"
        )


def verify_mosquitto_sources(test_root: Path) -> None:
    for relative_path, expected in (
        MOSQUITTO_HELPER_SHA256 | MOSQUITTO_SOURCE_SHA256
    ).items():
        verify_source_hash(test_root / relative_path, expected)
