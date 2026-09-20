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
    "broker/02-subpub-qos0-subscription-id.py":
        "4ec4e803697b4051d1c63a1d3c78bad40400af6794795b904423930903d863ee",
    "broker/02-subpub-qos0-queued-bytes.py":
        "e39f61da69cff986a2255d29739788fa6fff9cd75f0c121f945a738c25f3b126",
    "broker/02-subpub-qos2-max-inflight-bytes.py":
        "59ab8100b5aa0cea3b1ae9b82a4afb44cd6027ed69b72e761533044dbc51a91c",
    "broker/02-subpub-qos2-receive-maximum-1.py":
        "39aea4f9f4c9484384b2c4fe7190ef00ca34729c7ddf65fac42aad7e23cc4d92",
    "broker/02-subpub-qos2-receive-maximum-2.py":
        "76c477790b4572ba13fc77e25dc1d3b3c556751ddfb796c7bcc43bdd1c4345a0",
    "broker/02-subscribe-persistence-flipflop.py":
        "a505ba09fbeea473296914d9bc7704c88ef99e2db0a5c952c220ab7104b8dffe",
    "broker/03-pattern-matching.py":
        "042fa7fa8728632551bdecb632aa5f41b539a69780bc4d4bdf25582e2ff8fd32",
    "broker/03-publish-qos1-queued-bytes.conf":
        "81264cf8b5af7d7248c2e968ff373e20d07d6b414c4770cca275a38c02beea6a",
    "broker/03-publish-qos1-queued-bytes.py":
        "d320a78b93a39c8ea02e2b5c57e13b2c4d558e39fb4f0be8ce52e70b6dc9980d",
    "broker/03-publish-b2c-disconnect-qos1.py":
        "ff2c13c469c6ba35060a752c3cfb21b43556312c1fa4f1aca71e069697289b44",
    "broker/04-retain-check-source-persist.py":
        "9accde1f896d26b7c798ce3c5ca0a75b28bdad89f3e5e557b5cff0957ba0579c",
    "broker/07-will-delay-invalid-573191.py":
        "f0f02675b050e023c5331696142f0d8bf0e3360f39011bd0dc7efdce3a382285",
    "broker/07-will-delay-recover.py":
        "94060369730e84a37b39f3414e8d976a96939fa0f31e7e8301ce173ffdefe1dc",
    "broker/11-message-expiry.py":
        "c52a9210a12b58c6a51c295c2239e38d82689a7f7ef28c83f449a1f38d00e5dc",
    "broker/11-subscription-id.py":
        "bc736a56c9d4e53e346e17d21d17e1dcc477b1693c34fdc6c0dac50854d448aa",
    "broker/15-persist-client-msg-out-v5-0.py":
        "2612901cb197a0c602ae6dc34b46d80a742f6b35cdc3757a81ddf10d77093b97",
    "broker/15-persist-client-will-persistent.py":
        "95b2079245e724956128e1a62d6fa46b9972ddc9166b97d51ae3d3a131d1ed6d",
    "broker/persist_client_will_core.py":
        "0085074a986f587ac681dd73e318950a144fa2dadde22bb44c6e68aa97cc36a1",
    "broker/persist_module_helper.py":
        "ca7a38158e005603f4c5ec4583ddd6e45fe643cfbf3761f8a13981a743417f7d",
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
