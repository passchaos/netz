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
    "broker/01-connect-accept-protocol.py":
        "6fa62519cbb04bcad3e79244773d0354dfbab206b4b18f4234a96faf2ef3db11",
    "broker/01-connect-zero-length-id.py":
        "3e69a4a94622dbe6e3814d5a2457605a5f8b6b9a6affe8505be81bf64c8338cd",
    "broker/01-connect-global-max-clients.py":
        "17988c421847b7ded574192c8f7f30e5d5b01b4ee86eb5052eca5997e73852db",
    "broker/01-connect-global-max-connections.py":
        "c24875b36288f418f484107415da902d96708cd58e24de1fdf5dedabff15daff",
    "broker/01-connect-max-connections.py":
        "e45bdbc27c2966c22ae1add1d98da4256ca5f55cfa8c4601f2a2bcd28569e01a",
    "broker/12-prop-assigned-client-identifier.py":
        "8c65d0fd5cc74901f2ebe37c7ee9433db7225219c2908276335c358ac587e5fc",
    "broker/13-websocket-bad-origin.py":
        "edf2d87205dc2c67ccf147447039d9bc2ca0d4042e13b0ab1e226d77c6ef532d",
    "broker/02-subpub-b2c-topic-alias.py":
        "bd0035dfa6b66a9942749c004db129232275ebc12bbd2a8eda6e21152768a890",
    "broker/02-subpub-qos0-topic-alias.py":
        "141ac402bfe2af0205307a4dbe64f6a6ce21a3be89a90fd8d3321188c2675df9",
    "broker/02-subpub-qos0-long-topic.py":
        "3bf17e3a777982979e060f20e919a9f0e3a0bce0b7f2dbe3a9adf8100fee7773",
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
    "broker/02-subscribe-long-topic.py":
        "d94ceeaaec1733b19f8dd3270dc57f4945455b7c3f23fc518c580c48b20a5c8c",
    "broker/03-pattern-matching.py":
        "042fa7fa8728632551bdecb632aa5f41b539a69780bc4d4bdf25582e2ff8fd32",
    "broker/03-publish-qos1-max-inflight.py":
        "4863181b3799b1dd8c7d469d30e9d838ec0f3cf444cab142ec7d7bb4dd373bdc",
    "broker/03-publish-qos1-queued-bytes.conf":
        "81264cf8b5af7d7248c2e968ff373e20d07d6b414c4770cca275a38c02beea6a",
    "broker/03-publish-qos1-queued-bytes.py":
        "d320a78b93a39c8ea02e2b5c57e13b2c4d558e39fb4f0be8ce52e70b6dc9980d",
    "broker/03-publish-qos2-max-inflight-exceeded.py":
        "5bd529a2ca44c64967bf4276e70b6bf9262c38f0bb0860b375829593a31a73ca",
    "broker/03-publish-qos2-max-inflight.py":
        "37d431fc2c663fd3d35b083c829a3b73125322a356f2122e17ad851c94705256",
    "broker/03-publish-b2c-disconnect-qos1.py":
        "ff2c13c469c6ba35060a752c3cfb21b43556312c1fa4f1aca71e069697289b44",
    "broker/03-publish-c2b-disconnect-qos2.py":
        "b4842048512fd9719abfec32074a6d055ca88c1979c2f0588e281c8e9c40e2e7",
    "broker/03-publish-long-topic.py":
        "f09b04182bc587a819e007f462000b1c781f8af7d464ed058e8b51439ccb353e",
    "broker/04-retain-check-source-persist.py":
        "9accde1f896d26b7c798ce3c5ca0a75b28bdad89f3e5e557b5cff0957ba0579c",
    "broker/07-will-delay-invalid-573191.py":
        "f0f02675b050e023c5331696142f0d8bf0e3360f39011bd0dc7efdce3a382285",
    "broker/07-will-delay-reconnect.py":
        "b6f3b892fb51ebb65748ece41c6773f38fb496b92f7a6008a05a1133817c7224",
    "broker/07-will-delay-recover.py":
        "94060369730e84a37b39f3414e8d976a96939fa0f31e7e8301ce173ffdefe1dc",
    "broker/11-message-expiry.py":
        "c52a9210a12b58c6a51c295c2239e38d82689a7f7ef28c83f449a1f38d00e5dc",
    "broker/11-subscription-id.py":
        "bc736a56c9d4e53e346e17d21d17e1dcc477b1693c34fdc6c0dac50854d448aa",
    "broker/15-persist-client-msg-out-v5-0.py":
        "2612901cb197a0c602ae6dc34b46d80a742f6b35cdc3757a81ddf10d77093b97",
    "broker/15-persist-client-expired-session.py":
        "0aa829459c023b2c6f1e4974be242c727cd74b22ebf2b8a49f14d4e996a53796",
    "broker/15-persist-retain-clear.py":
        "e5797091eab0e807f74223f25dc4759371614bf69ae60779fe8d999090488ef9",
    "broker/15-persist-client-will-persistent.py":
        "95b2079245e724956128e1a62d6fa46b9972ddc9166b97d51ae3d3a131d1ed6d",
    "broker/16-config-parse-errors-without-tls.py":
        "e554db32fe8a7ee87dd54d6959913365202b4a32c893fbdeaa32ee2f7b273ae7",
    "broker/21-proxy-v1-success.py":
        "07c5c8f9b94dc49239190b680e1c3f858ed987734d5c879a88531590e1583d53",
    "broker/21-proxy-v2-websockets.py":
        "de1ea836095867cec17fe21afbbcd29c7b9d9f05bf734d995914227119764c3f",
    "broker/21-proxy-bad-version.py":
        "6a9410ad8e09f74466d794356623b0ba204f8d2f715d02251d57948bf074d711",
    "broker/21-proxy-v2-bad-config.py":
        "aa6042e987bbbd86f802152b2297b5e402d7abf6db1add69d22c6b9c67cdeb3b",
    "broker/21-proxy-v2-ssl-require-tls-success.py":
        "10f7f84d4b719c0c38ff2041884279b6197d4a8b581324668b6f7d1ca359c401",
    "broker/21-proxy-v2-ssl-require-tls-failure.py":
        "fbee4ea39be96f75248bb4ca8d88dc679bf49ce2be9601963ee8c5bfb4a5ce2f",
    "broker/21-proxy-v2-ssl-require-cert-success.py":
        "2d6438339085498af2ecd5127c9537e93461f0afd3030e99e64c04e6cef8aad5",
    "broker/21-proxy-v2-ssl-require-cert-failure.py":
        "d282170a458da501a6fe1169244c945dd78cbd01704b95feb8cd2eea38e82e31",
    "broker/21-proxy-v2-ssl-common-name-success.py":
        "63278ecce32d25aeede20f771aef62308343fbf01752301e57d6d099a9e69e39",
    "broker/21-proxy-v2-ssl-common-name-failure.py":
        "226effad299a6d7a6f9a4935730ab59be459320680b1dcb56b17525405aa8e52",
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
