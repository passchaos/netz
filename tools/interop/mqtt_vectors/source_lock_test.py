#!/usr/bin/env python3
"""Unit tests for fail-closed Mosquitto vector source identities."""

from pathlib import Path
import tempfile
import unittest

import disconnect_forms
import maximum_topic_hierarchy
import pattern_matching
import persistent_incoming_qos2
import persistent_subscriptions
import proxy_v1_bad
import proxy_v2_bad
import qos0_live_queue_scope
import qos2_receive_maximum
import source_lock
import subscription_flip_flop
import subscription_hierarchy
import subscription_identifiers
import will_delay_invalid_topic
import will_delay_recovery


class SourceLockTests(unittest.TestCase):
    def test_maximum_hierarchy_packet_uses_multibyte_remaining_length(self) -> None:
        topic = "/" * maximum_topic_hierarchy.MAXIMUM_TOPIC_BYTES
        packet_v4 = maximum_topic_hierarchy.unsubscribe_packet(56, topic, 4)
        packet_v5 = maximum_topic_hierarchy.unsubscribe_packet(56, topic, 5)
        self.assertEqual(packet_v4[:4], bytes.fromhex("a2 83 80 04"))
        self.assertEqual(packet_v5[:4], bytes.fromhex("a2 84 80 04"))
        self.assertEqual(len(packet_v4), 65_543)
        self.assertEqual(len(packet_v5), 65_544)

    def test_accepts_exact_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.py"
            path.write_bytes(b"locked source\n")
            source_lock.verify_source_hash(
                path,
                "8454df03c6142b8211ad66c10bf448fc022ba86eb99962f5bc14f65cb26725d8",
            )

    def test_rejects_changed_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.py"
            path.write_bytes(b"changed source\n")
            with self.assertRaisesRegex(RuntimeError, "unexpected SHA-256"):
                source_lock.verify_source_hash(path, "0" * 64)

    def test_manifest_has_exact_sources_and_scenario_counts(self) -> None:
        self.assertEqual(
            source_lock.MOSQUITTO_SOURCE_SHA256,
            {
                "broker/01-bad-initial-packets.py":
                    "e64f4db3735c90c22dc9995ff52838ab9136b82b5da2739e529999e12f56813a",
                "broker/01-connect-accept-protocol.py":
                    "6fa62519cbb04bcad3e79244773d0354dfbab206b4b18f4234a96faf2ef3db11",
                "broker/01-connect-auto-id.py":
                    "a3d7ae2aa2508e5e3f5086a5105536d992b4ae330988e3411797e8135625b28f",
                "broker/01-connect-disconnect-v5.py":
                    "79d9bd1015b35a8d8f54b9e3c2d76c1a9bc5a19aa22d1839c2d0d0bc8de0bb96",
                "broker/01-connect-zero-length-id.py":
                    "3e69a4a94622dbe6e3814d5a2457605a5f8b6b9a6affe8505be81bf64c8338cd",
                "broker/01-connect-global-max-clients.py":
                    "17988c421847b7ded574192c8f7f30e5d5b01b4ee86eb5052eca5997e73852db",
                "broker/01-connect-global-max-connections.py":
                    "c24875b36288f418f484107415da902d96708cd58e24de1fdf5dedabff15daff",
                "broker/01-connect-max-connections.py":
                    "e45bdbc27c2966c22ae1add1d98da4256ca5f55cfa8c4601f2a2bcd28569e01a",
                "broker/01-connect-max-keepalive.py":
                    "73b606c619fcf4aa02c68cbebd4f50d941f22d7e523662b1ba9a3dc717e96640",
                "broker/01-connect-take-over.py":
                    "855c3c37229955b0eb2ef28d916032aceed5f3ca6d20d36fe6e95447b115f174",
                "broker/01-connect-uname-no-password-denied.py":
                    "54ee22a53e5ebffb6245be9f76dfee4f7edb36d7cb0c3b934650de094aa22061",
                "broker/01-connect-uname-password-denied.py":
                    "35515d3abfb1eb1092552240bb57d972dc9059c6e7911c1929759bf737b32564",
                "broker/12-prop-assigned-client-identifier.py":
                    "8c65d0fd5cc74901f2ebe37c7ee9433db7225219c2908276335c358ac587e5fc",
                "broker/13-websocket-bad-origin.py":
                    "edf2d87205dc2c67ccf147447039d9bc2ca0d4042e13b0ab1e226d77c6ef532d",
                "broker/02-subpub-b2c-topic-alias.py":
                    "bd0035dfa6b66a9942749c004db129232275ebc12bbd2a8eda6e21152768a890",
                "broker/02-shared-qos0-v5.py":
                    "5f7b90d9190866a2879afc92d35398914f0cad07604b0b41fb040d9980c12497",
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
                "broker/02-subpub-qos0-send-retain.py":
                    "9127a9d4c098dd0be08c1c03d5fb1631b36824fe9ae9b0b408962f3c5dfb2d60",
                "broker/02-subpub-qos0-oversize-payload.py":
                    "42ba19c5c3c967184b3928252aacf020a4f637445f35e499525a1fd8c1ca58f7",
                "broker/02-subpub-qos1-oversize-payload.py":
                    "2a2037c45f0e291042b80676f302ee9df2ce98e8b014cd3bb3d836464b8065fe",
                "broker/02-subpub-qos1-message-expiry.py":
                    "218321f18e45ca6626ace1b621f306bdc83acaac6b050edbdf0cab796b2fd481",
                "broker/02-subpub-qos1-message-expiry-retain.py":
                    "c59d115aa49b71c31d782845b08711a2a67358e710ad7fdd7274d2b460a42b87",
                "broker/02-subpub-qos1-message-expiry-will.py":
                    "eb7ce8d6b0a089c2a43e48b6b0b5b3748e46bd09e4c74aa6ab7e59def06965e8",
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
                "broker/03-publish-qos1-max-inflight-expire.py":
                    "58c05d026d86335fb322dc5dcec9dcc8c41e2bf415b6cf02eccf1765a7c83a7e",
                "broker/03-publish-qos1-no-subscribers-v5.py":
                    "84dbe495e20c3142629d245daf43f8cf04f507fcf688792f790d43e3551afa5e",
                "broker/03-publish-qos1-retain-disabled.py":
                    "c297198c3f2dc27b3c7727a8ea3377a6ca741946e87e2e2d58009245db11fe4d",
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
                "broker/03-publish-b2c-disconnect-qos2.py":
                    "4762f349ba73e77a20473a7930e39d9fcad80d316c4643d4793c46ded9020c3e",
                "broker/03-publish-b2c-qos1-len.py":
                    "1aa543556b11e7aaf4a88f804b091509c781df2e7475b39042f56e1aaa283982",
                "broker/03-publish-b2c-qos2-len.py":
                    "f098da5ac03dcd857c6aec9427cd8978d0e99d910d0111baefa25bb315fadc2f",
                "broker/03-publish-c2b-disconnect-qos2.py":
                    "b4842048512fd9719abfec32074a6d055ca88c1979c2f0588e281c8e9c40e2e7",
                "broker/03-publish-bad-flags.py":
                    "0718770fe09c7df65a9553e6b4697b7a28050cb65ac7470f2494a57d157ce7d3",
                "broker/03-publish-long-topic.py":
                    "f09b04182bc587a819e007f462000b1c781f8af7d464ed058e8b51439ccb353e",
                "broker/05-clean-session-qos1.py":
                    "73b7109f7b4cc55e6734192f5d81c013bf13f4fca530bfd5f0844bd143623137",
                "broker/05-session-expiry-v5.py":
                    "c545a17f9740ffdec8a0c432af336bd22dca6f80b61ca4881164ed3aacd5ed68",
                "broker/05-session-expiry-kick.py":
                    "6177aec3d006b2c7d45a140860ffc36ffed1ad08ab2e0a4e064317038794604f",
                "broker/04-retain-check-source-persist.py":
                    "9accde1f896d26b7c798ce3c5ca0a75b28bdad89f3e5e557b5cff0957ba0579c",
                "broker/04-retain-check-source-persist-diff-port.py":
                    "e10ea590dcb8ca5ae07cfe4ac0df788fda254680220738fea59f0d9abbfcc094",
                "broker/04-retain-check-source.py":
                    "6752e84581f172cd59463fdde950f4b928025d8bda050169edd65fd3b45f5ab0",
                "broker/04-retain-clear-multiple.py":
                    "ad410dbbeedca9d9f8c3a0cb96f3c4d5d826edb1cf9709ba3b9146f4b191092c",
                "broker/04-retain-qos0-repeated.py":
                    "c2cb35ae716acd68b7622b557c2612af6467d3133728ecde5fc254084595c6ed",
                "broker/04-retain-upgrade-outgoing-qos.py":
                    "c0afa378487f9d0b90ae82986ad5b51f9e15bf2817a678a4ca11d81d185084a0",
                "broker/07-will-delay-invalid-573191.py":
                    "f0f02675b050e023c5331696142f0d8bf0e3360f39011bd0dc7efdce3a382285",
                "broker/07-will-delay.py":
                    "9a3db7d13e23a21d4ef17bce8e8145e3c4ff9d2e4a0fa7ec91b2cd3c85847c53",
                "broker/07-will-delay-reconnect.py":
                    "b6f3b892fb51ebb65748ece41c6773f38fb496b92f7a6008a05a1133817c7224",
                "broker/07-will-delay-recover.py":
                    "94060369730e84a37b39f3414e8d976a96939fa0f31e7e8301ce173ffdefe1dc",
                "broker/07-will-disconnect-with-will.py":
                    "4e74bd9dd6a79cec01b197cb09535062f7138af30aa94da9b99bf66297b9a8cb",
                "broker/07-will-no-flag.py":
                    "ca5bcc14a21e944e137db45745772db39fadbb7d4eb05caf03ce76a8c1735733",
                "broker/07-will-null.py":
                    "0287cee88b54613fdc7e37692064545ceb5c8ad65d34437bbe53167741fc4c24",
                "broker/07-will-null-topic.py":
                    "9b82e6126dbbc86ca981c7efd584d18844b242bd2c9e5e44876d4c5cdb9a5ae9",
                "broker/07-will-oversize-payload.py":
                    "20de02ef6d3b1c451af58e38514518e1e1df81288958ce2d2a8470840d9999be",
                "broker/07-will-properties.py":
                    "78e27c3406d1af3517a3a09190a2e3b95ff1c91ec503ce798e2e4184eb8db0f3",
                "broker/07-will-takeover.py":
                    "294a4441eef80b1a4fe9599870fd5e7bb1b0f77e0e56a3c64a15b7806bf2c604",
                "broker/09-acl-change.py":
                    "548ab0d7ba510dac77b47b2e1b606fcd6d1513cb953149b76e3e97cc643d3ebb",
                "broker/09-plugin-auth-acl-pub-prop.py":
                    "885df1d4f1556efd585b701c95279ea6c3e36a189498b2a58a41a98d5aba0cec",
                "broker/09-plugin-auth-acl-sub-denied.py":
                    "93c2af138cfb7be3b25f98d97658b60df07d6c43b3eebd04ff651e1c4e1fe1d7",
                "broker/11-persistent-subscription-no-local.py":
                    "2a77a9da197041f80129bdba981ac6a4577503b57436ea60153f78010d52b4d6",
                "broker/11-pub-props.py":
                    "b45ab64f7ebbc978b0b4b939cd1f9ac7babeca7098d3c5a0a5ad5c41464dd724",
                "broker/11-message-expiry.py":
                    "c52a9210a12b58c6a51c295c2239e38d82689a7f7ef28c83f449a1f38d00e5dc",
                "broker/11-subscription-id.py":
                    "bc736a56c9d4e53e346e17d21d17e1dcc477b1693c34fdc6c0dac50854d448aa",
                "broker/12-prop-response-topic.py":
                    "b6d7dd59618ae2134033bd419f95d5aff08b5d14540b2e63ffafa6ddadfcb9c1",
                "broker/12-prop-response-topic-correlation-data.py":
                    "9f5cd36f81a1dc861e9d8cf96a03778971cb91a6860b628db65d3c7a132a257c",
                "broker/12-prop-server-keepalive.py":
                    "55575b50c79634efa1789d0b998bd52ffd19054217c60ec35865261c9d97b561",
                "broker/12-prop-maximum-packet-size-broker.py":
                    "49255859d6f2562f63d73fe18faa15023f5e28bf5d4066270c427dee41919ed5",
                "broker/12-prop-maximum-packet-size-publish-qos1.py":
                    "871e0a39d1d270e30eb0c762ff0613d04e31a54d44882474bc7b7c37db19a587",
                "broker/12-prop-maximum-packet-size-publish-qos2.py":
                    "5eadd09d3415f0150df793b96d4201995452defa263a5c662a133f2e0a8d0787",
                "broker/15-persist-client-msg-in-v3-1-1.py":
                    "87221b66d976bb842569f258ecb7d50e5edc3eab7eeb448b9eec3d4296df03a5",
                "broker/15-persist-client-msg-in-v5-0.py":
                    "54c3878816bfa0b5a8e25138c72ed2a95384052db640bd5226f4f8a1f9e1617b",
                "broker/15-persist-client-msg-modify-acl.py":
                    "c865bd2e87ed6f17f28c89d07006cd628e7ef3c3fa8669d75ee1ed1db425fc30",
                "broker/15-persist-client-msg-out-clear-v3-1-1.py":
                    "2ffad66eeda21078788179587c8dbc7539415126d94c12044c03a57cb7b43ef9",
                "broker/15-persist-client-msg-out-v5-0.py":
                    "2612901cb197a0c602ae6dc34b46d80a742f6b35cdc3757a81ddf10d77093b97",
                "broker/15-persist-publish-properties-v5-0.py":
                    "3ed5230d2bf1284ced12f0afa4e162ebd170cf6185389e161b4b972f9eefe4e0",
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
                "broker/21-proxy-v1-bad.py":
                    "5d89fb0350ad2c09470ce758fa1be0b92d74353f4ffe265011897e78fdeb4701",
                "broker/21-proxy-v2-ipv4.py":
                    "daf117e685ac994b45cce89c0c43269f3a799d2b0dd3ea2f358fb1fe2faab0c8",
                "broker/21-proxy-v2-ipv6.py":
                    "c918b204464775d1e6430b6b31f13e1a4488b40da6a2c6edd6f8e3fc5bec0d22",
                "broker/21-proxy-v2-bad-header.py":
                    "1450a24c04e3f88897d7e42ae63d8809fdb4bc642ca7844175602a1fa2706486",
                "broker/21-proxy-v2-long-tlv.py":
                    "40c392a92269836d6218e9a4694424b7f46c777cdcdeffb10437a3dcc62a28e2",
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
            },
        )
        self.assertEqual(disconnect_forms.SCENARIO_COUNT, 4)
        self.assertEqual(persistent_incoming_qos2.SCENARIO_COUNT, 2)
        self.assertEqual(proxy_v1_bad.SCENARIO_COUNT, 22)
        self.assertEqual(proxy_v2_bad.SCENARIO_COUNT, 12)
        self.assertEqual(persistent_subscriptions.SCENARIO_COUNT, 2)
        self.assertEqual(maximum_topic_hierarchy.MAXIMUM_TOPIC_BYTES, 65_535)
        self.assertEqual(maximum_topic_hierarchy.PROTOCOL_VERSIONS, (4, 5))
        self.assertEqual(maximum_topic_hierarchy.SCENARIO_COUNT, 4)
        self.assertEqual(subscription_flip_flop.SCENARIO_COUNT, 2)
        self.assertEqual(subscription_hierarchy.SCENARIO_COUNT, 2)
        self.assertEqual(subscription_identifiers.SCENARIO_COUNT, 1)
        self.assertEqual(pattern_matching.SCENARIO_COUNT, 46)
        self.assertEqual(qos0_live_queue_scope.SCENARIO_COUNT, 2)
        self.assertLess(
            qos0_live_queue_scope.QUEUED_PAYLOAD_BYTE_LIMIT,
            len(qos0_live_queue_scope.PAYLOAD.encode()),
        )
        self.assertEqual(qos2_receive_maximum.RECEIVE_MAXIMUMS, (1, 2))
        self.assertEqual(qos2_receive_maximum.MESSAGE_COUNT, 3)
        self.assertEqual(qos2_receive_maximum.SCENARIO_COUNT, 2)
        self.assertEqual(will_delay_invalid_topic.WILL_DELAY_SECONDS, 3)
        self.assertEqual(will_delay_invalid_topic.SCENARIO_COUNT, 1)
        self.assertEqual(
            will_delay_recovery.CLEAN_START_VALUES, (True, False)
        )
        self.assertEqual(will_delay_recovery.SCENARIO_COUNT, 2)

    def test_subscription_identifier_transitions_match_upstream(self) -> None:
        self.assertEqual(
            subscription_identifiers.INITIAL_SUBSCRIPTIONS,
            (
                (1, "02/subpub/subid/id1", 1),
                (2, "02/subpub/subid/+/id2", 14),
                (3, "02/subpub/subid/noid", None),
            ),
        )
        self.assertEqual(
            subscription_identifiers.INITIAL_PUBLISHES,
            (
                ("02/subpub/subid/noid", "message3", None),
                ("02/subpub/subid/test/id2", "message2", 14),
                ("02/subpub/subid/id1", "message1", 1),
            ),
        )
        self.assertEqual(
            subscription_identifiers.UPDATED_SUBSCRIPTIONS,
            (
                (4, "02/subpub/subid/id1", None),
                (5, "02/subpub/subid/+/id2", 19),
                (6, "02/subpub/subid/noid", 21),
            ),
        )
        self.assertEqual(
            subscription_identifiers.UPDATED_PUBLISHES,
            (
                ("02/subpub/subid/test/id2", "message2", 19),
                ("02/subpub/subid/noid", "message3", 21),
                ("02/subpub/subid/id1", "message1", None),
            ),
        )

    def test_pattern_matrix_matches_upstream_source(self) -> None:
        self.assertEqual(
            pattern_matching.PATTERN_CASES,
            (
                ("#", "test/topic"),
                ("#", "/test/topic"),
                ("foo/#", "foo/bar/baz"),
                ("foo/+/baz", "foo/bar/baz"),
                ("foo/+/baz/#", "foo/bar/baz"),
                ("foo/+/baz/#", "foo/bar/baz/bar"),
                ("foo/foo/baz/#", "foo/foo/baz/bar"),
                ("foo/#", "foo"),
                ("foo/#", "foo/"),
                ("/#", "/foo"),
                ("test/topic/", "test/topic/"),
                ("test/topic/+", "test/topic/"),
                (
                    "+/+/+/+/+/+/+/+/+/+/test",
                    "one/two/three/four/five/six/seven/eight/nine/ten/test",
                ),
                ("#", "test////a//topic"),
                ("#", "/test////a//topic"),
                ("foo/#", "foo//bar///baz"),
                ("foo/+/baz", "foo//baz"),
                ("foo/+/baz//", "foo//baz//"),
                ("foo/+/baz/#", "foo//baz"),
                ("foo/+/baz/#", "foo//baz/bar"),
                ("foo//baz/#", "foo//baz/bar"),
                ("foo/foo/baz/#", "foo/foo/baz/bar"),
                ("/#", "////foo///bar"),
            ),
        )


if __name__ == "__main__":
    unittest.main()
