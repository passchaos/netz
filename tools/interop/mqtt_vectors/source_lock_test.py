#!/usr/bin/env python3
"""Unit tests for fail-closed Mosquitto vector source identities."""

from pathlib import Path
import tempfile
import unittest

import pattern_matching
import persistent_subscriptions
import qos0_live_queue_scope
import qos2_receive_maximum
import source_lock
import subscription_flip_flop
import subscription_hierarchy
import subscription_identifiers
import will_delay_invalid_topic
import will_delay_recovery


class SourceLockTests(unittest.TestCase):
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
                "broker/15-persist-retain-clear.py":
                    "e5797091eab0e807f74223f25dc4759371614bf69ae60779fe8d999090488ef9",
                "broker/15-persist-client-will-persistent.py":
                    "95b2079245e724956128e1a62d6fa46b9972ddc9166b97d51ae3d3a131d1ed6d",
                "broker/persist_client_will_core.py":
                    "0085074a986f587ac681dd73e318950a144fa2dadde22bb44c6e68aa97cc36a1",
                "broker/persist_module_helper.py":
                    "ca7a38158e005603f4c5ec4583ddd6e45fe643cfbf3761f8a13981a743417f7d",
            },
        )
        self.assertEqual(persistent_subscriptions.SCENARIO_COUNT, 2)
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
