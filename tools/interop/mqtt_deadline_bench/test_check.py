import unittest

from mqtt_deadline_bench.check import verify


RESULT = (
    "record=result schema=1 implementation=netz protocol=mqtt transport=tcp "
    "build_mode=ReleaseFast mqtt_version=5 qos=2 topic_alias=true "
    "client_api=reconnect-stage-flush-poll client_io=zio-std-io server_io=zio-std-io "
    "connections=1 window=1 validation=full-bytes+terminal deadline=single-awake-budget "
    "warmup=2 iterations=3 payload_bytes=512 logical_bytes=1536 elapsed_ns=6000 "
    "ns_per_delivery=2000 completed_deliveries=3 session_pending=0 stats_enabled=false"
)
PEER = (
    "record=peer-completion schema=1 implementation=netz protocol=mqtt mqtt_version=5 qos=2 topic_alias=true "
    "received_messages=5 terminal_acks=5 pubrels=5 payload_bytes=512 disconnected=true"
)


class DeliveryCompletionTest(unittest.TestCase):
    def test_complete_qos2_delivery(self):
        self.assertEqual(verify(RESULT + "\n" + PEER)["qos"], "2")

    def test_qos1_has_no_release_phase(self):
        text = (RESULT + "\n" + PEER).replace("qos=2", "qos=1").replace("pubrels=5", "pubrels=0")
        self.assertEqual(verify(text)["qos"], "1")

    def test_mqtt311_has_no_topic_alias(self):
        text = (RESULT + "\n" + PEER).replace("mqtt_version=5", "mqtt_version=4")
        with self.assertRaises(ValueError):
            verify(text)
        self.assertEqual(verify(text.replace("topic_alias=true", "topic_alias=false"))["mqtt_version"], "4")

    def test_rejects_missing_or_duplicate_completion(self):
        for text in (RESULT, RESULT + "\n" + PEER + "\n" + PEER):
            with self.subTest(text=text), self.assertRaises(ValueError):
                verify(text)

    def test_rejects_unconfirmed_or_inconsistent_work(self):
        for old, new in (
            ("terminal_acks=5", "terminal_acks=4"),
            ("pubrels=5", "pubrels=0"),
            ("session_pending=0", "session_pending=1"),
            ("disconnected=true", "disconnected=false"),
            ("logical_bytes=1536", "logical_bytes=1024"),
            ("ns_per_delivery=2000", "ns_per_delivery=2001"),
            ("completed_deliveries=3", "completed_deliveries=2"),
            ("iterations=3", "iterations=0"),
        ):
            with self.subTest(field=old), self.assertRaises(ValueError):
                verify((RESULT + "\n" + PEER).replace(old, new))

    def test_rejects_altered_profile_and_duplicate_fields(self):
        for old, new in (
            ("window=1", "window=8"),
            ("stats_enabled=false", "stats_enabled=true"),
            ("mqtt_version=5", "mqtt_version=3"),
            ("validation=full-bytes+terminal", "validation=checksum"),
            ("qos=2", "qos=0"),
            ("deadline=single-awake-budget", "deadline=none"),
            ("iterations=3", "iterations=3 iterations=3"),
        ):
            with self.subTest(field=old), self.assertRaises(ValueError):
                verify((RESULT + "\n" + PEER).replace(old, new))

    def test_debug_smoke_cannot_be_used_as_timing_evidence(self):
        text = (RESULT + "\n" + PEER).replace("build_mode=ReleaseFast", "build_mode=Debug")
        verify(text)
        with self.assertRaises(ValueError):
            verify(text, require_release_fast=True)


if __name__ == "__main__":
    unittest.main()
