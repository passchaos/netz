import unittest

from mqtt_shared_properties_ab import records, summarize


def fixture():
    return "\n".join(
        "record=result benchmark=mqtt-shared-properties io=zio-std-io "
        f"metadata={metadata} shared={shared} sample={sample} "
        "sessions=64 messages=256 deliveries=16384 elapsed_ns=1000 "
        "allocations=10 live_bytes=100 logical_bytes=200 "
        f"checksum={12730368 if metadata == 'true' else 1605632} "
        "teardown_live_bytes=0 complete=true"
        for metadata in ("false", "true")
        for shared in ("false", "true")
        for sample in range(7)
    )


class SharedPropertyBenchmarkTests(unittest.TestCase):
    def test_accepts_exact_sample_matrix_and_accounting(self):
        rows = records(fixture())
        self.assertEqual(len(rows), 28)
        summary = summarize(rows)
        self.assertEqual(len(summary), 4)
        self.assertTrue(all(value["logical_bytes"] == 200 for value in summary.values()))

    def test_rejects_missing_duplicate_and_invalid_records(self):
        valid = fixture()
        for invalid in (
            "\n".join(valid.splitlines()[1:]),
            valid + "\n" + valid.splitlines()[0],
            valid.replace("complete=true", "complete=false", 1),
            valid.replace("teardown_live_bytes=0", "teardown_live_bytes=1", 1),
            valid.replace("checksum=1605632", "checksum=1", 1),
            valid.replace("sessions=64", "sessions=32", 1),
            valid.replace("elapsed_ns=1000", "elapsed_ns=0", 1),
            valid + "\nunverified output",
        ):
            with self.subTest(invalid=invalid[:120]), self.assertRaises(ValueError):
                records(invalid)

    def test_rejects_accounting_drift_between_internal_samples(self):
        rows = records(fixture().replace("live_bytes=100", "live_bytes=101", 1))
        with self.assertRaisesRegex(ValueError, "unstable benchmark accounting"):
            summarize(rows)


if __name__ == "__main__":
    unittest.main()
