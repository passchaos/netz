#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).with_name("mqtt_broker_benchmark_config.py")
SPEC = importlib.util.spec_from_file_location(
    "mqtt_broker_benchmark_config", MODULE
)
assert SPEC is not None and SPEC.loader is not None
CONFIG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIG)


class MqttBrokerBenchmarkConfigTest(unittest.TestCase):
    def test_preserves_standard_capacity_for_short_runs(self) -> None:
        self.assertEqual(1_024, CONFIG.queue_capacity(10, 200))

    def test_capacity_covers_longer_measured_phase(self) -> None:
        self.assertEqual(5_000, CONFIG.queue_capacity(100, 5_000))

    def test_capacity_covers_longer_warmup_phase(self) -> None:
        self.assertEqual(5_000, CONFIG.queue_capacity(5_000, 100))

    def test_accepts_larger_explicit_capacity(self) -> None:
        self.assertEqual(6_000, CONFIG.queue_capacity(100, 5_000, 6_000))

    def test_rejects_capacity_that_permits_delivery_loss(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot preserve exact delivery"):
            CONFIG.queue_capacity(100, 5_000, 1_024)
        with self.assertRaisesRegex(ValueError, "required 1024-message bound"):
            CONFIG.queue_capacity(10, 200, 200)

    def test_rejects_invalid_phase_counts(self) -> None:
        with self.assertRaisesRegex(ValueError, "warmup must be non-negative"):
            CONFIG.queue_capacity(-1, 5_000)
        with self.assertRaisesRegex(ValueError, "messages positive"):
            CONFIG.queue_capacity(100, 0)

    def test_rejects_capacity_outside_mosquitto_range(self) -> None:
        with self.assertRaisesRegex(ValueError, "Mosquitto's queue limit"):
            CONFIG.queue_capacity(0, 1 << 31)
        with self.assertRaisesRegex(ValueError, "between 1 and 2147483647"):
            CONFIG.queue_capacity(0, 1, 1 << 31)


if __name__ == "__main__":
    unittest.main()
