from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import websocket_slices_benchmark_check as check


class WebSocketSlicesBenchmarkCheckTest(unittest.TestCase):
    def record(self, shape: str, checksum: int = 1275) -> str:
        return (
            "record=result implementation=netz protocol=websocket-h2 "
            "transport=h2c mode=binary-echo role_pair=netz-self "
            "connection_scope=persistent "
            "benchmark_scope=caller-copy-vs-direct-slices connections=1 "
            f"warmup=1 iterations=5 payload_bytes=4096 payload_schedule=fixed "
            f"send_shape={shape} parts=8 compression=false elapsed_ns=100 "
            f"logical_bytes=40960 checksum={checksum} complete=true\n"
        )

    def test_accepts_matched_records(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            contiguous = root / "contiguous.log"
            slices = root / "slices.log"
            contiguous.write_text(self.record("contiguous"), encoding="utf-8")
            slices.write_text(self.record("slices"), encoding="utf-8")
            check.verify(
                "websocket-h2", 8, 1, 5, 4096, 1, contiguous, slices
            )

    def test_rejects_checksum_mismatch(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            contiguous = root / "contiguous.log"
            slices = root / "slices.log"
            contiguous.write_text(self.record("contiguous"), encoding="utf-8")
            slices.write_text(self.record("slices", 1274), encoding="utf-8")
            with self.assertRaises(ValueError):
                check.verify(
                    "websocket-h2", 8, 1, 5, 4096, 1, contiguous, slices
                )

    def test_rejects_wrong_shape(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            contiguous = root / "contiguous.log"
            slices = root / "slices.log"
            contiguous.write_text(self.record("slices"), encoding="utf-8")
            slices.write_text(self.record("slices"), encoding="utf-8")
            with self.assertRaises(ValueError):
                check.verify(
                    "websocket-h2", 8, 1, 5, 4096, 1, contiguous, slices
                )

    def test_rejects_missing_sample(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            contiguous = root / "contiguous.log"
            slices = root / "slices.log"
            contiguous.write_text(self.record("contiguous"), encoding="utf-8")
            slices.write_text(self.record("slices"), encoding="utf-8")
            with self.assertRaises(ValueError):
                check.verify(
                    "websocket-h2", 8, 1, 5, 4096, 3, contiguous, slices
                )

    def test_rejects_even_sample_count(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            contiguous = root / "contiguous.log"
            slices = root / "slices.log"
            contiguous.write_text(self.record("contiguous"), encoding="utf-8")
            slices.write_text(self.record("slices"), encoding="utf-8")
            with self.assertRaises(ValueError):
                check.verify(
                    "websocket-h2", 8, 1, 5, 4096, 2, contiguous, slices
                )


if __name__ == "__main__":
    unittest.main()
