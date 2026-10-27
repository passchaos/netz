#!/usr/bin/env python3
import unittest
import json
from pathlib import Path
import tempfile

from grpc_benchmark_check import verify
from grpc_benchmark import cpp_results, MODES, PAYLOADS


def log(mode: str = "persistent", payload: int = 1024) -> str:
    protobuf = 0 if payload == 0 else payload + 1 + (payload.bit_length() + 6) // 7
    return (
        "record=result implementation=netz protocol=grpc transport=h2c "
        f"mode={mode} client_api=shared client_io=zio-std-io server_io=zio-std-io "
        "connection_scope=persistent connections=1 validation=full-bytes "
        "protobuf_scope=preencoded allocation_scope=client+server+protocol stats_enabled=true "
        f"warmup=1 iterations=2 payload_bytes={payload} protobuf_bytes={protobuf} "
        f"logical_bytes={payload * 4} elapsed_ns=100 ns_per_roundtrip=50 "
        "roundtrips_per_second=20000000 p50_ns=40 p95_ns=60 p99_ns=60 "
        "alloc_count=10 allocated_bytes=100 freed_bytes=90 live_bytes=10\n"
        f"record=peer-completion implementation=netz protocol=grpc mode={mode} "
        f"request_messages=3 response_messages=3 terminal_calls={1 if mode == 'persistent' else 3} "
        f"protobuf_bytes={protobuf}\n"
    )


class VerificationTests(unittest.TestCase):
    def test_complete_modes_and_varint_boundaries(self) -> None:
        for mode in ("persistent", "calls"):
            for payload in (0, 1, 127, 128, 1024, 16383, 16384, 131101):
                with self.subTest(mode=mode, payload=payload):
                    self.assertEqual(verify(log(mode, payload))["mode"], mode)

    def test_rejects_missing_completion(self) -> None:
        with self.assertRaisesRegex(ValueError, "one peer completion"):
            verify(log().splitlines()[0])

    def test_rejects_duplicate_run(self) -> None:
        with self.assertRaisesRegex(ValueError, "one result"):
            verify(log() + log())

    def test_rejects_corrupt_evidence(self) -> None:
        changes = (
            ("response_messages=3", "response_messages=2", "response_messages"),
            ("request_messages=3", "request_messages=4", "request_messages"),
            ("terminal_calls=1", "terminal_calls=3", "terminal_calls"),
            ("logical_bytes=4096", "logical_bytes=4095", "logical_bytes"),
            ("protobuf_bytes=1027", "protobuf_bytes=1026", "protobuf_bytes"),
            ("ns_per_roundtrip=50", "ns_per_roundtrip=51", "ns_per_roundtrip"),
            ("roundtrips_per_second=20000000", "roundtrips_per_second=1", "roundtrips_per_second"),
            ("p50_ns=40", "p50_ns=61", "quantiles"),
            ("elapsed_ns=100", "elapsed_ns=0", "elapsed_ns"),
            ("stats_enabled=true", "stats_enabled=false", "telemetry"),
            ("client_io=zio-std-io", "client_io=threaded", "client_io"),
            ("payload_bytes=1024", "payload_bytes=-1", "payload_bytes"),
            ("iterations=2", "iterations=0", "iterations"),
        )
        for before, after, diagnostic in changes:
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaisesRegex(ValueError, diagnostic):
                    verify(log().replace(before, after))

    def test_rejects_duplicate_field(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify(log().replace("elapsed_ns=100", "elapsed_ns=100 elapsed_ns=100"))


class ReferenceTests(unittest.TestCase):
    def check(self, change=None):
        entries = []
        for mode in MODES:
            for payload in PAYLOADS:
                name = f"BM_StreamingPingPong{'Msgs' if mode == 'persistent' else ''}<TCP, NoOpMutator, NoOpMutator>/{payload}" + ("/1" if mode == "calls" else "")
                entries.append({"name": name, "iterations": 100, "real_time": 2, "cpu_time": 1, "time_unit": "us"})
        if change is not None:
            change(entries)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reference.json"
            path.write_text(json.dumps({"benchmarks": entries}))
            return cpp_results(path)

    def test_wall_time_and_units(self) -> None:
        self.assertEqual(set(self.check().values()), {2000})

    def test_rejects_incomplete_reference(self) -> None:
        for change in (
            lambda rows: rows.pop(),
            lambda rows: rows.append(rows[0]),
            lambda rows: rows[0].update(error_occurred=True),
            lambda rows: rows[0].update(iterations=0),
            lambda rows: rows[0].update(real_time=float("nan")),
        ):
            with self.assertRaises(ValueError):
                self.check(change)


def window_log(*, stream=65535, connection=65535, adaptive=False, maximum=1048576, final=None):
    final = stream if final is None else final
    tail = f" stream_window={stream} connection_window={connection} adaptive_window={str(adaptive).lower()} adaptive_window_max={maximum} final_client_stream_window={final} final_server_stream_window={final}"
    return "\n".join(line.replace("record=result ", "record=result schema=2 ").replace("record=peer-completion ", "record=peer-completion schema=2 ") + tail for line in log().splitlines())


class WindowTests(unittest.TestCase):
    def test_fixed_and_adaptive_windows(self) -> None:
        for value in (window_log(), window_log(stream=1), window_log(stream=1048576, connection=1048576), window_log(adaptive=True, final=1048576)):
            self.assertEqual(verify(value)["schema"], "2")

    def test_invalid_windows_and_growth(self) -> None:
        for value in (window_log(stream=0), window_log(connection=65534), window_log(stream=16777217), window_log(adaptive=True, maximum=65534), window_log(final=1048576), window_log(adaptive=True, final=1048577)):
            with self.assertRaises(ValueError):
                verify(value)

    def test_schema_and_peer_evidence(self) -> None:
        for value in (window_log().replace("schema=2", "schema=3"), window_log().replace("record=peer-completion schema=2", "record=peer-completion"), window_log().replace("schema=2", "schema=1"), window_log().replace("final_client_stream_window=65535", "final_client_stream_window=65534", 1)):
            with self.assertRaises(ValueError):
                verify(value)


if __name__ == "__main__":
    unittest.main()
