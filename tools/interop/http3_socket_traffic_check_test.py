#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("http3_socket_traffic_check.py")
SPEC = importlib.util.spec_from_file_location("http3_socket_traffic_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class Http3SocketTrafficCheckTests(unittest.TestCase):
    def write_pair(self, directory: str, *, missing_server: bool = False):
        common = (
            "record=socket-traffic protocol=http3 mode=download "
            "role_pair=quic-go-client+netz-server sender_role=server "
            "client_io=quic-go-netpoll server_io=zio-std-io "
            "warmup=1 iterations=2 streams=4 body_bytes=1024 "
            "application_chunk_effective=512 stream_window=1048576 quic_version=2 "
            "traffic_scope=all-rounds socket_boundary=userspace-udp-payload "
            "benchmark_scope=socket-traffic-same-application-shape "
            "logical_udp_segments=true complete=true"
        )
        client = pathlib.Path(directory, "client.log")
        server = pathlib.Path(directory, "server.log")
        client.write_text(
            f"implementation=quic-go endpoint_role=client {common} "
            "udp_sent_datagrams=40 udp_sent_payload_bytes=800 "
            "udp_received_datagrams=90 udp_received_payload_bytes=10000\n",
            encoding="utf-8",
        )
        server.write_text(
            "" if missing_server else
            f"implementation=netz endpoint_role=server {common} "
            "udp_sent_datagrams=92 udp_sent_payload_bytes=10020 "
            "udp_received_datagrams=39 udp_received_payload_bytes=790\n",
            encoding="utf-8",
        )
        return client, server

    def verify_pair(self, client: pathlib.Path, server: pathlib.Path) -> None:
        CHECK.verify(
            role_pair="quic-go-client+netz-server",
            mode="download",
            warmup=1,
            iterations=2,
            streams=4,
            body_bytes=1024,
            chunk_bytes=512,
            stream_window=1048576,
            quic_version=2,
            client_log=client,
            server_log=server,
        )

    def test_complete_pair_is_accepted_and_summarized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.verify_pair(*self.write_pair(directory))
            self.assertIn("sender_implementation=netz", output.getvalue())
            self.assertIn("sender_mean_udp_payload_bytes=108.913", output.getvalue())

    def test_missing_endpoint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "expected one"):
                self.verify_pair(*self.write_pair(directory, missing_server=True))

    def test_impossible_peer_observation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client, server = self.write_pair(directory)
            server.write_text(
                server.read_text(encoding="utf-8").replace(
                    "udp_received_datagrams=39",
                    "udp_received_datagrams=41",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "observed more traffic"):
                self.verify_pair(client, server)


if __name__ == "__main__":
    unittest.main()
