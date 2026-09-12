from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import quic_handshake_fault_check as check


class QuicHandshakeFaultCheckTest(unittest.TestCase):
    def write_case(
        self, directory: str, *, role_pair: str, direction: str, fault: str,
        version: int = 1,
    ) -> tuple[Path, Path, Path]:
        root = Path(directory)
        client = root / "client.log"
        server = root / "server.log"
        proxy = root / "proxy.log"
        if role_pair == "netz-client+quic-go-server":
            client.write_text(
                "netz QUIC client interoperated with quic-go: verified=true "
                f"version={version} retry=false alpn=hq-interop streams=2 bytes=10 "
                "peer_close=57\n",
                encoding="utf-8",
            )
            server.write_text(
                f"prefix go_quic_echo_server: handshake_done=true version={version} "
                "retry=false key_updates=0 echo_streams=2 echo_bytes=10\n",
                encoding="utf-8",
            )
            scope_impl = "netz" if direction == "client" else "quic-go"
        else:
            client.write_text(
                'go_quic_peer_close_client: handshake_done=true peer_close=58 '
                'reason="netz interop complete" echo_streams=2 echo_bytes=10\n',
                encoding="utf-8",
            )
            server.write_text(
                ("netz QUIC close server interoperated with quic-go: "
                 "alpn=hq-interop peer_close=58\n")
                if version == 1 else
                ("netz QUIC v2 close server interoperated with quic-go: "
                 "version=2 alpn=hq-interop peer_close=58\n"),
                encoding="utf-8",
            )
            scope_impl = "quic-go" if direction == "client" else "netz"
        counters = (
            "considered=1 dropped=1 held=0 reordered=0"
            if fault == "loss"
            else "considered=1 dropped=0 held=0 reordered=0 corrupted=1"
        )
        proxy.write_text(
            f"udp fault proxy passed: fault={fault} fault_direction={direction} "
            f"fault_scope={scope_impl}-{direction}-handshake-outbound "
            f"{counters}\n",
            encoding="utf-8",
        )
        return client, server, proxy

    def verify_case(
        self, role_pair: str, direction: str, fault: str, version: int
    ) -> None:
        with TemporaryDirectory() as directory:
            client, server, proxy = self.write_case(
                directory, role_pair=role_pair, direction=direction, fault=fault,
                version=version,
            )
            check.verify(
                role_pair=role_pair, direction=direction, fault=fault, version=version,
                client_log=client, server_log=server, proxy_log=proxy,
            )

    def test_accepts_all_matrix_shapes(self) -> None:
        for role_pair in (
            "netz-client+quic-go-server",
            "quic-go-client+netz-server",
        ):
            for version in (1, 2):
                for direction in ("client", "server"):
                    for fault in ("loss", "corrupt"):
                        with self.subTest(
                            role_pair=role_pair, version=version,
                            direction=direction, fault=fault,
                        ):
                            self.verify_case(role_pair, direction, fault, version)

    def test_rejects_missing_peer_completion(self) -> None:
        with TemporaryDirectory() as directory:
            client, server, proxy = self.write_case(
                directory, role_pair="netz-client+quic-go-server",
                direction="client", fault="loss",
            )
            server.write_text("handshake incomplete\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                check.verify(
                    role_pair="netz-client+quic-go-server", direction="client",
                    fault="loss", version=1, client_log=client, server_log=server, proxy_log=proxy,
                )

    def test_rejects_extra_fault(self) -> None:
        with TemporaryDirectory() as directory:
            client, server, proxy = self.write_case(
                directory, role_pair="quic-go-client+netz-server",
                direction="server", fault="corrupt",
            )
            proxy.write_text(
                proxy.read_text(encoding="utf-8").replace(
                    "corrupted=1", "corrupted=2"
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                check.verify(
                    role_pair="quic-go-client+netz-server", direction="server",
                    fault="corrupt", version=1, client_log=client, server_log=server, proxy_log=proxy,
                )


if __name__ == "__main__":
    unittest.main()
