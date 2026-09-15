#!/usr/bin/env python3
"""Verify external QUIC handshake fault recovery with exact peer evidence."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def require_once(path: Path, expected: str) -> None:
    count = path.read_text(encoding="utf-8").count(expected)
    if count != 1:
        raise ValueError(f"{path}: expected one {expected!r}, found {count}")


def proxy_record(path: Path) -> dict[str, str]:
    prefix = "udp fault proxy passed: "
    matches = [
        line[len(prefix) :]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]
    if len(matches) != 1:
        raise ValueError(f"{path}: expected one proxy result, found {len(matches)}")
    fields: dict[str, str] = {}
    for token in matches[0].split():
        if token.count("=") != 1:
            raise ValueError(f"{path}: malformed token {token!r}")
        key, value = token.split("=", 1)
        if not re.fullmatch(r"[a-z_]+", key) or not value or key in fields:
            raise ValueError(f"{path}: malformed or duplicate field {token!r}")
        fields[key] = value
    return fields


def verify(
    *,
    role_pair: str,
    direction: str,
    fault: str,
    version: int,
    client_log: Path,
    server_log: Path,
    proxy_log: Path,
) -> None:
    implementations = {
        "netz-client+quic-go-server": ("netz", "quic-go"),
        "quic-go-client+netz-server": ("quic-go", "netz"),
    }.get(role_pair)
    if implementations is None or direction not in ("client", "server"):
        raise ValueError("invalid role pair or direction")
    if fault not in ("loss", "corrupt") or version not in (1, 2):
        raise ValueError("invalid handshake fault")

    client_impl, server_impl = implementations
    scope_impl = client_impl if direction == "client" else server_impl
    scope = f"{scope_impl}-{direction}-handshake-outbound"
    if role_pair == "netz-client+quic-go-server":
        require_once(
            client_log,
            "netz QUIC interop runtime: endpoint_role=client "
            "client_io=zio-std-io server_io=quic-go-netpoll",
        )
        require_once(
            client_log,
            "netz QUIC client interoperated with quic-go: verified=true "
            f"version={version} retry=false alpn=hq-interop streams=2 bytes=10 "
            "peer_close=57",
        )
        require_once(
            server_log,
            f"go_quic_echo_server: handshake_done=true version={version} retry=false "
            "key_updates=0 echo_streams=2 echo_bytes=10",
        )
    else:
        require_once(
            server_log,
            "netz QUIC interop runtime: endpoint_role=server "
            "client_io=quic-go-netpoll server_io=zio-std-io",
        )
        require_once(
            client_log,
            "go_quic_peer_close_client: handshake_done=true peer_close=58 "
            'reason="netz interop complete" echo_streams=2 echo_bytes=10',
        )
        if version == 1:
            require_once(
                server_log,
                "netz QUIC close server interoperated with quic-go: "
                "alpn=hq-interop peer_close=58",
            )
        else:
            require_once(
                server_log,
                "netz QUIC v2 close server interoperated with quic-go: "
                "version=2 alpn=hq-interop peer_close=58",
            )

    proxy = proxy_record(proxy_log)
    expected = {
        "fault": fault,
        "fault_direction": direction,
        "fault_scope": scope,
        "considered": "1",
        "dropped": "1" if fault == "loss" else "0",
        "held": "0",
        "reordered": "0",
    }
    if fault == "corrupt":
        expected["corrupted"] = "1"
    if proxy != expected:
        raise ValueError(f"proxy result mismatch: {proxy!r}, expected {expected!r}")

    active = "dropped" if fault == "loss" else "corrupted"
    print(
        "verified QUIC handshake fault recovery: "
        f"role_pair={role_pair} direction={direction} fault={fault} "
        f"fault_scope={scope} {active}=1 certificate=true alpn=hq-interop "
        f"version={version} streams=2 bytes=10 client_io="
        f"{'zio-std-io' if client_impl == 'netz' else 'quic-go-netpoll'} "
        f"server_io={'zio-std-io' if server_impl == 'netz' else 'quic-go-netpoll'} "
        "peer_close=true complete=true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--direction", choices=("client", "server"), required=True)
    parser.add_argument("--fault", choices=("loss", "corrupt"), required=True)
    parser.add_argument("--version", choices=(1, 2), type=int, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    parser.add_argument("--proxy-log", type=Path, required=True)
    args = parser.parse_args()
    verify(
        role_pair=args.role_pair,
        direction=args.direction,
        fault=args.fault,
        version=args.version,
        client_log=args.client_log,
        server_log=args.server_log,
        proxy_log=args.proxy_log,
    )


if __name__ == "__main__":
    main()
