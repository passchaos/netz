#!/usr/bin/env python3
"""Strict verifier for raw QUIC mixed FIN/RESET churn with quic-go."""

import argparse
import re
from pathlib import Path


def record(path: Path, prefix: str) -> dict[str, str]:
    matches = [line for line in path.read_text().splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError(f"{path}: expected one {prefix!r}, found {len(matches)}")
    fields: dict[str, str] = {}
    for token in matches[0][len(prefix) :].split():
        if token.count("=") != 1:
            raise ValueError(f"{path}: malformed token {token!r}")
        key, value = token.split("=", 1)
        if not re.fullmatch(r"[a-z_-]+", key) or not value or key in fields:
            raise ValueError(f"{path}: malformed or duplicate field {token!r}")
        fields[key] = value
    return fields


def expected(streams: int, size: int, prefix: int, every: int) -> dict[str, int]:
    result = {
        "streams": streams,
        "fin": 0,
        "reset": 0,
        "bytes": 0,
        "checksum": 0,
        "reset_mask": 0,
        "reset_code_sum": 0,
    }
    for stream in range(streams):
        reset = (stream + 1) % every == 0
        count = prefix if reset else size
        result["reset" if reset else "fin"] += 1
        result["bytes"] += count
        result["checksum"] = (
            result["checksum"]
            + sum((offset * 131 + stream * 17) & 0xFF for offset in range(count))
        ) & ((1 << 64) - 1)
        if reset:
            result["reset_mask"] |= 1 << stream
            result["reset_code_sum"] += 0x4000 + stream
    return result


def integer(value: str) -> int:
    return int(value, 16) if value.startswith("0x") else int(value)


def verify(
    *,
    role_pair: str,
    sender: str,
    fault: str,
    streams: int,
    bytes_per_stream: int,
    reset_after_bytes: int,
    reset_every: int,
    client_log: Path,
    server_log: Path,
    proxy_log: Path,
) -> None:
    implementations = {
        "netz-client+quic-go-server": ("netz", "quic-go"),
        "quic-go-client+netz-server": ("quic-go", "netz"),
    }.get(role_pair)
    if implementations is None or sender not in ("client", "server"):
        raise ValueError("invalid role pair or sender")
    if fault not in ("loss", "reorder") or streams not in (32, 64):
        raise ValueError("invalid fault or stream shape")
    if bytes_per_stream < 1 or not 0 < reset_after_bytes <= bytes_per_stream:
        raise ValueError("invalid byte shape")
    if reset_every < 1:
        raise ValueError("invalid reset cadence")
    client_impl, server_impl = implementations
    client_io = "zio-std-io" if client_impl == "netz" else "quic-go-netpoll"
    server_io = "zio-std-io" if server_impl == "netz" else "quic-go-netpoll"
    client = record(client_log, "raw QUIC churn client passed:")
    server = record(server_log, "raw QUIC churn server passed:")
    proxy = record(proxy_log, "udp fault proxy passed:")
    wanted = expected(streams, bytes_per_stream, reset_after_bytes, reset_every)
    scope = f"{client_impl}-client" if sender == "client" else f"{server_impl}-server"
    for label, values, implementation in (
        ("client", client, client_impl),
        ("server", server, server_impl),
    ):
        if values.get("implementation") != implementation:
            raise ValueError(f"{label}: implementation mismatch")
        for key, value in {
            "role_pair": role_pair,
            "sender": sender,
            "client_io": client_io,
            "server_io": server_io,
            "fault": fault,
            "fault_scope": f"{scope}-outbound",
            "sibling": "true",
        }.items():
            if values.get(key) != value:
                raise ValueError(f"{label}: {key} mismatch")
        for key, value in wanted.items():
            if integer(values.get(key, "-1")) != value:
                raise ValueError(f"{label}: {key} mismatch")
    if client.get("peer-close") != "true":
        raise ValueError("client did not observe peer close")
    receiver_impl = server_impl if sender == "client" else client_impl
    for values, implementation in ((client, client_impl), (server, server_impl)):
        direct = values.get("reset_final_size_verified")
        expected_direct = "true" if implementation == receiver_impl == "netz" else "false"
        if direct != expected_direct:
            raise ValueError("reset final-size evidence mismatch")
    if (
        proxy.get("fault") != fault
        or proxy.get("fault_direction") != sender
        or proxy.get("fault_scope") != f"{scope}-outbound"
    ):
        raise ValueError("proxy metadata mismatch")
    for key in ("considered", "dropped", "held", "reordered"):
        if proxy.get(key) != client.get(key):
            raise ValueError(f"proxy/client {key} mismatch")
    active = "dropped" if fault == "loss" else "reordered"
    inactive = "held" if fault == "loss" else "dropped"
    expected_considered = 2 if fault == "loss" else 4
    if integer(client.get("considered", "0")) != expected_considered:
        raise ValueError("unexpected considered datagram count")
    if integer(client.get(active, "0")) != 2 or integer(client.get(inactive, "-1")) != 0:
        raise ValueError("invalid active/inactive fault counters")
    if integer(client.get("reset_faults", "0")) != 1 or integer(client.get("fin_faults", "0")) != 1:
        raise ValueError("both phases must contain exactly one fault")
    if integer(client[active]) != integer(client["reset_faults"]) + integer(client["fin_faults"]):
        raise ValueError("phase fault counters do not sum to the total")
    if fault == "reorder" and client.get("held") != client.get("reordered"):
        raise ValueError("not every held datagram was reordered")
    print(
        "verified raw QUIC churn: "
        f"role_pair={role_pair} sender={sender} fault={fault} streams={streams} "
        f"client_io={client_io} server_io={server_io} "
        f"fin={wanted['fin']} reset={wanted['reset']} bytes={wanted['bytes']} "
        f"checksum={wanted['checksum']} reset_mask=0x{wanted['reset_mask']:016x} "
        f"reset_code_sum={wanted['reset_code_sum']} {active}={client[active]}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--sender", choices=("client", "server"), required=True)
    parser.add_argument("--fault", choices=("loss", "reorder"), required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--bytes-per-stream", type=int, required=True)
    parser.add_argument("--reset-after-bytes", type=int, required=True)
    parser.add_argument("--reset-every", type=int, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    parser.add_argument("--proxy-log", type=Path, required=True)
    args = parser.parse_args()
    verify(
        role_pair=args.role_pair, sender=args.sender, fault=args.fault,
        streams=args.streams, bytes_per_stream=args.bytes_per_stream,
        reset_after_bytes=args.reset_after_bytes, reset_every=args.reset_every,
        client_log=args.client_log, server_log=args.server_log, proxy_log=args.proxy_log,
    )


if __name__ == "__main__":
    main()
