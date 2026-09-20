#!/usr/bin/env python3
"""Strict verifier for both netz/wtransport WebTransport churn roles."""

import argparse
import re
from pathlib import Path


def record(path: Path, prefix: str) -> dict[str, str]:
    matches = [line for line in path.read_text().splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError(f"{path}: expected one {prefix!r} record, found {len(matches)}")
    fields: dict[str, str] = {}
    for token in matches[0][len(prefix) :].split():
        if token.count("=") != 1:
            raise ValueError(f"{path}: malformed token {token!r}")
        key, value = token.split("=", 1)
        if not re.fullmatch(r"[a-z_-]+", key) or not value:
            raise ValueError(f"{path}: malformed field {token!r}")
        if key in fields:
            raise ValueError(f"{path}: duplicate field {key!r}")
        fields[key] = value
    return fields


MASK64 = (1 << 64) - 1
SPLITMIX_INCREMENT = 0x9E37_79B9_7F4A_7C15


def should_reset(seed: int, streams: int, stream: int) -> bool:
    if not 0 <= seed <= MASK64:
        raise ValueError("reset seed must fit u64")
    if not 2 <= streams <= 256 or not 0 <= stream < streams:
        raise ValueError("invalid reset selection index")
    if stream == 0:
        return True
    if stream == 1:
        return False
    value = (seed + SPLITMIX_INCREMENT * (stream + 1)) & MASK64
    value = ((value ^ (value >> 30)) * 0xBF58_476D_1CE4_E5B9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94D0_49BB_1331_11EB) & MASK64
    value ^= value >> 31
    return value & 1 != 0


def expected(streams: int, size: int, prefix: int, seed: int) -> dict[str, int]:
    total = checksum = reset_mask = code_sum = resets = 0
    for stream in range(streams):
        reset = should_reset(seed, streams, stream)
        count = prefix if reset else size
        total += count
        checksum = (checksum + sum(((offset * 131 + stream * 17) & 0xFF) for offset in range(count))) & ((1 << 64) - 1)
        if reset:
            resets += 1
            reset_mask |= 1 << stream
            code_sum += 0x4000 + stream
    return {
        "streams": streams,
        "fin": streams - resets,
        "reset": resets,
        "bytes": total,
        "checksum": checksum,
        "reset_mask": reset_mask,
        "reset_code_sum": code_sum,
    }


def parse_int(value: str) -> int:
    return int(value, 16) if value.startswith("0x") else int(value)


def verify(
    *,
    sender: str,
    fault: str,
    streams: int,
    bytes_per_stream: int,
    reset_after_bytes: int,
    reset_seed: int,
    client_log: Path,
    server_log: Path,
    proxy_log: Path | None = None,
) -> None:
    if sender not in ("netz", "wtransport"):
        raise ValueError("invalid sender")
    if fault not in ("loss", "reorder"):
        raise ValueError("invalid fault mode")
    if not 2 <= streams <= 256:
        raise ValueError("streams must be in 2..256")
    if bytes_per_stream < 1 or not 0 <= reset_after_bytes <= bytes_per_stream:
        raise ValueError("invalid byte shape")
    if not 0 <= reset_seed <= MASK64:
        raise ValueError("reset seed must fit u64")
    wanted = expected(streams, bytes_per_stream, reset_after_bytes, reset_seed)
    client_prefix = f"{sender} client churn passed:"
    server_implementation = "wtransport" if sender == "netz" else "netz"
    server_prefix = f"{server_implementation} server churn passed:"
    scope = f"{sender}-client-outbound"
    endpoint_io = (
        {"client": "zio-std-io", "server": "wtransport-quinn-tokio"}
        if sender == "netz"
        else {"client": "wtransport-quinn-tokio", "server": "zio-std-io"}
    )
    client = record(client_log, client_prefix)
    server = record(server_log, server_prefix)
    for name, values in (("client", client), ("server", server)):
        if values.get("fault") != fault:
            raise ValueError(f"{name}: fault mismatch")
        if values.get("fault_scope") != scope:
            raise ValueError(f"{name}: invalid fault scope")
        if values.get("sibling") != "true":
            raise ValueError(f"{name}: sibling did not survive")
        if parse_int(values.get("reset_seed", "-1")) != reset_seed:
            raise ValueError(f"{name}: reset seed mismatch")
        if (
            values.get("client_io") != endpoint_io["client"]
            or values.get("server_io") != endpoint_io["server"]
        ):
            raise ValueError(f"{name}: backend identity mismatch")
        for field, value in wanted.items():
            actual = parse_int(values.get(field, "-1"))
            if actual != value:
                raise ValueError(f"{name}: {field}={actual}, expected {value}")
    if client.get("peer-close") != "true":
        raise ValueError("client did not observe peer close")
    if int(client.get("considered", "0")) <= 0:
        raise ValueError("fault interceptor considered no datagrams")
    counter = "dropped" if fault == "loss" else "held"
    if int(client.get(counter, "0")) <= 0:
        raise ValueError(f"fault interceptor {counter} no datagrams")
    inactive_counter = "held" if fault == "loss" else "dropped"
    if int(client.get(inactive_counter, "-1")) != 0:
        raise ValueError(f"inactive fault counter {inactive_counter} was nonzero")
    if sender == "wtransport":
        if proxy_log is None:
            raise ValueError("wtransport sender requires proxy log")
        proxy = record(proxy_log, "udp fault proxy passed:")
        if (
            proxy.get("fault") != fault
            or proxy.get("fault_direction") != "client"
            or proxy.get("fault_scope") != scope
        ):
            raise ValueError("proxy fault metadata mismatch")
        for field in ("considered", "dropped", "held", "reordered"):
            if proxy.get(field) != client.get(field):
                raise ValueError(f"proxy/client {field} mismatch")
        if fault == "reorder":
            if int(client.get("reordered", "0")) <= 0:
                raise ValueError("proxy reordered no datagrams")
            if client.get("held") != client.get("reordered"):
                raise ValueError("not every held datagram was pair-reordered")
        phase_counter = "dropped" if fault == "loss" else "reordered"
        for phase in ("reset", "fin"):
            field = f"{phase}_{phase_counter}"
            if int(client.get(field, "0")) != 1:
                raise ValueError(
                    f"{phase} phase did not have exactly one {phase_counter} datagram"
                )
        expected_considered = 2 if fault == "loss" else 4
        if int(client.get("considered", "0")) != expected_considered:
            raise ValueError("unexpected proxy considered count")
        if int(client.get(phase_counter, "0")) != 2:
            raise ValueError("proxy phase counters do not sum to two")
    print(
        "verified WebTransport churn: "
        f"fault={fault} reset_seed={reset_seed} streams={streams} "
        f"fin={wanted['fin']} "
        f"reset={wanted['reset']} bytes={wanted['bytes']} "
        f"checksum={wanted['checksum']} reset_mask=0x{wanted['reset_mask']:064x} "
        f"reset_code_sum={wanted['reset_code_sum']} "
        f"client_io={endpoint_io['client']} server_io={endpoint_io['server']} "
        f"considered={client['considered']} {counter}={client[counter]}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sender", choices=("netz", "wtransport"), default="netz")
    parser.add_argument("--fault", choices=("loss", "reorder"), required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--bytes-per-stream", type=int, required=True)
    parser.add_argument("--reset-after-bytes", type=int, required=True)
    parser.add_argument("--reset-seed", type=int, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    parser.add_argument("--proxy-log", type=Path)
    args = parser.parse_args()
    verify(
        sender=args.sender,
        fault=args.fault,
        streams=args.streams,
        bytes_per_stream=args.bytes_per_stream,
        reset_after_bytes=args.reset_after_bytes,
        reset_seed=args.reset_seed,
        client_log=args.client_log,
        server_log=args.server_log,
        proxy_log=args.proxy_log,
    )


if __name__ == "__main__":
    main()
