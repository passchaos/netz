#!/usr/bin/env python3
"""Summarize verified persistent raw QUIC benchmark result records."""

from __future__ import annotations

import argparse
import importlib.util
import statistics
from pathlib import Path

CHECKER = Path(__file__).with_name("quic_persistent_benchmark_check.py")
SPEC = importlib.util.spec_from_file_location("quic_persistent_check", CHECKER)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
fields = CHECK.fields


ROLE_PAIRS = (
    "netz-client+quic-go-server",
    "quic-go-client+quic-go-server",
    "quic-go-client+netz-server",
    "netz-client+netz-server",
)


def rows(path: Path, mode: str, topology: str) -> list[dict[str, str]]:
    endpoint_topology = (
        "shared-server-udp" if topology == "shared"
        else "one-udp-socket-per-connection"
    )
    return [
        row
        for line in path.read_text(encoding="utf-8").splitlines()
        if (row := fields(line)).get("record") == "result"
        and row.get("protocol") == "quic-stream"
        and row.get("mode") == mode
        and (mode == "echo" or row.get("endpoint_topology") == endpoint_topology)
    ]


def positive(row: dict[str, str], key: str) -> int:
    try:
        value = int(row[key])
    except (KeyError, ValueError) as error:
        raise ValueError(f"invalid {key}: {row}") from error
    if value <= 0:
        raise ValueError(f"non-positive {key}: {row}")
    return value


def summarize(
    path: Path, mode: str, samples: int, topology: str = "independent",
    shared_receive_batch: int = 32, server_ack_every: int = 1,
    server_ack_delay_us: int = 0,
) -> list[str]:
    if samples <= 0 or samples % 2 == 0:
        raise ValueError("samples must be a positive odd number")
    if topology not in ("independent", "shared"):
        raise ValueError("invalid server topology")
    if topology == "shared" and mode != "aggregate":
        raise ValueError("shared topology requires aggregate mode")
    if (
        shared_receive_batch < 1 or shared_receive_batch > 64
        or server_ack_every < 1 or server_ack_every > 64
        or server_ack_delay_us < 0 or server_ack_delay_us > 25000
    ):
        raise ValueError("invalid shared receive or ACK configuration")
    source = rows(path, mode, topology)
    if not source:
        raise ValueError(f"no {mode} result records")
    shape_keys = (
        ("warmup", "iterations", "connections", "streams", "payload_bytes")
        if mode == "echo"
        else ("connections", "streams", "bytes_per_stream", "timing_scope") +
            (("server_receive_batch", "server_ack_every", "server_ack_delay_us")
             if topology == "shared" else ())
    )
    expected_shape = tuple(source[0].get(key) for key in shape_keys)
    if any(value is None for value in expected_shape) or any(
        tuple(row.get(key) for key in shape_keys) != expected_shape for row in source
    ):
        raise ValueError(f"mixed or incomplete {mode} benchmark shapes")
    if topology == "shared" and expected_shape[-3:] != (
        str(shared_receive_batch), str(server_ack_every),
        str(server_ack_delay_us),
    ):
        raise ValueError("shared receive or ACK policy mismatch")
    role_pairs = (
        ("netz-client+netz-server",)
        if topology == "shared" else ROLE_PAIRS
    )
    senders = ("client",) if mode == "echo" or topology == "shared" else ("client", "server")
    grouped: dict[tuple[str, str], float] = {}
    output: list[str] = []
    for role_pair in role_pairs:
        for sender in senders:
            group = [
                row for row in source
                if row.get("role_pair") == role_pair
                and row.get("sender_role") == sender
            ]
            if len(group) != samples:
                raise ValueError(
                    f"{role_pair}/{sender}: expected {samples} results, found {len(group)}"
                )
            runs = {positive(row, "run") for row in group}
            if runs != set(range(1, samples + 1)):
                raise ValueError(f"{role_pair}/{sender}: invalid run set {runs}")
            if any(row.get("complete") != "true" for row in group):
                raise ValueError(f"{role_pair}/{sender}: incomplete result")
            client_impl, server_impl = CHECK.endpoint_implementations(role_pair)
            implementation = client_impl if mode == "echo" or sender == "client" else server_impl
            if any(
                row.get("implementation") != implementation
                or row.get("result_owner") != "client"
                or row.get("benchmark_scope") != "same-application-shape"
                or row.get("completion_exchange_verified") != "true"
                for row in group
            ):
                raise ValueError(f"{role_pair}/{sender}: invalid result identity or proof")
            if mode == "echo":
                values = [positive(row, "p50_ns") for row in group]
                p99_values = [positive(row, "p99_ns") for row in group]
                p999_values = [positive(row, "p999_ns") for row in group]
                median = int(statistics.median(values))
                grouped[(role_pair, sender)] = float(median)
                output.append(
                    "record=summary protocol=quic-stream mode=echo "
                    f"role_pair={role_pair} sender_role=client samples={samples} "
                    f"median_p50_ns={median} min_p50_ns={min(values)} "
                    f"max_p50_ns={max(values)} "
                    f"median_p99_ns={int(statistics.median(p99_values))} "
                    f"median_p999_ns={int(statistics.median(p999_values))} "
                    "complete=true"
                )
            else:
                elapsed = [positive(row, "elapsed_ns") for row in group]
                throughput = [float(row["logical_MiB_s"]) for row in group]
                if any(value <= 0 for value in throughput):
                    raise ValueError(f"{role_pair}/{sender}: invalid throughput")
                median_elapsed = int(statistics.median(elapsed))
                median_throughput = statistics.median(throughput)
                grouped[(role_pair, sender)] = median_throughput
                batch_field = (
                    f"server_receive_batch={shared_receive_batch} "
                    f"server_ack_every={server_ack_every} "
                    f"server_ack_delay_us={server_ack_delay_us} "
                    if topology == "shared" else ""
                )
                output.append(
                    "record=summary protocol=quic-stream mode=aggregate "
                    f"role_pair={role_pair} sender_role={sender} samples={samples} "
                    f"median_elapsed_ns={median_elapsed} "
                    f"median_logical_MiB_s={median_throughput:.3f} "
                    f"min_logical_MiB_s={min(throughput):.3f} "
                    f"max_logical_MiB_s={max(throughput):.3f} "
                    f"{batch_field}complete=true"
                )

    comparisons = () if topology == "shared" else (
        ("fixed_server=quic-go", "client",
         "netz-client+quic-go-server", "quic-go-client+quic-go-server"),
        ("fixed_server=netz", "client",
         "netz-client+netz-server", "quic-go-client+netz-server"),
    ) if mode == "echo" else (
        ("fixed_server=quic-go", "client",
         "netz-client+quic-go-server", "quic-go-client+quic-go-server"),
        ("fixed_server=netz", "client",
         "netz-client+netz-server", "quic-go-client+netz-server"),
        ("fixed_client=netz", "server",
         "netz-client+netz-server", "netz-client+quic-go-server"),
        ("fixed_client=quic-go", "server",
         "quic-go-client+netz-server", "quic-go-client+quic-go-server"),
    )
    for fixed, sender, netz_pair, go_pair in comparisons:
        netz = grouped[(netz_pair, sender)]
        quic_go = grouped[(go_pair, sender)]
        ratio = (quic_go / netz) if mode == "echo" else (netz / quic_go)
        metric = "median_p50_ns" if mode == "echo" else "median_logical_MiB_s"
        netz_value = str(int(netz)) if mode == "echo" else f"{netz:.3f}"
        quic_go_value = (
            str(int(quic_go)) if mode == "echo" else f"{quic_go:.3f}"
        )
        output.append(
            f"record=comparison protocol=quic-stream mode={mode} {fixed} "
            f"sender_role={sender} {metric}_netz={netz_value} "
            f"{metric}_quic_go={quic_go_value} "
            f"netz_speedup={ratio:.3f} benchmark_scope=same-application-shape "
            "complete=true"
        )
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("echo", "aggregate"), required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument(
        "--server-topology", choices=("independent", "shared"),
        default="independent",
    )
    parser.add_argument("--shared-receive-batch", type=int, default=32)
    parser.add_argument("--server-ack-every", type=int, default=1)
    parser.add_argument("--server-ack-delay-us", type=int, default=0)
    args = parser.parse_args()
    for line in summarize(
        args.log, args.mode, args.samples, args.server_topology,
        args.shared_receive_batch,
        args.server_ack_every,
        args.server_ack_delay_us,
    ):
        print(line)


if __name__ == "__main__":
    main()
