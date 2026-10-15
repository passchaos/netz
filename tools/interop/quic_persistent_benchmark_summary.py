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


def rows(
    path: Path, mode: str, topology: str, connections: int | None = None,
) -> list[dict[str, str]]:
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
        and (connections is None or row.get("connections") == str(connections))
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
    shared_receive_batch: int = 32, server_ack_every: int = 2,
    server_ack_delay_us: int = 25000, netz_only: bool = False,
    connections: int | None = None,
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
    if connections is not None and connections <= 0:
        raise ValueError("connections must be positive")
    source = rows(path, mode, topology, connections)
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
        if topology == "shared" or netz_only else ROLE_PAIRS
    )
    senders = ("client",) if mode == "echo" else ("client", "server")
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
            client_io, server_io = CHECK.endpoint_ios(role_pair)
            implementation = client_impl if mode == "echo" or sender == "client" else server_impl
            if any(
                row.get("implementation") != implementation
                or row.get("client_io") != client_io
                or row.get("server_io") != server_io
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
                    f"client_io={client_io} server_io={server_io} "
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
                    f"connections={expected_shape[0]} "
                    f"client_io={client_io} server_io={server_io} "
                    f"median_elapsed_ns={median_elapsed} "
                    f"median_logical_MiB_s={median_throughput:.3f} "
                    f"min_logical_MiB_s={min(throughput):.3f} "
                    f"max_logical_MiB_s={max(throughput):.3f} "
                    f"{batch_field}complete=true"
                )

    comparisons = () if topology == "shared" or netz_only else (
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
    connection_field = (
        f"connections={expected_shape[0]} " if mode == "aggregate" else ""
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
            f"{connection_field}"
            f"netz_speedup={ratio:.3f} benchmark_scope=same-application-shape "
            "complete=true"
        )
    return output


def compare_topologies(
    path: Path, samples: int, shared_receive_batch: int = 32,
    server_ack_every: int = 2, server_ack_delay_us: int = 25000,
    connections: int | None = None,
) -> list[str]:
    if server_ack_every != 2 or server_ack_delay_us != 25000:
        raise ValueError("topology comparison requires identical ACK policy 2/25000")
    independent = summarize(
        path, "aggregate", samples, "independent", netz_only=True,
        connections=connections,
    )
    shared = summarize(
        path, "aggregate", samples, "shared", shared_receive_batch,
        server_ack_every, server_ack_delay_us, True,
        connections,
    )
    medians: dict[tuple[str, str], float] = {}
    for topology, lines in (("independent", independent), ("shared", shared)):
        for line in lines:
            row = fields(line)
            sender = row.get("sender_role")
            if sender not in ("client", "server"):
                raise ValueError("invalid topology summary sender")
            try:
                medians[(topology, sender)] = float(
                    row["median_logical_MiB_s"]
                )
            except (KeyError, ValueError) as error:
                raise ValueError("invalid topology summary throughput") from error
    output = independent + shared
    connection_count = (
        connections if connections is not None
        else positive(fields(independent[0]), "connections")
    )
    for sender in ("client", "server"):
        independent_value = medians[("independent", sender)]
        shared_value = medians[("shared", sender)]
        output.append(
            "record=topology-comparison protocol=quic-stream mode=aggregate "
            f"sender_role={sender} samples={samples} "
            f"connections={connection_count} "
            f"independent_median_logical_MiB_s={independent_value:.3f} "
            f"shared_median_logical_MiB_s={shared_value:.3f} "
            f"shared_over_independent={shared_value / independent_value:.3f} "
            f"server_ack_every={server_ack_every} "
            f"server_ack_delay_us={server_ack_delay_us} "
            "client_io=zio-std-io server_io=zio-std-io "
            "benchmark_scope=same-application-shape complete=true"
        )
    return output


def summarize_scaling(
    path: Path, samples: int, topology: str, connection_counts: list[int],
    shared_receive_batch: int = 32, server_ack_every: int = 2,
    server_ack_delay_us: int = 25000,
) -> list[str]:
    if (
        len(connection_counts) < 2
        or connection_counts != sorted(set(connection_counts))
    ):
        raise ValueError("connection counts must be strictly increasing")
    output: list[str] = []
    medians: dict[tuple[int, str], float] = {}
    for connections in connection_counts:
        lines = summarize(
            path, "aggregate", samples, topology, shared_receive_batch,
            server_ack_every, server_ack_delay_us, True, connections,
        )
        output.extend(lines)
        for line in lines:
            row = fields(line)
            if row.get("record") != "summary":
                continue
            sender = row.get("sender_role")
            if sender not in ("client", "server"):
                raise ValueError("invalid scaling summary sender")
            try:
                medians[(connections, sender)] = float(
                    row["median_logical_MiB_s"]
                )
            except (KeyError, ValueError) as error:
                raise ValueError("invalid scaling throughput") from error

    base_connections = connection_counts[0]
    endpoint_topology = (
        "shared-server-udp" if topology == "shared"
        else "one-udp-socket-per-connection"
    )
    for sender in ("client", "server"):
        base = medians[(base_connections, sender)]
        for connections in connection_counts:
            value = medians[(connections, sender)]
            throughput_ratio = value / base
            output.append(
                "record=connection-scaling protocol=quic-stream mode=aggregate "
                f"server_topology={topology} endpoint_topology={endpoint_topology} "
                f"sender_role={sender} samples={samples} "
                f"base_connections={base_connections} connections={connections} "
                f"base_median_logical_MiB_s={base:.3f} "
                f"median_logical_MiB_s={value:.3f} "
                f"throughput_over_base={throughput_ratio:.3f} "
                f"work_normalized_elapsed_over_base={base / value:.3f} "
                f"median_per_connection_MiB_s={value / connections:.3f} "
                f"server_ack_every={server_ack_every} "
                f"server_ack_delay_us={server_ack_delay_us} "
                "client_io=zio-std-io server_io=zio-std-io "
                "benchmark_scope=same-application-shape complete=true"
            )
    return output


def parse_connection_counts(value: str) -> list[int]:
    try:
        counts = [int(part) for part in value.split(",")]
    except ValueError as error:
        raise ValueError("invalid connection counts") from error
    if not counts or any(count <= 0 for count in counts):
        raise ValueError("invalid connection counts")
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("echo", "aggregate"), required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument(
        "--server-topology", choices=("independent", "shared", "compare"),
        default="independent",
    )
    parser.add_argument("--shared-receive-batch", type=int, default=32)
    parser.add_argument("--server-ack-every", type=int, default=2)
    parser.add_argument("--server-ack-delay-us", type=int, default=25000)
    parser.add_argument("--connections", type=int)
    parser.add_argument("--connection-counts")
    parser.add_argument("--netz-only", action="store_true")
    args = parser.parse_args()
    if args.connection_counts is not None:
        if args.mode != "aggregate":
            raise ValueError("connection scaling requires aggregate mode")
        if args.server_topology == "compare" or not args.netz_only:
            raise ValueError("connection scaling requires one netz-only topology")
        if args.connections is not None:
            raise ValueError("connections and connection-counts are mutually exclusive")
        output = summarize_scaling(
            args.log, args.samples, args.server_topology,
            parse_connection_counts(args.connection_counts),
            args.shared_receive_batch, args.server_ack_every,
            args.server_ack_delay_us,
        )
    elif args.server_topology == "compare":
        if args.mode != "aggregate" or not args.netz_only:
            raise ValueError("topology comparison requires aggregate netz-only mode")
        output = compare_topologies(
            args.log, args.samples, args.shared_receive_batch,
            args.server_ack_every, args.server_ack_delay_us,
            args.connections,
        )
    else:
        output = summarize(
            args.log, args.mode, args.samples, args.server_topology,
            args.shared_receive_batch,
            args.server_ack_every,
            args.server_ack_delay_us,
            args.netz_only,
            args.connections,
        )
    for line in output:
        print(line)


if __name__ == "__main__":
    main()
