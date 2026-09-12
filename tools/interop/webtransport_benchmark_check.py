#!/usr/bin/env python3
"""Validate WebTransport benchmark results and optional memory records."""

from __future__ import annotations

import argparse
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in result:
            raise SystemExit(f"duplicate field {key!r} in {line!r}")
        result[key] = value
    return result


def records(path: Path, kind: str, role_pair: str) -> list[dict[str, str]]:
    found = []
    for line in path.read_text(encoding="utf-8").splitlines():
        record = fields(line)
        if record.get("record") == kind and record.get("role_pair") == role_pair:
            found.append(record)
    return found


def integer(record: dict[str, str], key: str, *, positive: bool = False) -> int:
    try:
        value = int(record[key])
    except (KeyError, ValueError) as error:
        raise SystemExit(f"invalid {key}: {record}") from error
    if value < 0 or positive and value == 0:
        raise SystemExit(f"invalid {key}: {record}")
    return value


def stream_checksum(streams: int, bytes_per_stream: int) -> int:
    periods, remainder = divmod(bytes_per_stream, 256)
    period_sum = sum(range(256))
    return sum(
        periods * period_sum
        + sum((offset * 131 + stream_index * 17) & 0xFF for offset in range(remainder))
        for stream_index in range(streams)
    )


def ping_checksum(rounds: int, payload_bytes: int) -> int:
    checksum = 0
    for sequence in range(rounds):
        payload = (
            b"NZPING"
            + sequence.to_bytes(8, "big")
            + bytes(
                (sequence * 17 + index * 131) & 0xFF
                for index in range(payload_bytes - 14)
            )
        )
        checksum += sum(payload)
    return checksum


def validate_shape(
    record: dict[str, str],
    *,
    role_pair: str,
    implementation: str,
    endpoint_role: str,
    mode: str,
    warmup: int,
    iterations: int,
    streams: int,
    bytes_per_stream: int,
    payload_bytes: int,
    chunk_bytes: int,
    stream_window: int,
    timeout_ms: int,
    netz_ack_every: int,
    netz_max_ack_delay_us: int,
) -> None:
    direction = "upload" if mode == "stream-upload" else "roundtrip"
    expected = {
        "implementation": implementation,
        "protocol": "webtransport",
        "transport": "h3",
        "mode": mode,
        "direction": direction,
        "role_pair": role_pair,
        "endpoint_role": endpoint_role,
        "connection_scope": "persistent",
        "warmup": str(warmup),
        "iterations": str(iterations),
        "streams": str(streams),
        "bytes_per_stream": str(bytes_per_stream),
        "payload_bytes": str(payload_bytes),
        "chunk_bytes": str(chunk_bytes),
        "stream_window": str(stream_window),
        "timeout_ms": str(timeout_ms),
        "netz_ack_every": str(netz_ack_every),
        "netz_max_ack_delay_us": str(netz_max_ack_delay_us),
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise SystemExit(
                f"record has {key}={record.get(key)!r}, expected {value!r}"
            )


def read_rss(path: Path) -> int:
    try:
        value = int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError) as error:
        raise SystemExit(f"invalid peak RSS file {path}") from error
    if value <= 0:
        raise SystemExit(f"non-positive peak RSS in {path}")
    return value


def validate_traffic(
    record: dict[str, str],
    *,
    role_pair: str,
    implementation: str,
    endpoint_role: str,
    mode: str,
    warmup: int,
    iterations: int,
    streams: int,
    bytes_per_stream: int,
    payload_bytes: int,
    chunk_bytes: int,
    stream_window: int,
    timeout_ms: int,
    netz_ack_every: int,
    netz_max_ack_delay_us: int,
) -> None:
    validate_shape(
        record, role_pair=role_pair, implementation=implementation,
        endpoint_role=endpoint_role, mode=mode, warmup=warmup,
        iterations=iterations, streams=streams,
        bytes_per_stream=bytes_per_stream, payload_bytes=payload_bytes,
        chunk_bytes=chunk_bytes, stream_window=stream_window,
        timeout_ms=timeout_ms,
        netz_ack_every=netz_ack_every,
        netz_max_ack_delay_us=netz_max_ack_delay_us,
    )
    expected_source = (
        "netz-socket-counters"
        if implementation == "netz"
        else "quinn-connection-stats"
    )
    if (
        record.get("traffic_scope") != "connection"
        or record.get("socket_boundary") != "userspace-udp-payload"
        or record.get("traffic_source") != expected_source
        or record.get("logical_udp_segments") != "true"
        or record.get("complete") != "true"
    ):
        raise SystemExit(f"invalid traffic scope/completion: {record}")
    for key in (
        "udp_sent_datagrams", "udp_sent_payload_bytes",
        "udp_received_datagrams", "udp_received_payload_bytes",
    ):
        integer(record, key, positive=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-pair", required=True)
    parser.add_argument("--mode", choices=("stream-upload", "datagram-pingpong"), required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--streams", type=int, required=True)
    parser.add_argument("--bytes-per-stream", type=int, required=True)
    parser.add_argument("--payload-bytes", type=int, required=True)
    parser.add_argument("--chunk-bytes", type=int, required=True)
    parser.add_argument("--stream-window", type=int, required=True)
    parser.add_argument("--timeout-ms", type=int, required=True)
    parser.add_argument("--netz-ack-every", type=int, required=True)
    parser.add_argument("--netz-max-ack-delay-us", type=int, required=True)
    parser.add_argument("--client-log", required=True, type=Path)
    parser.add_argument("--server-log", required=True, type=Path)
    parser.add_argument("--client-rss", type=Path)
    parser.add_argument("--server-rss", type=Path)
    parser.add_argument("--require-traffic", action="store_true")
    args = parser.parse_args()

    implementations = {
        "netz-client+wtransport-server": {"client": "netz", "server": "wtransport"},
        "wtransport-client+netz-server": {"client": "wtransport", "server": "netz"},
    }.get(args.role_pair)
    if (
        implementations is None
        or args.warmup <= 0
        or args.iterations <= 0
        or args.streams <= 0
        or args.bytes_per_stream <= 0
        or args.payload_bytes < 14
        or args.chunk_bytes <= 0
        or args.stream_window <= 0
        or args.timeout_ms <= 0
        or args.netz_ack_every <= 0
        or not 0 <= args.netz_max_ack_delay_us <= 25_000
    ):
        raise SystemExit("invalid WebTransport validation configuration")

    results = records(args.client_log, "result", args.role_pair)
    server_records = records(args.server_log, "server-complete", args.role_pair)
    expected_results = args.iterations if args.mode == "stream-upload" else 1
    if len(results) != expected_results or len(server_records) != 1:
        raise SystemExit(
            f"expected {expected_results} results and one server completion, found "
            f"{len(results)} and {len(server_records)}"
        )
    for result in results:
        validate_shape(
            result, role_pair=args.role_pair, implementation=implementations["client"],
            endpoint_role="client", mode=args.mode, warmup=args.warmup,
            iterations=args.iterations, streams=args.streams,
            bytes_per_stream=args.bytes_per_stream, payload_bytes=args.payload_bytes,
            chunk_bytes=args.chunk_bytes, stream_window=args.stream_window,
            timeout_ms=args.timeout_ms,
            netz_ack_every=args.netz_ack_every,
            netz_max_ack_delay_us=args.netz_max_ack_delay_us,
        )
        if result.get("benchmark_scope") != "same-application-shape" or result.get("complete") != "true":
            raise SystemExit(f"invalid result completion: {result}")
    server = server_records[0]
    validate_shape(
        server, role_pair=args.role_pair, implementation=implementations["server"],
        endpoint_role="server", mode=args.mode, warmup=args.warmup,
        iterations=args.iterations, streams=args.streams,
        bytes_per_stream=args.bytes_per_stream, payload_bytes=args.payload_bytes,
        chunk_bytes=args.chunk_bytes, stream_window=args.stream_window,
        timeout_ms=args.timeout_ms,
        netz_ack_every=args.netz_ack_every,
        netz_max_ack_delay_us=args.netz_max_ack_delay_us,
    )
    if server.get("server_complete") != "true":
        raise SystemExit(f"invalid server completion: {server}")

    if args.mode == "stream-upload":
        bytes_per_result = args.streams * args.bytes_per_stream
        checksum_per_result = stream_checksum(args.streams, args.bytes_per_stream)
        for sample, result in enumerate(results, 1):
            if integer(result, "sample") != sample:
                raise SystemExit(f"invalid sample sequence: {result}")
            if integer(result, "elapsed_ns", positive=True) <= 0:
                raise SystemExit(f"invalid elapsed time: {result}")
            if integer(result, "streams_finished") != args.streams:
                raise SystemExit(f"invalid finished stream count: {result}")
            if integer(result, "sent_bytes") != bytes_per_result or integer(result, "received_bytes") != bytes_per_result:
                raise SystemExit(f"invalid stream byte count: {result}")
            if integer(result, "checksum") != checksum_per_result:
                raise SystemExit(f"invalid stream checksum: {result}")
        expected_bytes = args.iterations * bytes_per_result
        expected_checksum = args.iterations * checksum_per_result
    else:
        result = results[0]
        for key in ("p50_ns", "p90_ns", "p99_ns", "p999_ns", "mean_ns", "min_ns", "max_ns"):
            integer(result, key, positive=True)
        if not (
            integer(result, "min_ns") <= integer(result, "p50_ns")
            <= integer(result, "p90_ns") <= integer(result, "p99_ns")
            <= integer(result, "p999_ns") <= integer(result, "max_ns")
        ):
            raise SystemExit(f"invalid latency ordering: {result}")
        expected_bytes = (args.warmup + args.iterations) * args.payload_bytes
        expected_checksum = ping_checksum(args.warmup + args.iterations, args.payload_bytes)
        if integer(result, "sent_bytes") != expected_bytes or integer(result, "received_bytes") != expected_bytes:
            raise SystemExit(f"invalid DATAGRAM byte count: {result}")
        if integer(result, "checksum") != expected_checksum:
            raise SystemExit(f"invalid DATAGRAM checksum: {result}")

    for key in ("sent_bytes", "received_bytes"):
        if integer(server, key) != expected_bytes:
            raise SystemExit(f"invalid server {key}: {server}")
    if integer(server, "checksum") != expected_checksum:
        raise SystemExit(f"invalid server checksum: {server}")

    print(
        f"protocol=webtransport mode={args.mode} role_pair={args.role_pair} "
        f"warmup={args.warmup} iterations={args.iterations} streams={args.streams} "
        f"bytes={expected_bytes} checksum={expected_checksum} complete=true"
    )

    if args.require_traffic:
        joined: dict[str, dict[str, str]] = {}
        for role, log_path in (("client", args.client_log), ("server", args.server_log)):
            traffic_records = records(log_path, "traffic", args.role_pair)
            if len(traffic_records) != 1:
                raise SystemExit(
                    f"expected one traffic record in {log_path}, found {len(traffic_records)}"
                )
            traffic_record = traffic_records[0]
            validate_traffic(
                traffic_record, role_pair=args.role_pair,
                implementation=implementations[role], endpoint_role=role,
                mode=args.mode, warmup=args.warmup, iterations=args.iterations,
                streams=args.streams, bytes_per_stream=args.bytes_per_stream,
                payload_bytes=args.payload_bytes, chunk_bytes=args.chunk_bytes,
                stream_window=args.stream_window, timeout_ms=args.timeout_ms,
                netz_ack_every=args.netz_ack_every,
                netz_max_ack_delay_us=args.netz_max_ack_delay_us,
            )
            joined[role] = traffic_record
        client = joined["client"]
        server = joined["server"]
        client_tx_datagrams = integer(client, "udp_sent_datagrams", positive=True)
        client_tx_bytes = integer(client, "udp_sent_payload_bytes", positive=True)
        client_rx_datagrams = integer(client, "udp_received_datagrams", positive=True)
        client_rx_bytes = integer(client, "udp_received_payload_bytes", positive=True)
        server_tx_datagrams = integer(server, "udp_sent_datagrams", positive=True)
        server_tx_bytes = integer(server, "udp_sent_payload_bytes", positive=True)
        server_rx_datagrams = integer(server, "udp_received_datagrams", positive=True)
        server_rx_bytes = integer(server, "udp_received_payload_bytes", positive=True)
        deltas = (
            client_tx_datagrams - server_rx_datagrams,
            client_tx_bytes - server_rx_bytes,
            server_tx_datagrams - client_rx_datagrams,
            server_tx_bytes - client_rx_bytes,
        )
        if any(delta < 0 for delta in deltas):
            raise SystemExit(f"peer observed traffic not sent: deltas={deltas}")
        print(
            f"record=traffic-summary protocol=webtransport mode={args.mode} "
            f"role_pair={args.role_pair} traffic_scope=connection "
            f"socket_boundary=userspace-udp-payload "
            f"client_udp_sent_datagrams={client_tx_datagrams} "
            f"client_udp_sent_payload_bytes={client_tx_bytes} "
            f"server_udp_sent_datagrams={server_tx_datagrams} "
            f"server_udp_sent_payload_bytes={server_tx_bytes} "
            f"total_udp_sent_datagrams={client_tx_datagrams + server_tx_datagrams} "
            f"total_udp_sent_payload_bytes={client_tx_bytes + server_tx_bytes} "
            f"client_to_server_observation_delta_datagrams={deltas[0]} "
            f"client_to_server_observation_delta_bytes={deltas[1]} "
            f"server_to_client_observation_delta_datagrams={deltas[2]} "
            f"server_to_client_observation_delta_bytes={deltas[3]} "
            "benchmark_scope=same-application-shape complete=true"
        )

    if (args.client_rss is None) != (args.server_rss is None):
        raise SystemExit("both RSS files are required together")
    if args.client_rss is None:
        return
    for role, log_path, rss_path in (
        ("client", args.client_log, args.client_rss),
        ("server", args.server_log, args.server_rss),
    ):
        memory_records = records(log_path, "memory", args.role_pair)
        if len(memory_records) != 1:
            raise SystemExit(
                f"expected one memory record in {log_path}, found {len(memory_records)}"
            )
        memory = memory_records[0]
        implementation = implementations[role]
        validate_shape(
            memory, role_pair=args.role_pair, implementation=implementation,
            endpoint_role=role, mode=args.mode, warmup=args.warmup,
            iterations=args.iterations, streams=args.streams,
            bytes_per_stream=args.bytes_per_stream, payload_bytes=args.payload_bytes,
            chunk_bytes=args.chunk_bytes, stream_window=args.stream_window,
            timeout_ms=args.timeout_ms,
            netz_ack_every=args.netz_ack_every,
            netz_max_ack_delay_us=args.netz_max_ack_delay_us,
        )
        expected_scope = "netz-explicit" if implementation == "netz" else "rust-system-requested"
        expected_memory_scope = (
            "benchmark-run-after-argument-parse"
            if implementation == "netz"
            else "process-start-through-runtime-teardown"
        )
        if (
            memory.get("allocator_scope") != expected_scope
            or memory.get("memory_scope") != expected_memory_scope
            or memory.get("complete") != "true"
        ):
            raise SystemExit(f"invalid memory scope/completion: {memory}")
        for key in ("alloc_count", "total_allocated_bytes", "peak_live_bytes"):
            integer(memory, key, positive=True)
        if implementation == "netz" and integer(memory, "live_bytes") != 0:
            raise SystemExit(f"netz allocator retained live bytes: {memory}")
        if implementation == "wtransport" and integer(memory, "peak_live_bytes") < integer(memory, "live_bytes_end"):
            raise SystemExit(f"wtransport peak below live bytes: {memory}")
        excluded = {
            "record", "implementation", "protocol", "transport",
            "mode", "direction", "role_pair", "endpoint_role",
            "connection_scope", "warmup", "iterations", "streams",
            "bytes_per_stream", "payload_bytes", "chunk_bytes",
            "stream_window", "timeout_ms", "complete",
            "netz_ack_every", "netz_max_ack_delay_us",
        }
        detail = " ".join(
            f"{key}={value}" for key, value in memory.items() if key not in excluded
        )
        print(
            f"record=memory implementation={implementation} protocol=webtransport "
            f"transport=h3 mode={args.mode} "
            f"direction={'upload' if args.mode == 'stream-upload' else 'roundtrip'} "
            f"role_pair={args.role_pair} "
            f"endpoint_role={role} connection_scope=persistent "
            f"warmup={args.warmup} iterations={args.iterations} "
            f"streams={args.streams} bytes_per_stream={args.bytes_per_stream} "
            f"payload_bytes={args.payload_bytes} chunk_bytes={args.chunk_bytes} "
            f"stream_window={args.stream_window} timeout_ms={args.timeout_ms} "
            f"rss_scope=whole-process rss_source=gnu-time-maxrss "
            f"process_peak_rss_kib={read_rss(rss_path)} {detail} complete=true"
        )


if __name__ == "__main__":
    main()
