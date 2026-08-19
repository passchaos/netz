const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("support/counting_allocator.zig")
    .CountingAllocator;

// Match ~/Work/quicz/examples/quic_bench_hs.zig by default: each sample uses
// a fresh real TLS 1.3 handshake, a 64 MiB aggregate upload, and CUBIC.
const default_iterations: usize = 5;
const default_transfer_bytes: usize = 64 * 1024 * 1024;
const default_streams: usize = 1;
const default_echo_iterations: usize = 5000;
const echo_payload_bytes: usize = 1024;
const default_stream_churn_iterations: usize = 100_000;
const stream_churn_credit: u64 = 1_048_576;
const max_streams: usize = 64;
const max_datagram_size: usize = 8900;
const stream_payload_size: usize = max_datagram_size - 128;
// Keep the benchmark close to quicz's ordinary UDP path. GSO/GRO have their
// own netz benchmark; disabling them here avoids turning raw STREAM comparison
// into a test of experimental coalesced receive behavior.
const max_packet_batch_size: usize = netz.quic.one_rtt.max_batch_packets;
const flow_control_floor: u64 = 256 * 1024 * 1024;
const transfer_timeout_ns: u64 = 30 * std.time.ns_per_s;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const benchmark_server_key_bytes = [32]u8{
    0x9b, 0xce, 0xc3, 0x15, 0x18, 0x9b, 0x65, 0xee,
    0x7a, 0xe0, 0xd7, 0x1d, 0xec, 0x0d, 0x1c, 0xa6,
    0xb3, 0xf4, 0x67, 0x72, 0x4e, 0x0c, 0x8e, 0x14,
    0xd4, 0x6a, 0xa2, 0xd2, 0x69, 0xd1, 0xa9, 0xae,
};
const benchmark_server_public = [65]u8{
    0x04, 0x6a, 0x96, 0x1e, 0x4a, 0x09, 0x85, 0x77,
    0xd5, 0x2e, 0xa2, 0x86, 0x11, 0x86, 0xda, 0xe0,
    0x6b, 0xd3, 0x69, 0x39, 0x6d, 0x44, 0x4a, 0xc0,
    0x95, 0x12, 0xf7, 0xfb, 0xfc, 0x8a, 0xb6, 0x62,
    0xb8, 0xb2, 0xd1, 0x3e, 0x9f, 0x36, 0xed, 0x52,
    0xb2, 0x41, 0xd8, 0xdd, 0x24, 0x16, 0x6f, 0xd8,
    0x1d, 0x0b, 0xae, 0xcb, 0x12, 0x88, 0x86, 0xc7,
    0xda, 0x00, 0xd1, 0x63, 0x6d, 0x47, 0xe8, 0xa7,
    0xdf,
};

fn makeBenchmarkServerKey() !EcdsaP256Sha256.KeyPair {
    // P-256 public-key derivation is expensive but the benchmark identity is
    // immutable. Materialize the KeyPair once per process so each iteration
    // measures a fresh TLS signature, not redundant long-term key loading.
    const secret = try EcdsaP256Sha256.SecretKey.fromBytes(
        benchmark_server_key_bytes,
    );
    return EcdsaP256Sha256.KeyPair.fromSecretKey(secret);
}

const Mode = enum { upload, handshake, echo, stream_churn };

pub fn main(init: std.process.Init) !void {
    const config = try parseArgs(init, std.heap.smp_allocator);
    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = if (config.stats)
        counting.allocator()
    else
        std.heap.smp_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const server_key = try makeBenchmarkServerKey();

    if (config.mode == .handshake) {
        try runHandshakeBenchmark(allocator, io, config, server_key);
        if (config.stats) counting.snapshot().print();
        return;
    }
    if (config.mode == .echo) {
        try runEchoBenchmark(allocator, io, config, server_key);
        if (config.stats) counting.snapshot().print();
        return;
    }
    if (config.mode == .stream_churn) {
        try runStreamChurnBenchmark(allocator, io, config, server_key);
        if (config.stats) counting.snapshot().print();
        return;
    }

    const samples = try allocator.alloc(f64, config.iterations);
    defer allocator.free(samples);

    var aggregate_stats: AggregateStats = .{};
    for (samples, 0..) |*sample, iteration| {
        const result = try runIteration(
            allocator,
            io,
            config,
            iteration,
            server_key,
        );
        sample.* = mibPerSecond(config.transfer_bytes, result.elapsed_ns);
        aggregate_stats.add(result.client_stats, result.payload_bytes_received);
        if (config.verbose) {
            std.debug.print(
                "  [iter {d}] {d:.2} MiB/s, packets={d}, lost={d}, gso={}\n",
                .{
                    iteration,
                    sample.*,
                    result.client_stats.packets_sent,
                    result.client_stats.packets_lost,
                    result.gso_enabled,
                },
            );
        }
    }

    const summary = summarize(samples);
    std.debug.print(
        \\QUIC real-handshake STREAM upload benchmark
        \\  streams: {d}
        \\  iterations: {d}
        \\  transfer bytes/iteration: {d}
        \\  stream payload bytes/packet: {d}
        \\  mean MiB/s: {d:.2}
        \\  stddev MiB/s: {d:.2}
        \\  stddev percent: {d:.2}
        \\  packets sent: {d}
        \\  packets lost: {d}
        \\  payload bytes received: {d}
        \\
    , .{
        config.streams,
        config.iterations,
        config.transfer_bytes,
        stream_payload_size,
        summary.mean,
        summary.stddev,
        if (summary.mean == 0) 0 else summary.stddev * 100.0 / summary.mean,
        aggregate_stats.packets_sent,
        aggregate_stats.packets_lost,
        aggregate_stats.payload_bytes_received,
    });
    if (config.stats) counting.snapshot().print();
}

const Config = struct {
    mode: Mode = .upload,
    iterations: usize = default_iterations,
    transfer_bytes: usize = default_transfer_bytes,
    streams: usize = default_streams,
    batch_packets: usize = 1,
    verbose: bool = false,
    enable_hystart: bool = true,
    enable_pacing: bool = true,
    stats: bool = false,
};

const IterationResult = struct {
    elapsed_ns: u64,
    client_stats: netz.quic.one_rtt.ConnectionStats,
    gso_enabled: bool,
    payload_bytes_received: usize,
};

const Summary = struct {
    mean: f64,
    stddev: f64,
};

const AggregateStats = struct {
    packets_sent: u64 = 0,
    packets_lost: u64 = 0,
    payload_bytes_received: usize = 0,

    fn add(
        self: *AggregateStats,
        stats: netz.quic.one_rtt.ConnectionStats,
        payload_bytes_received: usize,
    ) void {
        self.packets_sent +|= stats.packets_sent;
        self.packets_lost +|= stats.packets_lost;
        self.payload_bytes_received +|= payload_bytes_received;
    }
};

fn runIteration(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    iteration: usize,
    server_key: EcdsaP256Sha256.KeyPair,
) !IterationResult {
    const transport_parameters = transferTransportParameters(config);
    const endpoint_limits: netz.quic.runtime.Limits = .{
        .max_datagram_size = max_datagram_size,
        .max_frames_per_datagram = 32,
        .socket_receive_buffer_bytes = 16 * 1024 * 1024,
        .enable_gso_send = false,
        .enable_gro_receive = false,
    };
    const one_rtt_config: netz.quic.handshake.OneRttConfig = .{
        .max_datagram_size = max_datagram_size,
        .congestion_algorithm = .cubic,
        .enable_hystart = config.enable_hystart,
        .enable_pacing = config.enable_pacing,
        .receive_window = flow_control_floor,
        .max_receive_window = flow_control_floor,
        .stream_receive_window = flow_control_floor,
        .max_stream_receive_window = flow_control_floor,
    };

    var server_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        endpoint_limits,
    );
    defer server_endpoint.deinit();
    var client_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        endpoint_limits,
    );
    defer client_endpoint.deinit();

    var server_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    server_cid[0] +%= @truncate(iteration);

    const Shared = struct {
        endpoint: *netz.quic.runtime.Endpoint,
        server_cid: []const u8,
        transport_parameters: netz.quic.TransportParameters,
        one_rtt_config: netz.quic.handshake.OneRttConfig,
        transfer_bytes: usize,
        streams: usize,
        batch_packets: usize,
        ready: *std.atomic.Value(bool),
        finished: *std.atomic.Value(bool),
        failed: *std.atomic.Value(bool),
        cancelled: *std.atomic.Value(bool),
        bytes_received: *std.atomic.Value(usize),
        verbose: bool,
        handshake_only: bool,
        echo_only: bool,
        echo_connection: *?netz.quic.handshake.EstablishedConnection,
        server_key: EcdsaP256Sha256.KeyPair,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
                shared.failed.store(true, .release);
                if (shared.verbose) {
                    std.debug.print("  server error: {}\n", .{err});
                }
            };
        }

        fn runFallible(shared: *@This()) !void {
            var established = try netz.quic.handshake.accept(
                shared.endpoint,
                .{
                    .local_connection_id = shared.server_cid,
                    .alpn_protocol = "netz-quic-bench",
                    .local_transport_parameters = shared.transport_parameters,
                    .initial_one_rtt_config = shared.one_rtt_config,
                    .random = [_]u8{0x61} ** 32,
                    .x25519_secret_key = [_]u8{0x62} ** 32,
                    .key_exchange_groups = &.{.x25519},
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    // Exercise the authenticated TLS 1.3 path just like the
                    // quicz handshake workload: send Certificate and create
                    // a P-256 CertificateVerify signature on every sample.
                    .identity = .{
                        .certificate_chain = &.{&benchmark_server_public},
                        .signer = .{ .ecdsa_p256_sha256 = .{
                            .key_pair = shared.server_key,
                        } },
                    },
                    .max_crypto_buffer = 64 * 1024,
                },
            );
            if (shared.echo_only) {
                // Transfer ownership to the benchmark thread. This mirrors
                // quicz's sequential post-handshake loop so echo latency does
                // not include one executor handoff per half round trip.
                shared.echo_connection.* = established;
                shared.ready.store(true, .release);
                return;
            }
            defer established.deinit();
            shared.ready.store(true, .release);
            if (shared.handshake_only) {
                shared.finished.store(true, .release);
                return;
            }
            var packets_since_ack: usize = 0;
            while (shared.bytes_received.load(.acquire) <
                shared.transfer_bytes)
            {
                if (shared.cancelled.load(.acquire)) return;
                var packet = established.connection.receivePacketTimeout(
                    progressPollTimeout(),
                ) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return err,
                };
                packet.deinit(shared.endpoint.allocator);
                packets_since_ack += 1;
                if (packets_since_ack >= shared.batch_packets) {
                    try established.connection.sendAck(0);
                    packets_since_ack = 0;
                }
                try drainReceivedStreams(
                    &established.connection,
                    shared.streams,
                    shared.bytes_received,
                );
            }
            if (packets_since_ack != 0) {
                try established.connection.sendAck(0);
            }
            for (0..shared.streams) |stream_index| {
                if (!established.connection.receivedStreamComplete(
                    streamId(stream_index),
                )) return error.IncompleteStream;
            }
            shared.finished.store(true, .release);
        }
    };

    var ready = std.atomic.Value(bool).init(false);
    var finished = std.atomic.Value(bool).init(false);
    var failed = std.atomic.Value(bool).init(false);
    var cancelled = std.atomic.Value(bool).init(false);
    var bytes_received = std.atomic.Value(usize).init(0);
    var echo_connection: ?netz.quic.handshake.EstablishedConnection = null;
    var shared = Shared{
        .endpoint = &server_endpoint,
        .server_cid = &server_cid,
        .transport_parameters = transport_parameters,
        .one_rtt_config = one_rtt_config,
        .transfer_bytes = config.transfer_bytes,
        .streams = config.streams,
        .batch_packets = config.batch_packets,
        .ready = &ready,
        .finished = &finished,
        .failed = &failed,
        .cancelled = &cancelled,
        .bytes_received = &bytes_received,
        .verbose = config.verbose,
        .handshake_only = config.mode == .handshake or
            config.mode == .stream_churn,
        .echo_only = config.mode == .echo,
        .echo_connection = &echo_connection,
        .server_key = server_key,
    };
    // Use the benchmark's existing I/O executor rather than creating and
    // destroying an OS thread for every fresh connection. `concurrent` still
    // guarantees the blocking accept has an execution resource before the
    // client starts, so it cannot be deferred behind connect.
    var server_future = try std.Io.concurrent(io, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        cancelled.store(true, .release);
        // Wake the server's blocking UDP receive on a failed client path.
        // The malformed packet is local-only and causes the worker to return;
        // its error is secondary to the client error already being unwound.
        client_endpoint.sendBytes(
            server_endpoint.address(),
            &.{0},
        ) catch {};
        server_future.await(io);
    };

    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);
    // Keep the latency sample focused on the live TLS/QUIC exchange. Endpoint
    // construction and connection teardown remain inside the outer rate timer,
    // matching quicz's split between handshake latency and new-connection rate.
    const handshake_started_ns = nowNs(io);
    var established = try netz.quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .alpn_protocols = &.{"netz-quic-bench"},
            // quicz's reference benchmark negotiates X25519 and
            // TLS_AES_128_GCM_SHA256. Pinning both avoids accidentally timing
            // netz's default post-quantum hybrid offer in this comparison.
            .key_exchange_groups = &.{.x25519},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            // A raw SEC1 public key is valid for this benchmark's pinned-key
            // identity and avoids making certificate-chain policy part of the
            // transport handshake measurement.
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = benchmark_server_public,
            },
            .local_transport_parameters = transport_parameters,
            .initial_one_rtt_config = one_rtt_config,
            .max_crypto_buffer = 64 * 1024,
            .handshake_recovery = .{
                .initial_pto_ms = 250,
                .max_pto_ms = 2000,
                .max_retries = 4,
                .max_duration_ms = 10_000,
            },
        },
    );
    defer established.deinit();

    while (!ready.load(.acquire)) {
        if (failed.load(.acquire)) return shared.err orelse error.ServerFailed;
        std.Thread.yield() catch {};
    }
    if (config.mode == .handshake) {
        const elapsed_ns = nowNs(io) -| handshake_started_ns;
        server_future.await(io);
        joined = true;
        if (shared.err) |err| return err;
        return .{
            .elapsed_ns = elapsed_ns,
            .client_stats = established.connection.stats(),
            .gso_enabled = client_endpoint.gsoSendEnabled(),
            .payload_bytes_received = 0,
        };
    }
    if (config.mode == .stream_churn) {
        const result = try measureStreamChurn(
            &established.connection,
            config.iterations,
        );
        server_future.await(io);
        joined = true;
        if (shared.err) |err| return err;
        return .{
            .elapsed_ns = result.elapsed_ns,
            .client_stats = established.connection.stats(),
            .gso_enabled = client_endpoint.gsoSendEnabled(),
            .payload_bytes_received = result.opened,
        };
    }
    if (config.mode == .echo) {
        server_future.await(io);
        joined = true;
        if (shared.err) |err| return err;
        var server_established = echo_connection orelse
            return error.ServerFailed;
        defer server_established.deinit();
        const result = try runEchoRounds(
            allocator,
            &established.connection,
            &server_established.connection,
            config.iterations,
        );
        return .{
            .elapsed_ns = result.elapsed_ns,
            .client_stats = established.connection.stats(),
            .gso_enabled = client_endpoint.gsoSendEnabled(),
            .payload_bytes_received = result.payload_bytes_received,
        };
    }

    const started_ns = nowNs(io);
    const deadline_ns = started_ns +| transfer_timeout_ns;
    try sendTransfer(
        &established.connection,
        config,
        &failed,
        &shared.err,
        deadline_ns,
    );
    try waitForReceiver(
        &established.connection,
        &finished,
        &failed,
        &shared.err,
        deadline_ns,
    );
    const elapsed_ns = nowNs(io) -| started_ns;

    cancelled.store(true, .release);
    server_future.await(io);
    joined = true;
    if (shared.err) |err| return err;
    const received = bytes_received.load(.acquire);
    if (received != config.transfer_bytes) return error.InvalidTransferSize;

    return .{
        .elapsed_ns = elapsed_ns,
        .client_stats = established.connection.stats(),
        .gso_enabled = client_endpoint.gsoSendEnabled(),
        .payload_bytes_received = received,
    };
}

fn drainReceivedStreams(
    connection: *netz.quic.one_rtt.Connection,
    streams: usize,
    total_received: *std.atomic.Value(usize),
) !void {
    for (0..streams) |stream_index| {
        const available = connection.availableReceivedStream(
            streamId(stream_index),
        ) orelse continue;
        const count = available.len;
        if (count == 0) continue;
        try connection.releaseReceivedCapacity(
            streamId(stream_index),
            count,
        );
        _ = total_received.fetchAdd(count, .release);
    }
}

const EchoResult = struct {
    elapsed_ns: u64,
    payload_bytes_received: usize,
};

fn runEchoRounds(
    allocator: std.mem.Allocator,
    client: *netz.quic.one_rtt.Connection,
    server: *netz.quic.one_rtt.Connection,
    iterations: usize,
) !EchoResult {
    const latencies = try allocator.alloc(u64, iterations);
    defer allocator.free(latencies);
    var payload: [echo_payload_bytes]u8 = @splat('E');
    const benchmark_started = nowNs(client.endpoint.io);
    for (latencies, 0..) |*latency, iteration| {
        const offset = std.math.mul(
            u64,
            iteration,
            echo_payload_bytes,
        ) catch return error.InvalidEchoPayload;
        const started = nowNs(client.endpoint.io);
        const frame = netz.quic.Frame{ .stream = .{
            .stream_id = 0,
            .offset = offset,
            .data = &payload,
            .fin = false,
        } };
        if (iteration == 0) {
            try client.send(&.{frame});
        } else {
            // Each request carries the ACK for the preceding response, just
            // as the server response carries the ACK for this request.
            try client.sendWithPendingAck(&.{frame}, 0);
        }
        try server.servicePacket();
        const request = server.availableReceivedStream(0) orelse
            return error.MissingEchoPayload;
        if (request.len != echo_payload_bytes or
            !std.mem.eql(u8, request, &payload))
        {
            return error.InvalidEchoPayload;
        }
        try server.sendWithPendingAck(&.{.{ .stream = .{
            .stream_id = 0,
            .offset = offset,
            .data = request,
            .fin = false,
        } }}, 0);
        try server.releaseReceivedCapacity(0, request.len);

        try client.servicePacket();
        const echoed = client.availableReceivedStream(0) orelse
            return error.MissingEchoPayload;
        if (echoed.len != echo_payload_bytes or
            !std.mem.eql(u8, echoed, &payload))
        {
            return error.InvalidEchoPayload;
        }
        latency.* = nowNs(client.endpoint.io) -| started;
        try client.releaseReceivedCapacity(0, echoed.len);
    }
    const elapsed = nowNs(client.endpoint.io) -| benchmark_started;
    std.mem.sort(u64, latencies, {}, lessThanU64);
    const roundtrips_per_second: f64 = if (elapsed == 0)
        0.0
    else
        @as(f64, @floatFromInt(iterations)) *
            @as(f64, @floatFromInt(std.time.ns_per_s)) /
            @as(f64, @floatFromInt(elapsed));
    const verified = std.math.mul(
        usize,
        iterations,
        echo_payload_bytes,
    ) catch return error.InvalidEchoPayload;
    std.debug.print(
        "QUIC real TLS 1.3 STREAM echo benchmark\n" ++
            "  iterations: {d}\n" ++
            "  payload bytes/roundtrip: {d}\n" ++
            "  roundtrips/s: {d:.1}\n" ++
            "  p50 ns: {d}\n" ++
            "  p99 ns: {d}\n" ++
            "  p99.9 ns: {d}\n" ++
            "  payload bytes verified: {d}\n",
        .{
            iterations,
            echo_payload_bytes,
            roundtrips_per_second,
            percentile(latencies, 50, 100),
            percentile(latencies, 99, 100),
            percentile(latencies, 999, 1000),
            verified,
        },
    );
    return .{
        .elapsed_ns = elapsed,
        .payload_bytes_received = verified,
    };
}

const StreamChurnResult = struct { elapsed_ns: u64, opened: usize };

fn measureStreamChurn(
    connection: *netz.quic.one_rtt.Connection,
    iterations: usize,
) !StreamChurnResult {
    var checksum: u64 = 0;
    const started = nowNs(connection.endpoint.io);
    for (0..iterations) |_| {
        const stream_id = try connection.openStream();
        checksum +%= stream_id;
        // Keep every state transition observable to the optimizer, matching
        // benchmark harness black-box semantics rather than timing a folded
        // arithmetic series.
        std.mem.doNotOptimizeAway(stream_id);
    }
    const elapsed = nowNs(connection.endpoint.io) -| started;
    std.mem.doNotOptimizeAway(checksum);
    const streams_per_second: f64 = if (elapsed == 0)
        0.0
    else
        @as(f64, @floatFromInt(iterations)) *
            @as(f64, @floatFromInt(std.time.ns_per_s)) /
            @as(f64, @floatFromInt(elapsed));
    std.debug.print(
        "QUIC real TLS 1.3 stream open benchmark\n" ++
            "  streams opened: {d}\n" ++
            "  elapsed ns: {d}\n" ++
            "  streams/s: {d:.0}\n" ++
            "  last stream id: {d}\n" ++
            "  checksum: {d}\n",
        .{
            iterations,
            elapsed,
            streams_per_second,
            (iterations - 1) * 4,
            checksum,
        },
    );
    return .{ .elapsed_ns = elapsed, .opened = iterations };
}

fn sendTransfer(
    connection: *netz.quic.one_rtt.Connection,
    config: Config,
    server_failed: *std.atomic.Value(bool),
    server_err: *?anyerror,
    deadline_ns: u64,
) !void {
    var payload: [stream_payload_size]u8 = undefined;
    @memset(&payload, 'S');
    var sent: [max_streams]usize = @splat(0);
    var frame_storage: [max_packet_batch_size][1]netz.quic.Frame = undefined;
    var packets: [max_packet_batch_size][]const netz.quic.Frame = undefined;
    var packet_streams: [max_packet_batch_size]usize = undefined;
    var packet_lengths: [max_packet_batch_size]usize = undefined;
    var next_stream: usize = 0;
    var total_sent: usize = 0;

    while (total_sent < config.transfer_bytes) {
        if (nowNs(connection.endpoint.io) >= deadline_ns) {
            return error.BenchmarkTimeout;
        }
        if (server_failed.load(.acquire)) {
            return server_err.* orelse error.ServerFailed;
        }

        var packet_count: usize = 0;
        var simulated_sent = sent;
        var simulated_total = total_sent;
        var stream_cursor = next_stream;
        while (packet_count < config.batch_packets and
            simulated_total < config.transfer_bytes)
        {
            const stream_index = nextPendingStream(
                config,
                &simulated_sent,
                stream_cursor,
            ) orelse break;
            const target = bytesForStream(
                config.transfer_bytes,
                config.streams,
                stream_index,
            );
            const count = @min(
                payload.len,
                target - simulated_sent[stream_index],
            );
            const end = simulated_sent[stream_index] + count;
            frame_storage[packet_count][0] = .{ .stream = .{
                .stream_id = streamId(stream_index),
                .offset = simulated_sent[stream_index],
                .data = payload[0..count],
                .fin = end == target,
            } };
            packets[packet_count] = &frame_storage[packet_count];
            packet_streams[packet_count] = stream_index;
            packet_lengths[packet_count] = count;
            simulated_sent[stream_index] = end;
            simulated_total += count;
            stream_cursor = (stream_index + 1) % config.streams;
            packet_count += 1;
        }
        if (packet_count == 0) return error.InvalidTransferSize;

        const result = connection.sendManyProgressAt(
            packets[0..packet_count],
            nowNs(connection.endpoint.io),
        ) catch |err| switch (err) {
            error.CongestionLimited, error.FlowControlBlocked => {
                try receiveClientProgress(
                    connection,
                    server_failed,
                    server_err,
                    deadline_ns,
                );
                continue;
            },
            // The transport's pacing deadline is private; wait for a short
            // scheduling quantum and retry rather than turning normal pacing
            // backpressure into a benchmark failure.
            error.PacingLimited => {
                try std.Io.sleep(
                    connection.endpoint.io,
                    .fromMicroseconds(10),
                    .awake,
                );
                continue;
            },
            else => return err,
        };
        if (result.send_error) |err| return err;
        if (result.sent_count != result.protected_count or
            result.sent_count == 0)
        {
            return error.PartialDatagramSend;
        }
        for (0..result.sent_count) |packet_index| {
            const stream_index = packet_streams[packet_index];
            sent[stream_index] += packet_lengths[packet_index];
            total_sent += packet_lengths[packet_index];
            next_stream = (stream_index + 1) % config.streams;
        }
        // Both endpoints run in this process. Yield once per sendmmsg batch so
        // the receiver can drain loopback before a large CUBIC window fills the
        // host's sysctl-capped UDP queue. Real deployments naturally get this
        // scheduling boundary from their event loop or network RTT.
        std.Thread.yield() catch {};
    }
}

fn receiveClientProgress(
    connection: *netz.quic.one_rtt.Connection,
    server_failed: *std.atomic.Value(bool),
    server_err: *?anyerror,
    deadline_ns: u64,
) !void {
    while (true) {
        if (server_failed.load(.acquire)) {
            return server_err.* orelse error.ServerFailed;
        }
        if (nowNs(connection.endpoint.io) >= deadline_ns) {
            return error.BenchmarkTimeout;
        }
        var packet = connection.receivePacketTimeout(
            progressPollTimeout(),
        ) catch |err| switch (err) {
            error.Timeout => {
                _ = connection.serviceNextTimerAt(
                    nowNs(connection.endpoint.io),
                ) catch |timer_err| switch (timer_err) {
                    error.CongestionLimited => {},
                    error.PacingLimited => {},
                    else => return timer_err,
                };
                continue;
            },
            else => return err,
        };
        packet.deinit(connection.endpoint.allocator);
        _ = try connection.retransmitPacketThresholdLosses(
            netz.quic.one_rtt.max_batch_packets,
        );
        return;
    }
}

fn waitForReceiver(
    connection: *netz.quic.one_rtt.Connection,
    finished: *std.atomic.Value(bool),
    server_failed: *std.atomic.Value(bool),
    server_err: *?anyerror,
    deadline_ns: u64,
) !void {
    while (!finished.load(.acquire)) {
        try receiveClientProgress(
            connection,
            server_failed,
            server_err,
            deadline_ns,
        );
    }
}

fn nextPendingStream(
    config: Config,
    sent: *const [max_streams]usize,
    start: usize,
) ?usize {
    for (0..config.streams) |delta| {
        const index = (start + delta) % config.streams;
        if (sent[index] < bytesForStream(
            config.transfer_bytes,
            config.streams,
            index,
        )) return index;
    }
    return null;
}

fn streamId(index: usize) u64 {
    return @as(u64, @intCast(index)) * 4;
}

fn bytesForStream(total: usize, streams: usize, index: usize) usize {
    const base = total / streams;
    const remainder = total % streams;
    return base + if (index < remainder) @as(usize, 1) else 0;
}

fn transferTransportParameters(config: Config) netz.quic.TransportParameters {
    var params = netz.quic.practical_transport_parameters;
    const transfer_u64 = std.math.cast(u64, config.transfer_bytes) orelse
        netz.quic.varint.max_value;
    const desired = transfer_u64 +| 1024 * 1024;
    const credit = @min(
        @max(flow_control_floor, desired),
        netz.quic.varint.max_value,
    );
    params.initial_max_data = credit;
    params.initial_max_stream_data_bidi_local = credit;
    params.initial_max_stream_data_bidi_remote = credit;
    params.initial_max_stream_data_uni = credit;
    params.initial_max_streams_bidi = if (config.mode == .stream_churn)
        stream_churn_credit
    else
        max_streams;
    params.initial_max_streams_uni = max_streams;
    params.max_udp_payload_size = max_datagram_size;
    return params;
}

fn parseArgs(
    init: std.process.Init,
    allocator: std.mem.Allocator,
) !Config {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();

    var config: Config = .{};
    var iterations_set = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--mode=upload")) {
            config.mode = .upload;
        } else if (std.mem.eql(u8, arg, "--mode=handshake")) {
            config.mode = .handshake;
        } else if (std.mem.eql(u8, arg, "--mode=echo")) {
            config.mode = .echo;
        } else if (std.mem.eql(u8, arg, "--mode=stream-churn")) {
            config.mode = .stream_churn;
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            config.iterations = try parsePositiveUsize(
                arg["--iterations=".len..],
            );
            iterations_set = true;
        } else if (std.mem.startsWith(u8, arg, "--transfer-bytes=")) {
            config.transfer_bytes = try parsePositiveUsize(
                arg["--transfer-bytes=".len..],
            );
        } else if (std.mem.startsWith(u8, arg, "--streams=")) {
            config.streams = try parsePositiveUsize(
                arg["--streams=".len..],
            );
        } else if (std.mem.startsWith(u8, arg, "--batch-packets=")) {
            config.batch_packets = try parsePositiveUsize(
                arg["--batch-packets=".len..],
            );
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
        } else if (std.mem.eql(u8, arg, "--stats")) {
            config.stats = true;
        } else if (std.mem.eql(u8, arg, "--disable-hystart")) {
            config.enable_hystart = false;
        } else if (std.mem.eql(u8, arg, "--disable-pacing")) {
            config.enable_pacing = false;
        } else {
            return error.InvalidArgument;
        }
    }
    if (config.mode == .echo and !iterations_set) {
        config.iterations = default_echo_iterations;
    }
    if (config.mode == .stream_churn and !iterations_set) {
        config.iterations = default_stream_churn_iterations;
    }
    if (config.mode == .echo) config.transfer_bytes =
        config.iterations *| echo_payload_bytes;
    if (config.mode == .stream_churn and
        config.iterations > stream_churn_credit)
    {
        return error.InvalidArgument;
    }
    if (config.streams > max_streams or
        config.batch_packets > max_packet_batch_size or
        config.streams > config.transfer_bytes)
    {
        return error.InvalidArgument;
    }
    return config;
}

fn runEchoBenchmark(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    server_key: EcdsaP256Sha256.KeyPair,
) !void {
    const result = try runIteration(
        allocator,
        io,
        config,
        0,
        server_key,
    );
    const expected = std.math.mul(
        usize,
        config.iterations,
        echo_payload_bytes,
    ) catch return error.InvalidEchoPayload;
    if (result.payload_bytes_received != expected) {
        return error.InvalidEchoPayload;
    }
}

fn runStreamChurnBenchmark(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    server_key: EcdsaP256Sha256.KeyPair,
) !void {
    const result = try runIteration(
        allocator,
        io,
        config,
        0,
        server_key,
    );
    if (result.payload_bytes_received != config.iterations) {
        return error.InvalidStreamCount;
    }
}

fn runHandshakeBenchmark(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    server_key: EcdsaP256Sha256.KeyPair,
) !void {
    const latencies = try allocator.alloc(u64, config.iterations);
    defer allocator.free(latencies);
    const started = nowNs(io);
    for (latencies, 0..) |*latency, iteration| {
        const result = try runIteration(
            allocator,
            io,
            config,
            iteration,
            server_key,
        );
        latency.* = result.elapsed_ns;
        if (config.verbose) {
            std.debug.print(
                "  [iter {d}] {d} ns\n",
                .{ iteration, latency.* },
            );
        }
    }
    const elapsed = nowNs(io) -| started;
    std.mem.sort(u64, latencies, {}, lessThanU64);
    const connections_per_second: f64 = if (elapsed == 0)
        0.0
    else
        @as(f64, @floatFromInt(config.iterations)) *
            @as(f64, @floatFromInt(std.time.ns_per_s)) /
            @as(f64, @floatFromInt(elapsed));
    std.debug.print("QUIC real TLS 1.3 handshake benchmark\n" ++
        "  iterations: {d}\n" ++
        "  total elapsed ns: {d}\n" ++
        "  connections/s: {d:.1}\n" ++
        "  p50 ns: {d}\n" ++
        "  p99 ns: {d}\n" ++
        "  p99.9 ns: {d}\n", .{
        config.iterations,
        elapsed,
        connections_per_second,
        percentile(latencies, 50, 100),
        percentile(latencies, 99, 100),
        percentile(latencies, 999, 1000),
    });
}

fn percentile(
    sorted: []const u64,
    numerator: usize,
    denominator: usize,
) u64 {
    std.debug.assert(sorted.len != 0);
    std.debug.assert(denominator != 0 and numerator <= denominator);
    // quicz selects sorted[len * percentile / 100]. Using the same zero-based
    // convention makes the reported tails directly comparable rather than
    // introducing a one-sample shift for the 200-iteration latency workload.
    const scaled_index =
        @as(u128, sorted.len) * @as(u128, numerator) / denominator;
    const index: usize = @intCast(@min(
        scaled_index,
        @as(u128, sorted.len - 1),
    ));
    return sorted[index];
}

fn lessThanU64(_: void, a: u64, b: u64) bool {
    return a < b;
}

fn parsePositiveUsize(raw: []const u8) !usize {
    const value = try std.fmt.parseInt(usize, raw, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

fn summarize(samples: []const f64) Summary {
    var mean: f64 = 0;
    for (samples) |sample| mean += sample;
    mean /= @floatFromInt(samples.len);

    var variance: f64 = 0;
    for (samples) |sample| {
        const delta = sample - mean;
        variance += delta * delta;
    }
    variance /= @floatFromInt(samples.len);
    return .{ .mean = mean, .stddev = @sqrt(variance) };
}

fn mibPerSecond(bytes: usize, elapsed_ns: u64) f64 {
    if (elapsed_ns == 0) return 0;
    const mib = @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
    const seconds =
        @as(f64, @floatFromInt(elapsed_ns)) /
        @as(f64, @floatFromInt(std.time.ns_per_s));
    return mib / seconds;
}

fn progressPollTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(1),
    } };
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
