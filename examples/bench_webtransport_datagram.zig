const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 10_000;
const max_batch_size: usize = netz.quic.one_rtt.max_batch_packets;
const default_ping_payload = "webtransport bench datagram";
const default_burst_payload = "webtransport bounded burst datagram";
const max_payload_bytes: usize = 1024;

const Config = struct {
    iterations: usize = default_iterations,
    send_timeout_ms: i64 = 1000,
    burst: bool = false,
    batch_size: usize = 1,
    max_in_flight: ?usize = null,
    payload_bytes: ?usize = null,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const config = try parseArgs(init, allocator);
    if (config.burst) return runBurst(allocator, config);
    return runPingPong(allocator, config);
}

fn runPingPong(allocator: std.mem.Allocator, config: Config) !void {
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try netz.webtransport.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    });
    defer server.deinit();

    const Shared = struct {
        server: *netz.webtransport.runtime.Server,
        iterations: usize,
        err: ?anyerror = null,
        handled: usize = 0,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept();
            defer accepted.deinit(shared.server.h3.quic_server.endpoint.allocator);

            while (shared.handled < shared.iterations) : (shared.handled += 1) {
                var datagram = try shared.server.receiveDatagram();
                defer datagram.deinit(shared.server.h3.quic_server.endpoint.allocator);
                if (datagram.datagram.session_id.value != accepted.session_id.value) {
                    return error.UnexpectedSessionId;
                }
                try shared.server.sendDatagram(
                    datagram.quic_datagram.from,
                    accepted.session_id,
                    datagram.datagram.payload,
                );
            }
        }
    };

    var shared = Shared{ .server = &server, .iterations = config.iterations };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try netz.webtransport.runtime.ClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/bench-wt",
            .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        },
    );
    defer client.deinit();

    var payload_storage: [max_payload_bytes]u8 = undefined;
    const payload = benchmarkPayload(&payload_storage, config);
    const start = nowNs(io);
    var checksum: usize = 0;
    for (0..config.iterations) |_| {
        try client.sendDatagram(payload);
        var response = try client.receiveDatagram();
        defer response.deinit(allocator);
        if (response.datagram.session_id.value != client.session_id.value) {
            return error.UnexpectedSessionId;
        }
        checksum +%= response.datagram.payload.len;
        checksum +%= response.datagram.payload[0];
    }
    const elapsed = nowNs(io) -| start;
    const datagrams = config.iterations * 2;
    const datagrams_per_second = if (elapsed == 0)
        0
    else
        (@as(u64, datagrams) *| std.time.ns_per_s) / elapsed;

    server_task.await(io);
    if (shared.err) |err| return err;

    std.debug.print(
        \\WebTransport datagram runtime benchmark
        \\  io backend: zio-std-io
        \\  iterations: {d}
        \\  datagrams: {d}
        \\  payload bytes: {d}
        \\  checksum: {d}
        \\  ns/roundtrip: {d}
        \\  ns/datagram: {d}
        \\  datagrams/s: {d}
        \\
    , .{
        config.iterations,
        datagrams,
        payload.len,
        checksum,
        elapsed / config.iterations,
        elapsed / datagrams,
        datagrams_per_second,
    });
}

fn runBurst(allocator: std.mem.Allocator, config: Config) !void {
    try runBurstHandshake(allocator, config);
}

fn runBurstHandshake(allocator: std.mem.Allocator, config: Config) !void {
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x44, 0x01, 0x57, 0x54, 0x44, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x44, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x44, 0x04 };
    const payload_len = payloadLen(config);
    const queued_bytes = std.math.mul(
        usize,
        config.iterations,
        payload_len,
    ) catch return error.InvalidArgument;
    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x45} ** 32,
                .x25519_secret_key = [_]u8{0x46} ** 32,
            },
            .session = .{
                .max_queued_connect_datagrams = config.iterations,
                .max_queued_connect_datagram_bytes = queued_bytes,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.webtransport.runtime.HandshakeServer,
        sent: *std.atomic.Value(usize),
        done: *std.Io.Event,
        received: std.atomic.Value(usize) = .init(0),
        checksum: u64 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept();
            defer accepted.deinit();
            var post_done_timeouts: usize = 0;
            while (!self.done.isSet() or
                self.received.load(.acquire) < self.sent.load(.acquire))
            {
                var datagram = accepted.receiveDatagramWithTimeout(
                    .fromMilliseconds(10),
                ) catch |err| switch (err) {
                    error.Timeout => {
                        if (self.done.isSet()) {
                            post_done_timeouts += 1;
                            if (post_done_timeouts == 100) {
                                return error.MissingDatagram;
                            }
                        }
                        continue;
                    },
                    else => return err,
                };
                post_done_timeouts = 0;
                defer datagram.deinit(
                    accepted.h3.established.connection.endpoint.allocator,
                );
                for (datagram.datagram.payload) |byte| self.checksum +%= byte;
                _ = self.received.fetchAdd(1, .release);
            }
        }
    };
    var sent: std.atomic.Value(usize) = .init(0);
    var done: std.Io.Event = .unset;
    var shared = Shared{
        .server = &server,
        .sent = &sent,
        .done = &done,
    };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try netz.webtransport.runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/bench-wt-burst",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            } } },
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x47} ** 32,
                .x25519_secret_key = [_]u8{0x48} ** 32,
            } },
        },
    );
    defer client.deinit();
    const result = try runBurstSends(
        allocator,
        io,
        &client,
        &sent,
        &shared.received,
        config,
    );
    done.set(io);
    server_task.await(io);
    if (shared.err) |err| return err;
    const received = shared.received.load(.acquire);
    if (received != result.sent) return error.InvalidDatagramCount;
    var expected_checksum = payloadChecksum(config);
    expected_checksum *%= result.sent;
    if (shared.checksum != expected_checksum) return error.InvalidChecksum;
    printBurstResult(result, received, shared.checksum);
}

const BurstSendResult = struct {
    attempted: usize,
    sent: usize,
    timed_out: usize,
    batch_size: usize,
    max_in_flight: usize,
    send_calls: usize,
    payload_bytes: usize,
    elapsed_ns: u64,
    p50_ns: u64,
    p99_ns: u64,
};

fn runBurstSends(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *netz.webtransport.runtime.HandshakeClientSession,
    sent_count: *std.atomic.Value(usize),
    received_count: *const std.atomic.Value(usize),
    config: Config,
) !BurstSendResult {
    var payload_storage: [max_payload_bytes]u8 = undefined;
    const payload = benchmarkPayload(&payload_storage, config);
    const latencies = try allocator.alloc(u64, config.iterations);
    defer allocator.free(latencies);
    const started = nowNs(io);
    var success_count: usize = 0;
    var timeout_count: usize = 0;
    var send_calls: usize = 0;
    const timeout = std.Io.Duration.fromMilliseconds(
        config.send_timeout_ms,
    );
    const payloads = try allocator.alloc([]const u8, config.batch_size);
    defer allocator.free(payloads);
    @memset(payloads, payload);
    while (success_count + timeout_count < config.iterations) {
        const remaining = config.iterations - success_count - timeout_count;
        const count = @min(
            config.batch_size,
            remaining,
            config.max_in_flight orelse std.math.maxInt(usize),
        );
        try waitForBurstWindow(
            io,
            success_count,
            received_count,
            count,
            config,
        );
        const send_started = nowNs(io);
        var committed: usize = 0;
        send_calls += 1;
        client.sendDatagramsWithTimeout(
            payloads[0..count],
            &committed,
            timeout,
        ) catch |err|
            switch (err) {
                error.Timeout => {
                    const elapsed = nowNs(io) -| send_started;
                    if (committed != 0) {
                        for (latencies[success_count..][0..committed]) |*latency| {
                            latency.* = elapsed / committed;
                        }
                    }
                    success_count += committed;
                    timeout_count += count - committed;
                    sent_count.store(success_count, .release);
                    continue;
                },
                else => return err,
            };
        const elapsed = nowNs(io) -| send_started;
        for (latencies[success_count..][0..committed]) |*latency| {
            latency.* = elapsed / committed;
        }
        success_count += committed;
        sent_count.store(success_count, .release);
    }
    const elapsed = nowNs(io) -| started;
    if (success_count == 0) return error.BenchmarkTimeout;
    const samples = latencies[0..success_count];
    std.mem.sort(u64, samples, {}, lessThanU64);
    return .{
        .attempted = config.iterations,
        .sent = success_count,
        .timed_out = timeout_count,
        .batch_size = config.batch_size,
        .max_in_flight = config.max_in_flight orelse 0,
        .send_calls = send_calls,
        .payload_bytes = payload.len,
        .elapsed_ns = elapsed,
        .p50_ns = percentile(samples, 50, 100),
        .p99_ns = percentile(samples, 99, 100),
    };
}

fn printBurstResult(
    result: BurstSendResult,
    received: usize,
    checksum: u64,
) void {
    std.debug.print(
        "WebTransport real-handshake bounded DATAGRAM burst: " ++
            "io_backend=zio-std-io attempted={d} " ++
            "sent={d} timed_out={d} received={d} payload_bytes={d} " ++
            "batch_size={d} max_in_flight={d} send_calls={d} " ++
            "logical_MiB/s={d:.2} send_p50_ns={d} send_p99_ns={d} " ++
            "checksum={d}\n",
        .{
            result.attempted,
            result.sent,
            result.timed_out,
            received,
            result.payload_bytes,
            result.batch_size,
            result.max_in_flight,
            result.send_calls,
            mibPerSecond(
                result.sent * result.payload_bytes,
                result.elapsed_ns,
            ),
            result.p50_ns,
            result.p99_ns,
            checksum,
        },
    );
}

fn parseArgs(init: std.process.Init, allocator: std.mem.Allocator) !Config {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var config: Config = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--burst")) {
            config.burst = true;
        } else if (std.mem.startsWith(u8, arg, "--batch-size=")) {
            config.batch_size = try std.fmt.parseInt(
                usize,
                arg["--batch-size=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            config.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
            if (config.iterations == 0) return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--max-in-flight=")) {
            config.max_in_flight = try std.fmt.parseInt(
                usize,
                arg["--max-in-flight=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--payload-bytes=")) {
            config.payload_bytes = try std.fmt.parseInt(
                usize,
                arg["--payload-bytes=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--send-timeout-ms=")) {
            config.send_timeout_ms = try std.fmt.parseInt(
                i64,
                arg["--send-timeout-ms=".len..],
                10,
            );
            if (config.send_timeout_ms <= 0) return error.InvalidArgument;
        } else return error.InvalidArgument;
    }
    if (config.batch_size == 0 or config.batch_size > max_batch_size) {
        return error.InvalidArgument;
    }
    if (config.payload_bytes) |payload_bytes| {
        if (payload_bytes == 0 or payload_bytes > max_payload_bytes) {
            return error.InvalidArgument;
        }
    }
    if (config.max_in_flight) |max_in_flight| {
        if (max_in_flight == 0) return error.InvalidArgument;
    }
    if (!config.burst and
        (config.batch_size != 1 or config.max_in_flight != null))
    {
        return error.InvalidArgument;
    }
    return config;
}

fn waitForBurstWindow(
    io: std.Io,
    sent: usize,
    received_count: *const std.atomic.Value(usize),
    next_count: usize,
    config: Config,
) !void {
    const limit = config.max_in_flight orelse return;
    const started = nowNs(io);
    const timeout_ns = std.math.mul(
        u64,
        @as(u64, @intCast(config.send_timeout_ms)),
        std.time.ns_per_ms,
    ) catch std.math.maxInt(u64);
    while (true) {
        const received = received_count.load(.acquire);
        const outstanding = sent -| received;
        if (outstanding <= limit - next_count) return;
        if (nowNs(io) -| started >= timeout_ns) return error.BenchmarkTimeout;
        try std.Io.sleep(io, .fromMicroseconds(1), .awake);
    }
}

fn payloadLen(config: Config) usize {
    return config.payload_bytes orelse if (config.burst)
        default_burst_payload.len
    else
        default_ping_payload.len;
}

fn benchmarkPayload(
    storage: *[max_payload_bytes]u8,
    config: Config,
) []const u8 {
    if (config.payload_bytes) |payload_bytes| {
        @memset(storage[0..payload_bytes], 0x5a);
        return storage[0..payload_bytes];
    }
    const payload = if (config.burst)
        default_burst_payload
    else
        default_ping_payload;
    @memcpy(storage[0..payload.len], payload);
    return storage[0..payload.len];
}

fn payloadChecksum(config: Config) u64 {
    if (config.payload_bytes) |payload_bytes| {
        return 0x5a * @as(u64, @intCast(payload_bytes));
    }
    const payload = if (config.burst)
        default_burst_payload
    else
        default_ping_payload;
    var checksum: u64 = 0;
    for (payload) |byte| checksum +%= byte;
    return checksum;
}

fn lessThanU64(_: void, a: u64, b: u64) bool {
    return a < b;
}

fn percentile(sorted: []const u64, numerator: usize, denominator: usize) u64 {
    const rank = (sorted.len * numerator + denominator - 1) / denominator;
    return sorted[@min(sorted.len - 1, @max(@as(usize, 1), rank) - 1)];
}

fn mibPerSecond(bytes: usize, elapsed_ns: u64) f64 {
    if (elapsed_ns == 0) return 0;
    return (@as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0)) /
        (@as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s);
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
