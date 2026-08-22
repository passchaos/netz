const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("support/counting_allocator.zig")
    .CountingAllocator;

const max_payload_bytes: usize = 4096;
const fixed_payload_bytes: usize = max_payload_bytes;
// Exercise both RFC 6455 length encodings and realistic tiny/medium/large
// application messages. Twenty warmups plus 200 measured iterations do not
// divide evenly by six, so accounting uses the exact deterministic schedule.
const mixed_payload_sizes = [_]usize{ 1, 7, 125, 126, 1024, 4096 };
// websocket.zig's client submits mask/header and payload separately, which can
// make long runs expensive on kernels that apply delayed ACK. Keep the shared
// comparison shape short enough for repeated pinned samples while retaining a
// meaningful untimed warmup.
const warmup_iterations: usize = 20;
const iterations: usize = 200;
const max_message_bytes: usize = max_payload_bytes;
const default_connections: usize = 1;
const max_connections: usize = 256;
const fragmented_slices: usize = 16;

pub fn main(init: std.process.Init) !void {
    const options = try parseOptions(init);
    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = if (options.stats)
        counting.allocator()
    else
        std.heap.smp_allocator;
    const connections = options.connections;
    // Every server-side connection handler blocks on its own socket while the
    // matching client runs on an OS thread. An executor capped near the CPU
    // count can therefore strand handlers above that count behind peers that
    // are waiting for their echoes. Unlimited async resources keep this
    // transport-concurrency benchmark from measuring scheduler starvation.
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.websocket.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = max_message_bytes,
            .max_message_bytes = max_message_bytes,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.websocket.runtime.Server,
        result: ?netz.websocket.runtime.ConcurrentServeResult = null,
        accept_error: ?anyerror = null,
        expected_exchanges: usize,
        connection_count: usize,
        compression: bool,
        mixed: bool,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(
                @This(),
                shared,
                handle,
                shared.connection_count,
                .{ .enable_permessage_deflate = shared.compression },
            ) catch |err| {
                shared.accept_error = err;
                return;
            };
        }

        fn handle(
            shared: *@This(),
            connection: *netz.websocket.runtime.Connection,
        ) netz.websocket.runtime.Error!void {
            var storage: [max_message_bytes]u8 align(64) = undefined;
            for (0..shared.expected_exchanges) |iteration| {
                const message = try connection.receiveMessageInto(&storage);
                if (message.opcode != .binary or
                    message.payload.len != payloadLength(
                        shared.mixed,
                        iteration,
                    ))
                {
                    return error.InvalidFrame;
                }
                try connection.sendBinary(message.payload);
            }
        }
    };
    var shared = Shared{
        .server = &server,
        .expected_exchanges = warmup_iterations + iterations,
        .connection_count = connections,
        .compression = options.compression,
        .mixed = options.mixed,
    };
    const server_thread = try std.Thread.spawn(
        .{},
        Shared.run,
        .{&shared},
    );

    const clients = try allocator.alloc(
        netz.websocket.runtime.Connection,
        connections,
    );
    defer allocator.free(clients);
    var connected: usize = 0;
    defer for (clients[0..connected]) |*client| client.close();
    for (clients) |*client| {
        client.* = try netz.websocket.runtime.Client.connect(
            allocator,
            io,
            server.address(),
            .{
                .host = "127.0.0.1",
                .target = "/echo-bench",
                .enable_permessage_deflate = options.compression,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = max_message_bytes,
                    .max_message_bytes = max_message_bytes,
                },
            },
        );
        connected += 1;
    }

    var ready = std.atomic.Value(usize).init(0);
    var failed = std.atomic.Value(bool).init(false);
    var start: std.Io.Event = .unset;
    const worker_errors = try allocator.alloc(?anyerror, connections);
    defer allocator.free(worker_errors);
    @memset(worker_errors, null);
    const finished_ns = try allocator.alloc(u64, connections);
    defer allocator.free(finished_ns);
    @memset(finished_ns, 0);
    const checksums = try allocator.alloc(u64, connections);
    defer allocator.free(checksums);
    @memset(checksums, 0);
    const latency_samples = if (options.latency)
        try allocator.alloc(u64, iterations * connections)
    else
        null;
    defer if (latency_samples) |samples| allocator.free(samples);
    const latency_scratch = if (options.latency)
        try allocator.alloc(u64, iterations * connections)
    else
        null;
    defer if (latency_scratch) |samples| allocator.free(samples);
    const workers = try allocator.alloc(std.Thread, connections);
    defer allocator.free(workers);
    const Worker = struct {
        client: *netz.websocket.runtime.Connection,
        io: std.Io,
        ready: *std.atomic.Value(usize),
        failed: *std.atomic.Value(bool),
        start: *std.Io.Event,
        err: *?anyerror,
        finished_ns: *u64,
        checksum: *u64,
        latency_samples: ?[]u64,
        seed: u8,
        fragmented: bool,
        mixed: bool,

        fn run(worker: *@This()) void {
            runFallible(worker) catch |err| {
                worker.err.* = err;
                worker.failed.store(true, .release);
            };
        }

        fn runFallible(worker: *@This()) !void {
            var payload: [max_payload_bytes]u8 align(64) = undefined;
            var response: [max_payload_bytes]u8 align(64) = undefined;
            for (&payload, 0..) |*byte, index| {
                byte.* = worker.seed +% @as(u8, @truncate(index));
            }
            for (0..warmup_iterations) |iteration| {
                _ = try exchange(
                    worker.client,
                    &payload,
                    &response,
                    worker.fragmented,
                    payloadLength(worker.mixed, iteration),
                );
            }
            _ = worker.ready.fetchAdd(1, .release);
            worker.start.waitUncancelable(worker.io);
            var checksum: u64 = 0;
            for (0..iterations) |iteration| {
                const started = if (worker.latency_samples != null)
                    nowNs(worker.io)
                else
                    0;
                checksum +%= try exchange(
                    worker.client,
                    &payload,
                    &response,
                    worker.fragmented,
                    payloadLength(
                        worker.mixed,
                        warmup_iterations + iteration,
                    ),
                );
                if (worker.latency_samples) |samples| {
                    samples[iteration] = nowNs(worker.io) -| started;
                }
            }
            worker.checksum.* = checksum;
            worker.finished_ns.* = nowNs(worker.io);
        }
    };
    const worker_contexts = try allocator.alloc(Worker, connections);
    defer allocator.free(worker_contexts);
    for (0..connections) |index| {
        worker_contexts[index] = .{
            .client = &clients[index],
            .io = io,
            .ready = &ready,
            .failed = &failed,
            .start = &start,
            .err = &worker_errors[index],
            .finished_ns = &finished_ns[index],
            .checksum = &checksums[index],
            .latency_samples = if (latency_samples) |samples|
                samples[index * iterations ..][0..iterations]
            else
                null,
            .seed = @truncate(index * 17),
            .fragmented = options.fragmented,
            .mixed = options.mixed,
        };
        workers[index] = try std.Thread.spawn(
            .{},
            Worker.run,
            .{&worker_contexts[index]},
        );
    }
    while (ready.load(.acquire) != connections) {
        if (failed.load(.acquire)) break;
        std.Thread.yield() catch {};
    }
    const started = nowNs(io);
    start.set(io);
    for (workers[0..connections]) |worker| worker.join();
    for (worker_errors) |maybe_err| {
        if (maybe_err) |err| return err;
    }
    var finished = started;
    var checksum: u64 = 0;
    for (finished_ns, checksums) |
        worker_finished,
        worker_checksum,
    | {
        finished = @max(finished, worker_finished);
        checksum +%= worker_checksum;
    }
    const elapsed = finished -| started;

    server_thread.join();
    if (shared.accept_error) |err| return err;
    var serve_result = shared.result orelse return error.ServerFailed;
    if (serve_result.firstError()) |err| {
        serve_result.deinit();
        return err;
    }
    serve_result.deinit();
    const measured_roundtrips = iterations * connections;
    const logical_payload_bytes =
        measuredPayloadBytes(options.mixed) * connections;
    const uncompressed_wire_bytes =
        measuredWireBytes(options.mixed) * connections;
    const roundtrips_per_second: u128 = if (elapsed == 0)
        0
    else
        (@as(u128, measured_roundtrips) * std.time.ns_per_s) /
            elapsed;
    std.debug.print(
        \\WebSocket persistent echo benchmark
        \\  connections: {d}
        \\  warmup iterations: {d}
        \\  measured iterations: {d}
        \\  payload schedule: {s}
        \\  logical payload bytes: {d}
        \\  permessage-deflate: {}
        \\  fragmented send slices: {d}
        \\  uncompressed-equivalent wire bytes: {d}
        \\  aggregate ns/roundtrip: {d}
        \\  roundtrips/s: {d}
        \\  uncompressed-equivalent wire MiB/s: {d:.2}
        \\  logical payload MiB/s: {d:.2}
        \\  checksum: {d}
        \\
    , .{
        connections,
        warmup_iterations,
        iterations,
        if (options.mixed) "1,7,125,126,1024,4096" else "4096",
        logical_payload_bytes,
        options.compression,
        if (options.fragmented) fragmented_slices else 1,
        uncompressed_wire_bytes,
        elapsed / measured_roundtrips,
        roundtrips_per_second,
        @as(f64, @floatFromInt(
            @as(u128, uncompressed_wire_bytes) * std.time.ns_per_s /
                @max(elapsed, 1),
        )) /
            (1024.0 * 1024.0),
        @as(f64, @floatFromInt(
            @as(u128, logical_payload_bytes) * std.time.ns_per_s /
                @max(elapsed, 1),
        )) / (1024.0 * 1024.0),
        checksum,
    });
    if (latency_samples) |samples| {
        printLatencyByPayload(
            samples,
            latency_scratch.?,
            options.mixed,
        );
    }
    if (options.stats) {
        const snapshot = counting.snapshot();
        snapshot.print();
    }
}

const Options = struct {
    connections: usize = default_connections,
    compression: bool = false,
    stats: bool = false,
    fragmented: bool = false,
    mixed: bool = false,
    latency: bool = false,
};

fn parseOptions(init: std.process.Init) !Options {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        std.heap.smp_allocator,
    );
    defer args.deinit();
    _ = args.next();
    var options = Options{};
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--connections=")) {
            options.connections = try std.fmt.parseInt(
                usize,
                arg["--connections=".len..],
                10,
            );
        } else if (std.mem.eql(u8, arg, "--compression")) {
            options.compression = true;
        } else if (std.mem.eql(u8, arg, "--stats")) {
            options.stats = true;
        } else if (std.mem.eql(u8, arg, "--fragmented")) {
            options.fragmented = true;
        } else if (std.mem.eql(u8, arg, "--mixed")) {
            options.mixed = true;
        } else if (std.mem.eql(u8, arg, "--latency")) {
            options.latency = true;
        } else {
            return error.InvalidArgument;
        }
    }
    if (options.connections == 0 or options.connections > max_connections) {
        return error.InvalidArgument;
    }
    if (options.fragmented and !options.compression) {
        return error.InvalidArgument;
    }
    return options;
}

fn exchange(
    client: *netz.websocket.runtime.Connection,
    payload: *[max_payload_bytes]u8,
    response_storage: *[max_payload_bytes]u8,
    fragmented: bool,
    payload_len: usize,
) !u64 {
    const data = payload[0..payload_len];
    if (fragmented) {
        var fragments: [fragmented_slices][]const u8 = undefined;
        const fragment_count = @min(fragments.len, data.len);
        for (fragments[0..fragment_count], 0..) |*fragment, index| {
            const start = index * data.len / fragment_count;
            const end = (index + 1) * data.len / fragment_count;
            fragment.* = data[start..end];
        }
        try client.sendFragmented(.binary, fragments[0..fragment_count]);
    } else if (client.permessage_deflate) {
        try client.sendBinary(data);
    } else {
        try client.sendBinaryInPlace(data);
    }
    const response = try client.receiveMessageInto(response_storage);
    if (response.opcode != .binary or
        response.payload.len != payload_len)
    {
        return error.InvalidFrame;
    }
    // sendBinaryInPlace deliberately leaves `payload` masked. Restoring it
    // from the echoed application bytes gives both compared clients the same
    // per-roundtrip copy and the same logical payload on their next send.
    @memcpy(data, response.payload);
    return @as(u64, response.payload[0]) +%
        @as(u64, response.payload[payload_len / 2]) +%
        @as(u64, response.payload[payload_len - 1]);
}

fn payloadLength(mixed: bool, iteration: usize) usize {
    return if (mixed)
        mixed_payload_sizes[iteration % mixed_payload_sizes.len]
    else
        fixed_payload_bytes;
}

fn measuredPayloadBytes(mixed: bool) usize {
    var total: usize = 0;
    for (0..iterations) |iteration| {
        total += payloadLength(mixed, warmup_iterations + iteration) * 2;
    }
    return total;
}

fn measuredWireBytes(mixed: bool) usize {
    var total: usize = 0;
    for (0..iterations) |iteration| {
        const len = payloadLength(mixed, warmup_iterations + iteration);
        total += clientFrameLen(len) + serverFrameLen(len);
    }
    return total;
}

fn clientFrameLen(payload_len: usize) usize {
    return 2 + payloadLengthFieldBytes(payload_len) + 4 + payload_len;
}

fn serverFrameLen(payload_len: usize) usize {
    return 2 + payloadLengthFieldBytes(payload_len) + payload_len;
}

fn payloadLengthFieldBytes(payload_len: usize) usize {
    return if (payload_len <= 125) 0 else if (payload_len <= 65_535) 2 else 8;
}

fn printLatencyByPayload(
    samples: []const u64,
    scratch: []u64,
    mixed: bool,
) void {
    if (mixed) {
        for (mixed_payload_sizes) |payload_bytes| {
            printLatencyClass(samples, scratch, true, payload_bytes);
        }
    } else {
        printLatencyClass(samples, scratch, false, fixed_payload_bytes);
    }
}

fn printLatencyClass(
    samples: []const u64,
    scratch: []u64,
    mixed: bool,
    payload_bytes: usize,
) void {
    var count: usize = 0;
    for (samples, 0..) |sample, index| {
        const iteration = index % iterations;
        if (payloadLength(
            mixed,
            warmup_iterations + iteration,
        ) != payload_bytes) continue;
        scratch[count] = sample;
        count += 1;
    }
    std.mem.sortUnstable(
        u64,
        scratch[0..count],
        {},
        lessThanU64,
    );
    std.debug.print(
        "  payload {d} B latency samples/p50/p99/p99.9 ns: {d}/{d}/{d}/{d}\n",
        .{
            payload_bytes,
            count,
            percentile(scratch[0..count], 50, 100),
            percentile(scratch[0..count], 99, 100),
            percentile(scratch[0..count], 999, 1000),
        },
    );
}

fn percentile(
    sorted: []const u64,
    numerator: usize,
    denominator: usize,
) u64 {
    std.debug.assert(sorted.len != 0);
    const rank = std.math.divCeil(
        usize,
        sorted.len * numerator,
        denominator,
    ) catch unreachable;
    return sorted[@min(sorted.len - 1, rank -| 1)];
}

fn lessThanU64(_: void, lhs: u64, rhs: u64) bool {
    return lhs < rhs;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
