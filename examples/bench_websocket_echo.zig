const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("support/counting_allocator.zig")
    .CountingAllocator;

const payload_bytes: usize = 4096;
// websocket.zig's client submits mask/header and payload separately, which can
// make long runs expensive on kernels that apply delayed ACK. Keep the shared
// comparison shape short enough for repeated pinned samples while retaining a
// meaningful untimed warmup.
const warmup_iterations: usize = 20;
const iterations: usize = 200;
const max_message_bytes: usize = payload_bytes;
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
    var threaded = std.Io.Threaded.init(allocator, .{});
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
            for (0..shared.expected_exchanges) |_| {
                const message = try connection.receiveMessageInto(&storage);
                if (message.opcode != .binary or
                    message.payload.len != payload_bytes)
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
        seed: u8,
        fragmented: bool,

        fn run(worker: *@This()) void {
            runFallible(worker) catch |err| {
                worker.err.* = err;
                worker.failed.store(true, .release);
            };
        }

        fn runFallible(worker: *@This()) !void {
            var payload: [payload_bytes]u8 align(64) = undefined;
            var response: [payload_bytes]u8 align(64) = undefined;
            for (&payload, 0..) |*byte, index| {
                byte.* = worker.seed +% @as(u8, @truncate(index));
            }
            for (0..warmup_iterations) |_| {
                _ = try exchange(
                    worker.client,
                    &payload,
                    &response,
                    worker.fragmented,
                );
            }
            _ = worker.ready.fetchAdd(1, .release);
            worker.start.waitUncancelable(worker.io);
            var checksum: u64 = 0;
            for (0..iterations) |_| {
                checksum +%= try exchange(
                    worker.client,
                    &payload,
                    &response,
                    worker.fragmented,
                );
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
            .seed = @truncate(index * 17),
            .fragmented = options.fragmented,
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
    defer serve_result.deinit();
    if (serve_result.firstError()) |err| return err;
    const uncompressed_roundtrip_wire_bytes =
        // Client frame: 2-byte base + 2-byte extended length + 4-byte mask.
        (2 + 2 + 4 + payload_bytes) +
        // Server frame: 2-byte base + 2-byte extended length.
        (2 + 2 + payload_bytes);
    const logical_roundtrip_bytes = payload_bytes * 2;
    const measured_roundtrips = iterations * connections;
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
        \\  payload bytes: {d}
        \\  permessage-deflate: {}
        \\  fragmented send slices: {d}
        \\  uncompressed-equivalent wire bytes/roundtrip: {d}
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
        payload_bytes,
        options.compression,
        if (options.fragmented) fragmented_slices else 1,
        uncompressed_roundtrip_wire_bytes,
        elapsed / measured_roundtrips,
        roundtrips_per_second,
        @as(f64, @floatFromInt(
            roundtrips_per_second * uncompressed_roundtrip_wire_bytes,
        )) /
            (1024.0 * 1024.0),
        @as(f64, @floatFromInt(
            roundtrips_per_second * logical_roundtrip_bytes,
        )) / (1024.0 * 1024.0),
        checksum,
    });
    if (options.stats) counting.snapshot().print();
}

const Options = struct {
    connections: usize = default_connections,
    compression: bool = false,
    stats: bool = false,
    fragmented: bool = false,
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
    payload: *[payload_bytes]u8,
    response_storage: *[payload_bytes]u8,
    fragmented: bool,
) !u64 {
    if (fragmented) {
        var fragments: [fragmented_slices][]const u8 = undefined;
        for (&fragments, 0..) |*fragment, index| {
            const start = index * payload.len / fragments.len;
            const end = (index + 1) * payload.len / fragments.len;
            fragment.* = payload[start..end];
        }
        try client.sendFragmented(.binary, &fragments);
    } else if (client.permessage_deflate) {
        try client.sendBinary(payload);
    } else {
        try client.sendBinaryInPlace(payload);
    }
    const response = try client.receiveMessageInto(response_storage);
    if (response.opcode != .binary or
        response.payload.len != payload_bytes)
    {
        return error.InvalidFrame;
    }
    // sendBinaryInPlace deliberately leaves `payload` masked. Restoring it
    // from the echoed application bytes gives both compared clients the same
    // per-roundtrip copy and the same logical payload on their next send.
    @memcpy(payload, response.payload);
    return @as(u64, response.payload[0]) +%
        @as(u64, response.payload[payload_bytes / 2]) +%
        @as(u64, response.payload[payload_bytes - 1]);
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
