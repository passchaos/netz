const std = @import("std");
const websocket = @import("websocket");
const CountingAllocator = @import("counting_allocator").CountingAllocator;

const max_payload_bytes: usize = 4096;
const fixed_payload_bytes: usize = max_payload_bytes;
const mixed_payload_sizes = [_]usize{ 1, 7, 125, 126, 1024, 4096 };
const warmup_iterations: usize = 20;
const iterations: usize = 200;
const default_connections: usize = 1;
const max_connections: usize = 256;

const Context = struct {
    mixed: bool,
};

const Handler = struct {
    conn: *websocket.Conn,
    mixed: bool,
    iteration: usize = 0,

    pub fn init(
        _: *const websocket.Handshake,
        conn: *websocket.Conn,
        context: *Context,
    ) !Handler {
        return .{ .conn = conn, .mixed = context.mixed };
    }

    pub fn clientMessage(
        self: *Handler,
        data: []const u8,
        message_type: websocket.MessageTextType,
    ) !void {
        if (message_type != .binary or
            data.len != payloadLength(self.mixed, self.iteration))
        {
            return error.InvalidMessage;
        }
        self.iteration += 1;
        try self.conn.writeBin(data);
    }
};

pub fn main(init: std.process.Init) !void {
    const options = try parseOptions(init, std.heap.smp_allocator);
    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = if (options.stats)
        counting.allocator()
    else
        std.heap.smp_allocator;
    const io = init.io;
    const connections = options.connections;
    var server = try websocket.Server(Handler).init(io, allocator, .{
        .port = 9924,
        .address = "127.0.0.1",
        .max_conn = connections,
        .max_message_size = max_payload_bytes,
        .thread_pool = .{ .buffer_size = max_payload_bytes + 32 },
        .buffers = .{
            .small_size = max_payload_bytes + 32,
            // Blocking mode allocates one small buffer per connection; the
            // configured pool is unused and only produces a warning.
            .small_pool = 1,
            .large_size = max_payload_bytes + 32,
            .large_pool = 2,
        },
    });
    defer server.deinit();
    var context = Context{ .mixed = options.mixed };
    const server_thread = try server.listenInNewThread(&context);

    const clients = try allocator.alloc(websocket.Client, connections);
    defer allocator.free(clients);
    var connected: usize = 0;
    defer for (clients[0..connected]) |*client| client.deinit();
    for (clients) |*client| {
        client.* = try websocket.Client.init(io, allocator, .{
            .port = 9924,
            .host = "127.0.0.1",
            .max_size = max_payload_bytes,
            .buffer_size = max_payload_bytes + 32,
        });
        connected += 1;
        if (options.enable_tcp_nodelay) {
            try setTcpNoDelay(client.stream.stream.socket.handle);
        }
        try client.handshake("/echo-bench", .{
            .headers = "Host: 127.0.0.1:9924",
        });
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
        client: *websocket.Client,
        io: std.Io,
        ready: *std.atomic.Value(usize),
        failed: *std.atomic.Value(bool),
        start: *std.Io.Event,
        err: *?anyerror,
        finished_ns: *u64,
        checksum: *u64,
        latency_samples: ?[]u64,
        seed: u8,
        mixed: bool,

        fn run(worker: *@This()) void {
            runFallible(worker) catch |err| {
                worker.err.* = err;
                worker.failed.store(true, .release);
            };
        }

        fn runFallible(worker: *@This()) !void {
            var payload: [max_payload_bytes]u8 align(64) = undefined;
            for (&payload, 0..) |*byte, index| {
                byte.* = worker.seed +% @as(u8, @truncate(index));
            }
            for (0..warmup_iterations) |iteration| {
                _ = try exchange(
                    worker.client,
                    &payload,
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

    for (clients) |*client| try client.close(.{});
    server.stop();
    server_thread.join();

    const measured_roundtrips = iterations * connections;
    const logical_payload_bytes =
        measuredPayloadBytes(options.mixed) * connections;
    const wire_bytes = measuredWireBytes(options.mixed) * connections;
    const roundtrips_per_second: u128 = if (elapsed == 0)
        0
    else
        (@as(u128, measured_roundtrips) * std.time.ns_per_s) /
            elapsed;
    std.debug.print(
        \\websocket.zig persistent echo benchmark
        \\  connections: {d}
        \\  warmup iterations: {d}
        \\  measured iterations: {d}
        \\  payload schedule: {s}
        \\  logical payload bytes: {d}
        \\  TCP_NODELAY: {}
        \\  wire bytes: {d}
        \\  aggregate ns/roundtrip: {d}
        \\  roundtrips/s: {d}
        \\  wire MiB/s: {d:.2}
        \\  checksum: {d}
        \\
    , .{
        connections,
        warmup_iterations,
        iterations,
        if (options.mixed) "1,7,125,126,1024,4096" else "4096",
        logical_payload_bytes,
        options.enable_tcp_nodelay,
        wire_bytes,
        elapsed / measured_roundtrips,
        roundtrips_per_second,
        @as(f64, @floatFromInt(
            @as(u128, wire_bytes) * std.time.ns_per_s / @max(elapsed, 1),
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
    if (options.stats) counting.snapshot().print();
}

const Options = struct {
    connections: usize = default_connections,
    enable_tcp_nodelay: bool = false,
    mixed: bool = false,
    stats: bool = false,
    latency: bool = false,
};

fn parseOptions(
    init: std.process.Init,
    allocator: std.mem.Allocator,
) !Options {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--tcp-nodelay")) {
            options.enable_tcp_nodelay = true;
        } else if (std.mem.eql(u8, arg, "--mixed")) {
            options.mixed = true;
        } else if (std.mem.eql(u8, arg, "--stats")) {
            options.stats = true;
        } else if (std.mem.eql(u8, arg, "--latency")) {
            options.latency = true;
        } else if (std.mem.startsWith(u8, arg, "--connections=")) {
            options.connections = try std.fmt.parseInt(
                usize,
                arg["--connections=".len..],
                10,
            );
        } else {
            return error.InvalidArgument;
        }
    }
    if (options.connections == 0 or options.connections > max_connections) {
        return error.InvalidArgument;
    }
    return options;
}

fn setTcpNoDelay(handle: std.Io.net.Socket.Handle) !void {
    const value: c_int = 1;
    try std.posix.setsockopt(
        handle,
        std.os.linux.IPPROTO.TCP,
        std.os.linux.TCP.NODELAY,
        std.mem.asBytes(&value),
    );
}

fn exchange(
    client: *websocket.Client,
    payload: *[max_payload_bytes]u8,
    payload_len: usize,
) !u64 {
    const data = payload[0..payload_len];
    try client.writeBin(data);
    const message = (try client.read()) orelse return error.MissingMessage;
    defer client.done(message);
    if (message.type != .binary or message.data.len != payload_len) {
        return error.InvalidMessage;
    }
    @memcpy(data, message.data);
    return @as(u64, message.data[0]) +%
        @as(u64, message.data[payload_len / 2]) +%
        @as(u64, message.data[payload_len - 1]);
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
