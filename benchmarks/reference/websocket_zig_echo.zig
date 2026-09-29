const std = @import("std");
const websocket = @import("websocket");
const zio = @import("zio");
const CountingAllocator = @import("counting_allocator").CountingAllocator;

const max_payload_bytes: usize = 4096;
const fixed_payload_bytes: usize = max_payload_bytes;
const mixed_payload_sizes = [_]usize{ 1, 7, 125, 126, 1024, 4096 };
const default_warmup_iterations: usize = 20;
const default_iterations: usize = 200;
const default_connections: usize = 1;
const max_connections: usize = 256;

const Context = struct {
    mixed: bool,
    mostly_idle: bool,
    expected_exchanges: usize,
};

const Handler = struct {
    conn: *websocket.Conn,
    mixed: bool,
    iteration: usize = 0,
    classified: bool,
    active: bool = true,
    expected_exchanges: usize,

    pub fn init(
        _: *const websocket.Handshake,
        conn: *websocket.Conn,
        context: *Context,
    ) !Handler {
        return .{
            .conn = conn,
            .mixed = context.mixed,
            .classified = !context.mostly_idle,
            .expected_exchanges = context.expected_exchanges,
        };
    }

    pub fn clientMessage(
        self: *Handler,
        data: []const u8,
        message_type: websocket.MessageTextType,
    ) !void {
        if (!self.classified) {
            if (message_type != .binary or data.len != 1 or
                (data[0] != 0 and data[0] != 1))
            {
                return error.InvalidMessage;
            }
            self.active = data[0] == 1;
            self.classified = true;
            try self.conn.writeBin(data);
            return;
        }
        if (!self.active or self.iteration == self.expected_exchanges) {
            if (message_type != .binary or !std.mem.eql(u8, data, &.{2})) {
                return error.InvalidMessage;
            }
            try self.conn.writeBin(data);
            return;
        }
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
    const runtime = try zio.Runtime.init(std.heap.smp_allocator, .{});
    defer runtime.deinit();
    const io = runtime.io();
    const connections = options.connections;
    const active_connections = options.active_connections orelse connections;
    const mostly_idle = active_connections != connections;
    var server = try websocket.Server(Handler).init(io, allocator, .{
        .port = options.port,
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
    var context = Context{
        .mixed = options.mixed,
        .mostly_idle = mostly_idle,
        .expected_exchanges = options.warmup_iterations + options.iterations,
    };
    const server_thread = try server.listenInNewThread(&context);

    const clients = try allocator.alloc(websocket.Client, connections);
    defer allocator.free(clients);
    var connected: usize = 0;
    defer for (clients[0..connected]) |*client| client.deinit();
    for (clients) |*client| {
        client.* = try websocket.Client.init(io, allocator, .{
            .port = options.port,
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
    var all_ready: std.Io.Event = .unset;
    var start: std.Io.Event = .unset;
    var workload_done: std.Io.Event = .unset;
    var finish: std.Io.Event = .unset;
    var finished_workloads = std.atomic.Value(usize).init(0);
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
        try allocator.alloc(u64, options.iterations * active_connections)
    else
        null;
    defer if (latency_samples) |samples| allocator.free(samples);
    const latency_scratch = if (options.latency)
        try allocator.alloc(u64, options.iterations * active_connections)
    else
        null;
    defer if (latency_scratch) |samples| allocator.free(samples);
    var workers: std.Io.Group = .init;
    defer workers.cancel(io);
    const Worker = struct {
        client: *websocket.Client,
        io: std.Io,
        ready: *std.atomic.Value(usize),
        failed: *std.atomic.Value(bool),
        all_ready: *std.Io.Event,
        start: *std.Io.Event,
        err: *?anyerror,
        finished_ns: *u64,
        checksum: *u64,
        latency_samples: ?[]u64,
        seed: u8,
        mixed: bool,
        connections: usize,
        active: bool,
        mostly_idle: bool,
        finished_workloads: *std.atomic.Value(usize),
        workload_done: *std.Io.Event,
        finish: *std.Io.Event,
        warmup_iterations: usize,
        iterations: usize,

        fn run(worker: *@This()) void {
            runFallible(worker) catch |err| {
                worker.err.* = err;
                worker.failed.store(true, .release);
                worker.all_ready.set(worker.io);
                worker.start.set(worker.io);
                worker.workload_done.set(worker.io);
                worker.finish.set(worker.io);
            };
        }

        fn runFallible(worker: *@This()) !void {
            var payload: [max_payload_bytes]u8 align(64) = undefined;
            for (&payload, 0..) |*byte, index| {
                byte.* = worker.seed +% @as(u8, @truncate(index));
            }
            if (worker.mostly_idle) {
                payload[0] = @intFromBool(worker.active);
                const classification = try exchange(worker.client, &payload, 1);
                if (classification != @as(u64, @intFromBool(worker.active)) * 3) {
                    return error.InvalidMessage;
                }
                payload[0] = worker.seed;
            }
            for (0..if (worker.active) worker.warmup_iterations else 0) |iteration| {
                _ = try exchange(
                    worker.client,
                    &payload,
                    payloadLength(worker.mixed, iteration),
                );
            }
            const previously_ready = worker.ready.fetchAdd(1, .acq_rel);
            if (previously_ready + 1 == worker.connections) {
                worker.all_ready.set(worker.io);
            }
            worker.start.waitUncancelable(worker.io);
            var checksum: u64 = 0;
            for (0..if (worker.active) worker.iterations else 0) |iteration| {
                const started = if (worker.latency_samples != null)
                    nowNs(worker.io)
                else
                    0;
                checksum +%= try exchange(
                    worker.client,
                    &payload,
                    payloadLength(
                        worker.mixed,
                        worker.warmup_iterations + iteration,
                    ),
                );
                if (worker.latency_samples) |samples| {
                    samples[iteration] = nowNs(worker.io) -| started;
                }
            }
            worker.checksum.* = checksum;
            worker.finished_ns.* = nowNs(worker.io);
            if (worker.mostly_idle) {
                const previous = worker.finished_workloads.fetchAdd(1, .acq_rel);
                if (previous + 1 == worker.connections)
                    worker.workload_done.set(worker.io);
                worker.finish.waitUncancelable(worker.io);
                payload[0] = 2;
                if (try exchange(worker.client, &payload, 1) != 6) {
                    return error.InvalidMessage;
                }
            }
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
            .all_ready = &all_ready,
            .start = &start,
            .err = &worker_errors[index],
            .finished_ns = &finished_ns[index],
            .checksum = &checksums[index],
            .latency_samples = if (latency_samples) |samples|
                if (index < active_connections)
                    samples[index * options.iterations ..][0..options.iterations]
                else
                    null
            else
                null,
            .seed = @truncate(index * 17),
            .mixed = options.mixed,
            .connections = connections,
            .active = index < active_connections,
            .mostly_idle = mostly_idle,
            .finished_workloads = &finished_workloads,
            .workload_done = &workload_done,
            .finish = &finish,
            .warmup_iterations = options.warmup_iterations,
            .iterations = options.iterations,
        };
        workers.async(io, Worker.run, .{&worker_contexts[index]});
    }
    all_ready.waitUncancelable(io);
    const started = nowNs(io);
    start.set(io);
    if (mostly_idle) workload_done.waitUncancelable(io);
    const live_snapshot = if (options.stats and mostly_idle)
        counting.snapshot()
    else
        null;
    if (mostly_idle) finish.set(io);
    try workers.await(io);
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

    if (mostly_idle) {
        for (clients) |*client| client.deinit();
        connected = 0;
    } else {
        for (clients) |*client| try client.close(.{});
    }
    server.stop();
    server_thread.join();

    const measured_roundtrips = options.iterations * active_connections;
    const logical_payload_bytes =
        measuredPayloadBytes(
            options.mixed,
            options.warmup_iterations,
            options.iterations,
        ) * active_connections;
    const wire_bytes = measuredWireBytes(
        options.mixed,
        options.warmup_iterations,
        options.iterations,
    ) * active_connections;
    const roundtrips_per_second: u128 = if (elapsed == 0)
        0
    else
        (@as(u128, measured_roundtrips) * std.time.ns_per_s) /
            elapsed;
    std.debug.print(
        \\websocket.zig persistent echo benchmark
        \\  io backend: zio-std-io
        \\  connections: {d}
        \\  active connections: {d}
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
        active_connections,
        options.warmup_iterations,
        options.iterations,
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
    std.debug.print(
        "record=result implementation=websocket-zig protocol=websocket-h1 " ++
            "transport=tcp mode=binary-echo role_pair=websocket-zig-self " ++
            "client_io=zio-std-io server_io=websocket-zig-worker " ++
            "connection_scope=persistent benchmark_scope={s} " ++
            "connections={d} active_connections={d} idle_connections={d} " ++
            "warmup={d} iterations={d} payload_bytes={d} " ++
            "payload_schedule={s} send_shape=contiguous parts=1 " ++
            "compression=false tcp_nodelay={} logical_bytes={d} " ++
            "elapsed_ns={d} checksum={d} complete=true\n",
        .{
            if (mostly_idle) "mostly-idle-buffer-retention" else "same-application-shape",
            connections,
            active_connections,
            connections - active_connections,
            options.warmup_iterations,
            options.iterations,
            fixed_payload_bytes,
            if (options.mixed) "mixed" else "fixed",
            options.enable_tcp_nodelay,
            logical_payload_bytes,
            elapsed,
            checksum,
        },
    );
    if (latency_samples) |samples| {
        printLatencyByPayload(
            samples,
            latency_scratch.?,
            options.mixed,
            options.warmup_iterations,
            options.iterations,
        );
    }
    if (options.stats) {
        const snapshot = live_snapshot orelse counting.snapshot();
        snapshot.print();
        if (mostly_idle) {
            std.debug.print(
                "record=memory implementation=websocket-zig protocol=websocket-h1 " ++
                    "transport=tcp role_pair=websocket-zig-self process_scope=client+server " ++
                    "client_io=zio-std-io server_io=websocket-zig-worker " ++
                    "benchmark_scope=mostly-idle-buffer-retention " ++
                    "memory_stage=connections-live-after-workload " ++
                    "connections={d} active_connections={d} idle_connections={d} " ++
                    "warmup={d} iterations={d} payload_bytes={d} payload_schedule={s} " ++
                    "send_shape=contiguous parts=1 compression=false tcp_nodelay={} " ++
                    "allocator_scope=explicit-library-and-harness " ++
                    "alloc_count={d} free_count={d} resize_count={d} remap_count={d} " ++
                    "total_allocated_bytes={d} total_freed_bytes={d} live_bytes={d} " ++
                    "peak_live_bytes={d} checksum={d} complete=true\n",
                .{
                    connections,                             active_connections,         connections - active_connections,
                    options.warmup_iterations,               options.iterations,         fixed_payload_bytes,
                    if (options.mixed) "mixed" else "fixed", options.enable_tcp_nodelay, snapshot.alloc_count,
                    snapshot.free_count,                     snapshot.resize_count,      snapshot.remap_count,
                    snapshot.total_allocated,                snapshot.total_freed,       snapshot.current_bytes,
                    snapshot.peak_bytes,                     checksum,
                },
            );
        }
    }
}

const Options = struct {
    connections: usize = default_connections,
    active_connections: ?usize = null,
    enable_tcp_nodelay: bool = false,
    mixed: bool = false,
    stats: bool = false,
    latency: bool = false,
    warmup_iterations: usize = default_warmup_iterations,
    iterations: usize = default_iterations,
    port: u16 = 9924,
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
        } else if (std.mem.startsWith(u8, arg, "--active-connections=")) {
            options.active_connections = try std.fmt.parseInt(
                usize,
                arg["--active-connections=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup_iterations = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--port=")) {
            options.port = try std.fmt.parseInt(
                u16,
                arg["--port=".len..],
                10,
            );
        } else {
            return error.InvalidArgument;
        }
    }
    if (options.connections == 0 or options.connections > max_connections) {
        return error.InvalidArgument;
    }
    if (options.active_connections) |active| {
        if (active == 0 or active > options.connections) return error.InvalidArgument;
    }
    if (options.iterations == 0) return error.InvalidArgument;
    if (options.port == 0) return error.InvalidArgument;
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

fn measuredPayloadBytes(
    mixed: bool,
    warmup_count: usize,
    iteration_count: usize,
) usize {
    var total: usize = 0;
    for (0..iteration_count) |iteration| {
        total += payloadLength(mixed, warmup_count + iteration) * 2;
    }
    return total;
}

fn measuredWireBytes(
    mixed: bool,
    warmup_count: usize,
    iteration_count: usize,
) usize {
    var total: usize = 0;
    for (0..iteration_count) |iteration| {
        const len = payloadLength(mixed, warmup_count + iteration);
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
    warmup_count: usize,
    iteration_count: usize,
) void {
    if (mixed) {
        for (mixed_payload_sizes) |payload_bytes| {
            printLatencyClass(
                samples,
                scratch,
                true,
                warmup_count,
                iteration_count,
                payload_bytes,
            );
        }
    } else {
        printLatencyClass(
            samples,
            scratch,
            false,
            warmup_count,
            iteration_count,
            fixed_payload_bytes,
        );
    }
}

fn printLatencyClass(
    samples: []const u64,
    scratch: []u64,
    mixed: bool,
    warmup_count: usize,
    iteration_count: usize,
    payload_bytes: usize,
) void {
    var count: usize = 0;
    for (samples, 0..) |sample, index| {
        const iteration = index % iteration_count;
        if (payloadLength(
            mixed,
            warmup_count + iteration,
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
