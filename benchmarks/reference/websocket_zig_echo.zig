const std = @import("std");
const websocket = @import("websocket");

const payload_bytes: usize = 4096;
const warmup_iterations: usize = 20;
const iterations: usize = 200;
const default_connections: usize = 1;
const max_connections: usize = 16;

const Context = struct {};

const Handler = struct {
    conn: *websocket.Conn,

    pub fn init(
        _: *const websocket.Handshake,
        conn: *websocket.Conn,
        _: *Context,
    ) !Handler {
        return .{ .conn = conn };
    }

    pub fn clientMessage(
        self: *Handler,
        data: []const u8,
        message_type: websocket.MessageTextType,
    ) !void {
        if (message_type != .binary or data.len != payload_bytes) {
            return error.InvalidMessage;
        }
        try self.conn.writeBin(data);
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const io = init.io;
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var enable_tcp_nodelay = false;
    var connections = default_connections;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--tcp-nodelay")) {
            enable_tcp_nodelay = true;
        } else if (std.mem.startsWith(u8, arg, "--connections=")) {
            connections = try std.fmt.parseInt(
                usize,
                arg["--connections=".len..],
                10,
            );
        } else {
            return error.InvalidArgument;
        }
    }
    if (connections == 0 or connections > max_connections) {
        return error.InvalidArgument;
    }
    var server = try websocket.Server(Handler).init(io, allocator, .{
        .port = 9924,
        .address = "127.0.0.1",
        .worker_count = @intCast(connections),
        .max_conn = connections,
        .max_message_size = payload_bytes,
        .thread_pool = .{ .buffer_size = payload_bytes + 32 },
        .buffers = .{
            .small_size = payload_bytes + 32,
            .small_pool = 2,
            .large_size = payload_bytes + 32,
            .large_pool = 2,
        },
    });
    defer server.deinit();
    var context = Context{};
    const server_thread = try server.listenInNewThread(&context);

    const clients = try allocator.alloc(websocket.Client, connections);
    defer allocator.free(clients);
    var connected: usize = 0;
    defer for (clients[0..connected]) |*client| client.deinit();
    for (clients) |*client| {
        client.* = try websocket.Client.init(io, allocator, .{
            .port = 9924,
            .host = "127.0.0.1",
            .max_size = payload_bytes,
            .buffer_size = payload_bytes + 32,
        });
        connected += 1;
        if (enable_tcp_nodelay) {
            try setTcpNoDelay(client.stream.stream.socket.handle);
        }
        try client.handshake("/echo-bench", .{
            .headers = "Host: 127.0.0.1:9924",
        });
    }

    var ready = std.atomic.Value(usize).init(0);
    var failed = std.atomic.Value(bool).init(false);
    var start: std.Io.Event = .unset;
    var worker_errors: [max_connections]?anyerror =
        .{null} ** max_connections;
    var finished_ns: [max_connections]u64 =
        .{0} ** max_connections;
    var checksums: [max_connections]u64 =
        .{0} ** max_connections;
    var workers: [max_connections]std.Thread = undefined;
    const Worker = struct {
        client: *websocket.Client,
        io: std.Io,
        ready: *std.atomic.Value(usize),
        failed: *std.atomic.Value(bool),
        start: *std.Io.Event,
        err: *?anyerror,
        finished_ns: *u64,
        checksum: *u64,
        seed: u8,

        fn run(worker: *@This()) void {
            runFallible(worker) catch |err| {
                worker.err.* = err;
                worker.failed.store(true, .release);
            };
        }

        fn runFallible(worker: *@This()) !void {
            var payload: [payload_bytes]u8 align(64) = undefined;
            for (&payload, 0..) |*byte, index| {
                byte.* = worker.seed +% @as(u8, @truncate(index));
            }
            for (0..warmup_iterations) |_| {
                _ = try exchange(worker.client, &payload);
            }
            _ = worker.ready.fetchAdd(1, .release);
            worker.start.waitUncancelable(worker.io);
            var checksum: u64 = 0;
            for (0..iterations) |_| {
                checksum +%= try exchange(worker.client, &payload);
            }
            worker.checksum.* = checksum;
            worker.finished_ns.* = nowNs(worker.io);
        }
    };
    var worker_contexts: [max_connections]Worker = undefined;
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
    for (worker_errors[0..connections]) |maybe_err| {
        if (maybe_err) |err| return err;
    }
    var finished = started;
    var checksum: u64 = 0;
    for (finished_ns[0..connections], checksums[0..connections]) |
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

    const roundtrip_wire_bytes =
        (2 + 2 + 4 + payload_bytes) +
        (2 + 2 + payload_bytes);
    const measured_roundtrips = iterations * connections;
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
        \\  payload bytes: {d}
        \\  TCP_NODELAY: {}
        \\  wire bytes/roundtrip: {d}
        \\  aggregate ns/roundtrip: {d}
        \\  roundtrips/s: {d}
        \\  wire MiB/s: {d:.2}
        \\  checksum: {d}
        \\
    , .{
        connections,
        warmup_iterations,
        iterations,
        payload_bytes,
        enable_tcp_nodelay,
        roundtrip_wire_bytes,
        elapsed / measured_roundtrips,
        roundtrips_per_second,
        @as(f64, @floatFromInt(
            roundtrips_per_second * roundtrip_wire_bytes,
        )) / (1024.0 * 1024.0),
        checksum,
    });
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
    payload: *[payload_bytes]u8,
) !u64 {
    try client.writeBin(payload);
    const message = (try client.read()) orelse return error.MissingMessage;
    defer client.done(message);
    if (message.type != .binary or message.data.len != payload_bytes) {
        return error.InvalidMessage;
    }
    @memcpy(payload, message.data);
    return @as(u64, message.data[0]) +%
        @as(u64, message.data[payload_bytes / 2]) +%
        @as(u64, message.data[payload_bytes - 1]);
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
