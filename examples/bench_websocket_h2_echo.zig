const std = @import("std");
const netz = @import("netz");

const payload_bytes: usize = 4096;
const warmup_iterations: usize = 20;
const iterations: usize = 200;
const fragmented_slices: usize = 16;

pub fn main(init: std.process.Init) !void {
    const fragmented = try parseFragmented(init);
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 16 * 1024,
            .max_body_bytes = payload_bytes,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http2.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self.server) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(server_ptr: *netz.http2.runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try netz.websocket.runtime.H2Server.accept(
                server_ptr.allocator,
                &h2,
                .{
                    .enable_permessage_deflate = true,
                    .limits = .{
                        .max_head_bytes = 4096,
                        .max_frame_bytes = payload_bytes,
                        .max_message_bytes = payload_bytes,
                    },
                },
            );
            defer ws.close();
            var storage: [payload_bytes]u8 align(64) = undefined;
            for (0..warmup_iterations + iterations) |_| {
                const message = try ws.receiveMessageInto(&storage);
                if (message.opcode != .binary or
                    message.payload.len != payload_bytes)
                {
                    return error.InvalidFrame;
                }
                try ws.sendBinary(message.payload);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2 = try netz.http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 16 * 1024,
            .max_body_bytes = payload_bytes,
        },
    );
    defer h2.close();
    var ws = try netz.websocket.runtime.H2Client.open(
        allocator,
        &h2,
        .{
            .authority = "localhost",
            .path = "/h2-echo-bench",
            .enable_permessage_deflate = true,
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = payload_bytes,
                .max_message_bytes = payload_bytes,
            },
        },
    );
    defer ws.close();

    var payload: [payload_bytes]u8 align(64) = undefined;
    var response: [payload_bytes]u8 align(64) = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    for (0..warmup_iterations) |_| {
        _ = try exchange(&ws, &payload, &response, fragmented);
    }
    const started = nowNs(io);
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        checksum +%= try exchange(&ws, &payload, &response, fragmented);
    }
    const elapsed = nowNs(io) -| started;

    server_thread.join();
    if (shared.err) |err| return err;
    const roundtrips_per_second: u128 = if (elapsed == 0)
        0
    else
        (@as(u128, iterations) * std.time.ns_per_s) / elapsed;
    std.debug.print(
        \\RFC 8441 WebSocket persistent echo benchmark
        \\  warmup iterations: {d}
        \\  measured iterations: {d}
        \\  payload bytes: {d}
        \\  fragmented send slices: {d}
        \\  ns/roundtrip: {d}
        \\  roundtrips/s: {d}
        \\  logical payload MiB/s: {d:.2}
        \\  checksum: {d}
        \\
    , .{
        warmup_iterations,
        iterations,
        payload_bytes,
        if (fragmented) fragmented_slices else 1,
        elapsed / iterations,
        roundtrips_per_second,
        @as(f64, @floatFromInt(
            roundtrips_per_second * payload_bytes * 2,
        )) / (1024.0 * 1024.0),
        checksum,
    });
}

fn exchange(
    ws: *netz.websocket.runtime.H2Connection,
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
        try ws.sendFragmented(.binary, &fragments);
    } else {
        try ws.sendBinary(payload);
    }
    const response = try ws.receiveMessageInto(response_storage);
    if (response.opcode != .binary or response.payload.len != payload_bytes) {
        return error.InvalidFrame;
    }
    @memcpy(payload, response.payload);
    return @as(u64, response.payload[0]) +%
        @as(u64, response.payload[payload_bytes / 2]) +%
        @as(u64, response.payload[payload_bytes - 1]);
}

fn parseFragmented(init: std.process.Init) !bool {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        std.heap.smp_allocator,
    );
    defer args.deinit();
    _ = args.next();
    var fragmented = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--fragmented")) {
            fragmented = true;
        } else {
            return error.InvalidArgument;
        }
    }
    return fragmented;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
