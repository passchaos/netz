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

    const original_dcid =
        [_]u8{ 0x48, 0x33, 0x57, 0x53, 0x42, 0x45, 0x4e, 0x43 };
    const client_cid = [_]u8{ 0x48, 0x33, 0x43, 0x4c };
    const server_cid = [_]u8{ 0x48, 0x33, 0x53, 0x56 };
    const h3_limits: netz.http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const session_options: netz.http3.runtime.HandshakeSessionOptions = .{
        .max_stream_frame_data = 3500,
        .paced_body_chunk_bytes = 3500,
    };
    var server = try netz.websocket.runtime.h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        h3_limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x53} ** 32,
                .x25519_secret_key = [_]u8{0x54} ** 32,
            },
            .session = session_options,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.websocket.runtime.h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var ws = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .limits = .{
                    .max_frame_bytes = payload_bytes,
                    .max_message_bytes = payload_bytes,
                },
            });
            defer ws.deinit();
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

    var ws = try netz.websocket.runtime.h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        h3_limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x43} ** 32,
                .x25519_secret_key = [_]u8{0x44} ** 32,
            },
            .session = session_options,
        },
        .{
            .authority = "localhost",
            .path = "/h3-echo-bench",
            .enable_permessage_deflate = true,
            .limits = .{
                .max_frame_bytes = payload_bytes,
                .max_message_bytes = payload_bytes,
            },
        },
    );
    defer ws.deinit();

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
        \\RFC 9220 WebSocket persistent echo benchmark
        \\  warmup iterations: {d}
        \\  measured iterations: {d}
        \\  payload bytes: {d}
        \\  fragmented send slices: {d}
        \\  QUIC max datagram bytes: {d}
        \\  HTTP/3 DATA chunk bytes: {d}
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
        h3_limits.quic.max_datagram_size,
        session_options.paced_body_chunk_bytes,
        elapsed / iterations,
        roundtrips_per_second,
        @as(f64, @floatFromInt(
            roundtrips_per_second * payload_bytes * 2,
        )) / (1024.0 * 1024.0),
        checksum,
    });
}

fn exchange(
    ws: *netz.websocket.runtime.h3.ClientConnection,
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
