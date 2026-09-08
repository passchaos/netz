const std = @import("std");
const netz = @import("netz");
const counting_allocator = @import("support/counting_allocator.zig");
const CountingAllocator = counting_allocator.CountingAllocator;

const payload_bytes: usize = 4096;
const default_warmup_iterations: usize = 20;
const default_iterations: usize = 200;
const fragmented_slices: usize = 16;

const Options = struct {
    fragmented: bool = false,
    stats: bool = false,
    warmup_iterations: usize = default_warmup_iterations,
    iterations: usize = default_iterations,
};

pub fn main(init: std.process.Init) !void {
    const options = try parseOptions(init);
    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = if (options.stats)
        counting.allocator()
    else
        std.heap.smp_allocator;
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
        iterations: usize,
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
            for (0..self.iterations) |_| {
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
    var shared = Shared{
        .server = &server,
        .iterations = options.warmup_iterations + options.iterations,
    };
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
    for (0..options.warmup_iterations) |_| {
        _ = try exchange(&ws, &payload, &response, options.fragmented);
    }
    const allocations_before = counting.snapshot();
    const started = nowNs(io);
    var checksum: u64 = 0;
    for (0..options.iterations) |_| {
        checksum +%= try exchange(
            &ws,
            &payload,
            &response,
            options.fragmented,
        );
    }
    const elapsed = nowNs(io) -| started;
    const allocations_after = counting.snapshot();

    server_thread.join();
    if (shared.err) |err| return err;
    const roundtrips_per_second: u128 = if (elapsed == 0)
        0
    else
        (@as(u128, options.iterations) * std.time.ns_per_s) / elapsed;
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
        options.warmup_iterations,
        options.iterations,
        payload_bytes,
        if (options.fragmented) fragmented_slices else 1,
        h3_limits.quic.max_datagram_size,
        session_options.paced_body_chunk_bytes,
        elapsed / options.iterations,
        roundtrips_per_second,
        @as(f64, @floatFromInt(
            roundtrips_per_second * payload_bytes * 2,
        )) / (1024.0 * 1024.0),
        checksum,
    });
    if (options.stats) {
        printAllocationDelta(allocations_before, allocations_after);
    }
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

fn parseOptions(init: std.process.Init) !Options {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        std.heap.smp_allocator,
    );
    defer args.deinit();
    _ = args.next();
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--fragmented")) {
            options.fragmented = true;
        } else if (std.mem.eql(u8, arg, "--stats")) {
            options.stats = true;
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
            if (options.iterations == 0) return error.InvalidArgument;
        } else {
            return error.InvalidArgument;
        }
    }
    return options;
}

fn printAllocationDelta(
    before: counting_allocator.Snapshot,
    after: counting_allocator.Snapshot,
) void {
    std.debug.print(
        "  measured allocator calls: {d}\n" ++
            "  measured frees: {d}\n" ++
            "  measured resize/remap: {d}/{d}\n" ++
            "  measured allocated bytes: {d}\n" ++
            "  measured allocation buckets:\n",
        .{
            after.alloc_count - before.alloc_count,
            after.free_count - before.free_count,
            after.resize_count - before.resize_count,
            after.remap_count - before.remap_count,
            after.total_allocated - before.total_allocated,
        },
    );
    for (counting_allocator.bucket_labels, 0..) |label, index| {
        std.debug.print(
            "    {s}: count={d}, bytes={d}\n",
            .{
                label,
                after.alloc_buckets[index] - before.alloc_buckets[index],
                after.alloc_bucket_bytes[index] -
                    before.alloc_bucket_bytes[index],
            },
        );
    }
    std.debug.print("  measured exact allocation sizes:\n", .{});
    for (after.exact_sizes[0..after.exact_size_len]) |entry| {
        var before_count: usize = 0;
        for (before.exact_sizes[0..before.exact_size_len]) |old_entry| {
            if (old_entry.size != entry.size) continue;
            before_count = old_entry.count;
            break;
        }
        if (entry.count <= before_count) continue;
        std.debug.print(
            "    {d} bytes: {d}\n",
            .{ entry.size, entry.count - before_count },
        );
    }
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
