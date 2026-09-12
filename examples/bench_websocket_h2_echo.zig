const std = @import("std");
const netz = @import("netz");
const send_shape = @import("support/websocket_send_shape.zig");
const counting_allocator = @import("support/counting_allocator.zig");
const CountingAllocator = counting_allocator.CountingAllocator;

const payload_bytes: usize = 4096;
const default_warmup_iterations: usize = 20;
const default_iterations: usize = 200;
const fragmented_slices: usize = 16;

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
        shape: send_shape.Shape,
        parts: usize,
        iterations: usize,
        compression: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try netz.websocket.runtime.H2Server.accept(
                self.server.allocator,
                &h2,
                .{
                    .enable_permessage_deflate = self.compression,
                    .limits = .{
                        .max_head_bytes = 4096,
                        .max_frame_bytes = payload_bytes,
                        .max_message_bytes = payload_bytes,
                    },
                },
            );
            defer ws.close();
            var storage: [payload_bytes]u8 align(64) = undefined;
            var joined: [payload_bytes]u8 align(64) = undefined;
            for (0..self.iterations) |_| {
                const message = try ws.receiveMessageInto(&storage);
                if (message.opcode != .binary or
                    message.payload.len != payload_bytes)
                {
                    return error.InvalidFrame;
                }
                try send_shape.sendBinary(
                    &ws,
                    message.payload,
                    self.shape,
                    self.parts,
                    &joined,
                );
            }
        }
    };
    var shared = Shared{
        .server = &server,
        .shape = options.send_shape,
        .parts = options.parts,
        .iterations = options.warmup_iterations + options.iterations,
        .compression = options.compression,
    };
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
            .enable_permessage_deflate = options.compression,
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
    var joined: [payload_bytes]u8 align(64) = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    for (0..options.warmup_iterations) |_| {
        _ = try exchange(
            &ws,
            &payload,
            &response,
            options.fragmented,
            options.send_shape,
            options.parts,
            &joined,
        );
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
            options.send_shape,
            options.parts,
            &joined,
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
        \\RFC 8441 WebSocket persistent echo benchmark
        \\  warmup iterations: {d}
        \\  measured iterations: {d}
        \\  payload bytes: {d}
        \\  send shape: {s}
        \\  application parts: {d}
        \\  permessage-deflate: {}
        \\  fragmented send slices: {d}
        \\  ns/roundtrip: {d}
        \\  roundtrips/s: {d}
        \\  logical payload MiB/s: {d:.2}
        \\  checksum: {d}
        \\
    , .{
        options.warmup_iterations,
        options.iterations,
        payload_bytes,
        options.send_shape.label(),
        options.parts,
        options.compression,
        if (options.fragmented) fragmented_slices else 1,
        elapsed / options.iterations,
        roundtrips_per_second,
        @as(f64, @floatFromInt(
            roundtrips_per_second * payload_bytes * 2,
        )) / (1024.0 * 1024.0),
        checksum,
    });
    std.debug.print(
        "record=result implementation=netz protocol=websocket-h2 " ++
            "transport=h2c mode=binary-echo role_pair=netz-self " ++
            "connection_scope=persistent benchmark_scope={s} " ++
            "connections=1 warmup={d} iterations={d} payload_bytes={d} " ++
            "payload_schedule=fixed send_shape={s} parts={d} compression={} " ++
            "logical_bytes={d} elapsed_ns={d} " ++
            "checksum={d} complete=true\n",
        .{
            if (options.parts == 1)
                "single-buffer-echo"
            else
                "caller-copy-vs-direct-slices",
            options.warmup_iterations,
            options.iterations,
            payload_bytes,
            options.send_shape.label(),
            options.parts,
            options.compression,
            options.iterations * payload_bytes * 2,
            elapsed,
            checksum,
        },
    );
    if (options.stats) {
        printAllocationDelta(allocations_before, allocations_after);
    }
}

fn exchange(
    ws: *netz.websocket.runtime.H2Connection,
    payload: *[payload_bytes]u8,
    response_storage: *[payload_bytes]u8,
    fragmented: bool,
    shape: send_shape.Shape,
    part_count: usize,
    joined: *[payload_bytes]u8,
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
        try send_shape.sendBinary(
            ws,
            payload,
            shape,
            part_count,
            joined,
        );
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

const Options = struct {
    fragmented: bool = false,
    send_shape: send_shape.Shape = .contiguous,
    parts: usize = 1,
    warmup_iterations: usize = default_warmup_iterations,
    iterations: usize = default_iterations,
    compression: bool = true,
    stats: bool = false,
};

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
        } else if (std.mem.eql(u8, arg, "--no-compression")) {
            options.compression = false;
        } else if (std.mem.eql(u8, arg, "--stats")) {
            options.stats = true;
        } else if (std.mem.startsWith(u8, arg, "--send-shape=")) {
            options.send_shape = try send_shape.Shape.parse(
                arg["--send-shape=".len..],
            );
        } else if (std.mem.startsWith(u8, arg, "--parts=")) {
            options.parts = try std.fmt.parseInt(
                usize,
                arg["--parts=".len..],
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
        } else {
            return error.InvalidArgument;
        }
    }
    try send_shape.validatePartCount(options.parts);
    if (options.iterations == 0) return error.InvalidArgument;
    if (options.fragmented and
        (options.send_shape != .contiguous or options.parts != 1))
    {
        return error.InvalidArgument;
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
            "  measured allocated bytes: {d}\n",
        .{
            after.alloc_count - before.alloc_count,
            after.free_count - before.free_count,
            after.resize_count - before.resize_count,
            after.remap_count - before.remap_count,
            after.total_allocated - before.total_allocated,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
