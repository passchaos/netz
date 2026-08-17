const std = @import("std");
const netz = @import("netz");

const payload_bytes: usize = 4096;
// websocket.zig's client submits mask/header and payload separately, which can
// make long runs expensive on kernels that apply delayed ACK. Keep the shared
// comparison shape short enough for repeated pinned samples while retaining a
// meaningful untimed warmup.
const warmup_iterations: usize = 20;
const iterations: usize = 200;
const max_message_bytes: usize = payload_bytes;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(
            server_ptr: *netz.websocket.runtime.Server,
        ) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();
            var storage: [max_message_bytes]u8 align(64) = undefined;
            for (0..warmup_iterations + iterations) |_| {
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
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try netz.websocket.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "127.0.0.1",
            .target = "/echo-bench",
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = max_message_bytes,
                .max_message_bytes = max_message_bytes,
            },
        },
    );
    defer client.close();

    var payload: [payload_bytes]u8 align(64) = undefined;
    var response: [payload_bytes]u8 align(64) = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);

    for (0..warmup_iterations) |_| {
        _ = try exchange(&client, &payload, &response);
    }
    const started = nowNs(io);
    var checksum: u64 = 0;
    for (0..iterations) |_| {
        checksum +%= try exchange(&client, &payload, &response);
    }
    const elapsed = nowNs(io) -| started;

    thread.join();
    if (shared.err) |err| return err;
    const roundtrip_wire_bytes =
        // Client frame: 2-byte base + 2-byte extended length + 4-byte mask.
        (2 + 2 + 4 + payload_bytes) +
        // Server frame: 2-byte base + 2-byte extended length.
        (2 + 2 + payload_bytes);
    const roundtrips_per_second: u128 = if (elapsed == 0)
        0
    else
        (@as(u128, iterations) * std.time.ns_per_s) / elapsed;
    const wire_bytes_per_second =
        roundtrips_per_second * roundtrip_wire_bytes;
    std.debug.print(
        \\WebSocket persistent echo benchmark
        \\  warmup iterations: {d}
        \\  measured iterations: {d}
        \\  payload bytes: {d}
        \\  wire bytes/roundtrip: {d}
        \\  ns/roundtrip: {d}
        \\  roundtrips/s: {d}
        \\  wire MiB/s: {d:.2}
        \\  checksum: {d}
        \\
    , .{
        warmup_iterations,
        iterations,
        payload_bytes,
        roundtrip_wire_bytes,
        elapsed / iterations,
        roundtrips_per_second,
        @as(f64, @floatFromInt(wire_bytes_per_second)) /
            (1024.0 * 1024.0),
        checksum,
    });
}

fn exchange(
    client: *netz.websocket.runtime.Connection,
    payload: *[payload_bytes]u8,
    response_storage: *[payload_bytes]u8,
) !u64 {
    try client.sendBinaryInPlace(payload);
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
