const std = @import("std");
const netz = @import("netz");

const stream_count: usize = 64;
const default_iterations: usize = 200_000;

pub fn main(init: std.process.Init) !void {
    const iterations = try parseIterations(init);
    const allocator = std.heap.smp_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = netz.quic.protection.deriveAes128Keys(
        [_]u8{0x73} ** netz.quic.protection.secret_len,
    );
    var connection = try netz.quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "ids-server",
        .peer_connection_id = "ids-client",
        .initial_receive_max_streams_uni = stream_count,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    for (0..stream_count) |sequence| {
        const stream_id: u62 = @intCast(2 + sequence * 4);
        try netz.quic.one_rtt.testing.applyReceivedFrames(
            &connection,
            sequence,
            &.{.{ .stream = .{
                .stream_id = stream_id,
                .data = "x",
                .fin = true,
            } }},
            null,
            .not_ect,
        );
    }

    var ids: [stream_count]u62 = undefined;
    var checksum: u64 = 0;
    const started = nowNs(io);
    for (0..iterations) |_| {
        const result = connection.receivedStreamIdsAfterInto(null, &ids);
        if (result.len != stream_count) return error.InvalidStreamCount;
        for (result, 0..) |stream_id, index| {
            const expected: u62 = @intCast(2 + index * 4);
            if (stream_id != expected) return error.InvalidStreamOrder;
            checksum +%= stream_id;
        }
        std.mem.doNotOptimizeAway(result.ptr);
    }
    const elapsed = nowNs(io) -| started;
    std.debug.print("QUIC receive-stream ID enumeration benchmark\n" ++
        "  io backend: zio-std-io\n" ++
        "  iterations: {d}\n" ++
        "  active streams: {d}\n" ++
        "  elapsed ns: {d}\n" ++
        "  ns/enumeration: {d:.3}\n" ++
        "  ns/stream: {d:.3}\n" ++
        "  checksum: {d}\n", .{
        iterations,
        stream_count,
        elapsed,
        @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations)),
        @as(f64, @floatFromInt(elapsed)) /
            @as(f64, @floatFromInt(iterations * stream_count)),
        checksum,
    });
}

fn parseIterations(init: std.process.Init) !usize {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 1) return default_iterations;
    if (args.len != 2 or !std.mem.startsWith(u8, args[1], "--iterations=")) {
        return error.InvalidArgument;
    }
    const value = try std.fmt.parseInt(
        usize,
        args[1]["--iterations=".len..],
        10,
    );
    if (value == 0 or value > 10_000_000) return error.InvalidArgument;
    return value;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
