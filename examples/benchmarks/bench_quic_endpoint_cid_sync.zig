const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 2_000_000;

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
        [_]u8{0x63} ** netz.quic.protection.secret_len,
    );
    var connection = try netz.quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "cid-sync-0",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
        .peer_active_connection_id_limit = 4,
    });
    defer connection.deinit();
    var dispatcher = netz.quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &connection);

    for (1..4) |index| {
        var cid = [_]u8{ 'c', 'i', 'd', '-', '0' };
        cid[4] = @intCast('0' + index);
        try dispatcher.sendNewConnectionId(
            1,
            &cid,
            @splat(@intCast(index)),
        );
    }
    if (dispatcher.routeCount() != 4) return error.InvalidBenchmarkResult;

    try dispatcher.syncConnectionIds(1);
    try dispatcher.syncConnectionIdsIfChanged(1);

    const first_count = iterations / 2;
    const second_count = iterations - first_count;

    const forced_first_started = nowNs(io);
    for (0..first_count) |_| {
        try dispatcher.syncConnectionIds(1);
        std.mem.doNotOptimizeAway(dispatcher.routeCount());
    }
    const forced_first_elapsed = nowNs(io) -| forced_first_started;

    const cached_first_started = nowNs(io);
    for (0..first_count) |_| {
        try dispatcher.syncConnectionIdsIfChanged(1);
        std.mem.doNotOptimizeAway(dispatcher.routeCount());
    }
    const cached_first_elapsed = nowNs(io) -| cached_first_started;

    const cached_second_started = nowNs(io);
    for (0..second_count) |_| {
        try dispatcher.syncConnectionIdsIfChanged(1);
        std.mem.doNotOptimizeAway(dispatcher.routeCount());
    }
    const cached_second_elapsed = nowNs(io) -| cached_second_started;

    const forced_second_started = nowNs(io);
    for (0..second_count) |_| {
        try dispatcher.syncConnectionIds(1);
        std.mem.doNotOptimizeAway(dispatcher.routeCount());
    }
    const forced_second_elapsed = nowNs(io) -| forced_second_started;
    const forced_elapsed = forced_first_elapsed +| forced_second_elapsed;
    const cached_elapsed = cached_first_elapsed +| cached_second_elapsed;

    if (dispatcher.routeCount() != 4 or
        connection.localConnectionIdRevision() != 4)
    {
        return error.InvalidBenchmarkResult;
    }
    const ratio_x100 = if (cached_elapsed == 0)
        0
    else
        forced_elapsed * 100 / cached_elapsed;
    std.debug.print(
        \\QUIC endpoint CID synchronization benchmark
        \\  io backend: zio-std-io
        \\  iterations: {d}, active CIDs: 4
        \\  forced sync: {d} ns/op
        \\  revision fast path: {d} ns/op
        \\  relative throughput: {d}.{d:0>2}x
        \\
    , .{
        iterations,
        forced_elapsed / iterations,
        cached_elapsed / iterations,
        ratio_x100 / 100,
        ratio_x100 % 100,
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
