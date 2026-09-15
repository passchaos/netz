const std = @import("std");
const netz = @import("netz");

const default_iterations: usize = 10_000_000;
const route_count: usize = 64;
const cid_len: usize = 16;

pub fn main(init: std.process.Init) !void {
    const iterations = try parseIterations(init);
    const allocator = std.heap.smp_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var router = netz.quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.ensureCapacity(route_count);

    var packets: [route_count][1 + cid_len + 4]u8 = undefined;
    for (&packets, 0..) |*packet, index| {
        packet.* = @splat(0xa5);
        packet[0] = 0x40;
        packet[1] = 0x11;
        std.mem.writeInt(u64, packet[1 + cid_len - 8 ..][0..8], index, .big);
        try router.register(packet[1..][0..cid_len], .{
            .connection_index = index + 1,
        });
    }
    var miss_packet: [1 + cid_len + 4]u8 = @splat(0xff);
    miss_packet[0] = 0x40;

    var checksum: usize = 0;
    const hit_started = nowNs(io);
    for (0..iterations) |iteration| {
        const expected = iteration % route_count + 1;
        const routed = (try router.routeDatagram(
            &packets[iteration % route_count],
        )) orelse return error.InvalidBenchmarkResult;
        checksum +%= routed.route.connection_index;
        if (routed.route.connection_index != expected) {
            return error.InvalidBenchmarkResult;
        }
    }
    const hit_elapsed = nowNs(io) -| hit_started;

    var misses: usize = 0;
    const miss_started = nowNs(io);
    for (0..iterations) |_| {
        misses += @intFromBool((try router.routeDatagram(&miss_packet)) == null);
    }
    const miss_elapsed = nowNs(io) -| miss_started;
    if (misses != iterations or checksum == 0) {
        return error.InvalidBenchmarkResult;
    }
    std.mem.doNotOptimizeAway(checksum);

    std.debug.print(
        \\QUIC connection router benchmark
        \\  io backend: zio-std-io
        \\  iterations: {d}, routes: {d}, CID bytes: {d}
        \\  hit:  {d}.{d:0>2} ns/op
        \\  miss: {d}.{d:0>2} ns/op
        \\  checksum: {d}
        \\
    , .{
        iterations,
        route_count,
        cid_len,
        hundredthsPerOperation(hit_elapsed, iterations) / 100,
        hundredthsPerOperation(hit_elapsed, iterations) % 100,
        hundredthsPerOperation(miss_elapsed, iterations) / 100,
        hundredthsPerOperation(miss_elapsed, iterations) % 100,
        checksum,
    });
}

fn hundredthsPerOperation(elapsed_ns: u64, iterations: usize) u64 {
    return elapsed_ns * 100 / iterations;
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
    if (value == 0 or value > 100_000_000) return error.InvalidArgument;
    return value;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
