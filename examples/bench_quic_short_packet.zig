const std = @import("std");
const netz = @import("netz");

const iterations: usize = 100_000;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const keys = netz.quic.protection.deriveAes128Keys([_]u8{0x51} ** netz.quic.protection.secret_len);
    const options: netz.quic.protection.ShortPacketOptions = .{
        .destination_connection_id = "bench-dcid",
        .packet_number = 0x12_3456,
        .packet_number_len = 3,
        .spin_bit = true,
        .key_phase = false,
        .payload = "stream frame payload used by the short packet benchmark",
    };
    const packet_len = try netz.quic.protection.shortPacketLen(options);

    var storage: [256]u8 = undefined;
    const in_place_start = nowNs(io);
    var in_place_total: usize = 0;
    for (0..iterations) |_| {
        const packet = try netz.quic.protection.sealShortPacketInto(&storage, keys, options);
        in_place_total += packet.len;
    }
    const in_place_ns = nowNs(io) -| in_place_start;

    const allocating_start = nowNs(io);
    var allocating_total: usize = 0;
    for (0..iterations) |_| {
        const packet = try netz.quic.protection.sealShortPacket(allocator, keys, options);
        allocating_total += packet.len;
        allocator.free(packet);
    }
    const allocating_ns = nowNs(io) -| allocating_start;

    std.debug.print(
        \\QUIC short packet benchmark
        \\  iterations: {d}
        \\  packet len: {d}
        \\  in-place total: {d}, ns/op: {d}
        \\  allocating total: {d}, ns/op: {d}
        \\
    , .{
        iterations,
        packet_len,
        in_place_total,
        in_place_ns / iterations,
        allocating_total,
        allocating_ns / iterations,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
