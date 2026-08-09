const std = @import("std");
const netz = @import("netz");

const iterations: usize = 100_000;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const secret = [_]u8{0x51} ** netz.quic.protection.secret_len;
    const aes_keys = netz.quic.protection.deriveAes128Keys(secret);
    const chacha_keys = netz.quic.protection.deriveChaCha20Keys(secret);
    const options: netz.quic.protection.ShortPacketOptions = .{
        .destination_connection_id = "bench-dcid",
        .packet_number = 0x12_3456,
        .packet_number_len = 3,
        .spin_bit = true,
        .key_phase = false,
        .payload = "stream frame payload used by the short packet benchmark",
    };
    const packet_len = try netz.quic.protection.shortPacketLen(options);

    const aes = try benchSuite(
        allocator,
        io,
        aes_keys,
        options,
    );
    const chacha = try benchSuite(
        allocator,
        io,
        chacha_keys,
        options,
    );
    const aes_in_place_ratio_x100 = ratioTimes100(
        aes.allocating_ns,
        aes.in_place_ns,
    );
    const chacha_in_place_ratio_x100 = ratioTimes100(
        chacha.allocating_ns,
        chacha.in_place_ns,
    );

    std.debug.print(
        \\QUIC short packet benchmark
        \\  iterations: {d}
        \\  packet len: {d}
        \\  AES in-place total: {d}, ns/op: {d}
        \\  AES allocating total: {d}, ns/op: {d}
        \\  AES in-place relative throughput: {d}.{d:0>2}x
        \\  ChaCha in-place total: {d}, ns/op: {d}
        \\  ChaCha allocating total: {d}, ns/op: {d}
        \\  ChaCha in-place relative throughput: {d}.{d:0>2}x
        \\
    , .{
        iterations,
        packet_len,
        aes.in_place_total,
        aes.in_place_ns / iterations,
        aes.allocating_total,
        aes.allocating_ns / iterations,
        aes_in_place_ratio_x100 / 100,
        aes_in_place_ratio_x100 % 100,
        chacha.in_place_total,
        chacha.in_place_ns / iterations,
        chacha.allocating_total,
        chacha.allocating_ns / iterations,
        chacha_in_place_ratio_x100 / 100,
        chacha_in_place_ratio_x100 % 100,
    });
}

const SuiteResult = struct {
    in_place_total: usize,
    in_place_ns: u64,
    allocating_total: usize,
    allocating_ns: u64,
};

fn benchSuite(
    allocator: std.mem.Allocator,
    io: std.Io,
    keys: netz.quic.protection.PacketProtectionKeys,
    options: netz.quic.protection.ShortPacketOptions,
) !SuiteResult {
    var storage: [256]u8 = undefined;
    const in_place_start = nowNs(io);
    var in_place_total: usize = 0;
    for (0..iterations) |_| {
        const packet = try netz.quic.protection.sealShortPacketInto(
            &storage,
            keys,
            options,
        );
        in_place_total += packet.len;
    }
    const in_place_ns = nowNs(io) -| in_place_start;

    const allocating_start = nowNs(io);
    var allocating_total: usize = 0;
    for (0..iterations) |_| {
        const packet = try netz.quic.protection.sealShortPacket(
            allocator,
            keys,
            options,
        );
        allocating_total += packet.len;
        allocator.free(packet);
    }
    return .{
        .in_place_total = in_place_total,
        .in_place_ns = in_place_ns,
        .allocating_total = allocating_total,
        .allocating_ns = nowNs(io) -| allocating_start,
    };
}

fn ratioTimes100(numerator: u64, denominator: u64) u64 {
    if (denominator == 0) return 0;
    return (numerator *| 100) / denominator;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
