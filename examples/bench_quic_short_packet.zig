const std = @import("std");
const netz = @import("netz");

const iterations: usize = 100_000;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const secret = [_]u8{0x51} ** netz.quic.protection.secret_len;
    const aes_keys = netz.quic.protection.deriveAes128Keys(secret);
    const aes256_keys =
        try netz.quic.protection.deriveKeysForSecretForVersion(
            netz.quic.Version.version_1.wireValue(),
            .aes_256_gcm_sha384,
            .fromSha384([_]u8{0x51} ** 48),
        );
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
    const aes256 = try benchSuite(
        allocator,
        io,
        aes256_keys,
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
    const aes256_in_place_ratio_x100 = ratioTimes100(
        aes256.allocating_ns,
        aes256.in_place_ns,
    );

    std.debug.print(
        "prepared key bytes: {d}\n",
        .{@sizeOf(netz.quic.protection.PreparedPacketProtectionKeys)},
    );
    std.debug.print(
        \\QUIC short packet benchmark
        \\  io backend: zio-std-io
        \\  iterations: {d}
        \\  packet len: {d}
        \\  AES in-place total: {d}, ns/op: {d}
        \\  AES allocating total: {d}, ns/op: {d}
        \\  AES in-place relative throughput: {d}.{d:0>2}x
        \\  AES-256 in-place total: {d}, ns/op: {d}
        \\  AES-256 allocating total: {d}, ns/op: {d}
        \\  AES-256 in-place relative throughput: {d}.{d:0>2}x
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
        aes256.in_place_total,
        aes256.in_place_ns / iterations,
        aes256.allocating_total,
        aes256.allocating_ns / iterations,
        aes256_in_place_ratio_x100 / 100,
        aes256_in_place_ratio_x100 % 100,
        chacha.in_place_total,
        chacha.in_place_ns / iterations,
        chacha.allocating_total,
        chacha.allocating_ns / iterations,
        chacha_in_place_ratio_x100 / 100,
        chacha_in_place_ratio_x100 % 100,
    });
    printPreparedComparison("AES", aes);
    printPreparedComparison("AES-256", aes256);
    printPreparedComparison("ChaCha", chacha);
    std.debug.print(
        "  prepared connection backend enabled: {}\n",
        .{netz.quic.protection.prepared_packet_protection_enabled},
    );
}

const SuiteResult = struct {
    in_place_total: usize,
    in_place_ns: u64,
    prepared_total: usize,
    prepared_ns: u64,
    open_ns: u64,
    prepared_open_ns: u64,
    allocating_total: usize,
    allocating_ns: u64,
};

fn printPreparedComparison(name: []const u8, result: SuiteResult) void {
    const seal_ratio = ratioTimes100(result.in_place_ns, result.prepared_ns);
    const open_ratio = ratioTimes100(result.open_ns, result.prepared_open_ns);
    std.debug.print(
        "  {s} prepared seal: {d} ns/op vs value-key {d} ns/op ({d}.{d:0>2}x); open: {d} ns/op vs {d} ns/op ({d}.{d:0>2}x); total: {d}\n",
        .{
            name,
            result.prepared_ns / iterations,
            result.in_place_ns / iterations,
            seal_ratio / 100,
            seal_ratio % 100,
            result.prepared_open_ns / iterations,
            result.open_ns / iterations,
            open_ratio / 100,
            open_ratio % 100,
            result.prepared_total,
        },
    );
}

fn benchSuite(
    allocator: std.mem.Allocator,
    io: std.Io,
    keys: netz.quic.protection.PacketProtectionKeys,
    options: netz.quic.protection.ShortPacketOptions,
) !SuiteResult {
    var storage: [256]u8 = undefined;
    var prepared = netz.quic.protection.PreparedPacketProtectionKeys.init(keys);
    defer prepared.deinit();
    const in_place_start = nowNs(io);
    var in_place_total: usize = 0;
    for (0..iterations) |_| {
        const packet = try netz.quic.protection.sealShortPacketInto(
            &storage,
            keys,
            options,
        );
        in_place_total +%= packet.len + packet[packet.len - 1];
    }
    const in_place_ns = nowNs(io) -| in_place_start;

    const prepared_start = nowNs(io);
    var prepared_total: usize = 0;
    for (0..iterations) |_| {
        const packet = try netz.quic.protection.sealShortPacketIntoPrepared(
            &storage,
            &prepared,
            options,
        );
        prepared_total +%= packet.len + packet[packet.len - 1];
    }
    const prepared_ns = nowNs(io) -| prepared_start;

    var sealed_storage: [256]u8 = undefined;
    const sealed = try netz.quic.protection.sealShortPacketInto(
        &sealed_storage,
        keys,
        options,
    );
    const open_start = nowNs(io);
    var open_total: usize = 0;
    for (0..iterations) |_| {
        @memcpy(storage[0..sealed.len], sealed);
        const opened = try netz.quic.protection
            .openShortPacketInPlaceForKeyPhaseWithFixedBitPolicy(
            keys,
            options.key_phase,
            storage[0..sealed.len],
            options.destination_connection_id.len,
            options.packet_number,
            false,
        );
        open_total +%= opened.opened.payload[0];
    }
    const open_ns = nowNs(io) -| open_start;

    const prepared_open_start = nowNs(io);
    var prepared_open_total: usize = 0;
    for (0..iterations) |_| {
        @memcpy(storage[0..sealed.len], sealed);
        const opened = try netz.quic.protection
            .openShortPacketInPlaceForPreparedKeyPhaseWithFixedBitPolicy(
            &prepared,
            options.key_phase,
            storage[0..sealed.len],
            options.destination_connection_id.len,
            options.packet_number,
            false,
        );
        prepared_open_total +%= opened.opened.payload[0];
    }
    const prepared_open_ns = nowNs(io) -| prepared_open_start;
    std.mem.doNotOptimizeAway(open_total);
    std.mem.doNotOptimizeAway(prepared_open_total);

    const allocating_start = nowNs(io);
    var allocating_total: usize = 0;
    for (0..iterations) |_| {
        const packet = try netz.quic.protection.sealShortPacket(
            allocator,
            keys,
            options,
        );
        allocating_total +%= packet.len + packet[packet.len - 1];
        allocator.free(packet);
    }
    return .{
        .in_place_total = in_place_total,
        .in_place_ns = in_place_ns,
        .prepared_total = prepared_total,
        .prepared_ns = prepared_ns,
        .open_ns = open_ns,
        .prepared_open_ns = prepared_open_ns,
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
