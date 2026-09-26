//! Durable MQTT inbound-bridge QoS 2 fuzzing over real loopback TCP.

const std = @import("std");
const harness = @import("mqtt_bridge_qos2_fuzz/harness.zig");
const model = @import("mqtt_bridge_qos2_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const recovery_seed = smithSliceSeed(&.{
    0x00, // Complete normally.
    0x05, // Reconnect transport and resume the PUBREL leg.
    0x0a, // Recreate Bridge and restore a retained transaction.
    0x17, // Fresh Session discards a DUP transaction before PUBREL.
    0x1d, // Retained DUP transaction resumes across transport loss.
    0x12, // DUP transaction resumes across Bridge recreation.
});

const epoch_seed = smithSliceSeed(&.{
    0x0b, // Fresh Session discards a retained transaction.
    0x04, // Topic one completes normally in the new epoch.
    0x13, // Another fresh Session discards topic zero.
    0x1a, // Recreate Bridge and restore topic zero with DUP input.
    0x09, // Retained topic zero resumes across transport loss.
});

const corpus = &.{ &recovery_seed, &epoch_seed };

test "structured durable MQTT bridge QoS2 sequences reach recovery states" {
    const recovery = try harness.runSequence(recovery_seed[4..]);
    try std.testing.expect(recovery.released >= 5);
    try std.testing.expect(recovery.transport_resumes >= 2);
    try std.testing.expect(recovery.process_resumes >= 2);
    try std.testing.expect(recovery.fresh_session_discards >= 1);
    try std.testing.expect(recovery.duplicate_inputs >= 2);
    try std.testing.expect(recovery.retained_probe_deliveries >= 1);
}

test "fuzz bounded durable MQTT bridge QoS2 ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic durable MQTT bridge QoS2 mutation smoke" {
    var mutated: [model.max_operations]u8 = undefined;
    inline for (corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (0..seed.len + 1) |length| {
            _ = try harness.runSequence(seed[0..length]);
        }
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = try harness.runSequence(mutated[0..seed.len]);
        }
    }

    var random_bytes: [model.max_operations]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x716f733262726467);
    const random = prng.random();
    for (0..3) |_| {
        const length = random.uintLessThan(usize, model.max_operations + 1);
        random.bytes(random_bytes[0..length]);
        _ = try harness.runSequence(random_bytes[0..length]);
    }
}

fn fuzzSequences(_: void, smith: *std.testing.Smith) !void {
    var storage: [model.max_operations]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try harness.runSequence(bytes);
}
