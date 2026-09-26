//! Durable outbound MQTT bridge QoS 2 fuzzing over two production brokers.

const std = @import("std");
const harness = @import("mqtt_outbound_bridge_qos2_fuzz/harness.zig");
const model = @import("mqtt_outbound_bridge_qos2_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const recovery_seed = smithSliceSeed(&.{
    0x00, // Normal transaction.
    0x11, // Recreate before target wire after source Session resume.
    0x02, // Recreate at target PUBREL boundary.
    0x03, // Resume target Session after losing PUBREC.
    0x0a, // Retained transaction restored at PUBREL boundary.
    0x28, // Retained deletion completes normally.
});

const retained_seed = smithSliceSeed(&.{
    0x08, // Retain topic zero.
    0x0d, // Replace retained topic one across pre-wire restart.
    0x18, // Replace retained topic zero after source reconnect.
    0x2b, // Delete retained topic zero across target reconnect.
    0x0e, // Retain topic one across PUBREL restart.
});

const corpus = &.{ &recovery_seed, &retained_seed };

test "structured durable outbound MQTT bridge sequences reach recovery states" {
    const recovery = try harness.runSequence(recovery_seed[4..]);
    try std.testing.expect(recovery.delivered >= 6);
    try std.testing.expect(recovery.ordinary >= 2);
    try std.testing.expect(recovery.pre_wire_restores >= 1);
    try std.testing.expect(recovery.pubrel_restores >= 2);
    try std.testing.expect(recovery.target_resumes >= 1);
    try std.testing.expect(recovery.source_resumes >= 1);
    try std.testing.expect(recovery.retained_deletes >= 1);
}

test "fuzz bounded durable outbound MQTT bridge QoS2 ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic durable outbound MQTT bridge mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x6f7574716f733266);
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
