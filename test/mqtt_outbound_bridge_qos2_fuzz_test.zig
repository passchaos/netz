//! Durable outbound MQTT bridge QoS 2 fuzzing over two production brokers.

const std = @import("std");
const harness = @import("mqtt_outbound_bridge_qos2_fuzz/harness.zig");
const model = @import("mqtt_outbound_bridge_qos2_fuzz/model.zig");

test "structured durable outbound MQTT bridge sequences reach recovery states" {
    try model.requireRecovery(try harness.runSequence(
        model.recovery_seed[4..],
    ));
    try model.requireRetained(try harness.runSequence(
        model.retained_seed[4..],
    ));
}

test "fuzz bounded durable outbound MQTT bridge QoS2 ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = model.corpus });
}

test "bounded deterministic durable outbound MQTT bridge mutation smoke" {
    var mutated: [model.max_operations]u8 = undefined;
    inline for (model.corpus) |seed_with_prefix| {
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
