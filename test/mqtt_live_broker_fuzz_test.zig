//! Bounded MQTT broker ordering fuzzing over real loopback TCP connections.

const std = @import("std");
const harness = @import("mqtt_live_broker_fuzz/harness.zig");
const model = @import("mqtt_live_broker_fuzz/model.zig");

test "structured live MQTT broker sequence reaches routing states" {
    try model.requireLifecycle(try harness.runSequence(
        model.lifecycle_seed[4..],
    ));
    const replacements = try harness.runSequence(model.replacement_seed[4..]);
    try std.testing.expect(replacements.subscription_replacements >= 2);
}

test "fuzz bounded live MQTT broker ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = model.corpus });
}

test "bounded deterministic live MQTT broker mutation smoke" {
    var mutated: [model.max_sequence_bytes]u8 = undefined;
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

    var random_bytes: [model.max_sequence_bytes]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x6d7174745f6c6976);
    const random = prng.random();
    for (0..4) |_| {
        const length = random.uintLessThan(
            usize,
            model.max_sequence_bytes + 1,
        );
        random.bytes(random_bytes[0..length]);
        _ = try harness.runSequence(random_bytes[0..length]);
    }
}

fn fuzzSequences(_: void, smith: *std.testing.Smith) !void {
    var storage: [model.max_sequence_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try harness.runSequence(bytes);
}
