//! Bounded MQTT reconnect fuzzing over authenticated native TLS 1.3.

const std = @import("std");
const harness = @import("mqtt_reconnect_fuzz/harness.zig");
const model = @import("mqtt_reconnect_fuzz/model.zig");

test "structured TLS MQTT reconnect sequences reach recovery states" {
    const qos = try harness.runTlsSequence(model.qos_recovery_seed[4..]);
    try model.requireQosRecovery(qos);
    const subscriptions = try harness.runTlsSequence(
        model.subscription_seed[4..],
    );
    try std.testing.expect(subscriptions.subscription_replays >= 3);
    try std.testing.expect(subscriptions.empty_reconnect_barriers >= 2);
}

test "fuzz bounded authenticated TLS MQTT reconnect ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = model.corpus });
}

test "bounded deterministic TLS MQTT reconnect mutation smoke" {
    var mutated: [model.max_operations]u8 = undefined;
    inline for (model.corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = try harness.runTlsSequence(mutated[0..seed.len]);
        }
    }

    var random_bytes: [model.max_operations]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x7265636f6e5f746c);
    const random = prng.random();
    for (0..2) |_| {
        const length = random.uintLessThan(usize, model.max_operations + 1);
        random.bytes(random_bytes[0..length]);
        _ = try harness.runTlsSequence(random_bytes[0..length]);
    }
}

fn fuzzSequences(_: void, smith: *std.testing.Smith) !void {
    var storage: [model.max_operations]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try harness.runTlsSequence(bytes);
}
