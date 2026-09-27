//! Bounded MQTT reconnect state-machine fuzzing over real loopback TCP.
//!
//! A production reconnect Client talks to a scripted runtime Server across a
//! sequence of successful acknowledgements, abrupt transport loss, preserved
//! and lost broker Sessions, QoS 1/2 retransmission, and subscription replay.

const std = @import("std");
const harness = @import("mqtt_reconnect_fuzz/harness.zig");
const model = @import("mqtt_reconnect_fuzz/model.zig");

test "structured live MQTT reconnect sequences reach recovery states" {
    const qos = try harness.runSequence(model.qos_recovery_seed[4..]);
    try model.requireQosRecovery(qos);

    const subscriptions = try harness.runSequence(model.subscription_seed[4..]);
    try std.testing.expect(subscriptions.subscription_replays >= 3);
    try std.testing.expect(subscriptions.empty_reconnect_barriers >= 2);
}

test "fuzz bounded live MQTT reconnect ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = model.corpus });
}

test "bounded deterministic live MQTT reconnect mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x7265636f6e6e6563);
    const random = prng.random();
    for (0..4) |_| {
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
