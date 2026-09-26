//! Bounded MQTT reconnect state-machine fuzzing over real loopback TCP.
//!
//! A production reconnect Client talks to a scripted runtime Server across a
//! sequence of successful acknowledgements, abrupt transport loss, preserved
//! and lost broker Sessions, QoS 1/2 retransmission, and subscription replay.

const std = @import("std");
const harness = @import("mqtt_reconnect_fuzz/harness.zig");
const model = @import("mqtt_reconnect_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const qos_recovery_seed = smithSliceSeed(&.{
    0x00, // QoS 1 success.
    0x09, // QoS 1 loses PUBACK, preserved Session replays PUBLISH.
    0x03, // QoS 2 loses PUBREC, fresh Session drops the transaction.
    0x0b, // QoS 2 loses PUBREC, preserved Session replays PUBLISH.
    0x02, // QoS 2 completes without reconnecting.
    0x0c, // QoS 2 loses PUBCOMP, preserved Session replays PUBREL.
    0x04, // QoS 2 loses PUBCOMP, fresh Session drops the transaction.
});

const subscription_seed = smithSliceSeed(&.{
    0x05, // Subscribe topic zero at QoS 0.
    0x55, // Subscribe topic one at QoS 1.
    0x0f, // Preserved Session: reconnect without SUBSCRIBE replay.
    0x07, // Fresh Session: replay both subscriptions in order.
    0x06, // Unsubscribe topic zero.
    0x07, // Fresh Session: replay only topic one.
    0x16, // Unsubscribe topic one.
    0x0f, // Preserved empty Session.
});

const mixed_seed = smithSliceSeed(&.{
    0x45, // Subscribe topic zero at QoS 1.
    0x29, // Retained QoS 1 loses PUBACK and loses the broker Session.
    0x47, // Fresh Session replays the subscription again.
    0x7b, // Retained QoS 2 loses PUBREC, preserved Session replays PUBLISH.
    0x36, // Unsubscribe absent topic one.
    0x7c, // Retained QoS 2 loses PUBCOMP, preserved Session replays PUBREL.
});

const corpus = &.{
    &qos_recovery_seed,
    &subscription_seed,
    &mixed_seed,
};

test "structured live MQTT reconnect sequences reach recovery states" {
    const qos = try harness.runSequence(qos_recovery_seed[4..]);
    try std.testing.expect(qos.reconnects >= 5);
    try std.testing.expect(qos.fresh_sessions >= 2);
    try std.testing.expect(qos.resumed_sessions >= 3);
    try std.testing.expect(qos.publish_replays >= 2);
    try std.testing.expect(qos.pubrel_replays >= 1);
    try std.testing.expect(qos.session_losses >= 2);

    const subscriptions = try harness.runSequence(subscription_seed[4..]);
    try std.testing.expect(subscriptions.subscription_replays >= 3);
    try std.testing.expect(subscriptions.empty_reconnect_barriers >= 2);
}

test "fuzz bounded live MQTT reconnect ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic live MQTT reconnect mutation smoke" {
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
