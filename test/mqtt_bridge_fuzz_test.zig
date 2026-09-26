//! Bounded inbound MQTT bridge fuzzing across real upstream and local TCP.

const std = @import("std");
const harness = @import("mqtt_bridge_fuzz/harness.zig");
const model = @import("mqtt_bridge_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const routing_seed = smithSliceSeed(&.{
    0x00, // Topic zero, QoS 0.
    0x09, // Topic one, QoS 1.
    0x02, // Retain topic zero at QoS 0.
    0x0b, // Retain topic one at QoS 1.
    0x03, // Replace retained topic zero at QoS 1.
    0x0c, // Delete retained topic one.
    0x07, // Upstream DUP input is normalized at the local boundary.
});

const reconnect_seed = smithSliceSeed(&.{
    0x03, // Establish retained state before reconnecting.
    0x05, // Fresh Session replays both bridge subscriptions.
    0x09, // Route on the fresh connection.
    0x06, // Preserved Session emits no redundant subscription.
    0x08, // Route QoS 0 on the resumed connection.
    0x0d, // Another fresh Session replay.
    0x0f, // DUP input on the fresh connection.
});

const corpus = &.{ &routing_seed, &reconnect_seed };

test "structured live MQTT bridge sequences reach routing states" {
    const routing = try harness.runSequence(routing_seed[4..]);
    try std.testing.expect(routing.deliveries >= 7);
    try std.testing.expect(routing.qos1_acknowledgements >= 5);
    try std.testing.expect(routing.retained_writes >= 3);
    try std.testing.expect(routing.retained_deletes >= 1);
    try std.testing.expect(routing.duplicate_inputs >= 1);
    try std.testing.expect(routing.retained_probe_deliveries >= 1);

    const reconnects = try harness.runSequence(reconnect_seed[4..]);
    try std.testing.expect(reconnects.fresh_reconnects >= 2);
    try std.testing.expect(reconnects.resumed_reconnects >= 1);
    try std.testing.expect(reconnects.subscription_replays >= 4);
}

test "fuzz bounded live MQTT bridge routing" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic live MQTT bridge mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x627269646765667a);
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
