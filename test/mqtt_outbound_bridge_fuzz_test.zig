//! Bounded outbound MQTT bridge fuzzing across two real TCP peers.

const std = @import("std");
const harness = @import("mqtt_outbound_bridge_fuzz/harness.zig");
const model = @import("mqtt_outbound_bridge_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const routing_seed = smithSliceSeed(&.{
    0x00, // QoS 0, topic zero.
    0x09, // QoS 1, topic one.
    0x11, // Retained QoS 1, topic zero.
    0x0f, // Source DUP is normalized on target.
    0x01, // QoS 1, topic zero.
});

const reconnect_seed = smithSliceSeed(&.{
    0x02, // Target reconnects with Session Present.
    0x0b, // Target reconnects with a fresh Session.
    0x14, // Source reconnects between messages with Session Present.
    0x0d, // Source reconnects fresh between messages and replays rules.
    0x1a, // Retained target Session resume.
    0x17, // Retained source-DUP normalization.
});

const corpus = &.{ &routing_seed, &reconnect_seed };

test "structured outbound MQTT bridge sequences reach recovery states" {
    const routing = try harness.runSequence(routing_seed[4..]);
    try std.testing.expect(routing.forwarded >= 5);
    try std.testing.expect(routing.qos0 >= 1);
    try std.testing.expect(routing.qos1 >= 4);
    try std.testing.expect(routing.retained >= 1);
    try std.testing.expect(routing.source_dup_normalized >= 1);

    const recovery = try harness.runSequence(reconnect_seed[4..]);
    try std.testing.expect(recovery.target_resumed >= 2);
    try std.testing.expect(recovery.target_fresh >= 1);
    try std.testing.expect(recovery.target_replays >= 3);
    try std.testing.expect(recovery.source_resumed >= 1);
    try std.testing.expect(recovery.source_fresh >= 1);
    try std.testing.expect(recovery.source_subscription_replays >= 2);
}

test "fuzz bounded outbound MQTT bridge ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic outbound MQTT bridge mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x6f75746272696467);
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
