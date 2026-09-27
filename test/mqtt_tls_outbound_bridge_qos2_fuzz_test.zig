//! Durable outbound MQTT bridge QoS 2 fuzzing over authenticated TLS peers.

const std = @import("std");
const harness = @import("mqtt_outbound_bridge_qos2_fuzz/harness.zig");
const model = @import("mqtt_outbound_bridge_qos2_fuzz/model.zig");

test "structured TLS durable outbound bridge reaches recovery states" {
    try model.requireRecovery(try harness.runTlsSequence(
        model.recovery_seed[4..],
    ));
    try model.requireRetained(try harness.runTlsSequence(
        model.retained_seed[4..],
    ));
}

test "fuzz bounded TLS durable outbound MQTT bridge QoS2 ordering" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = model.corpus });
}

test "bounded deterministic TLS durable outbound bridge mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x716f73325f746c73);
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
