//! Authenticated shared-endpoint WebTransport routing fuzzing.

const std = @import("std");
const harness = @import("webtransport_endpoint_fuzz/harness.zig");
const model = @import("webtransport_endpoint_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const lifecycle_seed = smithSliceSeed(&.{ 0, 1, 2, 3, 4, 5, 6, 7 });
const skew_seed = smithSliceSeed(&.{ 0, 2, 4, 0, 2, 4, 1, 7 });
const corpus = &.{ &lifecycle_seed, &skew_seed };

test "structured WebTransport endpoint sequences cover both sessions" {
    const summary = try harness.runSequence(lifecycle_seed[4..]);
    try std.testing.expectEqual(@as(usize, 2), summary.sessions);
    try std.testing.expectEqual(@as(usize, 8), summary.datagrams);
    try std.testing.expectEqual(@as(usize, 2), summary.streams);
    try std.testing.expectEqual(@as(usize, 2), summary.drains);
    try std.testing.expectEqual(@as(usize, 2), summary.closes);
    try std.testing.expect(summary.routed_to[0] != 0);
    try std.testing.expect(summary.routed_to[1] != 0);
}

test "fuzz authenticated WebTransport shared-endpoint routing" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic WebTransport endpoint mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x77745f656e647074);
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
