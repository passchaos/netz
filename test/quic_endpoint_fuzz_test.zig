//! Bounded authenticated QUIC endpoint ownership and capacity fuzzing.

const std = @import("std");
const harness = @import("quic_endpoint_fuzz/harness.zig");
const model = @import("quic_endpoint_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const mixed_versions_seed = smithSliceSeed(&.{ 0b1010, 0b1100 });
const inverted_seed = smithSliceSeed(&.{ 0b0101, 0b0011 });
const all_v2_aes256_seed = smithSliceSeed(&.{ 0b1111, 0b1111 });
const corpus = &.{
    &mixed_versions_seed,
    &inverted_seed,
    &all_v2_aes256_seed,
};

test "structured QUIC endpoint sequence covers capacity and socket ownership" {
    const summary = try harness.runSequence(mixed_versions_seed[4..]);
    try std.testing.expectEqual(model.client_count, summary.connected);
    try std.testing.expectEqual(@as(usize, 2), summary.version_2_connections);
    try std.testing.expectEqual(@as(usize, 2), summary.aes_256_connections);
    try std.testing.expectEqual(@as(usize, 2), summary.capacity_rejections);
    try std.testing.expectEqual(model.client_count, summary.removals);
    try std.testing.expectEqual(model.client_count, summary.stream_round_trips);
    try std.testing.expectEqual(model.capacity, summary.max_live_connections);
    try std.testing.expect(summary.stale_packets >= 2);
}

test "fuzz authenticated QUIC endpoint lifecycle" {
    try std.testing.fuzz({}, fuzzEndpoint, .{ .corpus = corpus });
}

test "bounded deterministic QUIC endpoint mutation smoke" {
    var mutated: [model.max_sequence_bytes]u8 = undefined;
    inline for (corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (seed, 0..) |_, index| {
            @memcpy(&mutated, seed);
            mutated[index] ^= 0xff;
            _ = try harness.runSequence(&mutated);
        }
    }
}

fn fuzzEndpoint(_: void, smith: *std.testing.Smith) !void {
    var storage: [model.max_sequence_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try harness.runSequence(bytes);
}
