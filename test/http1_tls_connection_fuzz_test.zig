//! Bounded HTTP/1 connection-state fuzzing over authenticated TLS 1.3.

const std = @import("std");
const harness = @import("http1_connection_fuzz/harness.zig");
const model = @import("http1_connection_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const lifecycle_seed = smithSliceSeed(&.{
    8, // GET after a TLS key update.
    9, // Complete POST after a TLS key update.
    10, // Streaming fixed-length POST after a TLS key update.
    11, // Streaming chunked POST/trailer after a TLS key update.
    12, // Streaming fixed response after a TLS key update.
    14, // HEAD response after a TLS key update.
    5, // Chunked response/trailer and server close.
    15, // Request-side close after a TLS key update.
});

const reuse_seed = smithSliceSeed(&.{ 10, 12, 11, 8, 14, 9, 5, 8, 15, 4 });
const corpus = &.{ &lifecycle_seed, &reuse_seed };

test "structured TLS HTTP1 sequences reach connection and key states" {
    const summary = try harness.runTlsSequence(lifecycle_seed[4..]);
    try std.testing.expectEqual(@as(usize, 8), summary.requests);
    try std.testing.expectEqual(@as(usize, 7), summary.key_updates);
    try std.testing.expect(summary.reused >= 6);
    try std.testing.expect(summary.reconnects >= 1);
    try std.testing.expect(summary.streaming_fixed_requests >= 1);
    try std.testing.expect(summary.streaming_chunked_requests >= 1);
    try std.testing.expect(summary.streaming_fixed_responses >= 1);
    try std.testing.expect(summary.streaming_chunked_responses >= 1);
    try std.testing.expect(summary.head_responses >= 1);
    try std.testing.expect(summary.client_closes >= 1);
    try std.testing.expect(summary.server_closes >= 1);
}

test "fuzz bounded authenticated TLS HTTP1 connection sequences" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic TLS HTTP1 connection mutation smoke" {
    var mutated: [model.max_operations]u8 = undefined;
    inline for (corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (0..seed.len + 1) |length| {
            _ = try harness.runTlsSequence(seed[0..length]);
        }
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = try harness.runTlsSequence(mutated[0..seed.len]);
        }
    }

    var random_bytes: [model.max_operations]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x68315f746c735f66);
    const random = prng.random();
    for (0..3) |_| {
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
