//! Bounded HTTP/2 connection-state fuzzing over authenticated TLS 1.3.

const std = @import("std");
const harness = @import("http2_connection_fuzz/harness.zig");
const model = @import("http2_connection_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const lifecycle_seed = smithSliceSeed(&.{
    8, // Complete GET after a TLS key update.
    9, // POST body and trailers after a TLS key update.
    10, // Streaming request body after a TLS key update.
    11, // Streaming response body after a TLS key update.
    12, // Reversed multiplexed responses after a TLS key update.
    13, // PING after a TLS key update.
    6, // Cancel after request FIN.
    7, // GOAWAY and rotate the authenticated connection.
});

const rotation_seed = smithSliceSeed(&.{ 8, 13, 7, 12, 9, 6, 10, 7 });
const corpus = &.{ &lifecycle_seed, &rotation_seed };

test "structured TLS HTTP2 sequences reach connection and key states" {
    const summary = try harness.runTlsSequence(lifecycle_seed[4..]);
    try std.testing.expectEqual(@as(usize, 7), summary.requests);
    try std.testing.expectEqual(@as(usize, 6), summary.key_updates);
    try std.testing.expect(summary.simple >= 1);
    try std.testing.expect(summary.request_trailers >= 1);
    try std.testing.expect(summary.streaming_requests >= 1);
    try std.testing.expect(summary.streaming_responses >= 1);
    try std.testing.expect(summary.batches >= 1);
    try std.testing.expect(summary.pings >= 1);
    try std.testing.expect(summary.cancellations >= 1);
    try std.testing.expect(summary.goaways >= 1);
}

test "fuzz bounded authenticated TLS HTTP2 connection sequences" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic TLS HTTP2 connection mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x68325f746c735f66);
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
