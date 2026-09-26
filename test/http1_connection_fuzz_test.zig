//! Bounded production HTTP/1 connection-state fuzzing over loopback TCP.

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
    0, // GET, fixed response.
    1, // Complete POST body.
    2, // Streaming fixed-length POST body.
    3, // Streaming chunked POST body and trailer.
    4, // Streaming fixed-length response.
    6, // HEAD suppresses response body.
    5, // Chunked response/trailer and server close.
    7, // Request-side Connection close.
});

const reuse_seed = smithSliceSeed(&.{
    2, 4, 3, 0, 6, 1, 5, 0, 7, 4,
});

const corpus = &.{ &lifecycle_seed, &reuse_seed };

test "structured live HTTP1 sequences reach connection states" {
    const summary = try harness.runSequence(lifecycle_seed[4..]);
    try std.testing.expectEqual(@as(usize, 8), summary.requests);
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

test "fuzz bounded live HTTP1 connection sequences" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic live HTTP1 connection mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x6874747031636f6e);
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
