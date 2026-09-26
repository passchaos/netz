//! Bounded HTTP/3 connection-state fuzzing over authenticated QUIC/TLS.

const std = @import("std");
const harness = @import("http3_connection_fuzz/harness.zig");
const model = @import("http3_connection_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const lifecycle_seed = smithSliceSeed(&.{
    0, // Complete GET.
    1, // Complete POST with trailers.
    2, // Streaming POST body with trailers.
    3, // Incrementally consumed response and trailers.
    4, // Two multiplexed requests, responses reversed.
    5, // Cancel a partial upload.
    6, // HEAD suppresses the response body.
    7, // GOAWAY terminates new request admission.
});

const multiplex_seed = smithSliceSeed(&.{ 4, 3, 0, 2, 4, 1, 6, 7 });
const corpus = &.{ &lifecycle_seed, &multiplex_seed };

test "structured live HTTP3 sequences reach connection states" {
    const summary = try harness.runSequence(lifecycle_seed[4..]);
    try std.testing.expectEqual(@as(usize, 8), summary.streams);
    try std.testing.expect(summary.simple >= 1);
    try std.testing.expect(summary.request_trailers >= 1);
    try std.testing.expect(summary.streaming_requests >= 1);
    try std.testing.expect(summary.streaming_responses >= 1);
    try std.testing.expect(summary.multiplexed_pairs >= 1);
    try std.testing.expect(summary.cancellations >= 1);
    try std.testing.expect(summary.head_responses >= 1);
    try std.testing.expect(summary.goaways >= 1);
}

test "fuzz bounded live HTTP3 connection sequences" {
    try std.testing.fuzz({}, fuzzSequences, .{ .corpus = corpus });
}

test "bounded deterministic live HTTP3 connection mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x6874747033636f6e);
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
