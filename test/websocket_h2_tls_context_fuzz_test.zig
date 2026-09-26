//! Bounded context-takeover fuzzing over authenticated RFC 8441 sessions.

const std = @import("std");
const support = @import("websocket_live_context_support.zig");
const harness = @import("websocket_h2_context_fuzz/harness.zig");

test "structured TLS RFC 8441 sequences cover TLS and runtime APIs" {
    try support.requireApiMatrix(try runSequence(
        support.api_matrix_seed[4..],
    ));
    const repeated = try runSequence(support.repeated_history_seed[4..]);
    try std.testing.expect(repeated.messages >= 8);
}

test "fuzz authenticated RFC 8441 context takeover" {
    try std.testing.fuzz({}, fuzzContextTakeover, .{
        .corpus = support.corpus,
    });
}

test "bounded deterministic TLS RFC 8441 context mutation smoke" {
    var mutated: [support.max_sequence_bytes]u8 = undefined;
    inline for (support.corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = try runSequence(mutated[0..seed.len]);
        }
    }

    var random_bytes: [support.max_sequence_bytes]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x77325f746c735f66);
    const random = prng.random();
    for (0..3) |_| {
        const length = random.uintLessThan(
            usize,
            support.max_sequence_bytes + 1,
        );
        random.bytes(random_bytes[0..length]);
        _ = try runSequence(random_bytes[0..length]);
    }
}

fn fuzzContextTakeover(_: void, smith: *std.testing.Smith) !void {
    var storage: [support.max_sequence_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try runSequence(bytes);
}

fn runSequence(bytes: []const u8) !support.Summary {
    return harness.runTlsSequence(bytes);
}
