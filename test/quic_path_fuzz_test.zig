//! Bounded authenticated QUIC path migration and rebinding fuzzing.

const std = @import("std");
const harness = @import("quic_path_fuzz/harness.zig");
const model = @import("quic_path_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const migration_seed = smithSliceSeed(&.{
    0, // Begin path B.
    7, // Reject an unmatched response.
    1, // Supersede B with path C.
    2, // Consume B's late response without validating C.
    3, // Validate C.
    4, // Carry stream data over C.
    5, // Rebind to a second C port.
    4, // Carry stream data over the rebound path.
});
const timeout_seed = smithSliceSeed(&.{ 0, 6, 6, 6, 4, 1, 3, 4 });
const corpus = &.{ &migration_seed, &timeout_seed };

test "structured QUIC path sequences reach migration states" {
    const migrated = try harness.runSequence(migration_seed[4..]);
    try std.testing.expect(migrated.migrations_started >= 2);
    try std.testing.expect(migrated.paths_validated >= 1);
    try std.testing.expect(migrated.late_responses >= 1);
    try std.testing.expect(migrated.invalid_responses >= 1);
    try std.testing.expect(migrated.rebindings >= 1);
    try std.testing.expect(migrated.application_round_trips >= 2);

    const timed = try harness.runSequence(timeout_seed[4..]);
    try std.testing.expect(timed.timeout_retries >= 2);
    try std.testing.expect(timed.failed_validations >= 1);
    try std.testing.expect(timed.application_round_trips >= 2);
}

test "fuzz bounded authenticated QUIC path sequences" {
    try std.testing.fuzz({}, fuzzPaths, .{ .corpus = corpus });
}

test "bounded deterministic QUIC path mutation smoke" {
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
    var prng = std.Random.DefaultPrng.init(0x717569635f706174);
    const random = prng.random();
    for (0..8) |_| {
        const length = random.uintLessThan(usize, model.max_operations + 1);
        random.bytes(random_bytes[0..length]);
        _ = try harness.runSequence(random_bytes[0..length]);
    }
}

fn fuzzPaths(_: void, smith: *std.testing.Smith) !void {
    var storage: [model.max_operations]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try harness.runSequence(bytes);
}
