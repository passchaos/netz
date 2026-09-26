//! Bounded authenticated QUIC/TLS handshake fault fuzzing.

const std = @import("std");
const harness = @import("quic_handshake_fuzz/harness.zig");
const model = @import("quic_handshake_fuzz/model.zig");

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const baseline_seed = smithSliceSeed(&.{ 0, 0, 0 });
const client_loss_seed = smithSliceSeed(&.{ 1, 1, 1 });
const server_loss_seed = smithSliceSeed(&.{ 2, 2, 2 });
const dual_loss_seed = smithSliceSeed(&.{ 3, 0, 3 });
const corrupt_client_seed = smithSliceSeed(&.{ 2, 1, 4 });
const corrupt_server_seed = smithSliceSeed(&.{ 3, 2, 5 });
const retry_seed = smithSliceSeed(&.{ 2, 1, 6 });
const corpus = &.{
    &baseline_seed,
    &client_loss_seed,
    &server_loss_seed,
    &dual_loss_seed,
    &corrupt_client_seed,
    &corrupt_server_seed,
    &retry_seed,
};

test "structured QUIC handshake sequences cover recovery states" {
    const client_loss = try harness.runSequence(client_loss_seed[4..]);
    try std.testing.expectEqual(@as(usize, 1), client_loss.recovered_client_flights);
    try std.testing.expectEqual(@as(usize, 1), client_loss.application_round_trips);
    const server_loss = try harness.runSequence(server_loss_seed[4..]);
    try std.testing.expectEqual(@as(usize, 1), server_loss.recovered_server_flights);
    try std.testing.expectEqual(@as(usize, 1), server_loss.application_round_trips);
    const corrupted = try harness.runSequence(corrupt_client_seed[4..]);
    try std.testing.expectEqual(@as(usize, 1), corrupted.rejected_client_flights);
    try std.testing.expectEqual(@as(usize, 1), corrupted.application_round_trips);
    const server_corrupted = try harness.runSequence(corrupt_server_seed[4..]);
    try std.testing.expectEqual(
        @as(usize, 1),
        server_corrupted.rejected_server_flights,
    );
    const retried = try harness.runSequence(retry_seed[4..]);
    try std.testing.expectEqual(@as(usize, 1), retried.retries);
    try std.testing.expectEqual(@as(usize, 1), retried.application_round_trips);
    try harness.runTimeout();
}

test "fuzz bounded authenticated QUIC handshake recovery" {
    try std.testing.fuzz({}, fuzzHandshakes, .{ .corpus = corpus });
}

test "bounded deterministic QUIC handshake mutation smoke" {
    var mutated: [model.max_input_bytes]u8 = undefined;
    inline for (corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (0..seed.len + 1) |length| {
            _ = try harness.runSequence(seed[0..length]);
        }
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = harness.runSequence(mutated[0..seed.len]) catch |err| {
                std.debug.print("failed mutation {any}: {s}\n", .{
                    mutated[0..seed.len],
                    @errorName(err),
                });
                return err;
            };
        }
    }
}

fn fuzzHandshakes(_: void, smith: *std.testing.Smith) !void {
    var storage: [model.max_input_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try harness.runSequence(bytes);
}
