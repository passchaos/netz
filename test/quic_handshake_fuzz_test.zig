//! Bounded authenticated QUIC/TLS handshake fault fuzzing.

const std = @import("std");
const netz = @import("netz");
const quic = netz.quic;
const harness = @import("quic_handshake_fuzz/harness.zig");
const model = @import("quic_handshake_fuzz/model.zig");
const RecoveryConfig = @FieldType(
    quic.handshake.ClientOptions,
    "handshake_recovery",
);

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

test "QUIC RFC 8879 compressed Certificate across an authenticated handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const repeated_chain = [_][]const u8{
        &certificate_der,
        &certificate_der,
        &certificate_der,
        &certificate_der,
        &certificate_der,
        &certificate_der,
    };
    const recovery = RecoveryConfig{
        .initial_pto_ms = 5,
        .max_pto_ms = 20,
        .max_retries = 6,
        .max_duration_ms = 3_000,
    };

    const runHandshake = struct {
        fn run(
            endpoint: *quic.runtime.Endpoint,
            chain: []const []const u8,
            keypair: @TypeOf(key_pair),
            rec: RecoveryConfig,
            compression: []const quic.tls.certificate_compression.Algorithm,
            err: *?anyerror,
        ) void {
            var established = quic.handshake.acceptWithTimeout(
                endpoint,
                .{
                    .local_connection_id = "server",
                    .identity = .{
                        .certificate_chain = chain,
                        .signer = .{ .ecdsa_p256_sha256 = .{
                            .key_pair = keypair,
                        } },
                    },
                    .certificate_compression_algorithms = compression,
                    .handshake_recovery = rec,
                    .initial_one_rtt_config = .{ .enable_pacing = false },
                },
                model.timeout,
            ) catch |e| {
                err.* = e;
                return;
            };
            established.deinit();
        }
    }.run;

    // Default algorithms: the client offers compression and the large
    // repeated chain is compressed.
    var server_err: ?anyerror = null;
    const server_thread = try std.Thread.spawn(.{}, runHandshake, .{
        &server_endpoint,
        &repeated_chain,
        key_pair,
        recovery,
        &quic.tls_client_hello.default_certificate_compression_algorithms,
        &server_err,
    });
    var joined = false;
    defer if (!joined) server_thread.join();

    var established = try quic.handshake.connectWithTimeout(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "cc-client",
            .local_connection_id = "client",
            .server_name = "localhost",
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .handshake_recovery = recovery,
            .initial_one_rtt_config = .{ .enable_pacing = false },
        },
        model.timeout,
    );
    try std.testing.expect(
        established.certificate_compression != null,
    );
    established.deinit();
    server_thread.join();
    joined = true;
    if (server_err) |err| return err;

    // Server compression disabled: the Certificate stays uncompressed while
    // the same client offer remains harmless.
    var plain_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer plain_endpoint.deinit();
    var plain_err: ?anyerror = null;
    const plain_thread = try std.Thread.spawn(.{}, runHandshake, .{
        &plain_endpoint,
        &repeated_chain,
        key_pair,
        recovery,
        &.{},
        &plain_err,
    });
    var plain_joined = false;
    defer if (!plain_joined) plain_thread.join();

    var plain = try quic.handshake.connectWithTimeout(
        &client_endpoint,
        plain_endpoint.address(),
        .{
            .original_destination_connection_id = "cc-plain",
            .local_connection_id = "client2",
            .server_name = "localhost",
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .handshake_recovery = recovery,
            .initial_one_rtt_config = .{ .enable_pacing = false },
        },
        model.timeout,
    );
    try std.testing.expect(plain.certificate_compression == null);
    plain.deinit();
    plain_thread.join();
    plain_joined = true;
    if (plain_err) |err| return err;
}
