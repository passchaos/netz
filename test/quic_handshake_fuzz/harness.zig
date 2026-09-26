const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const quic = netz.quic;
const RecoveryConfig = @FieldType(
    quic.handshake.ClientOptions,
    "handshake_recovery",
);

const Fault = struct {
    drop_first: bool,
    corrupt_first: bool,
    dropped: usize = 0,
    corrupted: usize = 0,

    fn drop(context: *anyopaque, _: []const u8) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (!self.drop_first or self.dropped != 0) return false;
        self.dropped += 1;
        return true;
    }

    fn corrupt(context: *anyopaque, bytes: []u8) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (!self.corrupt_first or self.corrupted != 0 or bytes.len == 0) {
            return false;
        }
        self.corrupted += 1;
        bytes[bytes.len - 1] ^= 0x80;
        return true;
    }
};

pub fn runSequence(input: []const u8) !model.Summary {
    const case = model.decode(input[0..@min(input.len, model.max_input_bytes)]);
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var client_fault = Fault{
        .drop_first = case.drop_client_first,
        .corrupt_first = case.corrupt_client_first,
    };
    var server_fault = Fault{
        .drop_first = case.drop_server_first,
        .corrupt_first = case.corrupt_server_first,
    };
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .send_interceptor = .{
                .context = &server_fault,
                .should_drop = Fault.drop,
                .corrupt = Fault.corrupt,
            },
        },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .send_interceptor = .{
                .context = &client_fault,
                .should_drop = Fault.drop,
                .corrupt = Fault.corrupt,
            },
        },
    );
    defer client_endpoint.deinit();

    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const recovery: RecoveryConfig = .{
        .initial_pto_ms = 5,
        .max_pto_ms = 20,
        .max_retries = 6,
        .max_duration_ms = 3_000,
    };
    var retry_filter = try quic.address_validation_token.SharedReplayFilter
        .init(allocator, io, 8);
    defer retry_filter.deinit();
    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        case: model.Case,
        key_pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
        certificate_chain: [1][]const u8,
        recovery: RecoveryConfig,
        retry_filter: *quic.address_validation_token.SharedReplayFilter,
        err: ?anyerror = null,
        application_received: bool = false,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var established = try quic.handshake.acceptWithTimeout(
                self.endpoint,
                serverOptions(
                    self.case,
                    self.key_pair,
                    &self.certificate_chain,
                    self.recovery,
                    self.retry_filter,
                ),
                model.timeout,
            );
            defer established.deinit();
            try validateEstablished(established, self.case);
            var request = try established.connection
                .receivePacketServicingTimersTimeout(.{
                .duration = .{
                    .clock = .awake,
                    .raw = model.timeout,
                },
            });
            defer request.deinit(self.endpoint.allocator);
            try expectStream(request.frames, 0, "hello");
            try established.connection.send(&.{.{ .stream = .{
                .stream_id = 0,
                .data = "world",
                .fin = true,
            } }});
            self.application_received = true;
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .case = case,
        .key_pair = key_pair,
        .certificate_chain = .{&public_key},
        .recovery = recovery,
        .retry_filter = &retry_filter,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var established = try quic.handshake.connectWithTimeout(
        &client_endpoint,
        server_endpoint.address(),
        clientOptions(case, public_key, recovery),
        model.timeout,
    );
    defer established.deinit();
    try validateEstablished(established, case);
    try established.connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "hello",
        .fin = true,
    } }});
    var response = try established.connection
        .receivePacketServicingTimersTimeout(.{
        .duration = .{ .clock = .awake, .raw = model.timeout },
    });
    defer response.deinit(allocator);
    try expectStream(response.frames, 0, "world");

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.application_received);
    return .{
        .recovered_client_flights = client_fault.dropped,
        .recovered_server_flights = server_fault.dropped,
        .rejected_client_flights = client_fault.corrupted,
        .rejected_server_flights = server_fault.corrupted,
        .retries = @intFromBool(case.retry),
        .application_round_trips = 1,
    };
}

fn clientOptions(
    case: model.Case,
    public_key: [65]u8,
    recovery: RecoveryConfig,
) quic.handshake.ClientOptions {
    var options = quic.handshake.ClientOptions{
        .original_destination_connection_id = "hs-fuzz0",
        .local_connection_id = "client",
        .server_name = "localhost",
        .server_auth = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .version = case.version,
        .available_versions = &.{ .version_1, .version_2 },
        .cipher_suites = switch (case.cipher_suite) {
            .aes_128_gcm_sha256 => &.{.aes_128_gcm_sha256},
            .aes_256_gcm_sha384 => &.{.aes_256_gcm_sha384},
            else => unreachable,
        },
        .random = [_]u8{0x61} ** 32,
        .handshake_recovery = recovery,
        .initial_one_rtt_config = .{ .enable_pacing = false },
    };
    switch (case.group) {
        .x25519 => {
            options.x25519_secret_key = [_]u8{0x63} ** 32;
            options.key_exchange_groups = &.{.x25519};
        },
        .secp256r1 => {
            options.p256_secret_key = [_]u8{0} ** 31 ++ [_]u8{1};
            options.key_exchange_groups = &.{.secp256r1};
        },
        .secp384r1 => {
            options.p384_secret_key = [_]u8{0} ** 47 ++ [_]u8{1};
            options.key_exchange_groups = &.{.secp384r1};
        },
    }
    return options;
}

fn serverOptions(
    case: model.Case,
    key_pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    certificate_chain: []const []const u8,
    recovery: RecoveryConfig,
    retry_filter: *quic.address_validation_token.SharedReplayFilter,
) quic.handshake.ServerOptions {
    var options = quic.handshake.ServerOptions{
        .local_connection_id = "server",
        .version = case.version,
        .available_versions = &.{ .version_1, .version_2 },
        .cipher_suites = switch (case.cipher_suite) {
            .aes_128_gcm_sha256 => &.{.aes_128_gcm_sha256},
            .aes_256_gcm_sha384 => &.{.aes_256_gcm_sha384},
            else => unreachable,
        },
        .identity = .{
            .certificate_chain = certificate_chain,
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        },
        .random = [_]u8{0x62} ** 32,
        .handshake_recovery = recovery,
        .initial_one_rtt_config = .{ .enable_pacing = false },
    };
    if (case.retry) {
        options.retry = .{
            .secret = [_]u8{0x73} **
                quic.address_validation_token.secret_len,
            .peer_address = "fuzz-peer",
            .issued_ns = 1_000,
            .lifetime_ns = 5_000,
            .nonce = [_]u8{0x74} **
                quic.address_validation_token.nonce_len,
        };
        options.address_validation_replay_filter = retry_filter;
    }
    switch (case.group) {
        .x25519 => {
            options.x25519_secret_key = [_]u8{0x64} ** 32;
            options.key_exchange_groups = &.{.x25519};
        },
        .secp256r1 => {
            options.p256_secret_key = [_]u8{0} ** 31 ++ [_]u8{2};
            options.key_exchange_groups = &.{.secp256r1};
        },
        .secp384r1 => {
            options.p384_secret_key = [_]u8{0} ** 47 ++ [_]u8{2};
            options.key_exchange_groups = &.{.secp384r1};
        },
    }
    return options;
}

fn validateEstablished(
    established: quic.handshake.EstablishedConnection,
    case: model.Case,
) !void {
    try std.testing.expectEqualStrings("h3", established.alpn);
    try std.testing.expectEqual(case.cipher_suite, established.cipher_suite);
    try std.testing.expectEqual(
        case.version,
        established.connection.config.version,
    );
    try std.testing.expectEqual(case.retry, established.retry_processed);
}

fn expectStream(
    frames: []const quic.Frame,
    stream_id: u62,
    expected: []const u8,
) !void {
    for (frames) |frame| switch (frame) {
        .stream => |stream| if (stream.stream_id == stream_id) {
            try std.testing.expectEqualStrings(expected, stream.data);
            return;
        },
        else => {},
    };
    return error.MissingStreamData;
}

pub fn runTimeout() !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fault = Fault{ .drop_first = true, .corrupt_first = false };
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .send_interceptor = .{
                .context = &fault,
                .should_drop = struct {
                    fn all(_: *anyopaque, _: []const u8) bool {
                        return true;
                    }
                }.all,
            },
        },
    );
    defer endpoint.deinit();
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    try std.testing.expectError(
        error.HandshakeTimeout,
        quic.handshake.connectWithTimeout(
            &endpoint,
            peer.address(),
            .{
                .original_destination_connection_id = "timeout0",
                .local_connection_id = "client",
                .random = [_]u8{0x71} ** 32,
                .x25519_secret_key = [_]u8{0x72} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 2,
                    .max_pto_ms = 4,
                    .max_retries = 1,
                },
            },
            .fromMilliseconds(20),
        ),
    );
}
