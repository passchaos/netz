const std = @import("std");
const grpc = @import("mod.zig");
const http2 = @import("../http2/mod.zig");
const tls_testing = @import("../tls/testing.zig");

const allocator = std.testing.allocator;

fn payload(index: u8) [8]u8 {
    return .{ 'G', 'R', 'P', 'C', 'P', 0, 0, index };
}

const strict_policy: grpc.ServerKeepAliveEnforcementPolicy = .{
    .min_interval = .fromSeconds(1),
    .idle_interval = .fromSeconds(1),
    .max_strikes = 2,
};

test "gRPC cleartext server applies grpc-core PING enforcement defaults" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var server = try grpc.runtime.Server.listen(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer server.deinit();
    try std.testing.expectEqualDeep(
        grpc.ServerKeepAliveEnforcementPolicy{},
        server.transport.limits.ping_enforcement.?,
    );

    var disabled = try grpc.runtime.Server.listenWithOptions(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .keepalive_enforcement = null },
    );
    defer disabled.deinit();
    try std.testing.expect(disabled.transport.limits.ping_enforcement == null);
}

test "gRPC TLS server enforces too_many_pings with exact GOAWAY" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try grpc.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .transport = .{ .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            } },
            .max_message_size = 4096,
            .keepalive_enforcement = strict_policy,
        },
    );
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.TlsServer) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(2));
            defer connection.deinit();
            for (0..3) |index| {
                try std.testing.expectEqual(
                    payload(@intCast(index)),
                    try connection.connection.readPingWithTimeout(.fromSeconds(2)),
                );
            }
            try std.testing.expectError(
                error.ConnectionGoAway,
                connection.connection.readPingWithTimeout(.fromSeconds(2)),
            );
            try std.testing.expectEqual(@as(u64, 1), connection.connection.pingEnforcementStats().violations);
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try grpc.runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } } },
    );
    defer client.deinit();
    try std.testing.expectEqualStrings("h2", client.negotiatedAlpn().?);
    for (0..3) |index| {
        _ = try client.connection.pingWithTimeout(
            payload(@intCast(index)),
            .fromSeconds(2),
        );
    }
    const final_payload = payload(3);
    try http2.runtime.testing.writeRawFrame(
        &client.connection,
        .ping,
        0,
        0,
        &final_payload,
    );
    var goaway = try client.connection.readGoAwayWithTimeout(.fromSeconds(2));
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.enhance_your_calm, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("too_many_pings", goaway.goaway.debug_data);
    try peer.await(io);
}
