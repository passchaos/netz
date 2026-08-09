const std = @import("std");
const quic = @import("../mod.zig");
const handshake = @import("../handshake.zig");

test "QUIC integrated secp384r1-only handshake exchanges 1-RTT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,
        suite: ?quic.tls_client_hello.CipherSuite = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xc2} ** 32,
                .p384_secret_key = [_]u8{0} ** 47 ++ [_]u8{2},
                .key_exchange_groups = &.{.secp384r1},
                .cipher_suites = &.{.aes_256_gcm_sha384},
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            shared.suite = established.connection.config.send_keys.suite;
            var packet = established.connection.receivePacket() catch |err| {
                shared.err = err;
                return;
            };
            defer packet.deinit(shared.endpoint.allocator);
            if (packet.frames.len != 1 or packet.frames[0] != .ping) {
                shared.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "p3840001",
            .local_connection_id = "client",
            .random = [_]u8{0xc3} ** 32,
            .p384_secret_key = [_]u8{0} ** 47 ++ [_]u8{1},
            .key_exchange_groups = &.{.secp384r1},
            .cipher_suites = &.{.aes_256_gcm_sha384},
        },
    );
    defer established.deinit();
    try std.testing.expectEqual(
        quic.tls_client_hello.CipherSuite.aes_256_gcm_sha384,
        established.connection.config.send_keys.suite,
    );
    try std.testing.expectEqual(
        quic.tls.secret.Hash.sha384,
        established.connection.config.send_keys.traffic_secret.hash,
    );
    try established.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        quic.tls_client_hello.CipherSuite.aes_256_gcm_sha384,
        shared.suite.?,
    );
}
