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
        .{ .max_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size },
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

test "QUIC integrated X25519MLKEM768-only handshake exchanges 1-RTT" {
    const allocator = std.testing.allocator;
    const Hybrid = quic.tls.key_exchange.x25519_mlkem768;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size },
    );
    defer client_endpoint.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xd2} ** 32,
                .x25519_mlkem768_secret_key = [_]u8{0xd3} ** Hybrid.x25519_secret_len,
                .x25519_mlkem768_encaps_seed = [_]u8{0xd4} ** Hybrid.encaps_seed_len,
                .key_exchange_groups = &.{.x25519_mlkem768},
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
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
            .original_destination_connection_id = "pqhybrid",
            .local_connection_id = "client",
            .random = [_]u8{0xd5} ** 32,
            .x25519_mlkem768_secret_key = [_]u8{0xd6} ** Hybrid.x25519_secret_len,
            .x25519_mlkem768_seed = [_]u8{0xd7} ** Hybrid.mlkem_seed_len,
            .key_exchange_groups = &.{.x25519_mlkem768},
        },
    );
    defer established.deinit();
    try established.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
}

fn testNistHybridHandshake(
    comptime Hybrid: type,
    comptime group: quic.tls_client_hello.NamedGroup,
    comptime material_field: []const u8,
    client_curve_secret: [Hybrid.curve_secret_len]u8,
    server_curve_secret: [Hybrid.curve_secret_len]u8,
    mlkem_seed: [Hybrid.mlkem_seed_len]u8,
    encaps_seed: [Hybrid.encaps_seed_len]u8,
) !void {
    const allocator = std.testing.allocator;
    try std.testing.expect(
        Hybrid.client_share_len >
            quic.initial_exchange.min_initial_udp_datagram_size,
    );

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const mtu = quic.initial_exchange.min_initial_udp_datagram_size;
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = mtu },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = mtu },
    );
    defer client_endpoint.deinit();

    var server_options = handshake.ServerOptions{
        .local_connection_id = "server",
        .random = [_]u8{0x81} ** 32,
        .key_exchange_groups = &.{group},
        .cipher_suites = &.{.aes_256_gcm_sha384},
    };
    @field(
        server_options.nist_hybrid_key_material,
        material_field,
    ) = .{
        .curve_secret = server_curve_secret,
        .encaps_seed = encaps_seed,
    };
    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        options: handshake.ServerOptions,
        err: ?anyerror = null,
        suite: ?quic.tls_client_hello.CipherSuite = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(
                shared.endpoint,
                shared.options,
            ) catch |err| {
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
    var shared = Shared{
        .endpoint = &server_endpoint,
        .options = server_options,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client_options = handshake.ClientOptions{
        .original_destination_connection_id = "nist-pq1",
        .local_connection_id = "client",
        .random = [_]u8{0x82} ** 32,
        .key_exchange_groups = &.{group},
        .cipher_suites = &.{.aes_256_gcm_sha384},
    };
    @field(
        client_options.nist_hybrid_key_material,
        material_field,
    ) = .{
        .curve_secret = client_curve_secret,
        .mlkem_seed = mlkem_seed,
    };
    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        client_options,
    );
    defer established.deinit();
    try std.testing.expectEqual(
        quic.tls_client_hello.CipherSuite.aes_256_gcm_sha384,
        established.connection.config.send_keys.suite,
    );
    try established.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        quic.tls_client_hello.CipherSuite.aes_256_gcm_sha384,
        shared.suite.?,
    );
}

test "QUIC secp256r1MLKEM768 handshake fragments at 1200-byte MTU" {
    const Hybrid = quic.tls.key_exchange.secp256r1_mlkem768;
    try testNistHybridHandshake(
        Hybrid,
        .secp256r1_mlkem768,
        "secp256r1_mlkem768",
        [_]u8{0} ** 31 ++ [_]u8{1},
        [_]u8{0} ** 31 ++ [_]u8{2},
        [_]u8{0x83} ** Hybrid.mlkem_seed_len,
        [_]u8{0x84} ** Hybrid.encaps_seed_len,
    );
}

test "QUIC secp384r1MLKEM1024 handshake fragments at 1200-byte MTU" {
    const Hybrid = quic.tls.key_exchange.secp384r1_mlkem1024;
    try testNistHybridHandshake(
        Hybrid,
        .secp384r1_mlkem1024,
        "secp384r1_mlkem1024",
        [_]u8{0} ** 47 ++ [_]u8{1},
        [_]u8{0} ** 47 ++ [_]u8{2},
        [_]u8{0x85} ** Hybrid.mlkem_seed_len,
        [_]u8{0x86} ** Hybrid.encaps_seed_len,
    );
}
