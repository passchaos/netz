const std = @import("std");
const quic = @import("../mod.zig");

const handshake = quic.handshake;

test "QUIC integrated handshake accepts authenticated 0-RTT stream data" {
    try runAcceptedEarlyData(.aes_128_gcm_sha256);
}

test "QUIC integrated handshake accepts ChaCha20 0-RTT and 1-RTT data" {
    try runAcceptedEarlyData(.chacha20_poly1305_sha256);
}

test "QUIC integrated handshake accepts AES-256 SHA-384 0-RTT and 1-RTT" {
    try runAcceptedEarlyData(.aes_256_gcm_sha384);
}

fn runAcceptedEarlyData(
    cipher_suite: quic.tls_client_hello.CipherSuite,
) !void {
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

    const ticket = "early-ticket";
    const psk = pskForSuite(cipher_suite);
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(earlyTicket(ticket, psk, cipher_suite));
    var lease = (try cache.beginEarlyData("localhost:443", "h3", 1500)).?;
    defer lease.deinit();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        replay_filter: *quic.zero_rtt.ReplayFilter,
        ticket: []const u8,
        psk: [32]u8,
        psk_secret: quic.tls.secret.Secret,
        cipher_suite: quic.tls_client_hello.CipherSuite,
        err: ?anyerror = null,
        resumed: bool = false,
        early_data_status: quic.zero_rtt.handshake.Status = .not_offered,
        early_data: ?[]u8 = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xb2} ** 32,
                .x25519_secret_key = [_]u8{0xb3} ** 32,
                .psk = .{
                    .identity = shared.ticket,
                    .secret = shared.psk,
                    .secret_value = shared.psk_secret,
                    .age_add = 17,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = 1500,
                    .cipher_suite = shared.cipher_suite,
                },
                .early_data = .{
                    .accept = true,
                    .replay_filter = shared.replay_filter,
                    .replay_key = "request-1",
                },
                .cipher_suites = &.{shared.cipher_suite},
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            shared.resumed = established.resumed;
            shared.early_data_status = established.early_data_status;
            shared.early_data = established.connection.copyReceivedStream(
                shared.endpoint.allocator,
                0,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .replay_filter = &replay_filter,
        .ticket = ticket,
        .psk = if (psk.hash == .sha256)
            psk.sha256() catch unreachable
        else
            [_]u8{0} ** 32,
        .psk_secret = psk,
        .cipher_suite = cipher_suite,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "early request",
        .fin = true,
    } }};
    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "12345678",
            .local_connection_id = "client",
            .random = [_]u8{0xb4} ** 32,
            .x25519_secret_key = [_]u8{0xb5} ** 32,
            .key_exchange_groups = &.{
                .x25519_mlkem768,
                .x25519,
            },
            .cipher_suites = &.{cipher_suite},
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
            .early_data = .{
                .cache = &cache,
                .lease = &lease,
                .frames = &frames,
            },
        },
    );
    defer established.deinit();
    thread.join();
    defer if (shared.early_data) |bytes| allocator.free(bytes);
    if (shared.err) |err| return err;

    try std.testing.expect(established.resumed);
    try std.testing.expectEqual(
        cipher_suite,
        established.connection.config.send_keys.suite,
    );
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.accepted,
        established.early_data_status,
    );
    try std.testing.expect(shared.resumed);
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.accepted,
        shared.early_data_status,
    );
    try std.testing.expectEqualStrings(
        "early request",
        shared.early_data orelse return error.TestUnexpectedResult,
    );
    try std.testing.expectEqual(.consumed, lease.state);
    // X25519MLKEM768 makes ClientHello exceed one 1200-byte Initial. Reaching
    // this assertion proves the server consumed the following standalone
    // 0-RTT datagram after cross-datagram Initial CRYPTO reassembly.
    try established.connection.send(&.{.{ .ping = {} }});
    var one_rtt = try sharedEndpointReceive(
        &server_endpoint,
        established.connection.config.send_keys,
        1,
    );
    one_rtt.deinit(allocator);
}

test "QUIC integrated handshake rejects 0-RTT but resumes with PSK" {
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

    const ticket = "rejected-ticket";
    const psk = [_]u8{0xc1} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(earlyTicket(
        ticket,
        .fromSha256(psk),
        .aes_128_gcm_sha256,
    ));
    var lease = (try cache.beginEarlyData("localhost:443", "h3", 1500)).?;
    defer lease.deinit();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        replay_filter: *quic.zero_rtt.ReplayFilter,
        ticket: []const u8,
        psk: [32]u8,
        err: ?anyerror = null,
        resumed: bool = false,
        status: quic.zero_rtt.handshake.Status = .not_offered,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xc2} ** 32,
                .x25519_secret_key = [_]u8{0xc3} ** 32,
                .psk = .{
                    .identity = shared.ticket,
                    .secret = shared.psk,
                    .age_add = 17,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = 1500,
                },
                // The ticket was issued under AES. Selecting ChaCha remains
                // valid for PSK-DHE resumption because both suites use
                // SHA-256, but RFC 8446 requires rejecting 0-RTT when the
                // selected AEAD differs from the ticket's suite.
                .cipher_suites = &.{.chacha20_poly1305_sha256},
                .early_data = .{
                    .accept = true,
                    .replay_filter = shared.replay_filter,
                    .replay_key = "suite-mismatch",
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            shared.resumed = established.resumed;
            shared.status = established.early_data_status;
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .replay_filter = &replay_filter,
        .ticket = ticket,
        .psk = psk,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "discard me",
    } }};
    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "87654321",
            .local_connection_id = "client",
            .random = [_]u8{0xc4} ** 32,
            .x25519_secret_key = [_]u8{0xc5} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
            .early_data = .{
                .cache = &cache,
                .lease = &lease,
                .frames = &frames,
            },
        },
    );
    defer established.deinit();
    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expect(established.resumed);
    try std.testing.expectEqual(
        quic.tls_client_hello.CipherSuite.chacha20_poly1305_sha256,
        established.connection.config.send_keys.suite,
    );
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        established.early_data_status,
    );
    try std.testing.expect(shared.resumed);
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        shared.status,
    );
    try std.testing.expectEqual(.consumed, lease.state);
}

test "QUIC integrated server replay gate rejects a repeated early-data key" {
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

    const ticket = "replayed-ticket";
    const psk = [_]u8{0xd1} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(earlyTicket(
        ticket,
        .fromSha256(psk),
        .aes_128_gcm_sha256,
    ));
    var lease = (try cache.beginEarlyData("localhost:443", "h3", 1500)).?;
    defer lease.deinit();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    try replay_filter.checkAndMark(
        "duplicate-request",
        1400,
        3_601_000,
    );

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        replay_filter: *quic.zero_rtt.ReplayFilter,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xd2} ** 32,
                .x25519_secret_key = [_]u8{0xd3} ** 32,
                .psk = .{
                    .identity = ticket,
                    .secret = psk,
                    .age_add = 17,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = 1500,
                },
                .early_data = .{
                    .accept = true,
                    .replay_filter = shared.replay_filter,
                    .replay_key = "duplicate-request",
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .replay_filter = &replay_filter,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const Client = struct {
        endpoint: *quic.runtime.Endpoint,
        peer: std.Io.net.IpAddress,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        err: ?anyerror = null,

        fn run(client: *@This()) void {
            const frames = [_]quic.Frame{.{ .stream = .{
                .stream_id = 0,
                .data = "replayed",
            } }};
            var established = handshake.connect(
                client.endpoint,
                client.peer,
                .{
                    .original_destination_connection_id = "replay01",
                    .local_connection_id = "client",
                    .random = [_]u8{0xd4} ** 32,
                    .x25519_secret_key = [_]u8{0xd5} ** 32,
                    .resumption_now_ms = 1500,
                    .resumption_server_id = "localhost:443",
                    .early_data = .{
                        .cache = client.cache,
                        .lease = client.lease,
                        .frames = &frames,
                    },
                },
            ) catch |err| {
                client.err = err;
                return;
            };
            established.deinit();
        }
    };
    var client = Client{
        .endpoint = &client_endpoint,
        .peer = server_endpoint.address(),
        .cache = &cache,
        .lease = &lease,
    };
    const client_thread = try std.Thread.spawn(.{}, Client.run, .{&client});
    server_thread.join();
    try std.testing.expectEqualStrings(
        "ReplayedEarlyData",
        @errorName(shared.err orelse return error.TestUnexpectedResult),
    );
    try server_endpoint.sendBytes(client_endpoint.address(), "invalid");
    client_thread.join();
    try std.testing.expect(client.err != null);
    try std.testing.expectEqual(.consumed, lease.state);
}

fn earlyTicket(
    ticket: []const u8,
    psk: quic.tls.secret.Secret,
    cipher_suite: quic.tls_client_hello.CipherSuite,
) quic.resumption.Ticket {
    return .{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = if (psk.hash == .sha256)
            psk.sha256() catch unreachable
        else
            [_]u8{0} ** 32,
        .psk_secret = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 17,
        .cipher_suite = cipher_suite,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    };
}

fn pskForSuite(
    suite: quic.tls_client_hello.CipherSuite,
) quic.tls.secret.Secret {
    return switch (suite.hash()) {
        .sha256 => .fromSha256([_]u8{0xb1} ** 32),
        .sha384 => .fromSha384([_]u8{0xb1} ** 48),
        .sm3 => unreachable,
    };
}

fn sharedEndpointReceive(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
) !quic.one_rtt.ReceivedPacket {
    return quic.one_rtt.receive(
        endpoint,
        keys,
        "server".len,
        expected_packet_number,
        8,
    );
}
