const std = @import("std");
const quic = @import("../mod.zig");

const net = std.Io.net;
const connect = quic.handshake.connect;
const accept = quic.handshake.accept;

test "QUIC integrated PSK-DHE handshake resumes from an owned session" {
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

    const ticket = "owned-session-ticket";
    const psk = [_]u8{0x6a} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 17,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var session = (try cache.acquire("localhost:443", "h3", 1500)).?;
    defer session.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        ticket: []const u8,
        psk: [32]u8,
        err: ?anyerror = null,
        resumed: bool = false,

        fn run(shared: *@This()) void {
            var established = accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0x72} ** 32,
                .x25519_secret_key = [_]u8{0x73} ** 32,
                .psk = .{
                    .identity = shared.ticket,
                    .secret = shared.psk,
                    .age_add = 17,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = 1500,
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            shared.resumed = established.resumed;
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .ticket = ticket,
        .psk = psk,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "12345678",
            .local_connection_id = "client",
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x74} ** 32,
            .resumption_session = &session,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
        },
    );
    defer established.deinit();
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(established.resumed);
    try std.testing.expect(shared.resumed);
}

test "QUIC integrated server falls back when PSK identity is unknown" {
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

    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = "unknown-ticket",
        .psk = [_]u8{0x80} ** 32,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 0,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var session = (try cache.acquire("localhost:443", "h3", 1100)).?;
    defer session.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,
        resumed: bool = true,
        fn run(shared: *@This()) void {
            var established = accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0x82} ** 32,
                .x25519_secret_key = [_]u8{0x83} ** 32,
                .psk = .{
                    .identity = "different-ticket",
                    .secret = [_]u8{0x81} ** 32,
                    .age_add = 0,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = 1100,
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            shared.resumed = established.resumed;
            established.deinit();
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var established = try connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "87654321",
            .local_connection_id = "client",
            .random = [_]u8{0x84} ** 32,
            .x25519_secret_key = [_]u8{0x85} ** 32,
            .resumption_session = &session,
            .resumption_now_ms = 1100,
            .resumption_server_id = "localhost:443",
        },
    );
    defer established.deinit();
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(!established.resumed);
    try std.testing.expect(!shared.resumed);
}

test "QUIC integrated server rejects a matching identity with bad binder" {
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

    const ticket = "matching-ticket";
    const correct_psk = [_]u8{0x90} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = [_]u8{0x91} ** 32, // Wrong client PSK produces bad binder.
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 0,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var session = (try cache.acquire("localhost:443", "h3", 1100)).?;
    defer session.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            var established = accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0x92} ** 32,
                .x25519_secret_key = [_]u8{0x93} ** 32,
                .psk = .{
                    .identity = ticket,
                    .secret = correct_psk,
                    .age_add = 0,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = 1100,
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    // Client blocks waiting for ServerHello while server rejects before send.
    // Wake it after the server exits so no thread can hang.
    const Client = struct {
        endpoint: *quic.runtime.Endpoint,
        peer: net.IpAddress,
        session: *const quic.resumption.Session,
        err: ?anyerror = null,
        fn run(client: *@This()) void {
            var established = connect(client.endpoint, client.peer, .{
                .original_destination_connection_id = "12345678",
                .local_connection_id = "client",
                .random = [_]u8{0x94} ** 32,
                .x25519_secret_key = [_]u8{0x95} ** 32,
                .resumption_session = client.session,
                .resumption_now_ms = 1100,
                .resumption_server_id = "localhost:443",
            }) catch |err| {
                client.err = err;
                return;
            };
            established.deinit();
        }
    };
    var client = Client{
        .endpoint = &client_endpoint,
        .peer = server_endpoint.address(),
        .session = &session,
    };
    const client_thread = try std.Thread.spawn(.{}, Client.run, .{&client});
    thread.join();
    try std.testing.expectEqualStrings(
        "InvalidPskBinder",
        @errorName(shared.err orelse return error.TestUnexpectedResult),
    );
    try server_endpoint.sendBytes(client_endpoint.address(), "invalid");
    client_thread.join();
    try std.testing.expect(client.err != null);
}

test "QUIC integrated client rejects resumption identity and ALPN mismatch" {
    const allocator = std.testing.allocator;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "expected:443",
        .alpn = "h3",
        .ticket = "ticket",
        .psk = [_]u8{0xa1} ** 32,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 0,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var session = (try cache.acquire("expected:443", "h3", 1100)).?;
    defer session.deinit();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    try std.testing.expectError(
        error.InvalidClientHello,
        connect(&endpoint, endpoint.address(), .{
            .original_destination_connection_id = "12345678",
            .local_connection_id = "client",
            .resumption_session = &session,
            .resumption_now_ms = 1100,
            .resumption_server_id = "wrong:443",
        }),
    );
    try std.testing.expectError(
        error.InvalidClientHello,
        connect(&endpoint, endpoint.address(), .{
            .original_destination_connection_id = "12345678",
            .local_connection_id = "client",
            .alpn_protocols = &.{"hq"},
            .resumption_session = &session,
            .resumption_now_ms = 1100,
            .resumption_server_id = "expected:443",
        }),
    );
}
