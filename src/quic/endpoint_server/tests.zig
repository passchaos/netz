const std = @import("std");
const quic = @import("../mod.zig");
const endpoint_server = @import("../endpoint_server.zig");

test "QUIC endpoint server rejects invalid admission limits" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{ .max_pending_handshakes = 0 }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{ .inbox_capacity = 0 }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{ .handshake_poll_interval = .zero }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{
            .stateless_reset_min_interval = .fromNanoseconds(-1),
        }),
    );

    const reset_key = [_]u8{0x51} **
        quic.stateless_reset.static_key_len;
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .transport_parameters = &.{0},
        }, .{ .stateless_reset_key = reset_key }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .local_transport_parameters = .{
                .preferred_address = .{
                    .ipv4_address = .{ 127, 0, 0, 1 },
                    .ipv4_port = 4433,
                    .connection_id = "preferred-cid",
                },
            },
        }, .{ .stateless_reset_key = reset_key }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .local_transport_parameters = .{
                .stateless_reset_token = [_]u8{0x52} **
                    quic.stateless_reset.token_len,
            },
        }, .{ .stateless_reset_key = reset_key }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .initial_one_rtt_config = .{
                .local_stateless_reset_key = reset_key,
            },
        }, .{}),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .initial_one_rtt_config = .{
                .local_stateless_reset_key = [_]u8{0x53} **
                    quic.stateless_reset.static_key_len,
            },
        }, .{ .stateless_reset_key = reset_key }),
    );
}

test "QUIC endpoint server keeps automatic stateless reset opt in" {
    const allocator = std.testing.allocator;
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
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    var server = try endpoint_server.Server.init(allocator, &endpoint, .{
        .local_connection_id = &.{},
    }, .{});
    defer server.deinit();

    const trigger = [_]u8{0x40} **
        (quic.endpoint_dispatcher.default_server_connection_id_len + 19);
    try peer.sendBytes(server.address(), &trigger);
    var event = (try server.receiveOnce(
        &.{quic.Version.version_1.wireValue()},
        .{ .raw = .fromSeconds(1), .clock = .awake },
    )) orelse return error.TestUnexpectedResult;
    defer event.deinit(allocator);
    try std.testing.expect(event == .unrouted);
    try std.testing.expectEqual(
        quic.endpoint_dispatcher.UnroutedKind.unknown_short_header,
        event.unrouted.unrouted.kind,
    );
    try std.testing.expectError(
        error.Timeout,
        peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );
}

test "QUIC endpoint server sends and rate limits automatic stateless resets" {
    const allocator = std.testing.allocator;
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
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    var other_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer other_peer.deinit();
    const reset_key = [_]u8{0x61} **
        quic.stateless_reset.static_key_len;
    var server = try endpoint_server.Server.init(allocator, &endpoint, .{
        .local_connection_id = &.{},
    }, .{
        .stateless_reset_key = reset_key,
        .stateless_reset_min_interval = .fromSeconds(1),
    });
    defer server.deinit();

    const cid_len = quic.endpoint_dispatcher.default_server_connection_id_len;
    var trigger = [_]u8{0xa5} ** (cid_len + 19);
    trigger[0] = 0x40;
    const cid = trigger[1 .. 1 + cid_len];
    const versions = [_]u32{quic.Version.version_1.wireValue()};

    try peer.sendBytes(server.address(), &trigger);
    try std.testing.expectEqual(
        @as(?endpoint_server.Event, null),
        try server.receiveOnce(
            &versions,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    var reset = try peer.receiveBytesWithTimeout(.fromSeconds(1));
    defer reset.deinit(allocator);
    try std.testing.expect(reset.bytes.len < trigger.len);
    try std.testing.expect(quic.stateless_reset.matches(
        reset.bytes,
        quic.stateless_reset.tokenForConnectionId(reset_key, cid),
    ));

    try other_peer.sendBytes(server.address(), &trigger);
    try std.testing.expectEqual(
        @as(?endpoint_server.Event, null),
        try server.receiveOnce(
            &versions,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        other_peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );

    server.last_stateless_reset_ns = null;
    const too_short = [_]u8{0x40} ** (cid_len + 18);
    try peer.sendBytes(server.address(), &too_short);
    try std.testing.expectEqual(
        @as(?endpoint_server.Event, null),
        try server.receiveOnce(
            &versions,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );

    var fixed_bit_clear = trigger;
    fixed_bit_clear[0] = 0;
    try peer.sendBytes(server.address(), &fixed_bit_clear);
    try std.testing.expectEqual(
        @as(?endpoint_server.Event, null),
        try server.receiveOnce(
            &versions,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );

    const unknown_long = [_]u8{ 0xc0, 0, 0, 0, 1 };
    try peer.sendBytes(server.address(), &unknown_long);
    var long_event = (try server.receiveOnce(
        &versions,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    )) orelse return error.TestUnexpectedResult;
    defer long_event.deinit(allocator);
    try std.testing.expect(long_event == .unrouted);
    try std.testing.expectEqual(
        quic.endpoint_dispatcher.UnroutedKind.malformed_long_header,
        long_event.unrouted.unrouted.kind,
    );
    try std.testing.expectError(
        error.Timeout,
        peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );
}

test "QUIC endpoint server resets unknown packets in visitor and batch receives" {
    const allocator = std.testing.allocator;
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
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const reset_key = [_]u8{0x71} **
        quic.stateless_reset.static_key_len;
    var server = try endpoint_server.Server.init(allocator, &endpoint, .{
        .local_connection_id = &.{},
    }, .{
        .stateless_reset_key = reset_key,
        .stateless_reset_min_interval = .zero,
    });
    defer server.deinit();

    const cid_len = quic.endpoint_dispatcher.default_server_connection_id_len;
    var trigger = [_]u8{0xb5} ** (cid_len + 19);
    trigger[0] = 0x40;
    const expected = quic.stateless_reset.tokenForConnectionId(
        reset_key,
        trigger[1 .. 1 + cid_len],
    );
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    const Visitor = struct {
        fn visit(
            _: void,
            _: quic.endpoint_dispatcher.RoutedPacketView,
        ) error{}!void {}
    };

    try peer.sendBytes(server.address(), &trigger);
    var storage: [4096]u8 = undefined;
    try std.testing.expectEqual(
        @as(?endpoint_server.VisitEvent, null),
        try server.receiveVisitingOnce(
            &versions,
            &storage,
            .fromMilliseconds(2),
            {},
            Visitor.visit,
        ),
    );
    var visitor_reset = try peer.receiveBytesWithTimeout(.fromSeconds(1));
    defer visitor_reset.deinit(allocator);
    try std.testing.expect(quic.stateless_reset.matches(
        visitor_reset.bytes,
        expected,
    ));

    try peer.sendBytes(server.address(), &trigger);
    var events: [1]endpoint_server.VisitEvent = undefined;
    try std.testing.expectError(
        error.Timeout,
        server.receiveManyVisitingWithDeadline(
            &versions,
            &storage,
            &events,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
            {},
            Visitor.visit,
        ),
    );
    var batch_reset = try peer.receiveBytesWithTimeout(.fromSeconds(1));
    defer batch_reset.deinit(allocator);
    try std.testing.expect(quic.stateless_reset.matches(
        batch_reset.bytes,
        expected,
    ));
}

test "QUIC endpoint server idle batch receive preserves caller deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var server = try endpoint_server.Server.init(
        allocator,
        &endpoint,
        .{ .local_connection_id = &.{} },
        .{ .max_pending_handshakes = 1 },
    );
    defer server.deinit();
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var storage: [4096]u8 = undefined;
    var events: [1]endpoint_server.VisitEvent = undefined;
    const Visitor = struct {
        fn visit(
            _: void,
            _: quic.endpoint_dispatcher.RoutedPacketView,
        ) error{}!void {}
    };
    try std.testing.expectError(
        error.Timeout,
        server.receiveManyVisitingWithDeadline(
            &versions,
            &storage,
            &events,
            .fromNow(threaded.io(), .{
                .raw = .fromMilliseconds(1),
                .clock = .awake,
            }),
            {},
            Visitor.visit,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveManyVisitingTimeout(
            &versions,
            &storage,
            &events,
            .{ .duration = .{ .raw = .zero, .clock = .awake } },
            {},
            Visitor.visit,
        ),
    );
}

test "QUIC endpoint server routes two authenticated connections on one socket" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    const server_key = try quic.tls.testing.serverKeyPair();
    const server_public = server_key.public_key.toUncompressedSec1();
    const stateless_reset_key = [_]u8{0x91} **
        quic.stateless_reset.static_key_len;
    var server = try endpoint_server.Server.init(
        allocator,
        &server_endpoint,
        .{
            .local_connection_id = &.{},
            .alpn_protocol = "netz-shared-endpoint-test",
            .random = [_]u8{0x31} ** 32,
            .x25519_secret_key = [_]u8{0x32} ** 32,
            .key_exchange_groups = &.{.x25519},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .identity = .{
                .certificate_chain = &.{&server_public},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = server_key,
                } },
            },
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        },
        .{
            .max_pending_handshakes = 2,
            .max_connections = 2,
            .inbox_capacity = 16,
            .handshake_timeout_ms = 2_000,
            .stateless_reset_key = stateless_reset_key,
        },
    );
    defer server.deinit();

    const Client = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        peer: std.Io.net.IpAddress,
        stateless_reset_key: [quic.stateless_reset.static_key_len]u8,
        index: u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var endpoint = try quic.runtime.Endpoint.bind(
                self.allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                .{ .max_datagram_size = 4096 },
            );
            defer endpoint.deinit();
            var original_dcid = [_]u8{0x40} ** 8;
            var client_cid = [_]u8{0x50} ** 8;
            original_dcid[0] +%= self.index;
            client_cid[0] +%= self.index;
            var random = [_]u8{0x60} ** 32;
            random[0] +%= self.index;
            var secret = [_]u8{0x70} ** 32;
            secret[0] +%= self.index;
            var established = try quic.handshake.connectWithTimeout(
                &endpoint,
                self.peer,
                .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .alpn_protocols = &.{"netz-shared-endpoint-test"},
                    .server_auth = .{
                        .pinned_ecdsa_p256_public_key = server_public,
                    },
                    .random = random,
                    .x25519_secret_key = secret,
                    .key_exchange_groups = &.{.x25519},
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .local_transport_parameters = .{
                        .initial_max_streams_bidi = 1,
                        .initial_max_streams_uni = 1,
                    },
                    .initial_one_rtt_config = .{ .enable_pacing = false },
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                },
                .fromSeconds(2),
            );
            defer established.deinit();
            const expected_reset_token =
                quic.stateless_reset.tokenForConnectionId(
                    self.stateless_reset_key,
                    established.peer_connection_id,
                );
            try std.testing.expectEqual(
                @as(?[quic.stateless_reset.token_len]u8, expected_reset_token),
                established.connection.config.peer_stateless_reset_token,
            );
            const payload = [_]u8{ 'c', 'l', 'i', 'e', 'n', 't', '-', self.index };
            try established.connection.send(&.{.{ .stream = .{
                .stream_id = 0,
                .data = &payload,
                .fin = true,
            } }});
            var response: [payload.len]u8 = undefined;
            const received = try established.connection
                .receiveStreamIdWithTimeout(
                0,
                &response,
                .fromSeconds(2),
            );
            const data = switch (received) {
                .reset => return error.TestUnexpectedResult,
                .data => |value| value,
            };
            try std.testing.expect(data.fin);
            try std.testing.expectEqual(payload.len, data.bytes);
            try std.testing.expectEqualSlices(u8, &payload, &response);
            var rotated_cid = [_]u8{0xa0} **
                quic.endpoint_dispatcher.default_server_connection_id_len;
            rotated_cid[0] +%= self.index;
            var reset_datagram = [_]u8{0x40} **
                quic.stateless_reset.min_datagram_len;
            const rotated_token = quic.stateless_reset.tokenForConnectionId(
                self.stateless_reset_key,
                &rotated_cid,
            );
            @memcpy(
                reset_datagram[reset_datagram.len - rotated_token.len ..],
                &rotated_token,
            );
            try std.testing.expectEqual(
                @as(?u64, 1),
                established.connection.detectStatelessReset(&reset_datagram),
            );
        }
    };

    var clients = [_]Client{
        .{ .allocator = allocator, .io = io, .peer = server.address(), .stateless_reset_key = stateless_reset_key, .index = 0 },
        .{ .allocator = allocator, .io = io, .peer = server.address(), .stateless_reset_key = stateless_reset_key, .index = 1 },
    };
    var threads: [clients.len]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |thread| thread.join();
    for (&clients, &threads) |*client, *thread| {
        thread.* = try std.Thread.spawn(.{}, Client.run, .{client});
        started += 1;
    }

    const versions = [_]u32{quic.Version.version_1.wireValue()};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
    var replies: usize = 0;
    var receive_storage: [4 * 4096]u8 = undefined;
    var receive_events: [4]endpoint_server.VisitEvent = undefined;
    const Visitor = struct {
        fn visit(
            _: void,
            packet: quic.endpoint_dispatcher.RoutedPacketView,
        ) !void {
            try std.testing.expect(packet.packet.frames.len != 0);
        }
    };
    while (replies < clients.len) {
        const event_count = try server.receiveManyVisitingWithDeadline(
            &versions,
            &receive_storage,
            &receive_events,
            deadline,
            {},
            Visitor.visit,
        );
        for (receive_events[0..event_count]) |*event| {
            defer event.deinit(allocator);
            switch (event.*) {
                .connected => |handle| {
                    const established = server.connection(handle) orelse
                        return error.TestUnexpectedResult;
                    try std.testing.expectEqual(
                        @as(?[quic.stateless_reset.static_key_len]u8, stateless_reset_key),
                        established.connection.config
                            .local_stateless_reset_key,
                    );
                    try std.testing.expectEqual(
                        @as(?u64, 1),
                        try server.pollOpenStream(handle),
                    );
                    try std.testing.expectEqual(
                        @as(?u64, 3),
                        try server.pollOpenUnidirectionalStream(handle),
                    );
                },
                .timer => {},
                .handshake_failed => |failure| return failure.err,
                .unrouted => return error.TestUnexpectedResult,
                .packet => |packet| {
                    var request: [8]u8 = undefined;
                    const received = (try server.pollStreamId(
                        packet.connection_handle,
                        0,
                        &request,
                    )) orelse continue;
                    const data = switch (received) {
                        .reset => return error.TestUnexpectedResult,
                        .data => |value| value,
                    };
                    if (!data.fin or data.bytes != request.len or
                        !std.mem.eql(u8, request[0..7], "client-") or
                        request[7] > 1)
                    {
                        return error.TestUnexpectedResult;
                    }
                    var rotated_cid = [_]u8{0xa0} **
                        quic.endpoint_dispatcher
                            .default_server_connection_id_len;
                    rotated_cid[0] +%= request[7];
                    try server.sendNewConnectionId(
                        packet.connection_handle,
                        &rotated_cid,
                    );
                    try server.trySend(
                        packet.connection_handle,
                        &.{.{ .stream = .{
                            .stream_id = 0,
                            .data = &request,
                            .fin = true,
                        } }},
                    );
                    replies += 1;
                },
            }
        }
    }

    for (threads) |thread| thread.join();
    started = 0;
    for (clients) |client| if (client.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), server.connectionCount());
}
