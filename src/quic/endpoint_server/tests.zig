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
        },
    );
    defer server.deinit();

    const Client = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        peer: std.Io.net.IpAddress,
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
        }
    };

    var clients = [_]Client{
        .{ .allocator = allocator, .io = io, .peer = server.address(), .index = 0 },
        .{ .allocator = allocator, .io = io, .peer = server.address(), .index = 1 },
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
