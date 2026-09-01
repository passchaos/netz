const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const handshake_stream = @import("stream.zig");
const session_control = @import("session_control.zig");

test "WebTransport connection close is distinct from session close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0xc0, 0x01, 0x57, 0x54, 0xc0, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0xc0, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0xc0, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xc3} ** 32,
            .x25519_secret_key = [_]u8{0xc4} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            const close = try session.receivePeerConnectionClose();
            switch (close) {
                .application => |application| {
                    try std.testing.expectEqual(
                        @as(u64, 0x4242),
                        application.error_code,
                    );
                    try std.testing.expectEqualStrings(
                        "connection done",
                        application.reason_phrase,
                    );
                },
                .transport => return error.UnexpectedConnectionClose,
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/connection-close",
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc1} ** 32,
                .x25519_secret_key = [_]u8{0xc2} ** 32,
            } },
        },
    );
    defer client.deinit();
    try client.closeConnection(0x4242, "connection done");
    try std.testing.expectError(
        error.ConnectionClosed,
        client.sendDatagram("too late"),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport connection close bounds retained reason text" {
    var client: runtime.HandshakeClientSession = undefined;
    const oversized = [_]u8{'x'} ** (runtime.max_connection_close_reason + 1);
    try std.testing.expectError(
        error.InvalidSessionState,
        client.closeConnection(1, &oversized),
    );
}

test "WebTransport peer connection close can be polled after packet dispatch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc7} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server_endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer peer_endpoint.deinit();
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-poll-server",
            .peer_connection_id = "wt-poll-client",
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    var h3_owned = true;
    defer if (h3_owned) h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.connect_datagrams.register(0);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var session = runtime.AcceptedHandshakeSession{
        .h3 = h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(.init(0)),
    };
    h3_owned = false;
    streams_owned = false;
    defer {
        session.streams.deinit();
        session.h3.deinit();
    }
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-poll-client",
        .peer_connection_id = "wt-poll-server",
        .enable_pacing = false,
    });
    defer peer.deinit();

    try std.testing.expect(session.pollPeerConnectionClose() == null);
    try peer.closeApplication(0x5151, "dispatched close");
    var packet = try session.h3.established.connection.receivePacket();
    defer packet.deinit(allocator);
    try session.processPacket(&packet);
    const close = session.pollPeerConnectionClose() orelse
        return error.TestUnexpectedResult;
    switch (close) {
        .application => |application| {
            try std.testing.expectEqual(@as(u64, 0x5151), application.error_code);
            try std.testing.expectEqualStrings(
                "dispatched close",
                application.reason_phrase,
            );
        },
        .transport => return error.UnexpectedConnectionClose,
    }
}
