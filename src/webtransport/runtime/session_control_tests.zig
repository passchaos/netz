const std = @import("std");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");

test "WebTransport handshake sessions exchange drain and close capsules" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x43, 0x01, 0x57, 0x54, 0x43, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x43, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x43, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xd3} ** 32,
                .x25519_secret_key = [_]u8{0xd4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try std.testing.expectEqualStrings(
                "/wt-control",
                session.request.request.path,
            );

            try session.drain();
            // DRAIN is advisory: opening and using streams remains legal.
            const stream_id = try session.openUnidirectionalStream();
            try session.sendStream(stream_id, "after drain", true);

            const event = try session.receiveSessionEvent();
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 77), event.closed.code);
            try std.testing.expectEqualStrings("client done", event.closed.reason);
            try std.testing.expectError(
                error.InvalidSessionState,
                session.openBidirectionalStream(),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-control",
            .limits = .{
                .http3 = .{
                    .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 8,
                    },
                },
            },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xd1} ** 32,
                    .x25519_secret_key = [_]u8{0xd2} ** 32,
                },
            },
        },
    );
    defer client.deinit();

    const drain = try client.receiveSessionEvent();
    try std.testing.expect(drain == .draining);

    var stream_buffer: [32]u8 = undefined;
    const stream = try client.readStream(&stream_buffer);
    try std.testing.expect(stream == .data);
    try std.testing.expectEqualStrings(
        "after drain",
        stream_buffer[0..stream.data.bytes],
    );
    if (!stream.data.fin) {
        const fin = try client.readStream(&stream_buffer);
        try std.testing.expect(fin == .data);
        try std.testing.expectEqual(stream.data.stream_id, fin.data.stream_id);
        try std.testing.expectEqual(@as(usize, 0), fin.data.bytes);
        try std.testing.expect(fin.data.fin);
    }

    try client.close(77, "client done");
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendDatagram("late"),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport handshake clean CONNECT FIN is normal close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x46, 0x01, 0x57, 0x54, 0x46, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x46, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x46, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            // A zero-length DATA frame followed by FIN carries no close capsule
            // and is therefore semantically equivalent to close(0, "").
            try session.h3.sendResponseBodyPaced(
                session.session_id.value,
                &.{},
                true,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-fin",
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xe1} ** 32,
                    .x25519_secret_key = [_]u8{0xe2} ** 32,
                },
            },
        },
    );
    defer client.deinit();
    const event = try client.receiveSessionEvent();
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 0), event.closed.code);
    try std.testing.expectEqualStrings("", event.closed.reason);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport handshake rejects FIN during Capsule type varint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server_cid = [_]u8{ 0x57, 0x54, 0x56, 0x00 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xa3} ** 32,
            .x25519_secret_key = [_]u8{0xa4} ** 32,
        } },
    );
    defer server.deinit();

    // Each value is one byte short of the length selected by its first two
    // bits. The enclosing HTTP/3 DATA frame is complete; only the Capsule type
    // varint is truncated when the CONNECT response direction reaches FIN.
    const truncated_types = [_][]const u8{
        &.{0x40},
        &.{ 0x80, 0x00, 0x00 },
        &.{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    };
    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            for (truncated_types) |truncated| {
                var session = try server_ptr.accept();
                defer session.deinit();
                try session.h3.sendResponseBodyPaced(
                    session.session_id.value,
                    truncated,
                    true,
                );

                const event = try session.receiveSessionEvent();
                try std.testing.expect(event == .reset);
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.message_error),
                    event.reset.http3_code,
                );
                try std.testing.expect(event.reset.application_code == null);
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for (truncated_types, 0..) |_, index| {
        const marker: u8 = @intCast(index + 1);
        const original_dcid =
            [_]u8{ 0x57, 0x54, 0x56, marker, 0x57, 0x54, 0x56, marker };
        const client_cid = [_]u8{ 0x57, 0x54, 0x57, marker };
        {
            var client = try runtime.HandshakeClientSession.connect(
                allocator,
                io,
                .{ .ip4 = .loopback(0) },
                server.address(),
                .{
                    .authority = "localhost",
                    .path = "/wt-truncated-capsule-type",
                    .h3 = .{ .handshake = .{
                        .original_destination_connection_id = &original_dcid,
                        .local_connection_id = &client_cid,
                        .server_name = "localhost",
                        .random = [_]u8{0xa1} ** 32,
                        .x25519_secret_key = [_]u8{0xa2} ** 32,
                    } },
                },
            );
            defer client.deinit();
            try std.testing.expectError(
                error.InvalidCapsule,
                client.receiveSessionEvent(),
            );
        }
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport handshake session receives peer QUIC close details" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x51, 0x01, 0x57, 0x54, 0x51, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x51, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x51, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xf3} ** 32,
                .x25519_secret_key = [_]u8{0xf4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try session.h3.established.connection.closeApplication(
                0,
                "interop complete",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-quic-close",
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xf1} ** 32,
                    .x25519_secret_key = [_]u8{0xf2} ** 32,
                },
            },
        },
    );
    defer client.deinit();

    switch (try client.receivePeerConnectionClose()) {
        .application => |close| {
            try std.testing.expectEqual(@as(u64, 0), close.error_code);
            try std.testing.expectEqualStrings(
                "interop complete",
                close.reason_phrase,
            );
        },
        .transport => return error.TestUnexpectedResult,
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport session control encodes bounds and rejects malformed close" {
    const control = @import("session_control.zig");
    var buffer: [4 + control.max_close_reason + 16]u8 = undefined;
    const close = try control.writeCloseInto(&buffer, 9, "done");
    const parsed = try webtransport.Capsule.parse(close);
    try std.testing.expectEqual(@as(u32, 9), parsed.capsule.close_session.code);
    try std.testing.expectEqualStrings("done", parsed.capsule.close_session.reason);

    var oversized: [control.max_close_reason + 1]u8 = undefined;
    @memset(&oversized, 'x');
    try std.testing.expectError(
        error.InvalidCapsule,
        control.writeCloseInto(&buffer, 1, &oversized),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        control.writeCloseInto(&buffer, 1, "\xff"),
    );

    // Keep the protocol code visible at the public boundary.
    try std.testing.expectEqual(
        @as(u64, 0x170d7b68),
        webtransport.ApplicationErrorCode.session_gone,
    );
    try std.testing.expectEqual(
        @as(u64, 0x10e),
        @import("../../http3/mod.zig").ApplicationErrorCode.message_error,
    );
    _ = quic;
}

test "WebTransport terminal sweep discovers buffered associated streams" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc7} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-sweep-server",
        .peer_connection_id = "wt-sweep-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 0, .max_peer_uni = 0 },
    );
    defer registry.deinit();

    var bidi_storage: [16]u8 = undefined;
    const bidi = try webtransport.BidirectionalStreamHeader.writeInto(
        &bidi_storage,
        session_id,
    );
    var uni: std.ArrayList(u8) = .empty;
    defer uni.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &uni,
        allocator,
        session_id,
    );
    var other_session: std.ArrayList(u8) = .empty;
    defer other_session.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &other_session,
        allocator,
        .init(4),
    );
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{ .stream_id = 4, .data = bidi } },
            .{ .stream = .{ .stream_id = 2, .data = uni.items } },
            .{ .stream = .{ .stream_id = 6, .data = other_session.items } },
            .{ .stream = .{ .stream_id = 8, .data = &.{0x41} } },
            .{ .stream = .{ .stream_id = 10, .data = &.{0x00} } },
        },
        null,
        .not_ect,
    );
    try std.testing.expect(registry.get(4) == null);
    try std.testing.expect(registry.get(2) == null);

    try std.testing.expectEqual(
        @import("session_control.zig").TerminateProgress.submitted,
        try @import("session_control.zig").terminateStreamsOnce(
            &connection,
            &registry,
        ),
    );
    try std.testing.expect(registry.get(4) == null);
    try std.testing.expect(registry.get(2) == null);
    try std.testing.expect(registry.get(6) == null);
    try std.testing.expect(registry.get(8) == null);
    try std.testing.expect(registry.get(10) == null);

    while (try @import("session_control.zig").terminateStreamsOnce(
        &connection,
        &registry,
    ) == .submitted) {}

    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.sendStreamStats(4).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.recvStreamStats(4).?.stop_sending_sent.?
            .application_error_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.recvStreamStats(2).?.stop_sending_sent.?
            .application_error_code,
    );
    try std.testing.expect(connection.recvStreamStats(6).?.stop_sending_sent == null);
    try std.testing.expect(connection.recvStreamStats(8).?.stop_sending_sent == null);
    try std.testing.expect(connection.recvStreamStats(10).?.stop_sending_sent == null);
    try std.testing.expectEqual(bidi.len, connection.availableReceivedStream(4).?.len);
    try std.testing.expectEqual(uni.items.len, connection.availableReceivedStream(2).?.len);

    // The blocking cleanup path uses the same discovery without relying on
    // registry capacity or consuming the association prefix.
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{ .stream_id = 12, .data = bidi } }},
        null,
        .not_ect,
    );
    try @import("session_control.zig").terminateStreams(
        &connection,
        &registry,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.sendStreamStats(12).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.recvStreamStats(12).?.stop_sending_sent.?
            .application_error_code,
    );
    try std.testing.expectEqual(
        bidi.len,
        connection.availableReceivedStream(12).?.len,
    );
}

test "WebTransport session control parses split framed capsules and skips unknown" {
    const control_module = @import("session_control.zig");

    var unknown_capsule: [64]u8 = undefined;
    const unknown = try @import("../../http3/capsule.zig").writeInto(
        &unknown_capsule,
        0x1234,
        "ignored",
    );
    var drain_capsule: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_capsule);
    var payload: [96]u8 = undefined;
    @memcpy(payload[0..unknown.len], unknown);
    @memcpy(payload[unknown.len..][0..drain.len], drain);

    var frame: [128]u8 = undefined;
    const frame_type = try quic.varint.encodeInto(
        &frame,
        @import("../../http3/mod.zig").FrameType.data,
    );
    const frame_length = try quic.varint.encodeInto(
        frame[frame_type.len..],
        unknown.len + drain.len,
    );
    const header_len = frame_type.len + frame_length.len;
    @memcpy(
        frame[header_len..][0 .. unknown.len + drain.len],
        payload[0 .. unknown.len + drain.len],
    );
    const bytes = frame[0 .. header_len + unknown.len + drain.len];

    // Feed every split point through the parser using a local helper that
    // mirrors transport availability. No complete value is buffered by the
    // state machine while the unknown capsule is skipped.
    for (1..bytes.len) |split| {
        var candidate = try control_module.Control.init(.init(0));
        const first = try candidate.feed(bytes[0..split]);
        try std.testing.expect(first == null);
        const second = try candidate.feed(bytes[split..]);
        try std.testing.expect(second.? == .draining);
    }
}

test "Protected session control retains close after drain event" {
    const protected =
        @import("protected_session_control.zig");
    const control_module = @import("session_control.zig");

    var drain_storage: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_storage);
    var close_storage: [64]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        17,
        "after drain",
    );
    var joined: [80]u8 = undefined;
    @memcpy(joined[0..drain.len], drain);
    @memcpy(joined[drain.len..][0..close.len], close);

    var reader = protected.Reader.init(
        try control_module.Control.init(.init(0)),
    );
    const first = (try reader.consume(
        joined[0 .. drain.len + close.len],
    )).?;
    try std.testing.expect(first == .draining);
    const second = (try reader.pollPending()).?;
    try std.testing.expect(second == .closed);
    try std.testing.expectEqual(@as(u32, 17), second.closed.code);
    try std.testing.expectEqualStrings(
        "after drain",
        second.closed.reason,
    );
}

test "Protected session control retains maximum close after drain event" {
    const protected =
        @import("protected_session_control.zig");
    const control_module = @import("session_control.zig");

    var reason: [control_module.max_close_reason]u8 = undefined;
    @memset(&reason, 'x');
    var drain_storage: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_storage);
    var close_storage: [4 + control_module.max_close_reason + 16]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        29,
        &reason,
    );
    var joined: [protected.buffer_capacity]u8 = undefined;
    try std.testing.expect(drain.len + close.len <= joined.len);
    @memcpy(joined[0..drain.len], drain);
    @memcpy(joined[drain.len..][0..close.len], close);

    var reader = protected.Reader.init(
        try control_module.Control.init(.init(0)),
    );
    const first = (try reader.consume(
        joined[0 .. drain.len + close.len],
    )).?;
    try std.testing.expect(first == .draining);
    const second = (try reader.pollPending()).?;
    try std.testing.expect(second == .closed);
    try std.testing.expectEqual(@as(u32, 29), second.closed.code);
    try std.testing.expectEqualSlices(u8, &reason, second.closed.reason);
}

test "Protected session control clean FIN closes only at capsule boundary" {
    const protected =
        @import("protected_session_control.zig");
    const control_module = @import("session_control.zig");

    var clean = protected.Reader.init(
        try control_module.Control.init(.init(0)),
    );
    const closed = (try clean.finish()).?;
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(@as(u32, 0), closed.closed.code);
    try std.testing.expectEqualStrings("", closed.closed.reason);

    var partial = protected.Reader.init(
        try control_module.Control.init(.init(0)),
    );
    var close_storage: [64]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        31,
        "partial",
    );
    try std.testing.expect((try partial.consume(close[0..3])) == null);
    try std.testing.expectError(error.InvalidCapsule, partial.finish());
}
