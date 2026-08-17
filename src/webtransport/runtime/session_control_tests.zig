const std = @import("std");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");
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
