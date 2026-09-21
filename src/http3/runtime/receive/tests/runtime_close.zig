const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

fn expectProtectedClientProtocolClose(
    frame: quic.Frame,
    expected_error: anyerror,
    expected_code: u64,
) !void {
    return expectProtectedClientProtocolCloseFrames(
        &.{frame},
        expected_error,
        expected_code,
    );
}

fn expectProtectedClientProtocolCloseFrames(
    frames: []const quic.Frame,
    expected_error: anyerror,
    expected_code: u64,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0x85, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x86, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x87} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x88} ** quic.protection.secret_len,
    );
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer peer.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        peer.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try quic.one_rtt.sendFrames(
        &peer,
        client.quic_client.address(),
        server_keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 0,
            .frames = frames,
        },
    );
    try std.testing.expectError(expected_error, client.pollControl());

    var close_packet = try quic.one_rtt.receive(
        &peer,
        client_keys,
        server_cid.len,
        0,
        1,
    );
    defer close_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), close_packet.frames.len);
    try std.testing.expect(close_packet.frames[0] == .application_close);
    try std.testing.expectEqual(
        expected_code,
        close_packet.frames[0].application_close.error_code,
    );
}

test "HTTP/3 protected client closes when peer stops a critical stream" {
    try expectProtectedClientProtocolClose(
        .{ .stop_sending = .{
            .stream_id = 2,
            .application_error_code = 0,
        } },
        error.ClosedCriticalStream,
        http3.ApplicationErrorCode.closed_critical_stream,
    );
}

test "HTTP/3 protected client closes on invalid SETTINGS" {
    try expectProtectedClientProtocolClose(.{
        .stream = .{
            .stream_id = 3,
            // Control prefix, SETTINGS frame, two-byte payload containing the
            // HTTP/2-only SETTINGS_ENABLE_PUSH identifier and value zero.
            .data = &.{ 0x00, 0x04, 0x02, 0x02, 0x00 },
        },
    }, error.InvalidSetting, http3.ApplicationErrorCode.settings_error);
}

test "HTTP/3 protected client closes on WebTransport frame on control stream" {
    try expectProtectedClientProtocolClose(.{
        .stream = .{
            .stream_id = 3,
            // Control prefix, empty SETTINGS, then a misplaced 0x41 frame.
            .data = &.{ 0x00, 0x04, 0x00, 0x40, 0x41, 0x00 },
        },
    }, error.UnexpectedFrame, http3.ApplicationErrorCode.frame_unexpected);
}

test "HTTP/3 protected client closes on invalid QPACK encoder instruction" {
    try expectProtectedClientProtocolClose(
        .{
            .stream = .{
                .stream_id = 7,
                // QPACK encoder prefix followed by Set Dynamic Table Capacity = 1;
                // the client advertised a zero-capacity table.
                .data = &.{ 0x02, 0x21 },
            },
        },
        error.QpackEncoderStreamError,
        http3.ApplicationErrorCode.qpack_encoder_stream_error,
    );
}

test "HTTP/3 protected client closes on duplicate QPACK encoder streams" {
    try expectProtectedClientProtocolCloseFrames(
        &.{
            .{ .stream = .{
                .stream_id = 7,
                .data = &.{@intFromEnum(http3.StreamType.qpack_encoder)},
            } },
            .{ .stream = .{
                .stream_id = 15,
                .data = &.{@intFromEnum(http3.StreamType.qpack_encoder)},
            } },
        },
        error.StreamCreationError,
        http3.ApplicationErrorCode.stream_creation_error,
    );
}

test "HTTP/3 protected server closes on unpromised CANCEL_PUSH" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0x95, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x96, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x97} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x98} ** quic.protection.secret_len,
    );
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer peer.deinit();
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();

    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&control_bytes, allocator);
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});
    try http3.writeMaxPushIdFrame(&control_bytes, allocator, 8);
    try http3.writeCancelPushFrame(&control_bytes, allocator, 3);
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 2,
        .data = control_bytes.items,
    } }};
    try quic.one_rtt.sendFrames(
        &peer,
        server.address(),
        client_keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = 0,
            .frames = &frames,
        },
    );

    try std.testing.expectError(error.IdError, server.pollControl());
    try std.testing.expectEqual(
        @as(usize, 0),
        server.control.cancelledPushRangeCount(),
    );

    var close_packet = try quic.one_rtt.receive(
        &peer,
        server_keys,
        client_cid.len,
        0,
        1,
    );
    defer close_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), close_packet.frames.len);
    try std.testing.expect(close_packet.frames[0] == .application_close);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.id_error),
        close_packet.frames[0].application_close.error_code,
    );
}

test "HTTP/3 protected server closes on ORIGIN request frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xa5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xa6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa8} ** quic.protection.secret_len,
    );
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer peer.deinit();
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();

    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&control_bytes, allocator);
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});
    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.origin,
        .payload = &.{},
        .consumed = 0,
    }).write(&request_bytes, allocator);
    try quic.one_rtt.sendFrames(
        &peer,
        server.address(),
        client_keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = 0,
            .frames = &.{
                .{ .stream = .{
                    .stream_id = 2,
                    .data = control_bytes.items,
                } },
                .{ .stream = .{
                    .stream_id = 0,
                    .data = request_bytes.items,
                    .fin = true,
                } },
            },
        },
    );

    try std.testing.expectError(error.ExpectedHeadersFrame, server.receiveRequest());
    var close_packet = try quic.one_rtt.receive(
        &peer,
        server_keys,
        client_cid.len,
        0,
        1,
    );
    defer close_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), close_packet.frames.len);
    try std.testing.expect(close_packet.frames[0] == .application_close);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.frame_unexpected),
        close_packet.frames[0].application_close.error_code,
    );
}
