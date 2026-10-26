const std = @import("std");
const runtime = @import("../../../runtime.zig");
const webtransport = @import("../../../mod.zig");
const http3 = @import("../../../../http3/mod.zig");
const quic = @import("../../../../quic/mod.zig");
const prefix = @import("../../stream/prefix.zig");

test "WebTransport standalone server early STREAM admission rejects excess" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    var parameters = quic.practical_transport_parameters;
    parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});
    var client = try http3.runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        endpoint.address(),
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-ea-client",
            .peer_connection_id = "wt-ea-server",
            .local_transport_parameters = parameters,
            .peer_transport_parameters = parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer client.deinit();
    var server_h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &endpoint,
        client.established.connection.endpoint.address(),
        .{ .local_settings = settings, .auto_date_header = false },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-ea-server",
            .peer_connection_id = "wt-ea-client",
            .local_transport_parameters = parameters,
            .peer_transport_parameters = parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    var server_owned = true;
    defer if (server_owned) server_h3.deinit();

    // Reserve the real HTTP/3 control/QPACK IDs before opening application
    // unidirectional streams, matching the owning handshake runtime.
    for (0..3) |_| {
        _ = try client.established.connection.openUnidirectionalStream();
        _ = try server_h3.established.connection.openUnidirectionalStream();
    }
    client.control.settings.markSent(settings);
    client.control.settings.markReceived(settings);
    server_h3.control.settings.markSent(settings);
    server_h3.control.settings.markReceived(settings);
    client.qpack_encoder_prefix_sent = true;
    client.qpack_decoder_prefix_sent = true;
    server_h3.qpack_encoder_prefix_sent = true;
    server_h3.qpack_decoder_prefix_sent = true;

    const first: u62 = @intCast(
        try client.established.connection.openUnidirectionalStream(),
    );
    const excess: u62 = @intCast(
        try client.established.connection.openUnidirectionalStream(),
    );
    var first_storage: [16]u8 = undefined;
    var excess_storage: [16]u8 = undefined;
    const first_header = try prefix.header(
        .init(0),
        .unidirectional,
        &first_storage,
    );
    const excess_header = try prefix.header(
        .init(0),
        .unidirectional,
        &excess_storage,
    );
    try client.established.connection.send(&.{
        .{ .stream = .{ .stream_id = first, .data = first_header } },
        .{ .stream = .{
            .stream_id = first,
            .offset = first_header.len,
            .data = "kept",
        } },
        .{ .stream = .{ .stream_id = excess, .data = excess_header } },
        .{ .stream = .{
            .stream_id = excess,
            .offset = excess_header.len,
            .data = "rejected",
        } },
    });
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .clock = .awake, .raw = .fromSeconds(2) },
    );
    while (server_h3.established.connection.recvStreamStats(excess) == null) {
        var packet = try server_h3.established.connection
            .receivePacketServicingTimersDeadline(deadline);
        packet.deinit(allocator);
    }

    const session_id = try client.startRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/early-admission",
        .headers = &.{
            .{ .name = ":protocol", .value = "webtransport-h3" },
            http3.capsule.protocol_header,
        },
    }, null);
    try std.testing.expectEqual(@as(u62, 0), session_id);
    var request_event = try server_h3.receiveRequestEventWithTimeout(
        .fromSeconds(1),
    );
    defer request_event.deinit(allocator);
    const request = switch (request_event) {
        .message => |*message| switch (message.value) {
            .head => |head| switch (head) {
                .request => |value| blk: {
                    message.value = .finished;
                    break :blk value;
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };
    var pending = runtime.PendingHandshakeSession{
        .h3 = server_h3,
        .request = .{ .stream_id = session_id, .request = request },
        .session_id = .init(session_id),
        .limits = .{ .early_connect_streams = .{ .max_streams = 1 } },
        .deadline = deadline,
    };
    server_owned = false;
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    var accepted = try pending.accept();
    pending_owned = false;
    defer accepted.deinit();

    var response_event = while (true) {
        if (try client.receiveResponseEventWithTimeout(
            session_id,
            .fromSeconds(1),
        )) |event| break event;
    };
    defer response_event.deinit(allocator);
    try std.testing.expect(
        response_event == .head and response_event.head == .response,
    );
    try std.testing.expectEqual(@as(u16, 200), response_event.head.response.status);

    var body: [16]u8 = undefined;
    const stream_event = (try accepted.pollStream(&body)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(stream_event == .data);
    try std.testing.expectEqual(first, stream_event.data.stream_id);
    try std.testing.expectEqualStrings(
        "kept",
        body[0..stream_event.data.bytes],
    );

    while (client.established.connection.sendStreamStats(excess).?.stopped == null) {
        var packet = try client.established.connection
            .receivePacketServicingTimersDeadline(deadline);
        try client.processResponsePacket(&packet);
        packet.deinit(allocator);
    }
    try std.testing.expect(
        client.established.connection.sendStreamStats(first).?.stopped == null,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.buffered_stream_rejected,
        client.established.connection.sendStreamStats(excess).?.stopped.?.application_error_code,
    );
}
