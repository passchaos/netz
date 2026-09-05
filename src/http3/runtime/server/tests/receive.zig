const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const control_sender = @import("../../control/send.zig");

const ProtectedServer = runtime.ProtectedServer;
const ProtectedClient = runtime.ProtectedClient;
const StreamingRequestEvent = runtime.StreamingRequestEvent;
const client_control_stream_id: u62 = 2;
const sendProtectedSettings = control_sender.sendProtectedSettings;

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    protected_send: anytype,
) !void {
    try protected_send.sendFrames(
        endpoint,
        to,
        keys,
        destination_connection_id,
        next_packet_number,
        frames,
        max_frames_per_packet,
    );
}

test "HTTP/3 protected server polls buffered request events" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xe9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xea, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xeb} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xec} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "POST",
        .path = "/poll",
        .authority = "localhost",
        .body = "buffered",
    });
    // Polling must not claim a datagram directly from the shared socket.
    try std.testing.expectEqual(
        @as(?StreamingRequestEvent, null),
        try server.pollRequestEvent(),
    );

    var head = try server.receiveRequestEvent();
    defer head.deinit(allocator);
    try std.testing.expect(head == .message);
    try std.testing.expectEqual(stream_id, head.message.stream_id);
    try std.testing.expect(head.message.value == .head);

    var data = (try server.pollRequestEvent()) orelse
        return error.TestUnexpectedResult;
    defer data.deinit(allocator);
    try std.testing.expect(data == .message);
    try std.testing.expectEqual(stream_id, data.message.stream_id);
    try std.testing.expect(data.message.value == .data_available);
    var body: [16]u8 = undefined;
    const body_len = try server.readRequestData(stream_id, &body);
    try std.testing.expectEqualStrings("buffered", body[0..body_len]);

    var finished = (try server.pollRequestEvent()) orelse
        return error.TestUnexpectedResult;
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .message);
    try std.testing.expectEqual(stream_id, finished.message.stream_id);
    try std.testing.expect(finished.message.value == .finished);
    try std.testing.expectEqual(
        @as(?StreamingRequestEvent, null),
        try server.pollRequestEvent(),
    );
}

test "HTTP/3 protected aggregate request deadline preserves progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xed, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xee, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xef} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf0} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const body = "request-after-timeout";
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/aggregate-deadline",
        .authority = "localhost",
        .body = body,
    }).write(&bytes, allocator);
    const split = bytes.items.len - body.len + body.len / 2;
    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = bytes.items[0..split],
        } }},
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithDeadline(.{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.count(),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(!server.request_streams.isEmpty());

    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &.{.{ .stream = .{
            .stream_id = 0,
            .offset = split,
            .data = bytes.items[split..],
            .fin = true,
        } }},
        client.config.max_frames_per_packet,
        &client.protected_send,
    );
    var request = try server.receiveRequestWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer request.deinit(allocator);
    try std.testing.expectEqual(@as(u62, 0), request.stream_id);
    try std.testing.expectEqualStrings(body, request.request.body);
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.count(),
    );
}

test "HTTP/3 protected server reports streamed request reset with stream id" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xd5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xd6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_stream_buffer = 512,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_stream_buffer = 512,
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/cancel-stream",
            .authority = "localhost",
        },
        null,
    );
    var event = try server.receiveRequestEvent();
    defer event.deinit(allocator);
    try std.testing.expect(event == .message);
    try std.testing.expect(event.message.value == .head);
    try std.testing.expectEqual(stream_id, event.message.stream_id);

    try client.cancelRequest(
        stream_id,
        http3.ApplicationErrorCode.request_cancelled,
    );
    var reset = try server.receiveRequestEvent();
    defer reset.deinit(allocator);
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.request_cancelled),
        reset.reset.application_error_code,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.streaming_requests.retainedCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_lifecycle.count(),
    );
}
