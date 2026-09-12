const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const server_response = @import("../response.zig");

const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const client_qpack_decoder_stream_id: u62 = 10;
const server_control_stream_id: u62 = 3;
const server_qpack_encoder_stream_id: u62 = 7;
const server_qpack_decoder_stream_id: u62 = 11;

test "HTTP/3 protected runtime exchanges request and response over QUIC 1-RTT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xca, 0xfe, 0x00, 0x01 };
    const server_cid = [_]u8{ 0xca, 0xfe, 0x00, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa2} ** quic.protection.secret_len,
    );

    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_settings = .{ .h3_datagram = true },
            .max_stream_frame_data = 7,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.ProtectedServer) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings(
                "/protected-h3",
                request.request.path,
            );
            try std.testing.expectEqualStrings(
                "ping split across stream frames",
                request.request.body,
            );
            try std.testing.expect(server_ptr.control.settings.received);
            try std.testing.expectEqual(
                @as(u64, 4),
                server_ptr.control.settings.peer.webtransport_max_sessions,
            );
            try std.testing.expectEqual(
                @as(?u64, client_control_stream_id),
                server_ptr.control.peer_control_stream_id,
            );
            try std.testing.expectEqual(
                @as(?u64, client_qpack_encoder_stream_id),
                server_ptr.control.peer_qpack_encoder_stream_id,
            );
            try std.testing.expectEqual(
                @as(?u64, client_qpack_decoder_stream_id),
                server_ptr.control.peer_qpack_decoder_stream_id,
            );
            const packet_number = server_ptr.next_packet_number;
            const control_offset = server_ptr.control_send.next_offset;
            const pending_sections =
                server_ptr.qpack_encode.pending_sections.items.len;
            try std.testing.expectError(
                error.Timeout,
                server_ptr.sendResponseWithDeadline(
                    request.from,
                    request.stream_id,
                    .{ .status = 204 },
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                packet_number,
                server_ptr.next_packet_number,
            );
            try std.testing.expectEqual(
                control_offset,
                server_ptr.control_send.next_offset,
            );
            try std.testing.expectEqual(
                pending_sections,
                server_ptr.qpack_encode.pending_sections.items.len,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                server_ptr.request_lifecycle.count(),
            );
            try server_ptr.sendResponseWithTimeout(
                request.from,
                request.stream_id,
                .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "content-type",
                        .value = "text/plain",
                    }},
                    .body = "pong",
                },
                .fromSeconds(1),
            );
            try std.testing.expect(server_ptr.control.settings.sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_settings = .{ .webtransport_max_sessions = 4 },
            .max_stream_frame_data = 7,
        },
    );
    defer client.deinit();

    var response = try client.request(.{
        .method = "POST",
        .path = "/protected-h3",
        .authority = "localhost",
        .body = "ping split across stream frames",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("pong", response.response.body);
    try std.testing.expect(client.control.settings.sent);
    try std.testing.expect(client.control.settings.received);
    try std.testing.expect(client.control.settings.peer.h3_datagram);
    const response_date = server_response.headerValue(
        response.response.headers,
        "date",
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(usize, server_response.date_value_len),
        response_date.len,
    );
    try std.testing.expectEqualStrings("GMT", response_date[26..]);
    try std.testing.expectEqual(
        @as(?u64, server_control_stream_id),
        client.control.peer_control_stream_id,
    );
    try std.testing.expectEqual(
        @as(?u64, server_qpack_encoder_stream_id),
        client.control.peer_qpack_encoder_stream_id,
    );
    try std.testing.expectEqual(
        @as(?u64, server_qpack_decoder_stream_id),
        client.control.peer_qpack_decoder_stream_id,
    );

    client.control.peer_goaway_id = client.next_stream_id;
    try std.testing.expectError(error.GoAwayReceived, client.request(.{
        .method = "GET",
        .path = "/after-goaway",
    }));
}

test "HTTP/3 protected server retains interleaved request streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x91, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x92, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x94} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
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
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
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
        },
    );
    defer client.deinit();

    var first_message: std.ArrayList(u8) = .empty;
    defer first_message.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/first",
        .authority = "localhost",
        .body = "first-body",
    }).write(&first_message, allocator);
    var second_message: std.ArrayList(u8) = .empty;
    defer second_message.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
        .body = "second-body",
    }).write(&second_message, allocator);
    const first_split = first_message.items.len / 2;

    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .offset = 0,
            .data = first_message.items[0..first_split],
        } },
        .{ .stream = .{
            .stream_id = 4,
            .offset = 0,
            .data = second_message.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 0,
            .offset = first_split,
            .data = first_message.items[first_split..],
            .fin = true,
        } },
    };
    try client.protected_send.sendFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &frames,
        frames.len,
    );

    var first = try server.receiveRequest();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u62, 0), first.stream_id);
    try std.testing.expectEqualStrings("/first", first.request.path);
    try std.testing.expectEqualStrings("first-body", first.request.body);
    try std.testing.expectEqual(@as(usize, 1), server.request_streams.count());

    var second = try server.receiveRequest();
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u62, 4), second.stream_id);
    try std.testing.expectEqualStrings("/second", second.request.path);
    try std.testing.expectEqualStrings("second-body", second.request.body);
    try std.testing.expectEqual(@as(usize, 0), server.request_streams.count());
}
