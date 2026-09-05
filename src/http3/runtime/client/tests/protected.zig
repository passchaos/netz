const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

test "HTTP/3 protected client retains interleaved responses" {
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

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 0), first_id);
    try std.testing.expectEqual(@as(u62, 4), second_id);

    var first_request = try server.receiveRequest();
    defer first_request.deinit(allocator);
    var second_request = try server.receiveRequest();
    defer second_request.deinit(allocator);
    try std.testing.expectEqual(first_id, first_request.stream_id);
    try std.testing.expectEqual(second_id, second_request.stream_id);

    var first_message: std.ArrayList(u8) = .empty;
    defer first_message.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "first-response",
    }).write(&first_message, allocator);
    var second_message: std.ArrayList(u8) = .empty;
    defer second_message.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "second-response",
    }).write(&second_message, allocator);
    const first_split = first_message.items.len / 2;
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = first_id,
            .data = first_message.items[0..first_split],
        } },
        .{ .stream = .{
            .stream_id = second_id,
            .data = second_message.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = first_id,
            .offset = first_split,
            .data = first_message.items[first_split..],
            .fin = true,
        } },
    };
    try server.protected_send.sendFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        frames[0..2],
        2,
    );
    try server.protected_send.sendFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        frames[2..],
        1,
    );

    var first_event = try client.receiveNextResponse();
    defer first_event.deinit(allocator);
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(second_id, first_event.response.stream_id);
    try std.testing.expectEqualStrings(
        "second-response",
        first_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        client.request_lifecycle.count(),
    );
    var second_event = try client.receiveNextResponse();
    defer second_event.deinit(allocator);
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(first_id, second_event.response.stream_id);
    try std.testing.expectEqualStrings(
        "first-response",
        second_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.count(),
    );
    try std.testing.expectError(
        error.UnexpectedStream,
        client.receiveResponse(first_id),
    );
}

test "HTTP/3 protected client reports next response reset without lifecycle allocation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xa9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xaa, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xab} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xac} ** quic.protection.secret_len,
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

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/reset",
        .authority = "localhost",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try server.rejectRequest(request.from, stream_id);

    var failed_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    client.request_lifecycle.allocator = failed_alloc.allocator();
    var event = try client.receiveNextResponse();
    defer event.deinit(allocator);
    client.request_lifecycle.allocator = allocator;
    try std.testing.expect(!failed_alloc.has_induced_failure);
    try std.testing.expect(event == .reset);
    try std.testing.expectEqual(stream_id, event.reset.stream_id);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.request_rejected),
        event.reset.application_error_code,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.count(),
    );
}

test "HTTP/3 protected client polls interleaved streaming responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xb9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xba, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xbb} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xbc} ** quic.protection.secret_len,
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

    const first_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/early",
            .authority = "localhost",
        },
        null,
    );
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/reset",
        .authority = "localhost",
    });
    try std.testing.expectEqual(
        @as(usize, 1),
        client.outbound_bodies.count(),
    );

    var first_response: std.ArrayList(u8) = .empty;
    defer first_response.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "early",
    }).write(&first_response, allocator);
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = first_id,
            .data = first_response.items,
            .fin = true,
        } },
        .{ .reset_stream = .{
            .stream_id = second_id,
            .application_error_code = http3.ApplicationErrorCode.request_rejected,
            .final_size = 0,
        } },
    };
    try server.protected_send.sendFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &frames,
        1,
    );
    // Polling is intentionally socket-free: bytes are not visible until a
    // blocking receive pumps the datagram into the client's retained sets.
    try std.testing.expectEqual(
        @as(?runtime.StreamingEvent, null),
        try client.pollResponseEvent(first_id),
    );
    try std.testing.expectEqual(
        @as(?runtime.StreamingResponseEvent, null),
        try client.pollNextResponseEvent(),
    );

    var saw_head = false;
    var saw_body = false;
    var saw_finished = false;
    var saw_reset = false;
    var read_buf: [16]u8 = undefined;
    while (!client.request_lifecycle.isEmpty()) {
        var event = try client.receiveNextResponseEvent();
        defer event.deinit(allocator);
        switch (event) {
            .reset => |reset| {
                try std.testing.expectEqual(second_id, reset.stream_id);
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.request_rejected),
                    reset.application_error_code,
                );
                saw_reset = true;
            },
            .message => |message| {
                try std.testing.expectEqual(first_id, message.stream_id);
                switch (message.value) {
                    .head => saw_head = true,
                    .push_promise => return error.TestUnexpectedResult,
                    .data_available => {
                        const read = try client.readResponseData(
                            first_id,
                            &read_buf,
                        );
                        try std.testing.expectEqualStrings(
                            "early",
                            read_buf[0..read],
                        );
                        saw_body = true;
                    },
                    .trailers => return error.TestUnexpectedResult,
                    .finished => saw_finished = true,
                }
            },
        }
    }
    try std.testing.expect(saw_head);
    try std.testing.expect(saw_body);
    try std.testing.expect(saw_finished);
    try std.testing.expect(saw_reset);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.outbound_bodies.count(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.streaming_responses.entryCount(),
    );
}
