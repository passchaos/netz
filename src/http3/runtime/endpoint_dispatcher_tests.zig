const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

test "HTTP/3 sessions consume dispatcher packets without socket races" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_a_cid = "h3-client-a";
    const client_b_cid = "h3-client-b";
    const server_a_cid = "h3-server-a";
    const server_b_cid = "h3-server-b";
    const client_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa1} ** quic.protection.secret_len,
    );
    const client_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb1} ** quic.protection.secret_len,
    );
    const server_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa2} ** quic.protection.secret_len,
    );
    const server_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb2} ** quic.protection.secret_len,
    );
    const limits = runtime.Limits{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };
    const session_options = runtime.HandshakeSessionOptions{
        .max_stream_frame_data = 1024,
    };

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer server_endpoint.deinit();
    var client_a = try runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_endpoint.address(),
        limits,
        session_options,
        .{
            .receive_keys = server_a_keys,
            .send_keys = client_a_keys,
            .local_connection_id = client_a_cid,
            .peer_connection_id = server_a_cid,
        },
    );
    defer client_a.deinit();
    var client_b = try runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_endpoint.address(),
        limits,
        session_options,
        .{
            .receive_keys = server_b_keys,
            .send_keys = client_b_keys,
            .local_connection_id = client_b_cid,
            .peer_connection_id = server_b_cid,
        },
    );
    defer client_b.deinit();
    var server_a = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client_a.address(),
        session_options,
        .{
            .receive_keys = client_a_keys,
            .send_keys = server_a_keys,
            .local_connection_id = server_a_cid,
            .peer_connection_id = client_a_cid,
        },
    );
    defer server_a.deinit();
    var server_b = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client_b.address(),
        session_options,
        .{
            .receive_keys = client_b_keys,
            .send_keys = server_b_keys,
            .local_connection_id = server_b_cid,
            .peer_connection_id = client_b_cid,
        },
    );
    defer server_b.deinit();

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &server_a.established.connection);
    try dispatcher.registerConnection(2, &server_b.established.connection);

    try std.testing.expectEqual(@as(?runtime.StreamingRequestEvent, null), try server_a.pollRequestEvent());
    try std.testing.expectEqual(@as(?runtime.StreamingRequestEvent, null), try server_b.pollRequestEvent());
    _ = try client_b.sendRequest(.{
        .method = "POST",
        .path = "/dispatcher-b",
        .authority = "localhost",
        .body = "body-b",
    });
    _ = try client_a.sendRequest(.{
        .method = "POST",
        .path = "/dispatcher-a",
        .authority = "localhost",
        .body = "body-a",
    });

    var seen_a = false;
    var seen_b = false;
    var body_a: [6]u8 = undefined;
    var body_b: [6]u8 = undefined;
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    while (!seen_a or !seen_b) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                const session = switch (routed.connection_handle) {
                    1 => &server_a,
                    2 => &server_b,
                    else => return error.TestUnexpectedResult,
                };
                try session.processRequestPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(
                    routed.connection_handle,
                );
                while (try session.pollRequestEvent()) |request_value| {
                    var request = request_value;
                    defer request.deinit(allocator);
                    if (request != .message) {
                        return error.TestUnexpectedResult;
                    }
                    switch (request.message.value) {
                        .head => |head| {
                            switch (routed.connection_handle) {
                                1 => try std.testing.expectEqualStrings(
                                    "/dispatcher-a",
                                    head.request.path,
                                ),
                                2 => try std.testing.expectEqualStrings(
                                    "/dispatcher-b",
                                    head.request.path,
                                ),
                                else => unreachable,
                            }
                        },
                        .data_available => {
                            const target = if (routed.connection_handle == 1)
                                &body_a
                            else
                                &body_b;
                            const read = try session.readRequestData(
                                request.message.stream_id,
                                target,
                            );
                            try std.testing.expectEqual(target.len, read);
                            if (routed.connection_handle == 1) {
                                try std.testing.expectEqualStrings(
                                    "body-a",
                                    &body_a,
                                );
                                seen_a = true;
                            } else {
                                try std.testing.expectEqualStrings(
                                    "body-b",
                                    &body_b,
                                );
                                seen_b = true;
                            }
                        },
                        .finished => {},
                        .push_promise, .trailers => return error.TestUnexpectedResult,
                    }
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(server_a.control.settings.received);
    try std.testing.expect(server_b.control.settings.received);
}

test "HTTP/3 clients poll dispatcher-routed responses without socket races" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_a_cid = "h3-response-client-a";
    const client_b_cid = "h3-response-client-b";
    const server_a_cid = "h3-response-server-a";
    const server_b_cid = "h3-response-server-b";
    const client_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa3} ** quic.protection.secret_len,
    );
    const client_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb3} ** quic.protection.secret_len,
    );
    const server_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa4} ** quic.protection.secret_len,
    );
    const server_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb4} ** quic.protection.secret_len,
    );
    const limits = runtime.Limits{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };
    const options = runtime.HandshakeSessionOptions{
        .max_stream_frame_data = 1024,
    };

    var server_a_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer server_a_endpoint.deinit();
    var server_b_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer server_b_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer client_endpoint.deinit();

    var client_a = try runtime.HandshakeClient.initEstablished(
        &client_endpoint,
        server_a_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_a_endpoint.address(),
            .client,
            .{
                .receive_keys = server_a_keys,
                .send_keys = client_a_keys,
                .local_connection_id = client_a_cid,
                .peer_connection_id = server_a_cid,
            },
        ),
        options,
    );
    defer client_a.deinit();
    var client_b = try runtime.HandshakeClient.initEstablished(
        &client_endpoint,
        server_b_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_b_endpoint.address(),
            .client,
            .{
                .receive_keys = server_b_keys,
                .send_keys = client_b_keys,
                .local_connection_id = client_b_cid,
                .peer_connection_id = server_b_cid,
            },
        ),
        options,
    );
    defer client_b.deinit();

    const stream_a = try client_a.sendRequest(.{
        .method = "GET",
        .path = "/response-a",
        .authority = "localhost",
    });
    const stream_b = try client_b.sendRequest(.{
        .method = "GET",
        .path = "/response-b",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 0), stream_a);
    try std.testing.expectEqual(@as(u62, 0), stream_b);

    var server_a = try quic.one_rtt.Connection.init(&server_a_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_a_keys,
        .send_keys = server_a_keys,
        .local_connection_id = server_a_cid,
        .peer_connection_id = client_a_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server_a.deinit();
    var server_b = try quic.one_rtt.Connection.init(&server_b_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_b_keys,
        .send_keys = server_b_keys,
        .local_connection_id = server_b_cid,
        .peer_connection_id = client_b_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server_b.deinit();

    var response_a: std.ArrayList(u8) = .empty;
    defer response_a.deinit(allocator);
    try (http3.Response{ .status = 200, .body = "response-a" }).write(
        &response_a,
        allocator,
    );
    var response_b: std.ArrayList(u8) = .empty;
    defer response_b.deinit(allocator);
    try (http3.Response{ .status = 201, .body = "response-b" }).write(
        &response_b,
        allocator,
    );
    const frames_a = [_]quic.Frame{.{ .stream = .{
        .stream_id = stream_a,
        .data = response_a.items,
        .fin = true,
    } }};
    const frames_b = [_]quic.Frame{.{ .stream = .{
        .stream_id = stream_b,
        .data = response_b.items,
        .fin = true,
    } }};
    try server_b.send(&frames_b);
    try server_a.send(&frames_a);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &client_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &client_a.established.connection);
    try dispatcher.registerConnection(2, &client_b.established.connection);

    try std.testing.expect((try client_a.pollNextResponseEvent()) == null);
    try std.testing.expect((try client_b.pollNextResponseEvent()) == null);

    var saw_a = false;
    var saw_b = false;
    var body_a: [10]u8 = undefined;
    var body_b: [10]u8 = undefined;
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    while (!saw_a or !saw_b) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                const client = switch (routed.connection_handle) {
                    1 => &client_a,
                    2 => &client_b,
                    else => return error.TestUnexpectedResult,
                };
                try client.processResponsePacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(
                    routed.connection_handle,
                );
                while (try client.pollNextResponseEvent()) |response_value| {
                    var response = response_value;
                    defer response.deinit(allocator);
                    if (response != .message) {
                        return error.TestUnexpectedResult;
                    }
                    switch (response.message.value) {
                        .head => |head| {
                            if (head != .response) {
                                return error.TestUnexpectedResult;
                            }
                            const expected: u16 =
                                if (routed.connection_handle == 1) 200 else 201;
                            try std.testing.expectEqual(
                                expected,
                                head.response.status,
                            );
                        },
                        .data_available => {
                            const target = if (routed.connection_handle == 1)
                                &body_a
                            else
                                &body_b;
                            const count = try client.readResponseData(
                                response.message.stream_id,
                                target,
                            );
                            const expected = if (routed.connection_handle == 1)
                                "response-a"
                            else
                                "response-b";
                            try std.testing.expectEqualStrings(
                                expected,
                                target[0..count],
                            );
                            if (routed.connection_handle == 1)
                                saw_a = true
                            else
                                saw_b = true;
                        },
                        .finished => {},
                        .push_promise, .trailers => return error.TestUnexpectedResult,
                    }
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
}
