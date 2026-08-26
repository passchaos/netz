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
            .timer => {},
            .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(server_a.control.settings.received);
    try std.testing.expect(server_b.control.settings.received);
}
