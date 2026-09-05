const std = @import("std");
const runtime = @import("../../../../runtime.zig");
const quic = @import("../../../../../quic/mod.zig");
const server_response = @import("../../../server/response.zig");

const first_server_push_stream_id: u62 = 15;

test "HTTP/3 protected server sends promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xf5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xf6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf8} ** quic.protection.secret_len,
    );
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
    var client = try runtime.ProtectedClient.connect(
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
    try client.sendMaxPushId(3);
    var parent_capacity: usize = 0;
    var pushed_capacity: usize = 0;
    var frame_capacity: usize = 0;
    var parent_ptr: [*]u8 = undefined;
    var pushed_ptr: [*]u8 = undefined;
    var frame_ptr: [*]quic.Frame = undefined;
    for (0..2) |exchange| {
        const request_stream_id = try client.sendRequest(.{
            .method = "GET",
            .path = "/",
            .authority = "example.test",
        });
        var request = try server.receiveRequest();
        defer request.deinit(allocator);
        const push_id: u64 = @intCast(exchange + 2);
        const push_stream_id = try server.sendResponseWithPush(
            request.from,
            request.stream_id,
            .{ .status = 204 },
            .{
                .push_id = push_id,
                .request = .{
                    .method = "GET",
                    .path = "/style.css",
                    .authority = "example.test",
                },
                .response = .{
                    .status = 200,
                    .body = "css",
                },
            },
        );
        try std.testing.expectEqual(
            first_server_push_stream_id + @as(u62, @intCast(exchange * 4)),
            push_stream_id,
        );
        if (exchange == 0) {
            parent_capacity = server.push_send_scratch.parent.capacity;
            pushed_capacity = server.push_send_scratch.pushed.capacity;
            frame_capacity = server.push_send_scratch.frames.capacity;
            try std.testing.expect(parent_capacity != 0);
            try std.testing.expect(pushed_capacity != 0);
            try std.testing.expect(frame_capacity != 0);
            parent_ptr = server.push_send_scratch.parent.allocatedSlice().ptr;
            pushed_ptr = server.push_send_scratch.pushed.allocatedSlice().ptr;
            frame_ptr = server.push_send_scratch.frames.allocatedSlice().ptr;
        } else {
            try std.testing.expectEqual(
                parent_capacity,
                server.push_send_scratch.parent.capacity,
            );
            try std.testing.expectEqual(
                pushed_capacity,
                server.push_send_scratch.pushed.capacity,
            );
            try std.testing.expectEqual(
                frame_capacity,
                server.push_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                parent_ptr,
                server.push_send_scratch.parent.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                pushed_ptr,
                server.push_send_scratch.pushed.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                frame_ptr,
                server.push_send_scratch.frames.allocatedSlice().ptr,
            );
        }
        var promise = while (true) {
            if (try client.receiveResponseEvent(request_stream_id)) |event| {
                break event;
            }
        };
        defer promise.deinit(allocator);
        try std.testing.expect(promise == .push_promise);
        try std.testing.expectEqual(push_id, promise.push_promise.push_id);
        try std.testing.expectEqualStrings(
            "/style.css",
            promise.push_promise.request.path,
        );
        var parent_head = while (true) {
            if (try client.receiveResponseEvent(request_stream_id)) |event| {
                break event;
            }
        };
        defer parent_head.deinit(allocator);
        try std.testing.expect(parent_head == .head);
        try std.testing.expectEqual(
            @as(u16, 204),
            parent_head.head.response.status,
        );
        const parent_date = server_response.headerValue(
            parent_head.head.response.headers,
            "date",
        ) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            @as(usize, server_response.date_value_len),
            parent_date.len,
        );
        var pushed = try client.receivePush();
        defer pushed.deinit(allocator);
        try std.testing.expectEqual(push_stream_id, pushed.stream_id);
        try std.testing.expectEqualStrings("css", pushed.response.body);
        const pushed_date = server_response.headerValue(
            pushed.response.headers,
            "date",
        ) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            @as(usize, server_response.date_value_len),
            pushed_date.len,
        );
    }
}
