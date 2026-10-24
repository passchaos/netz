const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime = @import("../../runtime.zig");

const allocator = std.testing.allocator;
const Kind = enum { request, response, push };

test "HTTP/3 protected late FIN DATA errors preserve exact stream and connection scope" {
    inline for (.{ Kind.request, Kind.response, Kind.push }) |kind| {
        inline for (.{ false, true }) |skip| {
            inline for (.{ false, true }) |truncated| try exercise(kind, skip, truncated);
        }
    }
}

fn exercise(comptime kind: Kind, comptime skip: bool, truncated: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = "client";
    const server_cid = "server";
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x71} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x72} ** quic.protection.secret_len);
    var server = try runtime.ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{}, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = server_cid,
        .peer_connection_id = client_cid,
    });
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{}, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = client_cid,
        .peer_connection_id = server_cid,
    });
    defer client.deinit();
    const parent = try client.sendRequest(.{ .method = "GET", .path = "/parent", .authority = "localhost" });
    const sibling = try client.sendRequest(.{ .method = "GET", .path = "/sibling", .authority = "localhost" });
    const push_id = 3;
    const stream_id = if (kind == .push) 19 else parent;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    if (kind == .push) {
        try client.sendMaxPushId(push_id);
        try client.push_streams.registerPromise(push_id, parent);
        try quic.varint.encode(&bytes, allocator, @intFromEnum(http3.StreamType.push));
        try quic.varint.encode(&bytes, allocator, push_id);
    }
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    if (kind == .request) {
        try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/partial" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "content-length", .value = "3" },
        });
    } else {
        try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "3" },
        });
    }
    try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, allocator);
    try quic.varint.encode(&bytes, allocator, http3.FrameType.data);
    try quic.varint.encode(&bytes, allocator, if (truncated) 3 else 2);
    try bytes.append(allocator, 'a');
    const prefix: quic.StreamFrame = .{ .stream_id = stream_id, .data = bytes.items };
    switch (kind) {
        .request => {
            try server.request_streams.insert(client.quic_client.address(), prefix);
            var head = (try server.pollRequestEventFor(stream_id)) orelse return error.TestUnexpectedResult;
            defer head.deinit(allocator);
            try std.testing.expect(head == .message and head.message.value == .head);
            var available = (try server.pollRequestEventFor(stream_id)) orelse return error.TestUnexpectedResult;
            defer available.deinit(allocator);
            try std.testing.expect(available == .message and available.message.value == .data_available);
        },
        .response => {
            try client.response_streams.insert(server.address(), prefix);
            var head = (try client.pollResponseEvent(stream_id)) orelse return error.TestUnexpectedResult;
            defer head.deinit(allocator);
            try std.testing.expect(head == .head);
            try std.testing.expect((try client.pollResponseEvent(stream_id)).? == .data_available);
        },
        .push => {
            try std.testing.expect(try client.push_streams.insert(server.address(), prefix, client.control));
            var head = (try client.pollPushEvent()) orelse return error.TestUnexpectedResult;
            defer head.deinit(allocator);
            try std.testing.expect(head.value == .head);
            var available = (try client.pollPushEvent()) orelse return error.TestUnexpectedResult;
            defer available.deinit(allocator);
            try std.testing.expect(available.value == .data_available);
        },
    }
    var byte: [1]u8 = undefined;
    const read = switch (kind) {
        .request => try server.readRequestData(stream_id, &byte),
        .response => try client.readResponseData(stream_id, &byte),
        .push => try client.readPushData(push_id, &byte),
    };
    try std.testing.expectEqual(@as(usize, 1), read);
    try std.testing.expectEqualStrings("a", &byte);
    const final: quic.StreamFrame = .{ .stream_id = stream_id, .offset = bytes.items.len, .data = "b", .fin = true };
    const inserted = switch (kind) {
        .request => try server.streaming_requests.insert(client.quic_client.address(), final),
        .response => try client.streaming_responses.insert(server.address(), final),
        .push => try client.push_streams.insert(server.address(), final, client.control),
    };
    try std.testing.expect(inserted);
    const expected = if (truncated) error.BufferTooShort else error.InvalidContentLength;
    var out = [_]u8{0xaa} ** 4;
    const result = switch (kind) {
        .request => if (skip) server.skipRequestData(stream_id) else server.readRequestData(stream_id, &out),
        .response => if (skip) client.skipResponseData(stream_id) else client.readResponseData(stream_id, &out),
        .push => if (skip) client.skipPushData(push_id) else client.readPushData(push_id, &out),
    };
    try std.testing.expectError(expected, result);
    try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
    if (!truncated) switch (kind) {
        .request => try std.testing.expect(!server.request_lifecycle.contains(stream_id)),
        .response => try std.testing.expect(!client.request_lifecycle.contains(stream_id)),
        .push => {
            try std.testing.expectEqual(@as(usize, 0), client.push_streams.promiseCount());
            try std.testing.expect(client.push_streams.hasPromise(push_id));
            try std.testing.expect(!client.push_streams.containsStream(stream_id));
            try std.testing.expect(client.request_lifecycle.contains(parent));
        },
    };
    try std.testing.expect(client.request_lifecycle.contains(sibling));
    const endpoint = if (kind == .request) &client.quic_client.endpoint else &server.quic_server.endpoint;
    const keys = if (kind == .request) server_keys else client_keys;
    const cid_len = if (kind == .request) client_cid.len else server_cid.len;
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    var stopped = false;
    var reset = false;
    while (true) {
        var datagram = try endpoint.receiveBytesWithDeadline(deadline);
        defer datagram.deinit(allocator);
        var packet = try quic.one_rtt.openReceivedBytes(endpoint, datagram.from, datagram.bytes, keys, cid_len, 0, 8);
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .application_close => |close| {
                try std.testing.expect(truncated);
                try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.frame_error), close.error_code);
                return;
            },
            .stop_sending => |stop| {
                try std.testing.expect(!truncated);
                try std.testing.expectEqual(@as(u64, stream_id), stop.stream_id);
                try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), stop.application_error_code);
                stopped = true;
            },
            .reset_stream => |value| {
                try std.testing.expect(!truncated and kind == .request);
                try std.testing.expectEqual(@as(u64, stream_id), value.stream_id);
                try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), value.application_error_code);
                try std.testing.expectEqual(@as(u64, 0), value.final_size);
                reset = true;
            },
            else => {},
        };
        if (stopped and (kind != .request or reset)) return;
    }
}
