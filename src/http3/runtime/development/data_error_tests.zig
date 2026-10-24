const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime = @import("../../runtime.zig");
const datagram_queue = @import("datagram_queue.zig");

const allocator = std.testing.allocator;
const Operation = enum { poll, read, skip };

test "HTTP/3 development known FIN DATA errors have exact wire and state scope" {
    inline for (.{ false, true }) |truncated| {
        try exerciseServer(.poll, truncated, false, false);
        try exerciseClient(.poll, truncated, false, false);
    }
}

test "HTTP/3 development late FIN DATA errors terminate without lock reentry" {
    inline for (.{ Operation.poll, Operation.read, Operation.skip }) |operation| {
        inline for (.{ false, true }) |truncated| {
            try exerciseServer(operation, truncated, true, false);
            try exerciseClient(operation, truncated, true, false);
        }
    }
}

test "HTTP/3 development message error respects finished local directions" {
    try exerciseServer(.read, false, true, true);
    try exerciseClient(.skip, false, true, true);
}

test "HTTP/3 development DATA API state errors preserve wire and reader state" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var client = try runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{});
    defer client.deinit();
    const from = client.address();
    server.streaming_mode = true;
    var request = try encodedMessage(false, false);
    defer request.deinit(allocator);
    try server.streaming_peers.insert(from, .{ .stream_id = 0, .data = request.items });
    var request_head = (try server.pollRequestEvent()) orelse return error.TestUnexpectedResult;
    defer request_head.deinit(allocator);
    var out = [_]u8{0xaa} ** 4;
    try std.testing.expectError(error.UnexpectedFrame, server.readRequestData(from, 0, &out));
    try std.testing.expectError(error.UnexpectedFrame, server.skipRequestData(from, 0));
    try std.testing.expect(server.streaming_peers.containsRequest(from, 0));
    try std.testing.expect(!server.streaming_peers.find(from).?.unusable);
    try std.testing.expectError(error.Timeout, client.quic_client.receiveWithTimeout(.{
        .duration = .{ .clock = .awake, .raw = .fromMilliseconds(10) },
    }));

    const stream_id = try client.startRequest(.{ .method = "GET", .path = "/api-state", .authority = "localhost" }, 0);
    var sent_request = try server.quic_server.receiveWithTimeout(.{
        .duration = .{ .clock = .awake, .raw = .fromSeconds(1) },
    });
    defer sent_request.deinit(allocator);
    var response = try encodedMessage(true, false);
    defer response.deinit(allocator);
    try client.response_streams.insert(server.address(), .{ .stream_id = stream_id, .data = response.items });
    var response_head = (try client.pollResponseEvent(stream_id)) orelse return error.TestUnexpectedResult;
    defer response_head.deinit(allocator);
    try std.testing.expectError(error.UnexpectedFrame, client.readResponseData(stream_id, &out));
    try std.testing.expectError(error.UnexpectedFrame, client.skipResponseData(stream_id));
    try std.testing.expect(client.request_lifecycle.contains(stream_id));
    try std.testing.expect(client.streaming_responses.contains(stream_id));
    try std.testing.expect(!client.request_unusable);
    try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
    try std.testing.expectError(error.Timeout, server.quic_server.receiveWithTimeout(.{
        .duration = .{ .clock = .awake, .raw = .fromMilliseconds(10) },
    }));
}

fn encodedMessage(response: bool, truncated: bool) !std.ArrayList(u8) {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    if (response) {
        try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "3" },
        });
    } else {
        try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/invalid-data" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "content-length", .value = "3" },
        });
    }
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&bytes, allocator);
    try quic.varint.encode(&bytes, allocator, http3.FrameType.data);
    try quic.varint.encode(&bytes, allocator, if (truncated) 3 else 2);
    try bytes.appendSlice(allocator, "ab");
    return bytes;
}

fn queueDatagram(queue: *datagram_queue.Queue, from: std.Io.net.IpAddress) !void {
    const bytes = try allocator.dupe(u8, "queued");
    errdefer allocator.free(bytes);
    const frames = try allocator.alloc(quic.Frame, 0);
    errdefer allocator.free(frames);
    var datagram: quic.runtime.OwnedDatagram = .{
        .from = from,
        .bytes = bytes,
        .frames = frames,
    };
    try queue.push(&datagram);
}

fn expectWire(
    endpoint: *quic.runtime.Endpoint,
    stream_id: u62,
    truncated: bool,
    local_final_size: u64,
    send_reset: bool,
) !void {
    var saw_reset = false;
    var saw_stop = false;
    var saw_close = false;
    const deadline: std.Io.Clock.Timestamp = .fromNow(endpoint.io, .{
        .clock = .awake,
        .raw = .fromSeconds(1),
    });
    while (if (truncated) !saw_close else !saw_stop or (send_reset and !saw_reset)) {
        var datagram = try endpoint.receiveWithDeadline(deadline);
        defer datagram.deinit(allocator);
        for (datagram.frames) |frame| switch (frame) {
            .stream => {}, // Local head/body packets precede the cancellation.
            .application_close => |close| {
                try std.testing.expect(truncated);
                try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.frame_error), close.error_code);
                saw_close = true;
            },
            .reset_stream => |reset| {
                try std.testing.expect(!truncated and send_reset);
                try std.testing.expectEqual(@as(u64, stream_id), reset.stream_id);
                try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), reset.application_error_code);
                try std.testing.expectEqual(local_final_size, reset.final_size);
                saw_reset = true;
            },
            .stop_sending => |stop| {
                try std.testing.expect(!truncated);
                try std.testing.expectEqual(@as(u64, stream_id), stop.stream_id);
                try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), stop.application_error_code);
                saw_stop = true;
            },
            else => return error.TestUnexpectedResult,
        };
    }
    try std.testing.expectEqual(send_reset and !truncated, saw_reset);
    try std.testing.expectEqual(!truncated, saw_stop);
    try std.testing.expectEqual(truncated, saw_close);
}

fn exerciseServer(comptime operation: Operation, truncated: bool, late_fin: bool, send_finished: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var client = try runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{});
    defer client.deinit();
    var other = try runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{});
    defer other.deinit();
    const from = client.quic_client.address();
    const other_from = other.quic_client.address();
    var bytes = try encodedMessage(false, truncated);
    defer bytes.deinit(allocator);
    server.streaming_mode = true;
    try server.streaming_peers.insert(from, .{
        .stream_id = 0,
        .data = bytes.items[0 .. bytes.items.len - @as(usize, if (late_fin) 1 else 0)],
        .fin = !late_fin,
    });
    var head = (try server.pollRequestEvent()) orelse return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .message and head.message.value == .head);
    try server.streaming_peers.insert(from, .{ .stream_id = 4, .data = "" });
    try server.streaming_peers.insert(other_from, .{ .stream_id = 0, .data = "" });
    try server.startResponse(from, 0, .{ .status = if (send_finished) 204 else 200 }, if (send_finished) 0 else 3);
    if (!send_finished) try server.sendResponseBody(from, 0, "z", false);
    const local_final_size = if (server.streaming_peers.find(from).?.outbound_bodies.find(0)) |body| body.send.next_offset else 0;
    if (!send_finished) try std.testing.expect(local_final_size > 1);

    if (late_fin) {
        var available = try server.receiveRequestEventForWithTimeout(from, 0, .fromSeconds(1));
        defer available.deinit(allocator);
        try std.testing.expect(available.message.value == .data_available);
        var prefix: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try server.readRequestData(from, 0, &prefix));
        try std.testing.expectEqualStrings("a", &prefix);
        try server.streaming_peers.insert(from, .{
            .stream_id = 0,
            .offset = bytes.items.len - 1,
            .data = "b",
            .fin = true,
        });
    }
    try server.development_streams.insert(from, .{ .stream_id = 17, .data = "partial" });
    try server.development_streams.insert(other_from, .{ .stream_id = 17, .data = "other" });
    try server.development_stream_sends.open(from, 0, 17);
    try server.development_stream_sends.open(other_from, 0, 17);
    try queueDatagram(&server.runtime_datagrams, from);
    try queueDatagram(&server.runtime_datagrams, other_from);
    const expected = if (truncated) error.BufferTooShort else error.InvalidContentLength;
    var out = [_]u8{0xaa} ** 4;
    switch (operation) {
        .poll => try std.testing.expectError(expected, server.pollRequestEvent()),
        .read => try std.testing.expectError(expected, server.readRequestData(from, 0, &out)),
        .skip => try std.testing.expectError(expected, server.skipRequestData(from, 0)),
    }
    try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
    try std.testing.expect(!server.streaming_peers.containsRequest(from, 0));
    try std.testing.expect(server.streaming_peers.containsRequest(other_from, 0));
    try std.testing.expect(server.development_streams.contains(other_from, 17));
    try std.testing.expect(server.development_stream_sends.hasPeerEntries(other_from));
    try expectWire(&client.quic_client.endpoint, 0, truncated, local_final_size, !send_finished);

    if (truncated) {
        try std.testing.expect(!server.streaming_peers.hasPeer(from));
        try std.testing.expect(!server.development_streams.contains(from, 17));
        try std.testing.expect(!server.development_stream_sends.hasPeerEntries(from));
        try std.testing.expectEqual(@as(usize, 1), server.runtime_datagrams.count());
    } else {
        try std.testing.expect(server.streaming_peers.containsRequest(from, 4));
        try std.testing.expect(server.development_streams.contains(from, 17));
        try std.testing.expectEqual(@as(usize, 2), server.runtime_datagrams.count());
        try expectValidRequest(&server, from, 4);
        try expectValidRequest(&server, from, 8);
    }
    try expectValidRequest(&server, other_from, 0);
}

fn expectValidRequest(server: *runtime.Server, from: std.Io.net.IpAddress, stream_id: u62) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try (http3.Request{ .method = "GET", .path = "/usable", .authority = "localhost" }).write(&bytes, allocator);
    try server.streaming_peers.insert(from, .{ .stream_id = stream_id, .data = bytes.items, .fin = true });
    var head = try server.receiveRequestEventForWithTimeout(from, stream_id, .fromSeconds(1));
    defer head.deinit(allocator);
    try std.testing.expect(head.message.value == .head);
    try std.testing.expectEqualStrings("/usable", head.message.value.head.request.path);
    var finished = try server.receiveRequestEventForWithTimeout(from, stream_id, .fromSeconds(1));
    defer finished.deinit(allocator);
    try std.testing.expect(finished.message.value == .finished);
    try server.sendResponse(from, stream_id, .{ .status = 204 });
}

fn exerciseClient(comptime operation: Operation, truncated: bool, late_fin: bool, send_finished: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var client = try runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{});
    defer client.deinit();
    const first = try client.startRequest(.{ .method = if (send_finished) "GET" else "POST", .path = "/invalid-data", .authority = "localhost" }, if (send_finished) 0 else 3);
    if (!send_finished) try client.sendRequestBody(first, "z", false);
    const second = try client.startRequest(.{ .method = "GET", .path = "/sibling", .authority = "localhost" }, 0);
    const local_final_size = if (client.outbound_bodies.find(first)) |body| body.send.next_offset else 0;
    if (!send_finished) try std.testing.expect(local_final_size > 1);
    var bytes = try encodedMessage(true, truncated);
    defer bytes.deinit(allocator);
    try client.response_streams.insert(server.address(), .{
        .stream_id = first,
        .data = bytes.items[0 .. bytes.items.len - @as(usize, if (late_fin) 1 else 0)],
        .fin = !late_fin,
    });
    var head = (try client.pollResponseEvent(first)) orelse return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    if (late_fin) {
        var available = (try client.pollResponseEvent(first)) orelse return error.TestUnexpectedResult;
        defer available.deinit(allocator);
        try std.testing.expect(available == .data_available);
        var prefix: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try client.readResponseData(first, &prefix));
        try std.testing.expectEqualStrings("a", &prefix);
        try std.testing.expect(try client.streaming_responses.insert(server.address(), .{
            .stream_id = first,
            .offset = bytes.items.len - 1,
            .data = "b",
            .fin = true,
        }));
    }
    try client.development_streams.insert(server.address(), .{ .stream_id = 17, .data = "partial" });
    try client.development_stream_sends.open(first, 17);
    try queueDatagram(&client.runtime_datagrams, server.address());
    const expected = if (truncated) error.BufferTooShort else error.InvalidContentLength;
    var out = [_]u8{0xaa} ** 4;
    switch (operation) {
        .poll => try std.testing.expectError(expected, client.pollResponseEvent(first)),
        .read => try std.testing.expectError(expected, client.readResponseData(first, &out)),
        .skip => try std.testing.expectError(expected, client.skipResponseData(first)),
    }
    try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
    try std.testing.expect(!client.request_lifecycle.contains(first));
    try std.testing.expect(client.streaming_responses.find(first) == null);
    try expectWire(&server.quic_server.endpoint, first, truncated, local_final_size, !send_finished);
    if (truncated) {
        try std.testing.expect(client.request_unusable);
        try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
        try std.testing.expect(client.outbound_bodies.isEmpty());
        try std.testing.expectEqual(@as(usize, 0), client.development_streams.entries.items.len);
        try std.testing.expectEqual(@as(usize, 0), client.development_stream_sends.entries.items.len);
        try std.testing.expectEqual(@as(usize, 0), client.runtime_datagrams.count());
        try std.testing.expectError(error.ConnectionUnusable, client.pollResponseEvent(second));
        try std.testing.expectError(error.ConnectionUnusable, client.startRequest(.{ .method = "GET", .path = "/closed", .authority = "localhost" }, 0));
        try std.testing.expectError(error.ConnectionUnusable, client.sendDevelopmentStream(first, 1, "closed", false));
        const match: runtime.DevelopmentStreamMatch = .{ .session_id = first, .local_role = .client };
        try std.testing.expectError(error.ConnectionUnusable, client.pollDevelopmentStream(match));
        try std.testing.expectError(error.ConnectionUnusable, client.receiveDevelopmentStreamWithTimeout(match, .fromSeconds(1)));
        try std.testing.expectError(error.ConnectionUnusable, client.receiveDatagramWithTimeout(.fromSeconds(1)));
    } else {
        try std.testing.expect(!client.request_unusable);
        try std.testing.expect(client.request_lifecycle.contains(second));
        try std.testing.expectEqual(@as(usize, 1), client.runtime_datagrams.count());
        try expectValidResponse(&client, server.address(), second);
        const third = try client.startRequest(.{ .method = "GET", .path = "/followup", .authority = "localhost" }, 0);
        try expectValidResponse(&client, server.address(), third);
    }
}

fn expectValidResponse(client: *runtime.Client, from: std.Io.net.IpAddress, stream_id: u62) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try (http3.Response{ .status = 204 }).write(&bytes, allocator);
    try client.response_streams.insert(from, .{ .stream_id = stream_id, .data = bytes.items, .fin = true });
    var head = (try client.pollResponseEvent(stream_id)) orelse return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    var finished = (try client.pollResponseEvent(stream_id)) orelse return error.TestUnexpectedResult;
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
}
