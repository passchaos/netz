const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime = @import("../../runtime.zig");

const Operation = enum { read, available, skip, read_once, skip_once };

test "HTTP/3 request late FIN short content resets stream before DATA delivery" {
    inline for (.{ Operation.read, Operation.available, Operation.skip, Operation.read_once, Operation.skip_once }) |operation| try exercise(operation, false);
}

test "HTTP/3 request late FIN truncated DATA closes connection before delivery" {
    inline for (.{ Operation.read, Operation.available, Operation.skip, Operation.read_once, Operation.skip_once }) |operation| try exercise(operation, true);
}

fn exercise(comptime operation: Operation, truncated: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8 };
    const client_cid = [_]u8{ 0xf9, 0xfa, 0xfb, 0xfc };
    const server_cid = [_]u8{ 0xfd, 0xfe, 0xff, 0x01 };
    var server = try runtime.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{}, .{
        .handshake = .{ .local_connection_id = &server_cid, .random = [_]u8{0x02} ** 32, .x25519_secret_key = [_]u8{0x03} ** 32 },
    });
    defer server.deinit();

    const Peer = struct {
        server: *runtime.HandshakeServer,
        truncated: bool,
        prefix_read: std.Io.Event = .unset,
        policy_observed: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.prefix_read.set(self.server.quic_server.endpoint.io);
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var head = try session.receiveRequestEventForWithTimeout(0, .fromSeconds(2));
            defer head.deinit(allocator);
            try std.testing.expect(head == .message);
            try std.testing.expect(head.message.value == .head);
            try std.testing.expect(head.message.value.head == .request);
            try std.testing.expectEqualStrings("/partial", head.message.value.head.request.path);
            try std.testing.expectEqual(@as(?usize, 3), head.message.value.head.request.content_length);

            var data = try session.receiveRequestEventForWithTimeout(0, .fromSeconds(2));
            defer data.deinit(allocator);
            try std.testing.expect(data == .message);
            try std.testing.expect(data.message.value == .data_available);
            var prefix: [1]u8 = undefined;
            try std.testing.expectEqual(@as(usize, 1), try session.readRequestData(0, &prefix));
            try std.testing.expectEqualStrings("a", &prefix);
            try std.testing.expect(!session.streaming_requests.find(0).?.reader.final_observed);
            self.prefix_read.set(self.server.quic_server.endpoint.io);

            // Only poll the sibling: packet routing must make the first FIN
            // visible without next() detecting its malformed DATA first.
            var sibling = try session.receiveRequestEventForWithTimeout(4, .fromSeconds(2));
            defer sibling.deinit(allocator);
            try std.testing.expect(sibling == .message);
            try std.testing.expect(sibling.message.value == .head);
            try std.testing.expectEqualStrings("/sibling", sibling.message.value.head.request.path);
            const reader = &session.streaming_requests.find(0).?.reader;
            try std.testing.expect(reader.final_observed);
            try std.testing.expectEqual(@as(usize, 1), reader.body_read);
            try std.testing.expect(reader.hasPendingFrame());

            const expected = if (self.truncated) error.BufferTooShort else error.InvalidContentLength;
            var out = [_]u8{0xaa} ** 4;
            switch (operation) {
                .read => try std.testing.expectError(expected, session.readRequestData(0, &out)),
                .available => try std.testing.expectError(expected, session.availableRequestData(0)),
                .skip => try std.testing.expectError(expected, session.skipRequestData(0)),
                .read_once => try std.testing.expectError(expected, session.readRequestDataOnce(0, &out)),
                .skip_once => try std.testing.expectError(expected, session.skipRequestDataOnce(0)),
            }
            try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
            if (self.truncated) {
                try std.testing.expect(session.established.connection.closing());
                // The failed bytes stay unread while the connection closes.
                try std.testing.expectEqual(@as(usize, 1), session.streaming_requests.find(0).?.reader.body_read);
                return;
            }

            try std.testing.expect(!session.established.connection.closing());
            try std.testing.expect(!session.request_lifecycle.contains(0));
            try std.testing.expect(!session.streaming_requests.contains(0));
            try std.testing.expect(session.request_lifecycle.contains(4));
            var finished = try session.receiveRequestEventForWithTimeout(4, .fromSeconds(2));
            defer finished.deinit(allocator);
            try std.testing.expect(finished == .message);
            try std.testing.expect(finished.message.value == .finished);
            try std.testing.expect(!session.streaming_requests.contains(4));
            // Keep the response packet out of the raw cancellation observer.
            try self.policy_observed.wait(self.server.quic_server.endpoint.io);
            try session.sendResponse(4, .{ .status = 204 });
            try std.testing.expect(!session.request_lifecycle.contains(4));
        }
    };

    var peer = Peer{ .server = &server, .truncated = truncated };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.policy_observed.set(io);
        thread.join();
    };
    var client = try runtime.HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{}, .{
        .handshake = .{ .original_destination_connection_id = &original_dcid, .local_connection_id = &client_cid, .server_name = "localhost", .random = [_]u8{0x04} ** 32, .x25519_secret_key = [_]u8{0x05} ** 32 },
    });
    defer client.deinit();

    // Send SETTINGS before bypassing the request writer to construct an
    // incomplete DATA frame on a normally allocated client request stream.
    try client.sendMaxPushId(0);
    const first = try client.openClientBidirectionalStream();
    try std.testing.expectEqual(@as(u62, 0), first);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/partial" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "3" },
    });
    try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, allocator);
    try quic.varint.encode(&bytes, allocator, http3.FrameType.data);
    try quic.varint.encode(&bytes, allocator, if (truncated) 3 else 2);
    try bytes.append(allocator, 'a');
    try client.established.connection.send(&.{.{ .stream = .{ .stream_id = first, .data = bytes.items } }});
    try peer.prefix_read.wait(io);
    try client.established.connection.send(&.{.{ .stream = .{
        .stream_id = first,
        .offset = bytes.items.len,
        .data = "b",
        .fin = true,
    } }});
    const second = try client.sendRequest(.{ .method = "GET", .path = "/sibling", .authority = "localhost" });
    try std.testing.expectEqual(@as(u62, 4), second);

    var saw_reset = false;
    var saw_stop = false;
    var saw_close = false;
    while (if (truncated) !saw_close else !saw_reset or !saw_stop) {
        var packet = try client.established.connection.receivePacketTimeout(.{
            .duration = .{ .clock = .awake, .raw = .fromSeconds(2) },
        });
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .application_close => |close| {
                try std.testing.expect(truncated);
                try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.frame_error), close.error_code);
                saw_close = true;
            },
            .reset_stream => |reset| {
                try std.testing.expect(!truncated);
                try std.testing.expectEqual(first, reset.stream_id);
                try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), reset.application_error_code);
                saw_reset = true;
            },
            .stop_sending => |stop| {
                try std.testing.expect(!truncated);
                try std.testing.expectEqual(first, stop.stream_id);
                try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), stop.application_error_code);
                saw_stop = true;
            },
            .connection_close => return error.TestUnexpectedResult,
            else => {},
        };
    }
    peer.policy_observed.set(io);
    if (!truncated) {
        try std.testing.expect(!client.established.connection.closing());
        var response = try client.receiveResponseWithTimeout(second, .fromSeconds(2));
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 204), response.response.status);
        try std.testing.expect(!client.request_lifecycle.contains(second));
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
