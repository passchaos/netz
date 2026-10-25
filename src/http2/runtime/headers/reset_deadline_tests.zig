//! Canceled-stream header blocks must obey the operation's original deadline.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const stream_io = @import("../../../internal/stream_io.zig");

fn send(connection: *runtime.Connection, frame_type: http2.FrameType, flags: u8, id: u31, payload: []const u8) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(connection.allocator);
    try (http2.Frame{ .header = .{ .length = @intCast(payload.len), .frame_type = frame_type, .flags = flags, .stream_id = id }, .payload = payload }).write(&encoded, connection.allocator);
    try stream_io.writeAllSlices(connection.io, connection.stream, &.{encoded.items});
}

const Probe = enum { ping, response, duplex, complete, duplex_complete };

test "HTTP/2 reset deadline bounds late HEADERS during PING" {
    try exerciseLateReset(.ping);
}

test "HTTP/2 reset deadline bounds late HEADERS during response receive" {
    try exerciseLateReset(.response);
}

test "HTTP/2 reset deadline bounds late HEADERS during duplex receive" {
    try exerciseLateReset(.duplex);
}

test "HTTP/2 reset deadline completed late HEADERS preserve HPACK and reuse" {
    try exerciseLateReset(.complete);
}

test "HTTP/2 reset deadline completed late HEADERS preserve duplex HPACK and reuse" {
    try exerciseLateReset(.duplex_complete);
}

fn exerciseLateReset(probe: Probe) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        probe: Probe,
        err: ?anyerror = null,
        headers_sent: std.Io.Event = .unset,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.headers_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            while (true) {
                var frame = try runtime.testing.readOwnedFrame(&connection);
                defer frame.deinit(connection.allocator);
                if (frame.frame.header.frame_type == .headers) {
                    const payload = try http2.HeadersPayload.parse(frame.frame);
                    try connection.hpack_decoder.discardBlock(connection.allocator, payload.header_block);
                    break;
                }
                if (!try runtime.testing.handleConnectionFrame(&connection, frame.frame)) return error.UnexpectedFrame;
            }
            var reset = try connection.readResetStreamWithTimeout(.fromSeconds(1));
            defer reset.deinit(connection.allocator);
            const complete = self.probe == .complete or self.probe == .duplex_complete;
            const block = if (complete)
                try connection.hpack_encoder.encodeBlockRetained(connection.allocator, &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "x-late", .value = "kept" },
                })
            else
                &[_]u8{0x88};
            try send(&connection, .headers, 0, reset.reset.stream_id, block[0..1]);
            self.headers_sent.set(connection.io);
            // Rescue the old unbounded implementation so a regression fails
            // with a useful assertion instead of leaving the test hung.
            if (!complete) try std.Io.sleep(connection.io, .fromMilliseconds(200), .awake);
            try send(&connection, .continuation, 0x4, reset.reset.stream_id, block[1..]);
            if (self.probe == .ping or self.probe == .complete) {
                _ = try connection.readPingWithTimeout(.fromSeconds(1));
            }
            if (self.probe != .ping) {
                var request = try connection.readRequestWithTimeout(.fromSeconds(1));
                defer request.deinit(connection.allocator);
                try connection.writeResponse(request.stream_id, .{
                    .headers = if (complete) &.{.{ .name = "x-late", .value = "kept" }} else &.{},
                    .body = "ok",
                });
            }
        }
    };
    var peer = Peer{ .server = &server, .probe = probe };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var request = try client.startRequest(.{ .path = "/canceled", .authority = "localhost", .body_length = 0 });
    request.deinit();
    try peer.headers_sent.wait(io);
    switch (probe) {
        .ping => try std.testing.expectError(error.Timeout, client.pingWithTimeout(.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .fromMilliseconds(30))),
        .response => {
            if (client.requestWithTimeout(.{ .path = "/sibling", .authority = "localhost" }, .fromMilliseconds(30))) |response_value| {
                var response = response_value;
                response.deinit(allocator);
                return error.TestExpectedError;
            } else |err| try std.testing.expectEqual(error.Timeout, err);
        },
        .duplex => {
            var writer = try client.startRequest(.{ .path = "/sibling", .authority = "localhost", .body_length = 0 });
            defer writer.deinit();
            try writer.finish();
            var duplex = try writer.beginDuplex();
            defer duplex.deinit();
            if (duplex.readResponseEventWithTimeout(.fromMilliseconds(30))) |event_value| {
                var event = event_value;
                event.deinit(allocator);
                return error.TestExpectedError;
            } else |err| try std.testing.expectEqual(error.Timeout, err);
        },
        .complete => {
            _ = try client.pingWithTimeout(.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .fromSeconds(1));
            var response = try client.requestWithTimeout(.{ .path = "/sibling", .authority = "localhost" }, .fromSeconds(1));
            defer response.deinit(allocator);
            try std.testing.expectEqualStrings("kept", runtime.testing.findHeader(response.headers, "x-late").?);
            try std.testing.expectEqualStrings("ok", response.body);
        },
        .duplex_complete => {
            var writer = try client.startRequest(.{ .path = "/sibling", .authority = "localhost", .body_length = 0 });
            defer writer.deinit();
            try writer.finish();
            var duplex = try writer.beginDuplex();
            defer duplex.deinit();
            var head = try duplex.readResponseEventWithTimeout(.fromSeconds(1));
            defer head.deinit(allocator);
            try std.testing.expect(head == .head);
            try std.testing.expectEqualStrings("kept", runtime.testing.findHeader(head.head.headers, "x-late").?);
            var body = try duplex.readResponseEventWithTimeout(.fromSeconds(1));
            defer body.deinit(allocator);
            try std.testing.expect(body == .data);
            try std.testing.expectEqualStrings("ok", body.data.data);
            var finished = try duplex.readResponseEventWithTimeout(.fromSeconds(1));
            defer finished.deinit(allocator);
            try std.testing.expect(finished == .finished);
        },
    }
    if (probe == .complete or probe == .duplex_complete) {
        try std.testing.expect(client.isReusable());
    } else {
        try std.testing.expect(!client.isReusable());
        try std.testing.expectError(error.ConnectionClosed, client.pingWithTimeout(.{ 8, 7, 6, 5, 4, 3, 2, 1 }, .fromSeconds(1)));
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
