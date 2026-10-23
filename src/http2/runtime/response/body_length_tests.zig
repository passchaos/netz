const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");

const Mode = enum {
    aggregate,
    callback,
    batch,
    batch_callback,
    independent,
    independent_callback,
    duplex,
    connect,

    fn hasSibling(self: Mode) bool {
        return switch (self) {
            .batch, .batch_callback, .independent, .independent_callback => true,
            else => false,
        };
    }

    fn hasIndependentDeadlines(self: Mode) bool {
        return self == .independent or self == .independent_callback;
    }
};

test "HTTP/2 response rejects Content-Length overrun before END_STREAM" {
    try exercise(.aggregate, false);
    try exercise(.aggregate, true);
}

test "HTTP/2 callback rejects Content-Length overrun before application delivery" {
    try exercise(.callback, false);
    try exercise(.callback, true);
}

test "HTTP/2 batch rejects Content-Length violations before END_STREAM or retention" {
    try exercise(.batch, false);
    try exercise(.batch, true);
}

test "HTTP/2 callback batch rejects Content-Length violations before delivery" {
    try exercise(.batch_callback, false);
    try exercise(.batch_callback, true);
}

test "HTTP/2 independent batch isolates Content-Length violations from healthy siblings" {
    try exercise(.independent, false);
    try exercise(.independent, true);
}

test "HTTP/2 independent callback batch validates Content-Length before delivery" {
    try exercise(.independent_callback, false);
    try exercise(.independent_callback, true);
}

test "HTTP/2 duplex rejects Content-Length violations before DATA events" {
    try exercise(.duplex, false);
    try exercise(.duplex, true);
}

test "HTTP/2 CONNECT rejection validates Content-Length before retention" {
    try exercise(.connect, false);
    try exercise(.connect, true);
}

fn exercise(comptime mode: Mode, final_short: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .enable_connect_protocol = true });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        final_short: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            const stream_id = if (mode == .connect) blk: {
                var request = try connection.readExtendedConnectRequestWithTimeout("websocket", .fromSeconds(3));
                defer request.deinit(self.server.allocator);
                break :blk request.stream_id;
            } else blk: {
                var request = try connection.readRequestWithTimeout(.fromSeconds(3));
                defer request.deinit(self.server.allocator);
                break :blk request.stream_id;
            };
            const sibling = if (mode.hasSibling()) blk: {
                var request = try connection.readRequestWithTimeout(.fromSeconds(3));
                defer request.deinit(self.server.allocator);
                break :blk request.stream_id;
            } else 0;
            const headers = try connection.hpack_encoder.encodeBlockRetained(self.server.allocator, &.{
                .{ .name = ":status", .value = if (mode == .connect) "403" else "200" },
                .{ .name = "content-length", .value = if (self.final_short) "3" else "1" },
            });
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(self.server.allocator);
            try wire.appendFrame(&bytes, self.server.allocator, .headers, 0x04, stream_id, headers);
            // Two content bytes, one Pad Length byte and two padding bytes.
            // Excess content is invalid even without END_STREAM. A short final
            // frame must likewise be rejected before exposing its content.
            try wire.appendFrame(&bytes, self.server.allocator, .data, 0x08 | @as(u8, if (self.final_short) 1 else 0), stream_id, "\x02ab\x00\x00");
            var writer = connection.stream.writer(connection.io, &.{});
            try writer.interface.writeAll(bytes.items);
            var reset = try connection.readResetStreamWithTimeout(.fromSeconds(2));
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(if (mode == .connect) http2.ErrorCode.cancel else http2.ErrorCode.protocol_error, reset.reset.error_code);
            if (mode.hasSibling()) {
                if (mode.hasIndependentDeadlines()) {
                    try connection.writeResponse(sibling, .{ .body = "sibling" });
                } else {
                    var sibling_reset = try connection.readResetStreamWithTimeout(.fromSeconds(2));
                    defer sibling_reset.deinit(self.server.allocator);
                    try std.testing.expectEqual(sibling, sibling_reset.reset.stream_id);
                    try std.testing.expectEqual(http2.ErrorCode.cancel, sibling_reset.reset.error_code);
                }
            }
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(self.server.allocator);
            try connection.writeResponse(next.stream_id, .{ .body = "healthy" });
        }
    };
    var peer = Peer{ .server = &server, .final_short = final_short };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    const before = client.recv_connection_window.value;
    const options = runtime.RequestOptions{ .path = "/overrun", .authority = "localhost" };
    const requests = [_]runtime.RequestOptions{ options, .{ .path = "/sibling", .authority = "localhost" } };
    var observed = Observer{};
    switch (mode) {
        .aggregate => try std.testing.expectError(error.InvalidContentLength, client.requestWithTimeout(options, .fromSeconds(1))),
        .callback => try std.testing.expectError(error.InvalidContentLength, client.requestStreamingWithTimeout(options, .fromSeconds(1), &observed, Observer.consume)),
        .batch => {
            var responses: [2]runtime.OwnedResponse = undefined;
            try std.testing.expectError(error.InvalidContentLength, client.requestBatchIntoWithTimeout(&requests, &responses, .fromSeconds(1)));
        },
        .batch_callback => {
            var responses: [2]runtime.StreamingResponse = undefined;
            try std.testing.expectError(error.InvalidContentLength, client.requestBatchStreamingIntoWithTimeout(&requests, &responses, .fromSeconds(1), &observed, Observer.consumeBatch));
        },
        .independent, .independent_callback => {
            const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake });
            if (mode == .independent) {
                try client.requestBatchWithPerStreamDeadlines(&requests, &.{ deadline, deadline }, .{ .context = &observed, .on_result = Observer.ownedResult });
            } else {
                try client.requestBatchStreamingWithPerStreamDeadlines(&requests, &.{ deadline, deadline }, .{ .context = &observed, .on_data = Observer.consumeOpaque, .on_result = Observer.streamingResult });
            }
            try std.testing.expectEqual(@as(?anyerror, error.InvalidContentLength), observed.errors[0]);
            try std.testing.expectEqual(@as(?anyerror, null), observed.errors[1]);
            try std.testing.expectEqual([2]usize{ 1, 1 }, observed.results);
            try std.testing.expectEqualStrings("sibling", observed.sibling[0..observed.sibling_len]);
        },
        .duplex => {
            var request = try client.startRequest(.{ .path = options.path, .authority = options.authority });
            defer request.deinit();
            try request.finish();
            var duplex = try request.beginDuplex();
            defer duplex.deinit();
            var head = try duplex.readResponseEventWithTimeout(.fromSeconds(1));
            defer head.deinit(allocator);
            try std.testing.expect(head == .head);
            try std.testing.expectError(error.InvalidContentLength, duplex.readResponseEventWithTimeout(.fromSeconds(1)));
            try std.testing.expectEqual(@as(usize, 0), duplex.response_body_bytes);
            // Direct event readers leave stream error policy to the caller.
            try duplex.reset(.protocol_error);
        },
        .connect => try std.testing.expectError(error.InvalidContentLength, client.openExtendedConnectAttemptWithTimeout(.{
            .method = "CONNECT",
            .path = "/overrun",
            .authority = "localhost",
            .protocol = "websocket",
        }, .fromSeconds(1))),
    }
    try std.testing.expectEqual(@as(usize, 0), observed.delivered);
    // Healthy sibling content follows normal low-watermark credit batching;
    // the rejected padded frame must contribute exactly zero held credit.
    try std.testing.expectEqual(before - @as(i64, if (mode.hasIndependentDeadlines()) "sibling".len else 0), client.recv_connection_window.value);
    var healthy = try client.requestWithTimeout(.{ .path = "/after-overrun", .authority = "localhost" }, .fromSeconds(2));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", healthy.body);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

const Observer = struct {
    delivered: usize = 0,
    errors: [2]?anyerror = .{ null, null },
    results: [2]usize = .{ 0, 0 },
    sibling: [7]u8 = undefined,
    sibling_len: usize = 0,

    fn consume(self: *@This(), bytes: []const u8) !void {
        self.delivered += bytes.len;
    }

    fn consumeBatch(self: *@This(), index: usize, bytes: []const u8) !void {
        if (index == 0) return self.consume(bytes);
        if (bytes.len > self.sibling.len - self.sibling_len) return error.TestUnexpectedResult;
        @memcpy(self.sibling[self.sibling_len..][0..bytes.len], bytes);
        self.sibling_len += bytes.len;
    }

    fn consumeOpaque(context: *anyopaque, index: usize, bytes: []const u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        try self.consumeBatch(index, bytes);
    }

    fn ownedResult(context: *anyopaque, index: usize, result: runtime.BatchOwnedResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.results[index] += 1;
        switch (result) {
            .err => |err| self.errors[index] = err,
            .response => |value| {
                var response = value;
                defer response.deinit(std.testing.allocator);
                self.consumeBatch(index, response.body) catch |err| {
                    self.errors[index] = err;
                };
            },
        }
    }

    fn streamingResult(context: *anyopaque, index: usize, result: runtime.BatchStreamingResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.results[index] += 1;
        switch (result) {
            .err => |err| self.errors[index] = err,
            .response => |value| {
                var response = value;
                response.deinit(std.testing.allocator);
            },
        }
    }
};
