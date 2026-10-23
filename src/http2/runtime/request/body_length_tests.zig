const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");

const Mode = enum { aggregate, padded, callback, batch, duplex, serve };
const Violation = enum { overrun, short, limit, cumulative };

test "HTTP/2 request aggregate validates DATA length before retention" {
    try exercise(.aggregate, .overrun);
    try exercise(.aggregate, .short);
    try exercise(.aggregate, .limit);
    try exercise(.aggregate, .cumulative);
}

test "HTTP/2 padded request validates content length and returns full credit" {
    try exercise(.padded, .overrun);
    try exercise(.padded, .short);
    try exercise(.padded, .limit);
    try exercise(.padded, .cumulative);
}

test "HTTP/2 request callback validates DATA length before delivery" {
    try exercise(.callback, .overrun);
    try exercise(.callback, .short);
    try exercise(.callback, .limit);
    try exercise(.callback, .cumulative);
}

test "HTTP/2 request batch classifies invalid DATA and cancels siblings" {
    try exercise(.batch, .overrun);
    try exercise(.batch, .short);
    try exercise(.batch, .limit);
    try exercise(.batch, .cumulative);
}

test "HTTP/2 request duplex validates DATA length before events" {
    try exercise(.duplex, .overrun);
    try exercise(.duplex, .short);
    try exercise(.duplex, .limit);
    try exercise(.duplex, .cumulative);
}

test "HTTP/2 serve rejects invalid request DATA before invoking handler" {
    try exercise(.serve, .overrun);
    try exercise(.serve, .short);
    try exercise(.serve, .limit);
    try exercise(.serve, .cumulative);
}

fn exercise(comptime mode: Mode, violation: Violation) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_body_bytes = if (violation == .limit) 1 else 100,
    });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        violation: Violation,
        err: ?anyerror = null,
        delivered: usize = 0,
        handler_calls: usize = 0,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
            self.delivered += bytes.len;
        }

        fn consumeBatch(self: *@This(), _: u31, bytes: []const u8) !void {
            try self.consume(bytes);
        }

        fn handler(self: *@This(), _: runtime.OwnedRequest) runtime.Error!runtime.ResponseOptions {
            self.handler_calls += 1;
            return .{};
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            const before = connection.recv_connection_window.value;
            const expected = if (self.violation == .limit) error.MessageTooLarge else error.InvalidContentLength;
            const code: http2.ErrorCode = if (self.violation == .limit) .enhance_your_calm else .protocol_error;
            switch (mode) {
                .aggregate, .padded => try std.testing.expectError(expected, connection.readRequestWithTimeout(.fromSeconds(1))),
                .callback => try std.testing.expectError(expected, connection.readRequestStreamingWithTimeout(.fromSeconds(1), self, @This().consume)),
                .batch => {
                    var requests: [2]runtime.StreamingRequest = undefined;
                    try std.testing.expectError(expected, connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromSeconds(1), self, @This().consumeBatch));
                },
                .duplex => {
                    var request = try connection.acceptDuplexRequestWithTimeout(.fromSeconds(1));
                    defer request.deinit();
                    if (self.violation == .cumulative) {
                        var prefix = try request.readRequestEventWithTimeout(.fromSeconds(1));
                        defer prefix.deinit(self.server.allocator);
                        try std.testing.expect(prefix == .data);
                        try std.testing.expectEqualStrings("a", prefix.data.data);
                    }
                    try std.testing.expectError(expected, request.readRequestEventWithTimeout(.fromSeconds(1)));
                    try std.testing.expectEqual(@as(usize, if (self.violation == .cumulative) 1 else 0), request.request_body_bytes);
                    try sendReset(&connection, 1, code);
                    connection.abandonPeerRequest(1, code);
                },
                .serve => try std.testing.expectError(expected, connection.serveOne(@This(), self, @This().handler)),
            }
            try std.testing.expectEqual(@as(usize, if (self.violation == .cumulative and (mode == .callback or mode == .batch)) 1 else 0), self.delivered);
            try std.testing.expectEqual(@as(usize, 0), self.handler_calls);
            // Legitimate prefix content retains normal low-watermark batching.
            // Only the rejected DATA's full payload must be returned immediately.
            try std.testing.expectEqual(before - @as(i64, if (self.violation == .cumulative) 1 else 0), connection.recv_connection_window.value);
            if (mode != .serve and mode != .batch and mode != .duplex) {
                // Direct readers leave reset policy to their caller.
                try sendReset(&connection, 1, code);
                connection.abandonPeerRequest(1, code);
            }
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(self.server.allocator);
            try connection.writeResponse(next.stream_id, .{ .body = "healthy" });
        }
    };
    var peer = Peer{ .server = &server, .violation = violation };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/invalid" },
        .{ .name = "content-length", .value = switch (violation) {
            .short => "3",
            .cumulative => "2",
            else => "1",
        } },
    };
    const block = try client.hpack_encoder.encodeBlockRetained(allocator, fields[0..if (violation == .limit) 4 else 5]);
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(allocator);
    try wire.appendFrame(&frames, allocator, .headers, 0x04, 1, block);
    if (mode == .batch) {
        const sibling = try client.hpack_encoder.encodeBlockRetained(allocator, fields[0..4]);
        try wire.appendFrame(&frames, allocator, .headers, 0x05, 3, sibling);
    }
    if (violation == .cumulative) try wire.appendFrame(&frames, allocator, .data, 0, 1, "a");
    const padded = mode != .aggregate;
    const flags: u8 = @as(u8, if (padded) 0x08 else 0) | @as(u8, if (violation == .short) 1 else 0);
    try wire.appendFrame(&frames, allocator, .data, flags, 1, if (padded) "\x02ab\x00\x00" else "ab");
    var writer = client.stream.writer(io, &.{});
    try writer.interface.writeAll(frames.items);
    // Raw requests intentionally bypass the sender's own length validation.
    client.next_client_stream_id = if (mode == .batch) 5 else 3;
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(if (violation == .limit) http2.ErrorCode.enhance_your_calm else http2.ErrorCode.protocol_error, reset.reset.error_code);
    if (mode == .batch) {
        var sibling_reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
        defer sibling_reset.deinit(allocator);
        try std.testing.expectEqual(@as(u31, 3), sibling_reset.reset.stream_id);
        try std.testing.expectEqual(http2.ErrorCode.cancel, sibling_reset.reset.error_code);
    }
    var healthy = try client.requestWithTimeout(.{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(2));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", healthy.body);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn sendReset(connection: *runtime.Connection, stream_id: u31, code: http2.ErrorCode) !void {
    var buffer: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
    const bytes = try http2.ResetStreamPayload.writeInto(&buffer, stream_id, code);
    var writer = connection.stream.writer(connection.io, &.{});
    try writer.interface.writeAll(bytes);
}
