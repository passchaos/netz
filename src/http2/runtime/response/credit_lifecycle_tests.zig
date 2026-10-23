const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const Termination = enum { malformed, deadline, callback };

test "HTTP/2 independent aggregate retains DATA credit across adaptive growth" {
    try exercise(false, .malformed);
}

test "HTTP/2 independent streaming retains DATA credit across adaptive growth" {
    try exercise(true, .malformed);
}

test "HTTP/2 independent aggregate deadline returns DATA credit after adaptive growth" {
    try exercise(false, .deadline);
}

test "HTTP/2 independent streaming deadline returns DATA credit after adaptive growth" {
    try exercise(true, .deadline);
}

test "HTTP/2 independent callback rejection returns DATA credit after adaptive growth" {
    try exercise(true, .callback);
}

fn exercise(comptime streaming: bool, termination: Termination) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var client: runtime.Connection = undefined;
    const Peer = struct {
        server: *runtime.Server,
        client: *runtime.Connection,
        termination: Termination,
        ready: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            try self.ready.wait(self.server.io);
            var request = try connection.readRequestWithTimeout(.fromSeconds(3));
            defer request.deinit(self.server.allocator);
            var sibling = try connection.readRequestWithTimeout(.fromSeconds(3));
            defer sibling.deinit(self.server.allocator);
            // Both request HEADERS have been submitted. Match the prepared
            // receive window on the wire before the server sends any DATA;
            // the client reader cannot write its deferred grant at this point.
            var increment: [4]u8 = undefined;
            const extra: u31 = @intCast(window.max_value - window.default_value);
            std.mem.writeInt(u32, &increment, extra, .big);
            try sendFrame(self.client, .window_update, 0, request.stream_id, &increment);
            var update = try connection.readWindowUpdateWithTimeout(.fromSeconds(2));
            defer update.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, update.window_update.stream_id);
            try std.testing.expectEqual(extra, update.window_update.increment);

            const head = try connection.hpack_encoder.encodeBlockRetained(self.server.allocator, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = if (self.termination == .callback) "6" else "3" },
            });
            try sendFrame(&connection, .headers, 0x04, request.stream_id, head);
            // Three charged bytes make room for the queued two-byte window
            // expansion. Its two content bytes remain held by this stream.
            try sendData(&connection, 0x08, request.stream_id, "\x00ab");
            // Reject a later DATA through message validation or the callback,
            // or wait for expiration with only the accepted prefix retained.
            if (self.termination != .deadline) try sendData(&connection, 0, request.stream_id, "cdef");
            var reset = try connection.readResetStreamWithTimeout(.fromSeconds(2));
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(if (self.termination == .malformed) http2.ErrorCode.protocol_error else http2.ErrorCode.cancel, reset.reset.error_code);
            try connection.writeResponse(sibling.stream_id, .{ .status = 204 });
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(self.server.allocator);
            try connection.writeResponse(next.stream_id, .{ .body = "healthy" });
        }
    };
    var peer = Peer{ .server = &server, .client = &client, .termination = termination };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.ready.set(io);
        thread.join();
    };
    client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    // The active stream's advertised maximum defers adaptive SETTINGS until
    // DATA reduces that window. This exercises a grant during DATA processing
    // rather than a grant between frame reads.
    (try runtime.testing.recvStreamWindow(&client, 1)).value = window.max_value;
    try runtime.testing.queueAdaptiveWindowTarget(&client, 65_537);
    try std.testing.expectEqual(@as(?u32, 65_537), client.adaptive_queued_target);
    peer.ready.set(io);
    var observed = Observer{ .termination = termination };
    const requests = [_]runtime.RequestOptions{
        .{ .path = "/growth", .authority = "localhost" },
        .{ .path = "/sibling", .authority = "localhost" },
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
    const first_deadline = if (termination == .deadline) std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromMilliseconds(250), .clock = .awake }) else deadline;
    if (streaming) {
        try client.requestBatchStreamingWithPerStreamDeadlines(&requests, &.{ first_deadline, deadline }, .{
            .context = &observed,
            .on_data = Observer.data,
            .on_result = Observer.streamingResult,
        });
        try std.testing.expectEqualStrings("ab", observed.prefix[0..observed.prefix_len]);
    } else {
        try client.requestBatchWithPerStreamDeadlines(&requests, &.{ first_deadline, deadline }, .{
            .context = &observed,
            .on_result = Observer.ownedResult,
        });
    }
    const expected: anyerror = switch (termination) {
        .malformed => error.InvalidContentLength,
        .deadline => error.Timeout,
        .callback => error.CallbackRejected,
    };
    try std.testing.expectEqual(@as(?anyerror, expected), observed.errors[0]);
    try std.testing.expectEqual(@as(?anyerror, null), observed.errors[1]);
    try std.testing.expectEqual([2]usize{ 1, 1 }, observed.results);
    try std.testing.expectEqual(@as(u32, 65_537), client.recv_connection_window_target);
    try std.testing.expectEqual(@as(?u32, null), client.adaptive_queued_target);
    try std.testing.expectEqual(@as(i64, 65_537), client.recv_connection_window.value);
    var healthy = try client.requestWithTimeout(.{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(2));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", healthy.body);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

const Observer = struct {
    termination: Termination,
    errors: [2]?anyerror = .{ null, null },
    results: [2]usize = .{ 0, 0 },
    prefix: [2]u8 = undefined,
    prefix_len: usize = 0,

    fn data(context: *anyopaque, index: usize, bytes: []const u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.termination == .callback and self.prefix_len != 0) return error.CallbackRejected;
        if (index != 0 or bytes.len > self.prefix.len - self.prefix_len) return error.TestUnexpectedResult;
        @memcpy(self.prefix[self.prefix_len..][0..bytes.len], bytes);
        self.prefix_len += bytes.len;
    }

    fn result(self: *@This(), index: usize, value: anytype) void {
        self.results[index] += 1;
        switch (value) {
            .err => |err| self.errors[index] = err,
            .response => |response_value| {
                var response = response_value;
                if (index != 1 or response.status != 204) self.errors[index] = error.TestUnexpectedResult;
                response.deinit(std.testing.allocator);
            },
        }
    }

    fn ownedResult(context: *anyopaque, index: usize, value: runtime.BatchOwnedResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.result(index, value);
    }

    fn streamingResult(context: *anyopaque, index: usize, value: runtime.BatchStreamingResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.result(index, value);
    }
};

fn sendFrame(connection: *runtime.Connection, kind: http2.FrameType, flags: u8, id: u31, payload: []const u8) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try wire.appendFrame(&bytes, std.testing.allocator, kind, flags, id, payload);
    var writer = connection.stream.writer(connection.io, &.{});
    try writer.interface.writeAll(bytes.items);
}

fn sendData(connection: *runtime.Connection, flags: u8, id: u31, payload: []const u8) !void {
    // Raw malformed message fixtures still honor the sender's flow-control
    // debits so the adaptive SETTINGS delta sees matching stream windows.
    try connection.send_connection_window.reserve(payload.len);
    const index = connection.send_stream_window_index.get(id) orelse return error.TestUnexpectedResult;
    try connection.send_stream_windows.items[index].window.reserve(payload.len);
    try sendFrame(connection, .data, flags, id, payload);
}
