const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;

const Mode = enum { aggregate, streaming, batch, batch_streaming, body_batch, body_streaming, independent, independent_streaming, independent_body, independent_body_streaming, duplex };

const Observer = struct {
    errors: [2]?anyerror = .{ null, null },
    results: [2]usize = .{ 0, 0 },
    delivered: usize = 0,
    fn data(self: *@This(), bytes: []const u8) !void {
        self.delivered += bytes.len;
    }
    fn batchData(self: *@This(), _: usize, bytes: []const u8) !void {
        try self.data(bytes);
    }
    fn opaqueData(context: *anyopaque, index: usize, bytes: []const u8) !void {
        try (@as(*@This(), @ptrCast(@alignCast(context)))).batchData(index, bytes);
    }
    fn owned(context: *anyopaque, index: usize, result: runtime.BatchOwnedResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.results[index] += 1;
        switch (result) {
            .err => |err| self.errors[index] = err,
            .response => |value| {
                var response = value;
                response.deinit(allocator);
            },
        }
    }
    fn streamed(context: *anyopaque, index: usize, result: runtime.BatchStreamingResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.results[index] += 1;
        switch (result) {
            .err => |err| self.errors[index] = err,
            .response => |value| {
                var response = value;
                response.deinit(allocator);
            },
        }
    }
};

test "HTTP/2 successful response DATA owns content credit without padding overhead" {
    for (std.enums.values(Mode)) |mode| {
        for ([_]bool{ false, true }) |content| {
            for ([_]bool{ false, true }) |head| {
                if (content and head) continue;
                try exercise(mode, content, head);
            }
        }
    }
}

fn exercise(mode: Mode, content: bool, head: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client };
    defer connection.close();
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, "\x88");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 8, 1, "\x03\x00\x00\x00");
    // PADDED with a zero pad length still charges its Pad Length byte.
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 8, 1, "\x00");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 9, 1, if (content) "\x02ab\x00\x00" else "\x02\x00\x00");
    const is_batch = mode != .aggregate and mode != .streaming and mode != .duplex;
    if (is_batch) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 3, "\x88");
    const body_batch = mode == .body_batch or mode == .body_streaming or mode == .independent_body or mode == .independent_body_streaming;
    const requests = [_]runtime.RequestOptions{
        .{ .method = if (head) "HEAD" else "GET", .authority = "localhost", .body = if (body_batch) "a" else "" },
        .{ .authority = "localhost", .body = if (body_batch) "b" else "" },
    };
    var observed: Observer = .{};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake });
    switch (mode) {
        .aggregate => {
            var response = try connection.requestWithTimeout(requests[0], .fromSeconds(1));
            defer response.deinit(allocator);
            try std.testing.expectEqualStrings(if (content) "ab" else "", response.body);
        },
        .streaming => {
            var response = try connection.requestStreamingWithTimeout(requests[0], .fromSeconds(1), &observed, Observer.data);
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(usize, if (content) 2 else 0), response.body_bytes);
        },
        .batch, .body_batch => {
            var responses: [2]runtime.OwnedResponse = undefined;
            if (body_batch) try connection.requestBodyBatchIntoWithTimeout(&requests, 1, &responses, .fromSeconds(1)) else try connection.requestBatchIntoWithTimeout(&requests, &responses, .fromSeconds(1));
            defer for (&responses) |*response| response.deinit(allocator);
            try std.testing.expectEqualStrings(if (content) "ab" else "", responses[0].body);
        },
        .batch_streaming, .body_streaming => {
            var responses: [2]runtime.StreamingResponse = undefined;
            if (body_batch) try connection.requestBodyBatchStreamingIntoWithTimeout(&requests, 1, &responses, .fromSeconds(1), &observed, Observer.batchData) else try connection.requestBatchStreamingIntoWithTimeout(&requests, &responses, .fromSeconds(1), &observed, Observer.batchData);
            defer for (&responses) |*response| response.deinit(allocator);
        },
        .independent => try connection.requestBatchWithPerStreamDeadlines(&requests, &.{ deadline, deadline }, .{ .context = &observed, .on_result = Observer.owned }),
        .independent_streaming => try connection.requestBatchStreamingWithPerStreamDeadlines(&requests, &.{ deadline, deadline }, .{ .context = &observed, .on_data = Observer.opaqueData, .on_result = Observer.streamed }),
        .independent_body => try connection.requestBodyBatchWithPerStreamDeadlines(&requests, 1, &.{ deadline, deadline }, .{ .context = &observed, .on_result = Observer.owned }),
        .independent_body_streaming => try connection.requestBodyBatchStreamingWithPerStreamDeadlines(&requests, 1, &.{ deadline, deadline }, .{ .context = &observed, .on_data = Observer.opaqueData, .on_result = Observer.streamed }),
        .duplex => {
            var request = try connection.startRequest(.{ .method = if (head) "HEAD" else "GET", .authority = "localhost" });
            defer request.deinit();
            try request.finish();
            var duplex = try request.beginDuplex();
            defer duplex.deinit();
            while (true) {
                var event = try duplex.readResponseEventWithTimeout(.fromSeconds(1));
                defer event.deinit(allocator);
                if (event == .data) try observed.data(event.data.data);
                if (event == .finished) break;
            }
        },
    }
    try std.testing.expectEqual([2]?anyerror{ null, null }, observed.errors);
    const expected = window.default_value - @as(i64, if (content) 2 else 0);
    if (connection.recv_connection_window.value != expected) {
        std.debug.print("{s} content={any} head={any} retained padding credit: window={d}\n", .{ @tagName(mode), content, head, connection.recv_connection_window.value });
        return error.PaddingCreditRetained;
    }
    try connection.stream.shutdown(io, .send);
    const frame_io = @import("../frame/io.zig");
    var reader: frame_io.Reader = .{};
    defer reader.deinit(allocator);
    var connection_credit: usize = 0;
    var stream_credit: usize = 0;
    while (true) {
        const frame = reader.read(allocator, io, peer, 16_384) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (frame.frame.header.frame_type == .window_update) {
            const update = try http2.WindowUpdatePayload.parse(frame.frame);
            if (update.stream_id == 0) connection_credit += update.increment else {
                try std.testing.expectEqual(@as(u31, 1), update.stream_id);
                stream_credit += update.increment;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 8), connection_credit);
    try std.testing.expectEqual(@as(usize, 5), stream_credit);
}
