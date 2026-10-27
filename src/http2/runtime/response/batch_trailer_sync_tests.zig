const std = @import("std");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const wire = @import("../frame/wire.zig");
const frame_io = @import("../frame/io.zig");
const allocator = std.testing.allocator;

pub const Mode = enum { aggregate, streaming, body, body_streaming, independent, independent_streaming, independent_body, independent_body_streaming };
const Kind = enum { head, no_content, not_modified, ordinary };

pub const Observer = struct {
    errors: [2]?anyerror = .{ null, null },
    results: [2]usize = .{ 0, 0 },
    delivered: usize = 0,

    fn data(self: *@This(), _: usize, bytes: []const u8) !void {
        self.delivered += bytes.len;
    }
    fn dataOpaque(context: *anyopaque, index: usize, bytes: []const u8) !void {
        try (@as(*@This(), @ptrCast(@alignCast(context)))).data(index, bytes);
    }
    fn owned(context: *anyopaque, index: usize, result: runtime.BatchOwnedResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.results[index] += 1;
        switch (result) {
            .err => |err| self.errors[index] = err,
            .response => |value| {
                var response = value;
                defer response.deinit(allocator);
                if (index == 1) self.checkSibling(response.headers);
            },
        }
    }
    fn streaming(context: *anyopaque, index: usize, result: runtime.BatchStreamingResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.results[index] += 1;
        switch (result) {
            .err => |err| self.errors[index] = err,
            .response => |value| {
                var response = value;
                defer response.deinit(allocator);
                if (index == 1) self.checkSibling(response.headers);
            },
        }
    }
    fn checkSibling(self: *@This(), fields: []const http2.Hpack.HeaderField) void {
        std.testing.expectEqualStrings("y", runtime.testing.findHeader(fields, "x") orelse "") catch |err| {
            self.errors[1] = err;
        };
    }
};

test "HTTP/2 batch forbidden trailers preserve HPACK for healthy sibling and later response" {
    for (std.enums.values(Mode)) |mode| {
        for (std.enums.values(Kind)) |kind| {
            for ([_]bool{ false, true }) |fragmented| {
                for ([_]bool{ false, true }) |ended| {
                    if (kind == .ordinary and ended) continue;
                    try exercise(mode, kind, fragmented, ended, false, true);
                }
            }
        }
    }
}

test "HTTP/2 batch forbidden trailers keep TCP decode order and reset codes" {
    for (std.enums.values(Mode)) |mode| {
        for (std.enums.values(Kind)) |kind| try exercise(mode, kind, true, kind != .ordinary, true, true);
    }
}

test "HTTP/2 batch forbidden trailers synchronize unbounded readers" {
    for (std.enums.values(Mode)) |mode| try exercise(mode, .head, true, true, false, false);
}

fn exercise(mode: Mode, kind: Kind, fragmented: bool, ended: bool, from_socket: bool, bounded: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    // Give reset writes room to finish before checking HPACK synchronization,
    // exact reset codes, and reuse across all aggregate/streaming batch modes.
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .limits = .{ .terminal_cleanup_timeout = .fromSeconds(1) } };
    defer connection.close();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = ":status", .value = switch (kind) {
        .head, .ordinary => "200",
        .no_content => "204",
        .not_modified => "304",
    } }});
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, block.items);
    const trailer = "\x40\x01x\x01y";
    const flags: u8 = @as(u8, if (ended) 1 else 0) | @as(u8, if (fragmented) 0 else 4);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, flags, 1, if (fragmented) trailer[0..2] else trailer);
    if (fragmented) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 4, 1, trailer[2..]);
    const independent = switch (mode) {
        .independent, .independent_streaming, .independent_body, .independent_body_streaming => true,
        else => false,
    };
    if (independent) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 3, "\x88\xbe");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 5, "\x88\xbe");
    if (from_socket) {
        const bytes = try connection.frame_reader.buffer.toOwnedSlice(allocator);
        defer allocator.free(bytes);
        var writer = peer.writer(io, &.{});
        try writer.interface.writeAll(bytes);
        try peer.shutdown(io, .send);
    }
    const with_body = switch (mode) {
        .body, .body_streaming, .independent_body, .independent_body_streaming => true,
        else => false,
    };
    const requests = [_]runtime.RequestOptions{
        .{ .method = if (kind == .head) "HEAD" else "GET", .authority = "localhost", .body = if (with_body) "a" else "" },
        .{ .authority = "localhost", .body = if (with_body) "b" else "" },
    };
    var observer: Observer = .{};
    const expected = if (kind == .ordinary) error.UnexpectedFrame else error.InvalidContentLength;
    const result = readBatch(&connection, mode, &requests, &observer, bounded);
    if (independent) try result else try std.testing.expectError(expected, result);
    if (independent) {
        try std.testing.expectEqual([2]usize{ 1, 1 }, observer.results);
        try std.testing.expectEqual(@as(?anyerror, expected), observer.errors[0]);
        try std.testing.expectEqual(@as(?anyerror, null), observer.errors[1]);
    }
    try std.testing.expectEqual(@as(usize, 0), observer.delivered);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    var healthy = try connection.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(1));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("y", runtime.testing.findHeader(healthy.headers, "x").?);
    try connection.stream.shutdown(io, .send);
    var reader: frame_io.Reader = .{};
    defer reader.deinit(allocator);
    var resets: [2]usize = .{ 0, 0 };
    while (true) {
        const incoming = reader.read(allocator, io, peer, 16_384) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (incoming.frame.header.frame_type == .rst_stream) {
            const reset = try http2.ResetStreamPayload.parse(incoming.frame);
            try std.testing.expect(reset.stream_id == 1 or reset.stream_id == 3);
            const index: usize = if (reset.stream_id == 1) 0 else 1;
            resets[index] += 1;
            try std.testing.expectEqual(if (index == 0) http2.ErrorCode.protocol_error else http2.ErrorCode.cancel, reset.error_code);
        }
    }
    try std.testing.expectEqual([2]usize{ 1, if (independent) 0 else 1 }, resets);
}

pub fn readBatch(connection: *runtime.Connection, mode: Mode, requests: []const runtime.RequestOptions, observer: *Observer, bounded: bool) !void {
    const deadline: ?std.Io.Clock.Timestamp = if (bounded) .fromNow(connection.io, .{ .raw = .fromSeconds(1), .clock = .awake }) else null;
    switch (mode) {
        .aggregate, .body => {
            var responses: [2]runtime.OwnedResponse = undefined;
            const result = if (mode == .body)
                (if (bounded) connection.requestBodyBatchIntoWithTimeout(requests, 1, &responses, .fromSeconds(1)) else connection.requestBodyBatchInto(requests, 1, &responses))
            else
                (if (bounded) connection.requestBatchIntoWithTimeout(requests, &responses, .fromSeconds(1)) else connection.requestBatchInto(requests, &responses));
            try result;
            for (&responses) |*response| response.deinit(connection.allocator);
        },
        .streaming, .body_streaming => {
            var responses: [2]runtime.StreamingResponse = undefined;
            const result = if (mode == .body_streaming)
                (if (bounded) connection.requestBodyBatchStreamingIntoWithTimeout(requests, 1, &responses, .fromSeconds(1), observer, Observer.data) else connection.requestBodyBatchStreamingInto(requests, 1, &responses, observer, Observer.data))
            else
                (if (bounded) connection.requestBatchStreamingIntoWithTimeout(requests, &responses, .fromSeconds(1), observer, Observer.data) else connection.requestBatchStreamingInto(requests, &responses, observer, Observer.data));
            try result;
            for (&responses) |*response| response.deinit(connection.allocator);
        },
        .independent => try connection.requestBatchWithPerStreamDeadlines(requests, &.{ deadline, deadline }, .{ .context = observer, .on_result = Observer.owned }),
        .independent_body => try connection.requestBodyBatchWithPerStreamDeadlines(requests, 1, &.{ deadline, deadline }, .{ .context = observer, .on_result = Observer.owned }),
        .independent_streaming => try connection.requestBatchStreamingWithPerStreamDeadlines(requests, &.{ deadline, deadline }, .{ .context = observer, .on_data = Observer.dataOpaque, .on_result = Observer.streaming }),
        .independent_body_streaming => try connection.requestBodyBatchStreamingWithPerStreamDeadlines(requests, 1, &.{ deadline, deadline }, .{ .context = observer, .on_data = Observer.dataOpaque, .on_result = Observer.streaming }),
    }
}
