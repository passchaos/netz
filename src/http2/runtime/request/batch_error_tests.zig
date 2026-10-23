const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");

const Mode = enum {
    bad_head,
    head_length,
    header_limit,
    trailer_length,
    bad_trailer,
    trailer_no_end,
    hpack,
    trailer_hpack,
    sequence,
    stray_continuation,
    continuation_limit,
    callback_protocol,
    callback_timeout,
    extra_request,
    connect,
    closed_headers,
    closed_data,

    fn connection(self: Mode) bool {
        return switch (self) {
            .hpack, .trailer_hpack, .sequence, .stray_continuation, .continuation_limit => true,
            else => false,
        };
    }

    fn callback(self: Mode) bool {
        return self == .callback_protocol or self == .callback_timeout;
    }

    fn errorValue(self: Mode) anyerror {
        return switch (self) {
            .bad_head, .bad_trailer, .connect => error.InvalidHeader,
            .head_length, .trailer_length, .callback_protocol => error.InvalidContentLength,
            .header_limit, .continuation_limit => error.MessageTooLarge,
            .hpack, .trailer_hpack => error.InvalidEncoding,
            .callback_timeout => error.Timeout,
            else => error.UnexpectedFrame,
        };
    }

    fn stream(self: Mode) u31 {
        return switch (self) {
            .bad_head, .head_length, .header_limit, .connect => 3,
            .extra_request => 5,
            else => 1,
        };
    }

    fn code(self: Mode) http2.ErrorCode {
        return switch (self) {
            .header_limit, .continuation_limit => .enhance_your_calm,
            .hpack, .trailer_hpack => .compression_error,
            .callback_protocol, .callback_timeout => .cancel,
            .extra_request, .connect => .refused_stream,
            .closed_headers, .closed_data => .stream_closed,
            else => .protocol_error,
        };
    }
};

test "HTTP/2 server batch classifies malformed request heads" {
    try exercise(.bad_head);
    try exercise(.head_length);
    try exercise(.header_limit);
}

test "HTTP/2 server batch classifies malformed trailers and preserves HPACK" {
    try exercise(.trailer_length);
    try exercise(.bad_trailer);
    try exercise(.trailer_no_end);
}

test "HTTP/2 server batch emits one compression GOAWAY before stream cleanup" {
    try exercise(.hpack);
    try exercise(.trailer_hpack);
}

test "HTTP/2 server batch emits one GOAWAY for broken CONTINUATION" {
    try exercise(.sequence);
    try exercise(.stray_continuation);
    try exercise(.continuation_limit);
}

test "HTTP/2 server batch preserves callback rejection wire policy" {
    try exercise(.callback_protocol);
    try exercise(.callback_timeout);
}

test "HTTP/2 server batch refuses valid requests beyond its API capacity" {
    try exercise(.extra_request);
    try exercise(.connect);
}

test "HTTP/2 server batch rejects closed request frames with synchronized HPACK and credit" {
    try exercise(.closed_headers);
    try exercise(.closed_data);
}

fn exercise(mode: Mode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_header_fields = if (mode == .header_limit) 4 else 100,
        .max_continuation_frames = if (mode == .continuation_limit) 1 else null,
    });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        mode: Mode,
        calls: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn consume(self: *@This(), _: u31, _: []const u8) !void {
            self.calls += 1;
            if (self.mode.callback()) return self.mode.errorValue();
            return error.TestUnexpectedResult;
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            const before = connection.recv_connection_window.value;
            var requests: [2]runtime.StreamingRequest = undefined;
            try std.testing.expectError(self.mode.errorValue(), connection.readRequestBatchStreamingIntoWithTimeout(
                &requests,
                .fromSeconds(2),
                self,
                @This().consume,
            ));
            try std.testing.expectEqual(@as(usize, if (self.mode.callback()) 1 else 0), self.calls);
            try std.testing.expectEqual(before, connection.recv_connection_window.value);
            if (self.mode.connection()) {
                try std.testing.expect(connection.aggregate_timeout_unusable);
                try std.testing.expect(connection.local_goaway_last_stream_id != null);
                return;
            }
            try std.testing.expect(!connection.aggregate_timeout_unusable);
            try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
            try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/healthy", next.path);
            try std.testing.expectEqualStrings("localhost", next.authority.?);
            try connection.writeResponse(next.stream_id, .{ .body = "healthy" });
        }
    };
    var peer = Peer{ .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(allocator);
    const first_extra: []const http2.Hpack.HeaderField = if (mode == .trailer_length) &.{.{ .name = "content-length", .value = "2" }} else &.{};
    try appendHead(&client, &frames, 1, if (mode == .closed_headers or mode == .closed_data) 0x05 else 0x04, first_extra);
    switch (mode) {
        .hpack => try wire.appendFrame(&frames, allocator, .headers, 0x04, 3, "\x80"),
        .sequence, .continuation_limit => {
            try wire.appendFrame(&frames, allocator, .headers, 0, 3, "\x82");
            if (mode == .sequence) {
                try wire.appendFrame(&frames, allocator, .data, 0, 3, "a");
            } else {
                try wire.appendFrame(&frames, allocator, .continuation, 0, 3, &.{});
                try wire.appendFrame(&frames, allocator, .continuation, 0, 3, &.{});
            }
        },
        .connect => {
            const block = try client.hpack_encoder.encodeBlockRetained(allocator, &.{
                .{ .name = ":method", .value = "CONNECT" }, .{ .name = ":authority", .value = "localhost:443" },
            });
            try wire.appendFrame(&frames, allocator, .headers, 0x04, 3, block);
        },
        else => {
            const extra: []const http2.Hpack.HeaderField = switch (mode) {
                .bad_head => &.{.{ .name = "connection", .value = "close" }},
                .head_length => &.{.{ .name = "content-length", .value = "1" }},
                .header_limit => &.{.{ .name = "x-dictionary", .value = "preserved" }},
                else => &.{},
            };
            const ended = switch (mode) {
                .head_length, .trailer_length, .bad_trailer, .trailer_no_end, .trailer_hpack => true,
                else => false,
            };
            try appendHead(&client, &frames, 3, if (ended) 0x05 else 0x04, extra);
            switch (mode) {
                .trailer_length, .bad_trailer, .trailer_no_end, .closed_headers => {
                    const fields: []const http2.Hpack.HeaderField = if (mode == .bad_trailer) &.{.{ .name = "content-length", .value = "0" }} else &.{.{ .name = "x-dictionary", .value = "preserved" }};
                    const block = try client.hpack_encoder.encodeBlockRetained(allocator, fields);
                    try wire.appendFrame(&frames, allocator, .headers, if (mode == .trailer_no_end) 0x04 else 0x05, 1, block);
                },
                .trailer_hpack => try wire.appendFrame(&frames, allocator, .headers, 0x04, 1, "\x80"),
                .stray_continuation => try wire.appendFrame(&frames, allocator, .continuation, 0x04, 1, "\x82"),
                .extra_request => try appendHead(&client, &frames, 5, 0x04, &.{}),
                .callback_protocol, .callback_timeout => {
                    try client.send_connection_window.reserve(4);
                    try wire.appendFrame(&frames, allocator, .data, 0x08, 1, "\x02a\x00\x00");
                },
                .closed_data => {
                    try client.send_connection_window.reserve(1);
                    try wire.appendFrame(&frames, allocator, .data, 0, 1, "a");
                },
                else => {},
            }
        },
    }
    var writer = client.stream.writer(io, &.{});
    try writer.interface.writeAll(frames.items);
    client.next_client_stream_id = if (mode == .extra_request) 7 else 5;
    if (mode.connection()) {
        var goaway = try client.readGoAwayWithTimeout(.fromSeconds(3));
        defer goaway.deinit(allocator);
        try std.testing.expectEqual(mode.code(), goaway.goaway.error_code);
        try std.testing.expect(!client.isReusable());
        try std.testing.expectError(error.ConnectionClosed, client.readGoAwayWithTimeout(.fromSeconds(1)));
    } else {
        var failure = try client.readResetStreamWithTimeout(.fromSeconds(3));
        defer failure.deinit(allocator);
        try std.testing.expectEqual(mode.stream(), failure.reset.stream_id);
        try std.testing.expectEqual(mode.code(), failure.reset.error_code);
        for ([_]u31{ 1, 3 }) |id| {
            if (id == mode.stream()) continue;
            var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
            defer reset.deinit(allocator);
            try std.testing.expectEqual(id, reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);
        }
        try std.testing.expectEqual(@as(i64, 65_535), client.send_connection_window.value);
        var healthy = try client.requestWithTimeout(.{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(2));
        defer healthy.deinit(allocator);
        try std.testing.expectEqualStrings("healthy", healthy.body);
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn appendHead(client: *runtime.Connection, frames: *std.ArrayList(u8), id: u31, flags: u8, extra: []const http2.Hpack.HeaderField) !void {
    var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer fields.deinit(std.testing.allocator);
    try fields.appendSlice(std.testing.allocator, &.{
        .{ .name = ":method", .value = "POST" },         .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/batch" },
    });
    try fields.appendSlice(std.testing.allocator, extra);
    const block = try client.hpack_encoder.encodeBlockRetained(std.testing.allocator, fields.items);
    try wire.appendFrame(frames, std.testing.allocator, .headers, flags, id, block);
}
