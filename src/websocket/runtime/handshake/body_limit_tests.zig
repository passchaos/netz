const std = @import("std");
const receive = @import("receive.zig");
const runtime = @import("../../runtime.zig");
const http1 = @import("../../../http1/mod.zig");

const Source = struct {
    calls: usize = 0,
    bytes: []const u8 = "",
    offset: usize = 0,

    pub const TransportType = *Source;
    pub const ErrorType = runtime.Error;

    pub fn read(self: *Source, output: []u8) ErrorType!usize {
        self.calls += 1;
        const count = @min(output.len, self.bytes.len - self.offset);
        @memcpy(output[0..count], self.bytes[self.offset..][0..count]);
        self.offset += count;
        return count;
    }

    pub fn readWithDeadline(self: *Source, output: []u8, _: std.Io.Clock.Timestamp) ErrorType!usize {
        return self.read(output);
    }
};

test "WebSocket rejected body limit precedes copying known excessive entities" {
    const allocator = std.testing.allocator;
    const cases = .{
        .{ "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n", "hello" },
        .{ "HTTP/1.1 401 Unauthorized\r\nContent-Length: 5\r\n\r\n", "" },
        .{ "HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n", "5\r\n" },
        .{ "HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: gzip\r\nContent-Length: 1\r\n\r\n", "hello" },
    };
    inline for (cases) |case| {
        var head = receive.Head{ .head = try allocator.dupe(u8, case[0]), .extra = try allocator.dupe(u8, case[1]) };
        defer head.deinit(allocator);
        var source: Source = .{};
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.BodyTooLarge, receive.Reader(Source).readResponseBytes(failing.allocator(), &source, &head, .{ .max_response_headers = 16, .max_rejection_body_bytes = 4 }, null));
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 0), source.calls);
        try std.testing.expectEqualStrings(case[0], head.head);
        try std.testing.expectEqualStrings(case[1], head.extra);
    }
}

test "WebSocket rejected body retention discards complete-response successors" {
    const allocator = std.testing.allocator;
    const cases = .{
        .{ "HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\n\r\n", "nope", @as(usize, 4), "nope" },
        .{ "HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n", "4\r\nnope\r\n0\r\nX-End: yes\r\n\r\n", @as(usize, 4), "nope" },
        .{ "HTTP/1.1 304 Not Modified\r\nContent-Length: 999\r\n\r\n", "", @as(usize, 0), "" },
    };
    inline for (cases) |case| {
        var extra: std.ArrayList(u8) = .empty;
        defer extra.deinit(allocator);
        try extra.appendSlice(allocator, case[1]);
        try extra.appendSlice(allocator, "discarded successor bytes");
        var head = receive.Head{ .head = try allocator.dupe(u8, case[0]), .extra = try extra.toOwnedSlice(allocator) };
        defer head.deinit(allocator);
        var source: Source = .{};
        const result = try receive.Reader(Source).readResponseBytes(allocator, &source, &head, .{ .max_response_headers = 16, .max_rejection_body_bytes = case[2] }, null);
        defer allocator.free(result.bytes);
        try std.testing.expect(result.extra == null);
        try std.testing.expectEqual(@as(usize, 0), source.calls);
        try std.testing.expectEqualStrings(case[0] ++ case[1], result.bytes);
        var response = try http1.parseResponse(allocator, result.bytes, .{});
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings(case[3], response.body);
        if (response.body_framing == .chunked) {
            try std.testing.expectEqual(@as(usize, 1), response.trailers.len);
            try std.testing.expectEqualStrings("yes", response.trailers[0].value);
        }
    }
}

test "WebSocket accepted 101 preserves coalesced frames with zero rejection limit" {
    const allocator = std.testing.allocator;
    var head = receive.Head{
        .head = try allocator.dupe(u8, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"),
        .extra = try allocator.dupe(u8, "\x82\x02ok"),
    };
    var owned = true;
    defer if (owned) head.deinit(allocator);
    const head_pointer = head.head.ptr;
    const frame_pointer = head.extra.ptr;
    var source: Source = .{};
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const result = try receive.Reader(Source).readResponseBytes(failing.allocator(), &source, &head, .{ .max_response_headers = 16, .max_rejection_body_bytes = 0 }, null);
    owned = false;
    defer allocator.free(result.bytes);
    defer allocator.free(result.extra.?);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(head_pointer, result.bytes.ptr);
    try std.testing.expectEqual(frame_pointer, result.extra.?.ptr);
    try std.testing.expectEqualStrings("\x82\x02ok", result.extra.?);
    try std.testing.expectEqual(@as(usize, 0), source.calls);
}

test "WebSocket EOF rejection preserves exact and zero body limits" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "", "nope" }) |body| {
        var head = receive.Head{ .head = try allocator.dupe(u8, "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n"), .extra = try allocator.dupe(u8, "") };
        defer head.deinit(allocator);
        var source = Source{ .bytes = body };
        const result = try receive.Reader(Source).readResponseBytes(allocator, &source, &head, .{ .max_response_headers = 16, .max_rejection_body_bytes = body.len }, null);
        defer allocator.free(result.bytes);
        try std.testing.expectEqualStrings(body, result.bytes[head.head.len..]);
        try std.testing.expectEqual(body.len, source.offset);
    }
}
