//! Persistence metadata must reflect HTTP message boundaries.
const std = @import("std");
const http1 = @import("mod.zig");

test "HTTP/1 EOF response metadata forbids persistent reuse" {
    const bytes = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\npayload";
    var headers: [4]http1.Header = undefined;
    const head = try http1.parseResponseHead(bytes, &headers, .{}, .{});
    try std.testing.expectEqual(http1.BodyFraming.close_delimited, head.body_framing);
    try std.testing.expect(!head.keepAlive());
    try std.testing.expect(head.must_close);
    var response = try http1.parseResponse(std.testing.allocator, bytes, .{});
    defer response.deinit(std.testing.allocator);
    try std.testing.expect(!response.keepAlive());
    try std.testing.expect(response.must_close);
    try std.testing.expectEqual(http1.BodyFraming.close_delimited, response.body_framing);
    try std.testing.expectEqualStrings("payload", response.body);
    try std.testing.expectEqual(bytes.len, response.consumed);
}

test "HTTP/1 response persistence metadata agrees across owned and borrowed parsers" {
    const cases = [_]struct { bytes: []const u8, method: http1.Method = .GET, framing: http1.BodyFraming, reusable: bool, close: bool = false, body: []const u8 = "" }{
        .{ .bytes = "HTTP/1.1 200 OK\r\n\r\npayload", .framing = .close_delimited, .reusable = false, .close = true, .body = "payload" },
        .{ .bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nConnection: keep-alive\r\n\r\npayload", .framing = .close_delimited, .reusable = false, .close = true, .body = "payload" },
        .{ .bytes = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, keep-alive\r\nUpgrade: netz-test\r\n\r\n", .framing = .none, .reusable = false, .close = true },
        .{ .bytes = "HTTP/1.1 200 Connected\r\nConnection: keep-alive\r\nContent-Length: invalid\r\n\r\n", .method = .CONNECT, .framing = .none, .reusable = false, .close = true },
        .{ .bytes = "HTTP/1.1 299 Connected\r\n\r\n", .method = .CONNECT, .framing = .none, .reusable = false, .close = true },
        .{ .bytes = "HTTP/1.1 300 Redirect\r\nContent-Length: 0\r\n\r\n", .method = .CONNECT, .framing = .content_length, .reusable = true },
        .{ .bytes = "HTTP/1.1 200 OK\r\n\r\n", .method = .HEAD, .framing = .none, .reusable = true },
        .{ .bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", .method = .HEAD, .framing = .none, .reusable = true },
        .{ .bytes = "HTTP/1.1 304 Not Modified\r\n\r\n", .framing = .none, .reusable = true },
        .{ .bytes = "HTTP/1.1 204 No Content\r\n\r\n", .framing = .none, .reusable = true },
        .{ .bytes = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload", .framing = .content_length, .reusable = true, .body = "payload" },
        .{ .bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", .framing = .chunked, .reusable = true },
        .{ .bytes = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", .framing = .content_length, .reusable = false },
    };
    for (cases) |case| {
        var headers: [4]http1.Header = undefined;
        const head = try http1.parseResponseHead(case.bytes, &headers, .{}, .{ .request_method = case.method });
        try std.testing.expectEqual(case.framing, head.body_framing);
        try std.testing.expectEqual(case.reusable, head.keepAlive());
        try std.testing.expectEqual(case.close, head.must_close);
        var owned = try http1.parseOwnedResponseHead(std.testing.allocator, case.bytes, .{}, .{ .request_method = case.method });
        defer owned.deinit(std.testing.allocator);
        try std.testing.expectEqual(case.framing, owned.head.body_framing);
        try std.testing.expectEqual(case.reusable, owned.head.keepAlive());
        try std.testing.expectEqual(case.close, owned.head.must_close);
        var response = try http1.parseResponseForRequest(std.testing.allocator, case.bytes, .{}, case.method);
        defer response.deinit(std.testing.allocator);
        try std.testing.expectEqual(case.framing, response.body_framing);
        try std.testing.expectEqual(case.reusable, response.keepAlive());
        try std.testing.expectEqual(case.close, response.must_close);
        try std.testing.expectEqualStrings(case.body, response.body);
    }
}

test "HTTP/1 response boundary consumes EOF bodies and preserves handoff suffixes" {
    const suffix = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    for ([_]http1.Method{ .GET, .HEAD, .CONNECT }) |method| {
        const head = "HTTP/1.1 200 OK\r\n\r\n";
        var response = try http1.parseResponseForRequest(std.testing.allocator, head ++ suffix, .{}, method);
        defer response.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(usize, if (method == .GET) head.len + suffix.len else head.len), response.consumed);
        try std.testing.expectEqualStrings(if (method == .GET) suffix else "", response.body);
    }
}
