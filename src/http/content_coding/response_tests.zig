const std = @import("std");
const http1 = @import("../../http1/mod.zig");
const http2 = @import("../../http2/mod.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const http3 = @import("../../http3/mod.zig");

pub fn expectEmpty(response: anytype) !void {
    var decoded = try response.decodeContentAlloc(std.testing.allocator, 0);
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("", decoded.bytes);
    try std.testing.expect(decoded.owned == null);
    var empty: [0]u8 = .{};
    try std.testing.expectEqualStrings("", try response.decodeContentInto(&empty, &empty));
    // The representation metadata remains available to cache/validator users.
    const encoding = try response.contentEncoding();
    try std.testing.expect(encoding.encoded());
}

pub fn expectEmptyStream(head: anytype) !void {
    var decoder = try head.streamContentDecoder(std.testing.allocator, .{
        .max_encoded_bytes = 0,
        .max_decoded_bytes = 0,
    });
    defer decoder.deinit();
    const result = try decoder.finish(&.{});
    try std.testing.expect(result.status == .done);
    try std.testing.expectEqual(@as(usize, 0), result.output_written);
}

test "HTTP content decoding treats HTTP1 HEAD and 304 fields as metadata" {
    const allocator = std.testing.allocator;
    for ([_]struct { status: u16, method: http1.Method }{
        .{ .status = 200, .method = .HEAD },
        .{ .status = 304, .method = .GET },
    }) |case| {
        var storage: [256]u8 = undefined;
        const wire = try std.fmt.bufPrint(
            &storage,
            "HTTP/1.1 {d} Metadata\r\nContent-Encoding: gzip\r\nContent-Length: 123\r\n\r\n",
            .{case.status},
        );
        var response = try http1.parseResponseForRequest(allocator, wire, .{}, case.method);
        defer response.deinit(allocator);
        try expectEmpty(response);
        var headers: [4]http1.Header = undefined;
        const head = try http1.parseResponseHead(wire, &headers, .{}, .{ .request_method = case.method });
        try expectEmptyStream(head);
    }
}

test "HTTP content decoding treats HTTP2 304 fields as metadata" {
    var headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "304" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "content-length", .value = "123" },
    };
    var body: [0]u8 = .{};
    const response = http2_runtime.OwnedResponse{
        .status = 304,
        .headers = &headers,
        .body = &body,
    };
    try expectEmpty(response);
}

test "HTTP content decoding treats HTTP3 HEAD and 304 fields as metadata" {
    const allocator = std.testing.allocator;
    for ([_]struct { status: u16, method: []const u8 }{
        .{ .status = 200, .method = "HEAD" },
        .{ .status = 304, .method = "GET" },
    }) |case| {
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(allocator);
        try (http3.Response{
            .status = case.status,
            .request_method = case.method,
            .headers = &.{
                .{ .name = "content-encoding", .value = "gzip" },
                .{ .name = "content-length", .value = "123" },
            },
        }).write(&wire, allocator);
        var response = try http3.decodeResponseWithOptions(allocator, wire.items, .{
            .request_method = case.method,
        });
        defer response.deinit(allocator);
        try expectEmpty(response);
        var table = http3.Qpack.DynamicTable.init(allocator, 0);
        defer table.deinit();
        var head = try http3.decodeResponseHeadWithDynamicTableAndOptions(allocator, wire.items, .{}, table, .{
            .request_method = case.method,
        });
        defer head.deinit(allocator);
        try expectEmptyStream(head);
    }
}

test "HTTP content decoding still rejects an empty encoded GET representation" {
    const allocator = std.testing.allocator;
    var h1 = try http1.parseResponseForRequest(
        allocator,
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
        .{},
        .GET,
    );
    defer h1.deinit(allocator);
    try std.testing.expectError(error.InvalidContentEncoding, h1.decodeContentAlloc(allocator, 1024));

    var headers = [_]http2.Hpack.HeaderField{.{ .name = "content-encoding", .value = "gzip" }};
    var body: [0]u8 = .{};
    const h2 = http2_runtime.OwnedResponse{ .status = 200, .headers = &headers, .body = &body };
    try std.testing.expectError(error.InvalidContentEncoding, h2.decodeContentAlloc(allocator, 1024));

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .headers = &.{.{ .name = "content-encoding", .value = "gzip" }},
    }).write(&wire, allocator);
    var h3 = try http3.decodeResponseWithOptions(allocator, wire.items, .{ .request_method = "GET" });
    defer h3.deinit(allocator);
    try std.testing.expectError(error.InvalidContentEncoding, h3.decodeContentAlloc(allocator, 1024));
}
