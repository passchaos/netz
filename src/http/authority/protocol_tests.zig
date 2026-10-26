const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const h2_headers = @import("../../http2/runtime/headers/message.zig");
const http3 = @import("../../http3/mod.zig");

const Case = struct { scheme: []const u8 = "https", authority: []const u8, host: []const u8 };
const valid = [_]Case{
    .{ .authority = "Example.test", .host = "example.test:443" },
    .{ .scheme = "HTTP", .authority = "example.test:", .host = "example.test:00080" },
    .{ .authority = "%65xample.test", .host = "example.test:443" },
    .{ .authority = "[2001:DB8::1]", .host = "[2001:db8:0:0:0:0:0:1]:443" },
    .{ .authority = "[::ffff:192.0.2.1]", .host = "[::ffff:c000:201]:443" },
    .{ .authority = "a%2Bb.test", .host = "a%2bb.test:443" },
};
const invalid = [_]Case{
    .{ .authority = "example.test", .host = "example.test:80" },
    .{ .authority = "example.test", .host = "other.test:443" },
    .{ .authority = "[::1]", .host = "[::2]:443" },
    .{ .authority = "[invalid]", .host = "[invalid]" },
    .{ .authority = "[1::2::3]", .host = "[1::2::3]" },
    .{ .authority = "bad%GG.test", .host = "bad%GG.test" },
    .{ .authority = "a%2Bb.test", .host = "a+b.test:443" },
};

test "HTTP authority HTTP2 and HTTP3 agree on equivalent request routing" {
    const allocator = std.testing.allocator;
    for (valid) |case| {
        try h2_headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" },       .{ .name = ":scheme", .value = case.scheme },
            .{ .name = ":path", .value = "/normalized" }, .{ .name = ":authority", .value = case.authority },
            .{ .name = "host", .value = case.host },
        }, .request);
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try (http3.Request{ .method = "GET", .scheme = case.scheme, .path = "/normalized", .authority = case.authority, .headers = &.{.{ .name = "host", .value = case.host }} }).write(&bytes, allocator);
        var decoded = try http3.decodeRequest(allocator, bytes.items);
        defer decoded.deinit(allocator);
        try std.testing.expectEqualStrings(case.authority, decoded.authority.?);
        try std.testing.expectEqualStrings(case.scheme, decoded.scheme);
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(allocator);
        try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":method", .value = "GET" },       .{ .name = ":scheme", .value = case.scheme },
            .{ .name = ":path", .value = "/normalized" }, .{ .name = ":authority", .value = case.authority },
            .{ .name = "host", .value = case.host },
        });
        var table = http3.Qpack.DynamicTable.init(allocator, 0);
        defer table.deinit();
        var head = try http3.decodeRequestHeadFieldSectionWithDynamicTable(allocator, block.items, .{}, table);
        defer head.deinit(allocator);
        try std.testing.expectEqualStrings(case.authority, head.authority.?);
    }
}

test "HTTP authority HTTP2 and HTTP3 reject invalid or different routing targets" {
    const allocator = std.testing.allocator;
    for (invalid) |case| {
        try std.testing.expectError(error.InvalidHeader, h2_headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" },    .{ .name = ":scheme", .value = case.scheme },
            .{ .name = ":path", .value = "/invalid" }, .{ .name = ":authority", .value = case.authority },
            .{ .name = "host", .value = case.host },
        }, .request));
        try std.testing.expectError(error.InvalidHeader, (http3.Request{ .method = "GET", .scheme = case.scheme, .path = "/invalid", .authority = case.authority, .headers = &.{.{ .name = "host", .value = case.host }} }).validateForContext(.direct));
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(allocator);
        try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":method", .value = "GET" },    .{ .name = ":scheme", .value = case.scheme },
            .{ .name = ":path", .value = "/invalid" }, .{ .name = ":authority", .value = case.authority },
            .{ .name = "host", .value = case.host },
        });
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, allocator);
        try std.testing.expectError(error.InvalidHeader, http3.decodeRequest(allocator, bytes.items));
        var table = http3.Qpack.DynamicTable.init(allocator, 0);
        defer table.deinit();
        try std.testing.expectError(error.InvalidHeader, http3.decodeRequestHeadFieldSectionWithDynamicTable(allocator, block.items, .{}, table));
    }
}

test "HTTP authority HTTP3 classic CONNECT validates Host without a default port" {
    for ([_][]const u8{ "example.test", "other.test:443", "example.test:", "[invalid]:443" }) |host| {
        try std.testing.expectError(error.InvalidHeader, (http3.Request{ .method = "CONNECT", .path = "", .authority = "example.test:443", .headers = &.{.{ .name = "host", .value = host }} }).validateForContext(.direct));
    }
    try (http3.Request{ .method = "CONNECT", .path = "", .authority = "[::1]:443", .headers = &.{.{ .name = "host", .value = "[0:0:0:0:0:0:0:1]:00443" }} }).validateForContext(.direct);
}
