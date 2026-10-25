//! A malformed scheduling hint must not invalidate an otherwise valid message.
const std = @import("std");
const http3 = @import("mod.zig");
const allocator = std.testing.allocator;

fn findPriority(fields: []const http3.Qpack.HeaderField) []const u8 {
    for (fields) |field| if (std.mem.eql(u8, field.name, "priority")) return field.value;
    unreachable;
}

test "HTTP/3 malformed Priority metadata remains available across request response and trailers" {
    const invalid = [_]http3.Qpack.HeaderField{.{ .name = "priority", .value = "u=0, custom=\"unterminated" }};
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const outgoing = http3.Request{ .method = "POST", .path = "/priority", .authority = "example.test", .headers = &invalid, .body = "abc", .trailers = &invalid };
    try outgoing.validateForContext(.direct);
    try outgoing.validateForContext(.proxy);
    try outgoing.write(&encoded, allocator);
    var request = try http3.decodeRequest(allocator, encoded.items);
    defer request.deinit(allocator);
    try std.testing.expectEqualStrings("abc", request.body);
    try std.testing.expectEqualStrings(invalid[0].value, findPriority(request.headers));
    try std.testing.expectEqualStrings(invalid[0].value, request.trailers[0].value);
    encoded.clearRetainingCapacity();
    try (http3.Response{ .status = 200, .headers = &invalid, .body = "ok", .trailers = &invalid }).write(&encoded, allocator);
    var response = try http3.decodeResponse(allocator, encoded.items);
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqualStrings(invalid[0].value, findPriority(response.headers));
    try std.testing.expectEqualStrings(invalid[0].value, response.trailers[0].value);
}

test "HTTP/3 Priority metadata still enforces HTTP field and content-length validity" {
    for ([_][]const u8{ "u=0\r\nx=1", "u=0\x00", " leading", "trailing " }) |value| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try std.testing.expectError(error.InvalidHeader, (http3.Request{ .method = "GET", .path = "/invalid", .authority = "example.test", .headers = &.{.{ .name = "priority", .value = value }} }).write(&encoded, allocator));
        try std.testing.expectError(error.InvalidHeader, (http3.Response{ .status = 200, .headers = &.{.{ .name = "priority", .value = value }} }).write(&encoded, allocator));
    }
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try std.testing.expectError(error.InvalidContentLength, (http3.Request{ .method = "POST", .path = "/invalid", .authority = "example.test", .body = "abc", .headers = &.{ .{ .name = "priority", .value = "u=0," }, .{ .name = "content-length", .value = "4" } } }).write(&encoded, allocator));
}
