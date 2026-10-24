const std = @import("std");
const http2 = @import("../http2/mod.zig");
const h2_message = @import("../http2/runtime/headers/message.zig");
const http3 = @import("../http3/mod.zig");
const values = @import("field_value.zig");
const allocator = std.testing.allocator;
const invalid_values = [_][]const u8{ " leading", "trailing ", "\tleading", "trailing\t", " ", "\t" };

test "HTTP/2 field value rejects surrounding whitespace in every message block" {
    for (invalid_values) |value| {
        const request = [_]http2.Hpack.HeaderField{
            .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },     .{ .name = "x-test", .value = value },
        };
        try std.testing.expectError(error.InvalidHeader, h2_message.validateHeaderBlock(&request, .request));
        try std.testing.expectError(error.InvalidHeader, h2_message.validateHeaderBlock(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "x-test", .value = value } }, .response));
        for ([_]h2_message.HeaderBlockKind{ .request_trailers, .response_trailers }) |kind| try std.testing.expectError(error.InvalidHeader, h2_message.validateHeaderBlock(&.{.{ .name = "x-test", .value = value }}, kind));
    }
}

test "HTTP/3 field value rejects surrounding whitespace before message output" {
    for (invalid_values) |value| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try bytes.append(allocator, 0xa5);
        const fields = [_]http3.Qpack.HeaderField{.{ .name = "x-test", .value = value }};
        try std.testing.expectError(error.InvalidHeader, (http3.Request{ .method = "GET", .path = "/", .authority = "localhost", .headers = &fields }).write(&bytes, allocator));
        try std.testing.expectEqualSlices(u8, &.{0xa5}, bytes.items);
        try std.testing.expectError(error.InvalidHeader, (http3.Response{ .status = 200, .headers = &fields }).write(&bytes, allocator));
        try std.testing.expectEqualSlices(u8, &.{0xa5}, bytes.items);
        try std.testing.expectError(error.InvalidHeader, (http3.Request{ .method = "POST", .path = "/", .authority = "localhost", .trailers = &fields }).write(&bytes, allocator));
        try std.testing.expectEqualSlices(u8, &.{0xa5}, bytes.items);
        try std.testing.expectError(error.InvalidHeader, (http3.Response{ .status = 200, .trailers = &fields }).write(&bytes, allocator));
        try std.testing.expectEqualSlices(u8, &.{0xa5}, bytes.items);
    }
}

test "HTTP field value preserves empty interior whitespace and opaque non-ASCII bytes" {
    for ([_][]const u8{ "", "one two", "one\ttwo", "\x80one\xff" }) |value| {
        try values.validate(value);
        try h2_message.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },     .{ .name = "x-test", .value = value },
        }, .request);
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try (http3.Request{ .method = "GET", .path = "/", .authority = "localhost", .headers = &.{.{ .name = "x-test", .value = value }} }).write(&bytes, allocator);
        try std.testing.expect(bytes.items.len != 0);
    }
    for ([_][]const u8{ "a\x00b", "a\rb", "a\nb", "a\x7fb" }) |value| try std.testing.expectError(error.InvalidHeader, values.validate(value));
}
