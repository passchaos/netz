//! Exact Origin allowlisting shared by HTTP/1 Upgrade and RFC 8441.

const std = @import("std");
const http1 = @import("../../http1/mod.zig");
const http2 = @import("../../http2/mod.zig");

pub const Error = error{ InvalidOrigin, InvalidHandshake };

pub fn validateHttp1(
    headers: []const http1.Header,
    allowed_origins: []const []const u8,
) Error!void {
    if (allowed_origins.len == 0) return;
    var origin: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName("origin")) continue;
        if (origin != null) return error.InvalidHandshake;
        origin = header.value;
    }
    try validateValue(origin, allowed_origins);
}

pub fn validateH2(
    headers: []const http2.Hpack.HeaderField,
    allowed_origins: []const []const u8,
) Error!void {
    if (allowed_origins.len == 0) return;
    var origin: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "origin")) continue;
        if (origin != null) return error.InvalidHandshake;
        origin = header.value;
    }
    try validateValue(origin, allowed_origins);
}

fn validateValue(
    origin: ?[]const u8,
    allowed_origins: []const []const u8,
) Error!void {
    const value = origin orelse return error.InvalidOrigin;
    for (allowed_origins) |allowed| {
        // Origins are serialized, case-sensitive values. Do not normalize
        // scheme, host, port, trailing slash, or the special `null` token:
        // policy owners must opt into exactly the origins they trust.
        if (std.mem.eql(u8, value, allowed)) return;
    }
    return error.InvalidOrigin;
}

test "Origin allowlist requires one exact HTTP/1 value" {
    const headers = [_]http1.Header{
        .{ .name = "Origin", .value = "https://example.org" },
    };
    try validateHttp1(&headers, &.{"https://example.org"});
    try std.testing.expectError(
        error.InvalidOrigin,
        validateHttp1(&headers, &.{"https://other.example"}),
    );
    try std.testing.expectError(
        error.InvalidOrigin,
        validateHttp1(&.{}, &.{"https://example.org"}),
    );
    try std.testing.expectError(
        error.InvalidHandshake,
        validateHttp1(
            &.{
                .{ .name = "Origin", .value = "https://example.org" },
                .{ .name = "origin", .value = "https://example.org" },
            },
            &.{"https://example.org"},
        ),
    );
}

test "Origin allowlist applies to RFC 8441 headers" {
    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = "origin", .value = "https://example.org" },
    };
    try validateH2(&headers, &.{"https://example.org"});
    try std.testing.expectError(
        error.InvalidOrigin,
        validateH2(&headers, &.{"https://other.example"}),
    );
}
