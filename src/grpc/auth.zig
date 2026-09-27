//! Allocation-free helpers for gRPC HTTP authentication metadata.

const std = @import("std");
const http2 = @import("../http2/mod.zig");

pub const Error = error{
    MissingAuthorization,
    DuplicateAuthorization,
    InvalidAuthorization,
};

/// Parse one RFC 6750 Bearer credential from gRPC request metadata.
///
/// The returned token borrows `headers`. The authentication scheme is
/// case-insensitive, while the token remains case-sensitive. Multiple
/// Authorization fields are rejected instead of selecting one ambiguously.
pub fn parseBearerToken(
    headers: []const http2.Hpack.HeaderField,
) Error![]const u8 {
    var authorization: ?[]const u8 = null;
    for (headers) |field| {
        if (!std.ascii.eqlIgnoreCase(field.name, "authorization")) continue;
        if (authorization != null) return error.DuplicateAuthorization;
        authorization = field.value;
    }
    const value = authorization orelse return error.MissingAuthorization;
    if (value.len <= "Bearer ".len or
        !std.ascii.eqlIgnoreCase(value[0.."Bearer".len], "Bearer") or
        value["Bearer".len] != ' ')
    {
        return error.InvalidAuthorization;
    }
    var token_start: usize = "Bearer".len;
    while (token_start < value.len and value[token_start] == ' ') {
        token_start += 1;
    }
    if (token_start == value.len) return error.InvalidAuthorization;
    const token = value[token_start..];
    var data_bytes: usize = 0;
    var padding = false;
    for (token) |byte| {
        if (byte == '=') {
            padding = true;
            continue;
        }
        if (padding or !isToken68Byte(byte)) {
            return error.InvalidAuthorization;
        }
        data_bytes += 1;
    }
    if (data_bytes == 0) return error.InvalidAuthorization;
    return token;
}

/// Validate one Bearer credential and compare its token without a
/// data-dependent early exit. Token length and metadata shape remain public.
pub fn bearerTokenMatches(
    headers: []const http2.Hpack.HeaderField,
    expected: []const u8,
) bool {
    const token = parseBearerToken(headers) catch return false;
    if (token.len != expected.len) return false;
    var difference: u8 = 0;
    for (token, expected) |actual, wanted| difference |= actual ^ wanted;
    return difference == 0;
}

fn isToken68Byte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '-' or byte == '.' or byte == '_' or byte == '~' or
        byte == '+' or byte == '/';
}

test "Bearer metadata parsing is strict and allocation free" {
    const token = try parseBearerToken(&.{.{
        .name = "authorization",
        .value = "bEaReR   abc-._~+/012==",
    }});
    try std.testing.expectEqualStrings("abc-._~+/012==", token);
    try std.testing.expect(bearerTokenMatches(&.{.{
        .name = "Authorization",
        .value = "Bearer secret-token",
    }}, "secret-token"));
    try std.testing.expect(!bearerTokenMatches(&.{.{
        .name = "authorization",
        .value = "Bearer secret-tokem",
    }}, "secret-token"));
    try std.testing.expect(!bearerTokenMatches(&.{.{
        .name = "authorization",
        .value = "Bearer short",
    }}, "long-token"));
}

test "Bearer metadata rejects absent duplicate and malformed credentials" {
    try std.testing.expectError(error.MissingAuthorization, parseBearerToken(&.{}));
    try std.testing.expectError(
        error.DuplicateAuthorization,
        parseBearerToken(&.{
            .{ .name = "authorization", .value = "Bearer one" },
            .{ .name = "Authorization", .value = "Bearer two" },
        }),
    );
    for ([_][]const u8{
        "",
        "Bearer",
        "Bearer ",
        "Bearer\ttoken",
        "Basic token",
        "Bearer token extra",
        "Bearer =",
        "Bearer ===",
        "Bearer token=middle",
        "Bearer token\r",
    }) |value| {
        try std.testing.expectError(
            error.InvalidAuthorization,
            parseBearerToken(&.{.{
                .name = "authorization",
                .value = value,
            }}),
        );
    }
}
