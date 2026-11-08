//! Bounded Hysteria 1-style CONNECT request codec.
//!
//! Hysteria carries an HTTP/1.1 CONNECT head over a QUIC stream and identifies
//! the client with a `Hysteria-Auth` header. The authority and method parsing
//! is shared with the HTTP CONNECT server so both paths enforce the same
//! bounded, smuggling-resistant grammar.

const std = @import("std");

const http = @import("../http_connect/protocol.zig");

pub const max_head_bytes = http.max_head_bytes;
pub const max_auth_bytes: usize = 1024;

pub const Error = http.Error || error{
    InvalidAuth,
    DuplicateAuth,
};

pub const Request = struct {
    version: http.Version,
    authority: http.Authority,
    auth: []const u8,
    /// Offset of the first byte after the request head. The same QUIC stream
    /// may already carry relay payload after this offset.
    end: usize,
};

pub const success_response = "HTTP/1.1 200 Connection established\r\n\r\n";
pub const auth_required_response =
    "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
pub const forbidden_response = "HTTP/1.1 403 Forbidden\r\n\r\n";

/// Parse a complete Hysteria request head. Every returned slice borrows
/// `head`; callers must keep the head alive for the lifetime of the request.
pub fn parseRequest(head: []const u8) Error!Request {
    const base = try http.parseRequest(head);

    var auth: ?[]const u8 = null;
    const request_line_end = std.mem.find(u8, head, "\r\n") orelse
        return error.Incomplete;
    var offset = request_line_end + 2;
    while (offset < head.len) {
        const line_end = std.mem.find(u8, head[offset..], "\r\n") orelse
            return error.Incomplete;
        const line = head[offset .. offset + line_end];
        if (line.len == 0) break;
        const colon = std.mem.findScalar(u8, line, ':') orelse
            return error.MalformedRequest;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Hysteria-Auth")) {
            if (auth != null) return error.DuplicateAuth;
            if (value.len == 0 or value.len > max_auth_bytes) {
                return error.InvalidAuth;
            }
            auth = value;
        }
        offset += line_end + 2;
    }

    return .{
        .version = base.version,
        .authority = base.authority,
        .auth = auth orelse return error.InvalidAuth,
        .end = head.len,
    };
}

pub fn buildRequest(
    allocator: std.mem.Allocator,
    authority: []const u8,
    auth: []const u8,
) ![]u8 {
    if (authority.len == 0 or auth.len == 0 or auth.len > max_auth_bytes) {
        return error.InvalidAuth;
    }
    return std.fmt.allocPrint(
        allocator,
        "CONNECT {s} HTTP/1.1\r\nHysteria-Auth: {s}\r\n\r\n",
        .{ authority, auth },
    );
}

test "Hysteria CONNECT request parses authority and auth" {
    const head = "CONNECT origin.example:443 HTTP/1.1\r\n" ++
        "Hysteria-Auth: secret\r\n" ++
        "Hysteria-CC-RX: 1000\r\n\r\n";
    const request = try parseRequest(head);
    try std.testing.expectEqual(@as(u16, 443), request.authority.getPort());
    try std.testing.expectEqualStrings("secret", request.auth);
    try std.testing.expectEqual(head.len, request.end);
}

test "Hysteria request rejects missing and duplicate auth" {
    try std.testing.expectError(
        error.InvalidAuth,
        parseRequest("CONNECT origin.example:443 HTTP/1.1\r\n\r\n"),
    );
    try std.testing.expectError(
        error.DuplicateAuth,
        parseRequest(
            "CONNECT origin.example:443 HTTP/1.1\r\n" ++
                "Hysteria-Auth: a\r\nHysteria-Auth: b\r\n\r\n",
        ),
    );
}

test "Hysteria request inherits HTTP CONNECT bounds" {
    try std.testing.expectError(
        error.UnsupportedMethod,
        parseRequest("GET / HTTP/1.1\r\nHysteria-Auth: a\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidAuthority,
        parseRequest("CONNECT origin.example HTTP/1.1\r\nHysteria-Auth: a\r\n\r\n"),
    );
}

test "Hysteria request builder round trips" {
    const allocator = std.testing.allocator;
    const head = try buildRequest(allocator, "127.0.0.1:8080", "secret");
    defer allocator.free(head);
    const request = try parseRequest(head);
    try std.testing.expectEqual(@as(u16, 8080), request.authority.getPort());
    try std.testing.expectEqualStrings("secret", request.auth);
}
