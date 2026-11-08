//! Bounded HTTP/1 CONNECT request-head parser and Basic authentication.

const std = @import("std");

const net = std.Io.net;

pub const max_head_bytes: usize = 16 * 1024;
pub const max_header_line_bytes: usize = 8 * 1024;
pub const max_headers: usize = 64;
pub const max_authorization_token_bytes: usize = 1024;

pub const Error = error{
    Incomplete,
    MalformedRequest,
    UnsupportedMethod,
    UnsupportedVersion,
    InvalidAuthority,
    InvalidPort,
    InvalidHostName,
    HeadTooLarge,
    TooManyHeaders,
    HeaderLineTooLarge,
    ObsoleteLineFolding,
    DuplicateAuthorization,
    InvalidAuthorization,
    UnsupportedBodyFraming,
    BufferTooSmall,
};

pub const Version = enum { http_1_0, http_1_1 };

pub const Domain = struct {
    host: []const u8,
    port: u16,
};

pub const Authority = union(enum) {
    ip: net.IpAddress,
    domain: Domain,

    pub fn getPort(self: Authority) u16 {
        return switch (self) {
            .ip => |ip| ip.getPort(),
            .domain => |domain| domain.port,
        };
    }
};

pub const Request = struct {
    version: Version,
    authority: Authority,
    /// Base64 token from `Proxy-Authorization: Basic ...`, if present.
    authorization: ?[]const u8,
};

/// Parse one complete request head. The caller must include the terminating
/// CRLFCRLF sequence; every returned slice borrows `head`.
pub fn parseRequest(head: []const u8) Error!Request {
    if (head.len > max_head_bytes) return error.HeadTooLarge;
    if (!std.mem.endsWith(u8, head, "\r\n\r\n")) return error.Incomplete;

    const request_line_end = std.mem.find(u8, head, "\r\n") orelse
        return error.Incomplete;
    if (request_line_end > max_header_line_bytes) {
        return error.HeaderLineTooLarge;
    }
    const request_line = head[0..request_line_end];

    const first_space = std.mem.findScalar(u8, request_line, ' ') orelse
        return error.MalformedRequest;
    const last_space = std.mem.lastIndexOfScalar(u8, request_line, ' ') orelse
        return error.MalformedRequest;
    if (first_space == 0 or last_space <= first_space or
        last_space + 1 == request_line.len)
    {
        return error.MalformedRequest;
    }

    const method = request_line[0..first_space];
    const target = request_line[first_space + 1 .. last_space];
    const version_text = request_line[last_space + 1 ..];
    if (!std.mem.eql(u8, method, "CONNECT")) {
        return error.UnsupportedMethod;
    }
    const version = try parseVersion(version_text);
    const authority = try parseAuthority(target);

    var authorization: ?[]const u8 = null;
    var offset = request_line_end + 2;
    var header_count: usize = 0;
    while (offset < head.len) {
        const line_end = std.mem.find(u8, head[offset..], "\r\n") orelse
            return error.Incomplete;
        const line = head[offset .. offset + line_end];
        if (line.len == 0) break;
        if (line.len > max_header_line_bytes) {
            return error.HeaderLineTooLarge;
        }
        header_count += 1;
        if (header_count > max_headers) return error.TooManyHeaders;
        if (line[0] == ' ' or line[0] == '\t') {
            return error.ObsoleteLineFolding;
        }

        const colon = std.mem.findScalar(u8, line, ':') orelse
            return error.MalformedRequest;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!validToken(name)) return error.MalformedRequest;
        if (!validHeaderValue(value)) return error.MalformedRequest;

        if (std.ascii.eqlIgnoreCase(name, "Proxy-Authorization")) {
            if (authorization != null) {
                return error.DuplicateAuthorization;
            }
            authorization = try parseAuthorization(value);
        } else if (std.ascii.eqlIgnoreCase(name, "Content-Length") or
            std.ascii.eqlIgnoreCase(name, "Transfer-Encoding"))
        {
            return error.UnsupportedBodyFraming;
        }
        offset += line_end + 2;
    }

    return .{
        .version = version,
        .authority = authority,
        .authorization = authorization,
    };
}

fn parseVersion(text: []const u8) Error!Version {
    if (std.mem.eql(u8, text, "HTTP/1.0")) return .http_1_0;
    if (std.mem.eql(u8, text, "HTTP/1.1")) return .http_1_1;
    return error.UnsupportedVersion;
}

fn parseAuthority(text: []const u8) Error!Authority {
    if (text.len == 0) return error.InvalidAuthority;
    if (std.mem.indexOfAny(u8, text, "/?#@") != null) {
        return error.InvalidAuthority;
    }

    if (text[0] == '[') {
        const close = std.mem.findScalar(u8, text, ']') orelse
            return error.InvalidAuthority;
        if (close + 1 >= text.len or text[close + 1] != ':') {
            return error.InvalidAuthority;
        }
        const host = text[1..close];
        const port = try parsePort(text[close + 2 ..]);
        const address = net.IpAddress.parse(host, port) catch
            return error.InvalidHostName;
        return switch (address) {
            .ip6 => .{ .ip = address },
            .ip4 => error.InvalidAuthority,
        };
    }

    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse
        return error.InvalidAuthority;
    if (colon == 0 or colon + 1 == text.len) {
        return error.InvalidAuthority;
    }
    const host = text[0..colon];
    const port = try parsePort(text[colon + 1 ..]);
    if (net.IpAddress.parse(host, port)) |address| {
        return switch (address) {
            .ip4 => .{ .ip = address },
            .ip6 => error.InvalidAuthority,
        };
    } else |_| {}
    _ = net.HostName.init(host) catch return error.InvalidHostName;
    return .{ .domain = .{ .host = host, .port = port } };
}

fn parsePort(text: []const u8) Error!u16 {
    if (text.len == 0 or text.len > 5) return error.InvalidPort;
    const port = std.fmt.parseInt(u16, text, 10) catch
        return error.InvalidPort;
    if (port == 0) return error.InvalidPort;
    return port;
}

fn parseAuthorization(value: []const u8) Error![]const u8 {
    if (value.len < 6 or !std.ascii.startsWithIgnoreCase(value, "Basic")) {
        return error.InvalidAuthorization;
    }
    if (value[5] != ' ' and value[5] != '\t') {
        return error.InvalidAuthorization;
    }
    const token = std.mem.trim(u8, value[6..], " \t");
    if (token.len == 0 or token.len > max_authorization_token_bytes) {
        return error.InvalidAuthorization;
    }
    for (token) |byte| {
        if (std.ascii.isWhitespace(byte)) return error.InvalidAuthorization;
    }
    return token;
}

fn validToken(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and
            byte != '_' and byte != '.')
        {
            return false;
        }
    }
    return true;
}

fn validHeaderValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return false;
        if (byte < 0x20 and byte != '\t') return false;
        if (byte == 0x7f) return false;
    }
    return true;
}

pub const BasicCredentials = struct {
    username: []const u8,
    password: []const u8,
};

/// Decode a Basic token into caller-provided storage. The returned slices
/// borrow `storage`.
pub fn decodeBasic(
    encoded: []const u8,
    storage: []u8,
) Error!BasicCredentials {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(
        encoded,
    ) catch return error.InvalidAuthorization;
    if (decoded_len > storage.len) return error.BufferTooSmall;
    std.base64.standard.Decoder.decode(
        storage[0..decoded_len],
        encoded,
    ) catch return error.InvalidAuthorization;
    const colon = std.mem.findScalar(u8, storage[0..decoded_len], ':') orelse
        return error.InvalidAuthorization;
    if (colon == 0 or colon + 1 == decoded_len) {
        return error.InvalidAuthorization;
    }
    return .{
        .username = storage[0..colon],
        .password = storage[colon + 1 .. decoded_len],
    };
}

test "CONNECT request parsing accepts IPv4 IPv6 and domain authorities" {
    const cases = [_]struct { head: []const u8, port: u16 }{
        .{
            .head = "CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n\r\n",
            .port = 443,
        },
        .{
            .head = "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n",
            .port = 8443,
        },
        .{
            .head = "CONNECT origin.example:8080 HTTP/1.0\r\n\r\n",
            .port = 8080,
        },
    };
    for (cases) |case| {
        const request = try parseRequest(case.head);
        try std.testing.expectEqual(case.port, request.authority.getPort());
    }
}

test "CONNECT request parsing extracts Basic authorization" {
    const head = "CONNECT origin.example:443 HTTP/1.1\r\n" ++
        "Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n";
    const request = try parseRequest(head);
    try std.testing.expect(request.authorization != null);
    try std.testing.expectEqualStrings(
        "dXNlcjpzZWNyZXQ=",
        request.authorization.?,
    );

    var storage: [64]u8 = undefined;
    const credentials = try decodeBasic(request.authorization.?, &storage);
    try std.testing.expectEqualStrings("user", credentials.username);
    try std.testing.expectEqualStrings("secret", credentials.password);
}

test "CONNECT parser rejects smuggling and malformed heads" {
    try std.testing.expectError(
        error.UnsupportedMethod,
        parseRequest("GET / HTTP/1.1\r\n\r\n"),
    );
    try std.testing.expectError(
        error.UnsupportedVersion,
        parseRequest("CONNECT origin.example:443 HTTP/2\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidAuthority,
        parseRequest("CONNECT origin.example HTTP/1.1\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidPort,
        parseRequest("CONNECT origin.example:0 HTTP/1.1\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidAuthority,
        parseRequest("CONNECT /path:443 HTTP/1.1\r\n\r\n"),
    );
    try std.testing.expectError(
        error.ObsoleteLineFolding,
        parseRequest("CONNECT origin.example:443 HTTP/1.1\r\n folded\r\n\r\n"),
    );
    try std.testing.expectError(
        error.DuplicateAuthorization,
        parseRequest(
            "CONNECT origin.example:443 HTTP/1.1\r\n" ++
                "Proxy-Authorization: Basic aaa\r\n" ++
                "Proxy-Authorization: Basic bbb\r\n\r\n",
        ),
    );
    try std.testing.expectError(
        error.UnsupportedBodyFraming,
        parseRequest(
            "CONNECT origin.example:443 HTTP/1.1\r\n" ++
                "Content-Length: 4\r\n\r\n",
        ),
    );
    try std.testing.expectError(
        error.InvalidAuthorization,
        parseRequest(
            "CONNECT origin.example:443 HTTP/1.1\r\n" ++
                "Proxy-Authorization: Bearer token\r\n\r\n",
        ),
    );
}

test "CONNECT parser rejects oversized heads and header lines" {
    var long_line: [max_header_line_bytes + 2]u8 = @splat('a');
    long_line[0] = 'X';
    long_line[1] = ':';
    const head = try std.fmt.allocPrint(
        std.testing.allocator,
        "CONNECT origin.example:443 HTTP/1.1\r\n{s}\r\n\r\n",
        .{long_line[0..]},
    );
    defer std.testing.allocator.free(head);
    try std.testing.expectError(
        error.HeaderLineTooLarge,
        parseRequest(head),
    );

    var many = std.ArrayList(u8).empty;
    defer many.deinit(std.testing.allocator);
    try many.appendSlice(
        std.testing.allocator,
        "CONNECT origin.example:443 HTTP/1.1\r\n",
    );
    for (0..max_headers + 1) |_| {
        try many.appendSlice(std.testing.allocator, "X-A: b\r\n");
    }
    try many.appendSlice(std.testing.allocator, "\r\n");
    try std.testing.expectError(
        error.TooManyHeaders,
        parseRequest(many.items),
    );
}

test "Basic decoding rejects missing separators and short storage" {
    var storage: [8]u8 = undefined;
    try std.testing.expectError(
        error.InvalidAuthorization,
        decodeBasic("dXNlcg==", &storage),
    );
    var small: [3]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        decodeBasic("dXNlcjpzZWNyZXQ=", &small),
    );
    try std.testing.expectError(
        error.InvalidAuthorization,
        decodeBasic("!!!!", &storage),
    );
}
