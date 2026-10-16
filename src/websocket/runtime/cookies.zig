//! Shared CookieJar adapter for RFC 8441 and RFC 9220 handshakes.

const std = @import("std");
const http_cookies = @import("../../http/cookies/mod.zig");

pub const Error = http_cookies.Error || error{CookieHeaderConflict};

pub const Options = struct {
    jar: *http_cookies.Jar,
    request_context: http_cookies.RequestContext = .{},
    store_context: http_cookies.StoreContext = .{},
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    value: []u8,

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.value);
        self.* = undefined;
    }
};

/// Build the Cookie scope from the exact Extended CONNECT pseudo-header
/// values. The caller owns the result. Deriving rather than accepting this URI
/// prevents an accidentally unrelated host or path from selecting cookies.
pub fn scopeUriAlloc(
    allocator: std.mem.Allocator,
    scheme: []const u8,
    authority: []const u8,
    target: []const u8,
) Error![]u8 {
    if (target.len == 0 or target[0] != '/' or
        std.mem.indexOfScalar(u8, target, '#') != null)
    {
        return error.InvalidUri;
    }
    const uri = try std.mem.concat(
        allocator,
        u8,
        &.{ scheme, "://", authority, target },
    );
    errdefer allocator.free(uri);
    try http_cookies.validateScopeUri(uri);
    return uri;
}

/// Validate caller ownership and a derived request URI without consulting the
/// clock or mutating the Jar. New-connection clients call this before network
/// I/O; `prepare` repeats it at the request boundary for direct callers.
pub fn validate(
    uri: []const u8,
    extra_headers: anytype,
) Error!void {
    for (extra_headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "cookie") or
            std.ascii.eqlIgnoreCase(header.name, "cookie2"))
        {
            return error.CookieHeaderConflict;
        }
    }
    try http_cookies.validateScopeUri(uri);
}

pub fn prepare(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    uri: []const u8,
    extra_headers: anytype,
) Error!Prepared {
    try validate(uri, extra_headers);
    var context = options.request_context;
    context.method = "GET";
    context.http_api = true;
    return .{
        .allocator = allocator,
        .value = try options.jar.cookieHeaderValueAlloc(
            allocator,
            uri,
            std.Io.Clock.real.now(io).toSeconds(),
            context,
        ),
    };
}

pub fn store(
    io: std.Io,
    options: Options,
    uri: []const u8,
    headers: anytype,
) Error!void {
    try http_cookies.validateScopeUri(uri);
    var context = options.store_context;
    context.http_api = true;
    const now = std.Io.Clock.real.now(io).toSeconds();
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "set-cookie")) continue;
        _ = try options.jar.storeSetCookieWithContext(
            uri,
            header.value,
            now,
            context,
        );
    }
}

test "WebSocket Cookie scope is derived from request pseudo-headers" {
    const allocator = std.testing.allocator;
    const uri = try scopeUriAlloc(
        allocator,
        "https",
        "[2001:db8::1]:8443",
        "/chat/room?token=a%2Fb",
    );
    defer allocator.free(uri);
    try std.testing.expectEqualStrings(
        "https://[2001:db8::1]:8443/chat/room?token=a%2Fb",
        uri,
    );

    try std.testing.expectError(
        error.InvalidUri,
        scopeUriAlloc(allocator, "https", "example.com", "missing-slash"),
    );
    try std.testing.expectError(
        error.InvalidUri,
        scopeUriAlloc(allocator, "https", "example.com", "/chat#fragment"),
    );
    try std.testing.expectError(
        error.InvalidUri,
        scopeUriAlloc(allocator, "https", "user@example.com", "/chat"),
    );
    try std.testing.expectError(
        error.InvalidUri,
        scopeUriAlloc(allocator, "ftp", "example.com", "/chat"),
    );
}
