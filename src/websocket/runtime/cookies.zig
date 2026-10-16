//! Shared CookieJar adapter for RFC 8441 and RFC 9220 handshakes.

const std = @import("std");
const http_cookies = @import("../../http/cookies/mod.zig");

pub const Error = http_cookies.Error || error{
    CookieHeaderConflict,
    CookieScopeRequired,
};

pub const Options = struct {
    jar: *http_cookies.Jar,
    /// WS/WSS URI used solely for Cookie scope. URI-based clients replace this
    /// with their actual input; existing H2/H3 connections require it.
    scope_uri: ?[]const u8 = null,
    request_context: http_cookies.RequestContext = .{},
    store_context: http_cookies.StoreContext = .{},

    pub fn withScope(self: Options, uri: []const u8) Options {
        var result = self;
        result.scope_uri = uri;
        return result;
    }
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    value: []u8,

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.value);
        self.* = undefined;
    }
};

/// Validate caller ownership and URI scope without consulting the clock or
/// mutating the Jar. New-connection clients call this before network I/O;
/// `prepare` repeats it at the request boundary for direct callers.
pub fn validate(options: Options, extra_headers: anytype) Error!void {
    for (extra_headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "cookie") or
            std.ascii.eqlIgnoreCase(header.name, "cookie2"))
        {
            return error.CookieHeaderConflict;
        }
    }
    const uri = options.scope_uri orelse return error.CookieScopeRequired;
    try http_cookies.validateScopeUri(uri);
}

pub fn prepare(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    extra_headers: anytype,
) Error!Prepared {
    try validate(options, extra_headers);
    const uri = options.scope_uri.?;
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
    headers: anytype,
) Error!void {
    const uri = options.scope_uri orelse return error.CookieScopeRequired;
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
