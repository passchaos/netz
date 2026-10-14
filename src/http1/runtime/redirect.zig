//! Bounded HTTP/HTTPS redirect policy for one-shot URI requests.

const std = @import("std");
const http1 = @import("../mod.zig");

const net = std.Io.net;

pub const Error = std.mem.Allocator.Error || error{
    InvalidRedirect,
    RedirectLimitExceeded,
    RedirectLoop,
    RedirectRejected,
    InsecureRedirect,
};

pub const Policy = struct {
    max_redirects: usize = 10,
    allow_insecure_downgrade: bool = false,
    /// Match common user-agent compatibility behavior for POST responses.
    /// RFC-preserving callers can disable this and retain POST on 301/302.
    rewrite_post_301_302_to_get: bool = true,
    /// Forward Authorization, Proxy-Authorization, Cookie, and Cookie2 fields
    /// to a different scheme/host/port origin.
    forward_cross_origin_credentials: bool = false,
    context: ?*anyopaque = null,
    authorize: ?*const fn (
        context: ?*anyopaque,
        from_uri: []const u8,
        to_uri: []const u8,
        status: u16,
    ) bool = null,
};

pub const MethodAction = enum {
    preserve,
    rewrite_get,
};

pub const Target = struct {
    allocator: std.mem.Allocator,
    uri: []u8,
    cross_origin: bool,

    pub fn deinit(self: *Target) void {
        self.allocator.free(self.uri);
        self.* = undefined;
    }
};

pub const Chain = struct {
    allocator: std.mem.Allocator,
    policy: Policy,
    visited: std.StringHashMapUnmanaged(void) = .empty,
    redirects: usize = 0,

    pub fn init(allocator: std.mem.Allocator, policy: Policy) Chain {
        return .{ .allocator = allocator, .policy = policy };
    }

    pub fn deinit(self: *Chain) void {
        var iterator = self.visited.keyIterator();
        while (iterator.next()) |key| self.allocator.free(key.*);
        self.visited.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn recordInitial(self: *Chain, uri_text: []const u8) Error!void {
        const canonical = try canonicalize(self.allocator, uri_text);
        errdefer self.allocator.free(canonical);
        try self.visited.put(self.allocator, canonical, {});
    }

    pub fn follow(
        self: *Chain,
        from_uri: []const u8,
        location_value: []const u8,
        status: u16,
    ) Error!Target {
        if (!isRedirectStatus(status) or location_value.len == 0) {
            return error.InvalidRedirect;
        }
        if (self.redirects >= self.policy.max_redirects) {
            return error.RedirectLimitExceeded;
        }
        const base = parseAbsolute(from_uri) catch return error.InvalidRedirect;
        const from_secure = isSecureScheme(base.scheme);
        var storage = try self.allocator.alloc(
            u8,
            location_value.len + from_uri.len + 1,
        );
        defer self.allocator.free(storage);
        @memcpy(storage[0..location_value.len], location_value);
        var aux = storage;
        const resolved = base.resolveInPlace(location_value.len, &aux) catch
            return error.InvalidRedirect;
        try validateAbsolute(resolved);
        if (from_secure and !isSecureScheme(resolved.scheme) and
            !self.policy.allow_insecure_downgrade)
        {
            return error.InsecureRedirect;
        }
        const cross_origin = !(try sameOrigin(
            self.allocator,
            base,
            resolved,
        ));
        const canonical = try canonicalizeUri(self.allocator, resolved);
        errdefer self.allocator.free(canonical);
        if (self.visited.contains(canonical)) return error.RedirectLoop;
        if (self.policy.authorize) |authorize| {
            if (!authorize(
                self.policy.context,
                from_uri,
                canonical,
                status,
            )) return error.RedirectRejected;
        }
        const recorded = try self.allocator.dupe(u8, canonical);
        errdefer self.allocator.free(recorded);
        try self.visited.put(self.allocator, recorded, {});
        self.redirects += 1;
        return .{
            .allocator = self.allocator,
            .uri = canonical,
            .cross_origin = cross_origin,
        };
    }
};

pub fn isRedirectStatus(status: u16) bool {
    return switch (status) {
        300, 301, 302, 303, 307, 308 => true,
        else => false,
    };
}

pub fn location(headers: []const http1.Header) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;
        if (found != null or header.value.len == 0) {
            return error.InvalidRedirect;
        }
        found = header.value;
    }
    return found;
}

pub fn methodAction(
    policy: Policy,
    status: u16,
    method: http1.Method,
) MethodAction {
    if (status == 303 and method != .HEAD) return .rewrite_get;
    if ((status == 301 or status == 302) and
        policy.rewrite_post_301_302_to_get and method == .POST)
    {
        return .rewrite_get;
    }
    return .preserve;
}

pub fn isCrossOriginCredential(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "authorization") or
        std.ascii.eqlIgnoreCase(name, "proxy-authorization") or
        std.ascii.eqlIgnoreCase(name, "cookie") or
        std.ascii.eqlIgnoreCase(name, "cookie2");
}

pub fn isBodyHeader(name: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(name, "content-") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "expect") or
        std.ascii.eqlIgnoreCase(name, "digest") or
        std.ascii.eqlIgnoreCase(name, "repr-digest") or
        std.ascii.eqlIgnoreCase(name, "want-repr-digest");
}

pub fn canonicalize(
    allocator: std.mem.Allocator,
    uri_text: []const u8,
) Error![]u8 {
    const uri = parseAbsolute(uri_text) catch return error.InvalidRedirect;
    return canonicalizeUri(allocator, uri);
}

fn canonicalizeUri(
    allocator: std.mem.Allocator,
    uri: std.Uri,
) Error![]u8 {
    try validateAbsolute(uri);
    const secure = isSecureScheme(uri.scheme);
    const port: u16 = uri.port orelse if (secure) 443 else 80;
    var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
    const raw_host = uri.host.?.toRaw(&host_buffer) catch
        return error.InvalidRedirect;
    if (raw_host.len == 0) return error.InvalidRedirect;
    const lower_host = try allocator.alloc(u8, raw_host.len);
    defer allocator.free(lower_host);
    for (raw_host, lower_host) |byte, *out| out.* = std.ascii.toLower(byte);
    var normalized = uri;
    if (componentBytes(normalized.path).len == 0) {
        normalized.path = .{ .raw = "/" };
    }
    const suffix = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{normalized.fmt(.{ .path = true, .query = true })},
    );
    defer allocator.free(suffix);
    return std.fmt.allocPrint(
        allocator,
        "{s}://{s}:{d}{s}",
        .{
            if (secure) "https" else "http",
            lower_host,
            port,
            suffix,
        },
    );
}

fn sameOrigin(
    allocator: std.mem.Allocator,
    lhs: std.Uri,
    rhs: std.Uri,
) Error!bool {
    const lhs_origin = try canonicalOrigin(allocator, lhs);
    defer allocator.free(lhs_origin);
    const rhs_origin = try canonicalOrigin(allocator, rhs);
    defer allocator.free(rhs_origin);
    return std.mem.eql(u8, lhs_origin, rhs_origin);
}

fn canonicalOrigin(
    allocator: std.mem.Allocator,
    uri: std.Uri,
) Error![]u8 {
    try validateAbsolute(uri);
    const secure = isSecureScheme(uri.scheme);
    const port: u16 = uri.port orelse if (secure) 443 else 80;
    var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
    const raw_host = uri.host.?.toRaw(&host_buffer) catch
        return error.InvalidRedirect;
    const value = try std.fmt.allocPrint(
        allocator,
        "{s}://{s}:{d}",
        .{
            if (secure) "https" else "http",
            raw_host,
            port,
        },
    );
    for (value) |*byte| byte.* = std.ascii.toLower(byte.*);
    return value;
}

fn parseAbsolute(uri_text: []const u8) std.Uri.ParseError!std.Uri {
    const uri = try std.Uri.parse(uri_text);
    validateAbsolute(uri) catch return error.InvalidFormat;
    return uri;
}

fn validateAbsolute(uri: std.Uri) Error!void {
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") and
        !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
    {
        return error.InvalidRedirect;
    }
    if (uri.host == null or uri.user != null or uri.password != null or
        uri.port == 0)
    {
        return error.InvalidRedirect;
    }
}

fn isSecureScheme(scheme: []const u8) bool {
    return std.ascii.eqlIgnoreCase(scheme, "https");
}

fn componentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |value| value,
        .percent_encoded => |value| value,
    };
}

test "HTTP redirect resolves relative Location and rejects downgrade loop" {
    const allocator = std.testing.allocator;
    var chain = Chain.init(allocator, .{});
    defer chain.deinit();
    try chain.recordInitial("https://EXAMPLE.test/a/start#ignored");
    var target = try chain.follow(
        "https://EXAMPLE.test/a/start#ignored",
        "../final?q=1#not-on-wire",
        307,
    );
    defer target.deinit();
    try std.testing.expectEqualStrings(
        "https://example.test:443/final?q=1",
        target.uri,
    );
    try std.testing.expect(!target.cross_origin);
    try std.testing.expectError(
        error.RedirectLoop,
        chain.follow(target.uri, "/a/start", 302),
    );

    var downgrade = Chain.init(allocator, .{});
    defer downgrade.deinit();
    try downgrade.recordInitial("https://example.test/start");
    try std.testing.expectError(
        error.InsecureRedirect,
        downgrade.follow(
            "https://example.test/start",
            "http://example.test/clear",
            302,
        ),
    );
}

test "HTTP redirect method and header policy is explicit" {
    try std.testing.expectEqual(
        MethodAction.rewrite_get,
        methodAction(.{}, 303, .PUT),
    );
    try std.testing.expectEqual(
        MethodAction.rewrite_get,
        methodAction(.{}, 302, .POST),
    );
    try std.testing.expectEqual(
        MethodAction.preserve,
        methodAction(.{ .rewrite_post_301_302_to_get = false }, 302, .POST),
    );
    try std.testing.expectEqual(
        MethodAction.preserve,
        methodAction(.{}, 307, .POST),
    );
    try std.testing.expect(isCrossOriginCredential("Authorization"));
    try std.testing.expect(isCrossOriginCredential("Cookie"));
    try std.testing.expect(!isCrossOriginCredential("Accept"));
    try std.testing.expect(isBodyHeader("Content-Length"));
    try std.testing.expect(isBodyHeader("Expect"));
    try std.testing.expect(!isBodyHeader("Accept"));
}
