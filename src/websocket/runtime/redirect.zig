//! Bounded HTTP redirect policy for WebSocket URI clients.
//!
//! Redirects are resolved with RFC 3986 semantics, canonicalized without URI
//! fragments, and recorded before the next network attempt. The default policy
//! permits ordinary and secure upgrades, rejects WSS-to-WS downgrade, strips
//! caller-provided Upgrade fields on cross-origin hops, and never forwards a
//! configured client certificate to a new origin without explicit opt-in.

const std = @import("std");
const http1 = @import("../../http1/mod.zig");
const http1_runtime = http1.runtime;

pub const Error = std.mem.Allocator.Error || error{
    InvalidRedirect,
    RedirectLimitExceeded,
    RedirectLoop,
    RedirectRejected,
    InsecureRedirect,
    CrossOriginIdentityRestricted,
};

pub const Policy = struct {
    max_redirects: usize = 3,
    /// Permit a redirect from authenticated WSS to cleartext WS.
    allow_insecure_downgrade: bool = false,
    /// Forward caller-supplied WebSocket Upgrade fields to a different origin.
    /// The default strips the complete `extra_headers` slice, avoiding guesses
    /// about which application-specific fields carry credentials.
    forward_cross_origin_headers: bool = false,
    /// Permit a configured TLS client certificate to be offered to another
    /// origin. Server trust settings remain active so every hop authenticates
    /// its own hostname even when this is enabled.
    allow_cross_origin_client_identity: bool = false,
    context: ?*anyopaque = null,
    authorize: ?*const fn (
        context: ?*anyopaque,
        from_uri: []const u8,
        to_uri: []const u8,
        status: u16,
    ) bool = null,
};

pub const Target = struct {
    allocator: std.mem.Allocator,
    uri: []u8,
    cross_origin: bool,
    secure: bool,

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

    /// Resolve, validate, authorize, and record one Location before the next
    /// connection attempt can perform network I/O.
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
        const secure = isSecureScheme(resolved.scheme);
        if (from_secure and !secure and !self.policy.allow_insecure_downgrade) {
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
            .secure = secure,
        };
    }
};

pub fn isRedirectStatus(status: u16) bool {
    return switch (status) {
        300, 301, 302, 303, 307, 308 => true,
        else => false,
    };
}

/// Return the sole non-empty Location value. Missing Location leaves the 3xx
/// response available to the caller as a final rejected `ConnectAttempt`;
/// duplicates or an empty value are malformed and fail closed.
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

pub fn enforceClientIdentityPolicy(
    policy: Policy,
    cross_origin: bool,
    has_identity: bool,
) Error!void {
    if (cross_origin and has_identity and
        !policy.allow_cross_origin_client_identity)
    {
        return error.CrossOriginIdentityRestricted;
    }
}

fn canonicalize(
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
    var endpoint = http1_runtime.uriEndpoint(
        allocator,
        uri,
        if (secure) 443 else 80,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidRedirect,
    };
    defer endpoint.deinit();
    const lower_host = try allocator.alloc(u8, endpoint.host_storage.len);
    defer allocator.free(lower_host);
    for (endpoint.host_storage, lower_host) |byte, *out| {
        out.* = std.ascii.toLower(byte);
    }
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
        .{ if (secure) "wss" else "ws", lower_host, endpoint.port, suffix },
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
    var endpoint = http1_runtime.uriEndpoint(
        allocator,
        uri,
        if (secure) 443 else 80,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidRedirect,
    };
    defer endpoint.deinit();
    const value = try std.fmt.allocPrint(
        allocator,
        "{s}://{s}:{d}",
        .{ if (secure) "wss" else "ws", endpoint.host_storage, endpoint.port },
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
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "ws") and
        !std.ascii.eqlIgnoreCase(uri.scheme, "wss"))
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
    return std.ascii.eqlIgnoreCase(scheme, "wss");
}

fn componentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |value| value,
        .percent_encoded => |value| value,
    };
}

test "WebSocket redirect resolves relative Location and canonicalizes loops" {
    const allocator = std.testing.allocator;
    var chain = Chain.init(allocator, .{});
    defer chain.deinit();
    try chain.recordInitial("ws://EXAMPLE.test/a/start#ignored");
    var target = try chain.follow(
        "ws://EXAMPLE.test/a/start#ignored",
        "../final?q=1#not-on-wire",
        307,
    );
    defer target.deinit();
    try std.testing.expectEqualStrings(
        "ws://example.test:80/final?q=1",
        target.uri,
    );
    try std.testing.expect(!target.cross_origin);
    try std.testing.expectError(
        error.RedirectLoop,
        chain.follow(target.uri, "/a/start", 302),
    );
}

test "WebSocket redirect policy rejects downgrade limit and callback denial" {
    const allocator = std.testing.allocator;
    var downgrade = Chain.init(allocator, .{});
    defer downgrade.deinit();
    try downgrade.recordInitial("wss://example.test/start");
    try std.testing.expectError(
        error.InsecureRedirect,
        downgrade.follow(
            "wss://example.test/start",
            "ws://example.test/clear",
            302,
        ),
    );

    var bounded = Chain.init(allocator, .{ .max_redirects = 0 });
    defer bounded.deinit();
    try bounded.recordInitial("ws://example.test/start");
    try std.testing.expectError(
        error.RedirectLimitExceeded,
        bounded.follow("ws://example.test/start", "/next", 301),
    );

    const Deny = struct {
        fn call(_: ?*anyopaque, _: []const u8, _: []const u8, _: u16) bool {
            return false;
        }
    };
    var denied = Chain.init(allocator, .{ .authorize = Deny.call });
    defer denied.deinit();
    try denied.recordInitial("ws://example.test/start");
    try std.testing.expectError(
        error.RedirectRejected,
        denied.follow("ws://example.test/start", "/next", 308),
    );
}

test "WebSocket redirect Location requires one non-empty field" {
    try std.testing.expectEqualStrings(
        "/next",
        (try location(&.{.{ .name = "Location", .value = "/next" }})).?,
    );
    try std.testing.expect((try location(&.{})) == null);
    try std.testing.expectError(
        error.InvalidRedirect,
        location(&.{
            .{ .name = "Location", .value = "/one" },
            .{ .name = "location", .value = "/two" },
        }),
    );
    try std.testing.expectError(
        error.InvalidRedirect,
        location(&.{.{ .name = "Location", .value = "" }}),
    );
    try std.testing.expectError(
        error.CrossOriginIdentityRestricted,
        enforceClientIdentityPolicy(.{}, true, true),
    );
    try enforceClientIdentityPolicy(
        .{ .allow_cross_origin_client_identity = true },
        true,
        true,
    );
}
