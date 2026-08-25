//! MQTT 5 Server Reference parsing and bounded redirect policy.
//!
//! The protocol intentionally leaves the Server Reference format to the
//! client. Netz accepts either a URI or the common host[:port] form, but never
//! interprets credentials, paths, queries, fragments, or an unknown scheme.
//! Redirect following is opt-in because changing authority is a security and
//! policy decision, especially for TLS certificate validation.

const std = @import("std");
const mqtt = @import("mod.zig");

pub const Transport = enum {
    tcp,
    tls,
    websocket,
    websocket_tls,

    pub fn defaultPort(self: Transport) u16 {
        return switch (self) {
            .tcp => 1883,
            .tls => 8883,
            .websocket => 80,
            .websocket_tls => 443,
        };
    }

    pub fn scheme(self: Transport) []const u8 {
        return switch (self) {
            .tcp => "mqtt",
            .tls => "mqtts",
            .websocket => "ws",
            .websocket_tls => "wss",
        };
    }
};

pub const Target = struct {
    allocator: std.mem.Allocator,
    uri: []u8,
    transport: Transport,
    host: []u8,
    port: u16,
    path: []u8,

    pub fn deinit(self: *Target) void {
        self.allocator.free(self.path);
        self.allocator.free(self.host);
        self.allocator.free(self.uri);
        self.* = undefined;
    }
};

pub const Error = mqtt.Error || std.mem.Allocator.Error || error{
    InvalidServerReference,
    UnsupportedRedirectScheme,
    RedirectLimitExceeded,
    RedirectLoop,
    RedirectRejected,
};

pub const Policy = struct {
    /// Zero disables automatic redirects. Explicit opt-in prevents an
    /// untrusted broker from silently selecting a new network authority.
    max_redirects: usize = 0,
    allow_transport_change: bool = false,
    context: ?*anyopaque = null,
    authorize: ?*const fn (
        context: ?*anyopaque,
        from_uri: []const u8,
        to_uri: []const u8,
        reason_code: u8,
    ) bool = null,
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

    pub fn recordInitial(
        self: *Chain,
        uri: []const u8,
        default_transport: Transport,
    ) Error!void {
        var target = try parse(self.allocator, uri, default_transport);
        defer target.deinit();
        try self.record(target.uri, false);
    }

    /// Validate and record one redirect before performing any network I/O.
    pub fn follow(
        self: *Chain,
        from_uri: []const u8,
        reference: []const u8,
        reason_code: u8,
    ) Error!Target {
        if (!isRedirectReason(reason_code)) return error.InvalidReasonCode;
        if (self.policy.max_redirects == 0 or
            self.redirects >= self.policy.max_redirects)
        {
            return error.RedirectLimitExceeded;
        }
        const from_transport = transportFromUri(from_uri) catch
            return error.InvalidServerReference;
        var target = try parse(
            self.allocator,
            reference,
            from_transport,
        );
        errdefer target.deinit();
        if (!self.policy.allow_transport_change and
            target.transport != from_transport)
        {
            return error.UnsupportedRedirectScheme;
        }
        const canonical_from = try canonicalize(
            self.allocator,
            from_uri,
            from_transport,
        );
        defer self.allocator.free(canonical_from);
        if (std.mem.eql(u8, target.uri, canonical_from) or
            self.visited.contains(target.uri))
        {
            return error.RedirectLoop;
        }
        if (self.policy.authorize) |authorize| {
            if (!authorize(
                self.policy.context,
                from_uri,
                target.uri,
                reason_code,
            )) return error.RedirectRejected;
        }
        try self.record(target.uri, true);
        self.redirects += 1;
        return target;
    }

    fn record(self: *Chain, uri: []const u8, reject_duplicate: bool) Error!void {
        if (self.visited.contains(uri)) {
            if (reject_duplicate) return error.RedirectLoop;
            return;
        }
        const owned = try self.allocator.dupe(u8, uri);
        errdefer self.allocator.free(owned);
        try self.visited.put(self.allocator, owned, {});
    }
};

pub fn isRedirectReason(reason_code: u8) bool {
    return reason_code == 0x9c or reason_code == 0x9d;
}

pub fn referenceForConnAck(connack: mqtt.ConnAck) Error!?[]const u8 {
    if (!isRedirectReason(connack.reason_code)) return null;
    return mqtt.serverReference(connack.properties) orelse
        error.InvalidServerReference;
}

pub fn referenceForDisconnect(disconnect: mqtt.Disconnect) Error!?[]const u8 {
    if (!isRedirectReason(disconnect.reason_code)) return null;
    return mqtt.serverReference(disconnect.properties) orelse
        error.InvalidServerReference;
}

pub fn parse(
    allocator: std.mem.Allocator,
    reference: []const u8,
    default_transport: Transport,
) Error!Target {
    if (reference.len == 0) return error.InvalidServerReference;
    const has_scheme = std.mem.find(u8, reference, "://") != null;
    const uri_text = if (has_scheme)
        try allocator.dupe(u8, reference)
    else
        try std.fmt.allocPrint(
            allocator,
            "{s}://{s}",
            .{ default_transport.scheme(), reference },
        );
    errdefer allocator.free(uri_text);
    const uri = std.Uri.parse(uri_text) catch return error.InvalidServerReference;
    const transport = transportFromScheme(uri.scheme) orelse
        return error.UnsupportedRedirectScheme;
    if (uri.user != null or uri.password != null or uri.query != null or
        uri.fragment != null or uri.host == null)
    {
        return error.InvalidServerReference;
    }
    if (uri.port == 0) return error.InvalidServerReference;
    const path = switch (uri.path) {
        .raw => |raw| raw,
        .percent_encoded => |encoded| encoded,
    };
    const owned_path = if (path.len == 0 and
        (transport == .websocket or transport == .websocket_tls))
        try allocator.dupe(u8, "/mqtt")
    else if (path.len == 0)
        try allocator.alloc(u8, 0)
    else
        try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    if ((transport == .websocket or transport == .websocket_tls) and
        (owned_path.len == 0 or owned_path[0] != '/'))
    {
        return error.InvalidServerReference;
    }
    if ((transport == .tcp or transport == .tls) and owned_path.len != 0) {
        return error.InvalidServerReference;
    }
    var host_buffer: [std.Io.net.HostName.max_len + 2]u8 = undefined;
    const host = uri.host.?.toRaw(&host_buffer) catch
        return error.InvalidServerReference;
    if (std.mem.indexOfScalar(u8, host, '%') != null) {
        return error.InvalidServerReference;
    }
    const owned_host = try allocator.alloc(u8, host.len);
    errdefer allocator.free(owned_host);
    _ = std.ascii.lowerString(owned_host, host);
    try validateHost(owned_host, uri.port orelse transport.defaultPort());
    const port = uri.port orelse transport.defaultPort();
    const canonical_uri = if (transport == .websocket or
        transport == .websocket_tls)
        try std.fmt.allocPrint(
            allocator,
            "{s}://{s}:{d}{s}",
            .{ transport.scheme(), host, port, owned_path },
        )
    else
        try std.fmt.allocPrint(
            allocator,
            "{s}://{s}:{d}",
            .{ transport.scheme(), host, port },
        );
    allocator.free(uri_text);
    return .{
        .allocator = allocator,
        .uri = canonical_uri,
        .transport = transport,
        .host = owned_host,
        .port = port,
        .path = owned_path,
    };
}

fn validateHost(host: []const u8, port: u16) Error!void {
    if (host.len == 0) return error.InvalidServerReference;
    if (host[0] == '[') {
        if (host.len < 3 or host[host.len - 1] != ']') {
            return error.InvalidServerReference;
        }
        _ = std.Io.net.IpAddress.parseIp6(host[1 .. host.len - 1], port) catch
            return error.InvalidServerReference;
        return;
    }
    if (std.Io.net.IpAddress.parseIp4(host, port)) |_| return else |_| {}
    std.Io.net.HostName.validate(host) catch
        return error.InvalidServerReference;
}

/// Resolve a reference against the current transport. Server Reference is not
/// an RFC 3986 relative URI, so a bare authority inherits only the transport;
/// an explicit URI must name its own scheme.
pub fn resolve(
    allocator: std.mem.Allocator,
    from_uri: []const u8,
    reference: []const u8,
) Error!Target {
    const from_transport = transportFromUri(from_uri) catch
        return error.InvalidServerReference;
    return parse(allocator, reference, from_transport);
}

fn transportFromUri(uri_text: []const u8) Error!Transport {
    const uri = std.Uri.parse(uri_text) catch
        return error.InvalidServerReference;
    return transportFromScheme(uri.scheme) orelse
        error.UnsupportedRedirectScheme;
}

fn canonicalize(
    allocator: std.mem.Allocator,
    uri: []const u8,
    default_transport: Transport,
) Error![]u8 {
    var target = try parse(allocator, uri, default_transport);
    defer target.deinit();
    return allocator.dupe(u8, target.uri);
}

fn transportFromScheme(scheme: []const u8) ?Transport {
    if (std.ascii.eqlIgnoreCase(scheme, "mqtt") or
        std.ascii.eqlIgnoreCase(scheme, "tcp")) return .tcp;
    if (std.ascii.eqlIgnoreCase(scheme, "mqtts") or
        std.ascii.eqlIgnoreCase(scheme, "ssl")) return .tls;
    if (std.ascii.eqlIgnoreCase(scheme, "ws")) return .websocket;
    if (std.ascii.eqlIgnoreCase(scheme, "wss")) return .websocket_tls;
    return null;
}

/// Own the next Server Reference before releasing the packet that contains it.
/// A caller can then close the current MQTT connection and dispatch the owned
/// URI through its transport-specific connect helper.
pub fn takeDisconnectTarget(
    chain: *Chain,
    from_uri: []const u8,
    disconnect: mqtt.Disconnect,
) Error!?Target {
    const reference = (try referenceForDisconnect(disconnect)) orelse
        return null;
    return chain.follow(
        from_uri,
        reference,
        disconnect.reason_code,
    );
}

test "MQTT Server Reference parses URI and authority forms" {
    const allocator = std.testing.allocator;
    var host = try parse(allocator, "other.example:2883", .tcp);
    defer host.deinit();
    try std.testing.expectEqual(Transport.tcp, host.transport);
    try std.testing.expectEqualStrings("other.example", host.host);
    try std.testing.expectEqual(@as(u16, 2883), host.port);

    var secure = try parse(
        allocator,
        "mqtts://secure.example",
        .tcp,
    );
    defer secure.deinit();
    try std.testing.expectEqual(Transport.tls, secure.transport);
    try std.testing.expectEqual(@as(u16, 8883), secure.port);

    var websocket = try parse(
        allocator,
        "wss://browser.example/custom",
        .websocket_tls,
    );
    defer websocket.deinit();
    try std.testing.expectEqualStrings("/custom", websocket.path);
    try std.testing.expectEqualStrings(
        "wss://browser.example:443/custom",
        websocket.uri,
    );
    var encoded_path = try parse(
        allocator,
        "ws://browser.example/%2Froom",
        .websocket,
    );
    defer encoded_path.deinit();
    try std.testing.expectEqualStrings("/%2Froom", encoded_path.path);

    try std.testing.expectError(
        error.InvalidServerReference,
        parse(allocator, "mqtt://user@other.example", .tcp),
    );
    try std.testing.expectError(
        error.InvalidServerReference,
        parse(allocator, "mqtt://other.example/path", .tcp),
    );
    try std.testing.expectError(
        error.UnsupportedRedirectScheme,
        parse(allocator, "file://other.example", .tcp),
    );
    try std.testing.expectError(
        error.InvalidServerReference,
        parse(allocator, "mqtt://other.example:0", .tcp),
    );
    try std.testing.expectError(
        error.InvalidServerReference,
        parse(allocator, "mqtt://bad_host.example", .tcp),
    );
}

test "MQTT redirect chain enforces opt-in transport and loop bounds" {
    const allocator = std.testing.allocator;
    var disabled = Chain.init(allocator, .{});
    defer disabled.deinit();
    try disabled.recordInitial("mqtt://a.example:1883", .tcp);
    try std.testing.expectError(
        error.RedirectLimitExceeded,
        disabled.follow(
            "mqtt://a.example:1883",
            "b.example:1883",
            0x9c,
        ),
    );

    var chain = Chain.init(allocator, .{ .max_redirects = 2 });
    defer chain.deinit();
    try chain.recordInitial("mqtt://a.example:1883", .tcp);
    var target = try chain.follow(
        "mqtt://a.example:1883",
        "b.example:1883",
        0x9c,
    );
    defer target.deinit();
    try std.testing.expectError(
        error.RedirectLoop,
        chain.follow(target.uri, "a.example:1883", 0x9d),
    );
    try std.testing.expectError(
        error.UnsupportedRedirectScheme,
        chain.follow(target.uri, "mqtts://c.example", 0x9c),
    );

    var canonical_loop = Chain.init(allocator, .{ .max_redirects = 1 });
    defer canonical_loop.deinit();
    try canonical_loop.recordInitial("MQTT://A.EXAMPLE", .tcp);
    try std.testing.expectError(
        error.RedirectLoop,
        canonical_loop.follow(
            "mqtt://a.example:1883",
            "a.example:1883",
            0x9c,
        ),
    );

    const Authorization = struct {
        fn deny(
            _: ?*anyopaque,
            _: []const u8,
            _: []const u8,
            _: u8,
        ) bool {
            return false;
        }
    };
    var guarded = Chain.init(allocator, .{
        .max_redirects = 1,
        .authorize = Authorization.deny,
    });
    defer guarded.deinit();
    try guarded.recordInitial("mqtt://a.example:1883", .tcp);
    try std.testing.expectError(
        error.RedirectRejected,
        guarded.follow(
            "mqtt://a.example:1883",
            "b.example:1883",
            0x9c,
        ),
    );
}

test "MQTT redirect reference requires matching reason and property" {
    try std.testing.expect((try referenceForConnAck(.{
        .session_present = false,
        .reason_code = 0,
    })) == null);
    try std.testing.expectError(
        error.InvalidServerReference,
        referenceForConnAck(.{
            .session_present = false,
            .reason_code = 0x9c,
        }),
    );
    var properties = [_]mqtt.Property{.{ .utf8 = .{
        .id = .server_reference,
        .value = "mqtt.example:1883",
    } }};
    try std.testing.expectEqualStrings(
        "mqtt.example:1883",
        (try referenceForDisconnect(.{
            .reason_code = 0x9d,
            .properties = &properties,
        })).?,
    );
    try std.testing.expect(
        (try referenceForDisconnect(.{
            .reason_code = 0,
            .properties = &properties,
        })) == null,
    );
}
