//! Explicit browser-origin policy for gRPC-Web's POST and OPTIONS exchange.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");

pub const Error = error{ InvalidCorsPolicy, InvalidCorsRequest };

pub const Policy = struct {
    allowed_origins: []const []const u8 = &.{},
    allow_any_origin: bool = false,
    allow_credentials: bool = false,
    allowed_headers: []const []const u8 = &.{
        "content-type", "x-grpc-web",    "x-user-agent",         "authorization",
        "grpc-timeout", "grpc-encoding", "grpc-accept-encoding",
    },
    exposed_headers: []const []const u8 = &.{
        "grpc-status",   "grpc-message",         "grpc-status-details-bin",
        "grpc-encoding", "grpc-accept-encoding",
    },
    max_age_seconds: u32 = 600,

    pub fn validate(self: Policy) Error!void {
        if (self.allow_any_origin and (self.allow_credentials or self.allowed_origins.len != 0)) return error.InvalidCorsPolicy;
        for (self.allowed_origins) |origin| _ = parseOrigin(origin) catch return error.InvalidCorsPolicy;
        for (self.allowed_headers) |name| if (!headerName(name)) return error.InvalidCorsPolicy;
        for (self.exposed_headers) |name| if (!headerName(name)) return error.InvalidCorsPolicy;
    }
};

pub const Decision = struct {
    kind: enum { none, allowed, preflight, denied },
    /// Borrows the validated request field, or the static wildcard string.
    origin: ?[]const u8 = null,
};

/// Origin and requested method are singular. Requested header lists may span
/// repeated HTTP fields; every name must be explicitly permitted by policy.
pub fn evaluate(policy: Policy, method: []const u8, headers: []const http2.Hpack.HeaderField) Error!Decision {
    try policy.validate();
    const origin_raw = try single(headers, "origin");
    const requested_method = try single(headers, "access-control-request-method");
    const preflight = std.mem.eql(u8, method, "OPTIONS") and requested_method != null;
    if (origin_raw == null) {
        if (requested_method != null or hasHeader(headers, "access-control-request-headers")) return error.InvalidCorsRequest;
        return .{ .kind = .none };
    }
    const origin = std.mem.trim(u8, origin_raw.?, " \t");
    const parsed = try parseOrigin(origin);
    if (!preflight and (requested_method != null or hasHeader(headers, "access-control-request-headers"))) return error.InvalidCorsRequest;
    var permitted = policy.allow_any_origin;
    for (policy.allowed_origins) |allowed| {
        if (parsed.eql(try parseOrigin(allowed))) permitted = true;
    }
    if (!permitted) return .{ .kind = .denied };
    if (preflight) {
        if (!std.mem.eql(u8, std.mem.trim(u8, requested_method.?, " \t"), "POST")) return .{ .kind = .denied };
        for (headers) |field| {
            if (!std.ascii.eqlIgnoreCase(field.name, "access-control-request-headers")) continue;
            const list = std.mem.trim(u8, field.value, " \t");
            if (list.len == 0) continue;
            var names = std.mem.splitScalar(u8, list, ',');
            while (names.next()) |raw| {
                const name = std.mem.trim(u8, raw, " \t");
                if (!headerName(name)) return error.InvalidCorsRequest;
                var found = false;
                for (policy.allowed_headers) |allowed| if (std.ascii.eqlIgnoreCase(name, allowed)) {
                    found = true;
                    break;
                };
                if (!found) return .{ .kind = .denied };
            }
        }
    }
    return .{ .kind = if (preflight) .preflight else .allowed, .origin = if (policy.allow_any_origin) "*" else origin };
}

fn hasHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) bool {
    for (headers) |field| if (std.ascii.eqlIgnoreCase(field.name, name)) return true;
    return false;
}

fn single(headers: []const http2.Hpack.HeaderField, name: []const u8) Error!?[]const u8 {
    var result: ?[]const u8 = null;
    for (headers) |field| {
        if (!std.ascii.eqlIgnoreCase(field.name, name)) continue;
        if (result != null) return error.InvalidCorsRequest;
        result = field.value;
    }
    return result;
}

fn headerName(name: []const u8) bool {
    if (name.len == 0 or std.mem.eql(u8, name, "*")) return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) == null) return false;
    }
    return true;
}

const Origin = struct {
    scheme: []const u8 = "",
    host: []const u8 = "",
    port: ?u16 = null,
    is_opaque: bool = false,
    fn eql(a: Origin, b: Origin) bool {
        return a.is_opaque == b.is_opaque and a.port == b.port and std.ascii.eqlIgnoreCase(a.scheme, b.scheme) and std.ascii.eqlIgnoreCase(a.host, b.host);
    }
};

fn parseOrigin(raw: []const u8) Error!Origin {
    if (std.mem.eql(u8, raw, "null")) return .{ .is_opaque = true };
    for (raw) |byte| if (byte <= 0x20 or byte > 0x7e or byte == '%' or byte == '\\') return error.InvalidCorsRequest;
    const uri = std.Uri.parse(raw) catch return error.InvalidCorsRequest;
    if (uri.scheme.len == 0 or !std.ascii.isAlphabetic(uri.scheme[0])) return error.InvalidCorsRequest;
    for (uri.scheme) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "+-.", byte) == null) return error.InvalidCorsRequest;
    if (uri.host == null or uri.user != null or uri.password != null or !uri.path.isEmpty() or uri.query != null or uri.fragment != null) return error.InvalidCorsRequest;
    const host = switch (uri.host.?) {
        .raw, .percent_encoded => |value| value,
    };
    if (host.len == 0) return error.InvalidCorsRequest;
    const port = uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) @as(?u16, 443) else if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) @as(?u16, 80) else null;
    return .{ .scheme = uri.scheme, .host = host, .port = port };
}
