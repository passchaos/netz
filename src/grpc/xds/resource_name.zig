//! xDS resource names, including the `xdstp://` federation form.
const std = @import("std");

pub const Error = error{InvalidXdsResourceName};

pub const Parsed = struct {
    /// Null for old-style names without an authority.
    authority: ?[]const u8,
    /// Short resource type (`envoy.config...`) for xdstp names.
    type_url: ?[]const u8,
    id: []const u8,
};

const prefix = "xdstp://";
const any_prefix = "type.googleapis.com/";

/// Strip the protobuf Any prefix from a netz type URL.
pub fn shortType(type_url: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, type_url, any_prefix)) type_url[any_prefix.len..] else type_url;
}

/// Parse an old-style name or an `xdstp://authority/<short-type>/<id>` name.
pub fn parse(name: []const u8) Error!Parsed {
    if (!std.mem.startsWith(u8, name, "xdstp:")) {
        return .{ .authority = null, .type_url = null, .id = name };
    }
    if (!std.mem.startsWith(u8, name, prefix)) return error.InvalidXdsResourceName;
    const rest = name[prefix.len..];
    const authority_end = std.mem.indexOfScalar(u8, rest, '/') orelse return error.InvalidXdsResourceName;
    const authority = rest[0..authority_end];
    if (authority.len == 0) return error.InvalidXdsResourceName;
    const path = rest[authority_end + 1 ..];
    const type_end = std.mem.indexOfScalar(u8, path, '/') orelse return error.InvalidXdsResourceName;
    const type_url = path[0..type_end];
    const id = path[type_end + 1 ..];
    if (type_url.len == 0 or id.len == 0) return error.InvalidXdsResourceName;
    if (!std.unicode.utf8ValidateSlice(authority) or
        !std.unicode.utf8ValidateSlice(type_url) or
        !std.unicode.utf8ValidateSlice(id))
    {
        return error.InvalidXdsResourceName;
    }
    return .{ .authority = authority, .type_url = type_url, .id = id };
}

/// True when `name` is either an old-style name or an xdstp name whose
/// authority is in `authorities` and whose short type matches.
pub fn matchesAuthorities(
    name: []const u8,
    authorities: []const []const u8,
    type_url: []const u8,
) bool {
    const parsed = parse(name) catch return false;
    const parsed_authority = parsed.authority orelse return true;
    if (!std.mem.eql(u8, parsed.type_url.?, shortType(type_url))) return false;
    for (authorities) |authority| {
        if (std.mem.eql(u8, parsed_authority, authority)) return true;
    }
    return false;
}

/// Single-authority convenience wrapper.
pub fn matches(name: []const u8, authority: ?[]const u8, type_url: []const u8) bool {
    if (authority) |value| {
        return matchesAuthorities(name, &.{value}, type_url);
    }
    return matchesAuthorities(name, &.{}, type_url);
}

test "xDS resource names parse old-style and xdstp forms" {
    const old = try parse("backend");
    try std.testing.expect(old.authority == null);
    try std.testing.expect(old.type_url == null);
    try std.testing.expectEqualStrings("backend", old.id);

    const federated = try parse("xdstp://auth-1/envoy.config.cluster.v3.Cluster/cluster-a");
    try std.testing.expectEqualStrings("auth-1", federated.authority.?);
    try std.testing.expectEqualStrings("envoy.config.cluster.v3.Cluster", federated.type_url.?);
    try std.testing.expectEqualStrings("cluster-a", federated.id);

    const nested = try parse("xdstp://auth/envoy.config.route.v3.RouteConfiguration/route/a");
    try std.testing.expectEqualStrings("route/a", nested.id);

    for ([_][]const u8{
        "xdstp:",
        "xdstp://",
        "xdstp://auth",
        "xdstp://auth/",
        "xdstp://auth/type",
        "xdstp:///type/id",
        "xdstp://auth//id",
    }) |invalid| try std.testing.expectError(error.InvalidXdsResourceName, parse(invalid));
}

test "xDS resource name matching checks authority and short type" {
    try std.testing.expect(matches("backend", "auth", "type.googleapis.com/envoy.config.cluster.v3.Cluster"));
    try std.testing.expect(matches("xdstp://auth/envoy.config.cluster.v3.Cluster/c", "auth", "type.googleapis.com/envoy.config.cluster.v3.Cluster"));
    try std.testing.expect(!matches("xdstp://other/envoy.config.cluster.v3.Cluster/c", "auth", "type.googleapis.com/envoy.config.cluster.v3.Cluster"));
    try std.testing.expect(!matches("xdstp://auth/envoy.config.listener.v3.Listener/c", "auth", "type.googleapis.com/envoy.config.cluster.v3.Cluster"));
    try std.testing.expect(!matches("xdstp://auth/envoy.config.cluster.v3.Cluster/c", null, "type.googleapis.com/envoy.config.cluster.v3.Cluster"));
}

test "xDS resource name matching accepts several authorities" {
    try std.testing.expect(matchesAuthorities(
        "xdstp://auth-2/envoy.config.cluster.v3.Cluster/c",
        &.{ "auth-1", "auth-2" },
        "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    ));
    try std.testing.expect(!matchesAuthorities(
        "xdstp://auth-3/envoy.config.cluster.v3.Cluster/c",
        &.{ "auth-1", "auth-2" },
        "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    ));
    try std.testing.expect(matchesAuthorities(
        "old-style",
        &.{ "auth-1", "auth-2" },
        "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    ));
    try std.testing.expect(!matchesAuthorities(
        "xdstp://auth-1/envoy.config.cluster.v3.Cluster/c",
        &.{},
        "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    ));
}
