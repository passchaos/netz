//! xDS resource names, including the `xdstp://` federation form.
const std = @import("std");

pub const Error = error{InvalidXdsResourceName};

pub const Parsed = struct {
    /// Borrowed URI-encoded bytes; null for old-style names. Percent escapes
    /// and the decoded UTF-8 are validated. Bootstrap names use decoded bytes.
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
    _ = try authorityLength(authority);
    if (!std.unicode.utf8ValidateSlice(type_url) or
        !std.unicode.utf8ValidateSlice(id))
    {
        return error.InvalidXdsResourceName;
    }
    return .{ .authority = authority, .type_url = type_url, .id = id };
}

fn authorityByte(encoded: []const u8, offset: *usize) Error!?u8 {
    if (offset.* == encoded.len) return null;
    const byte = encoded[offset.*];
    if (byte != '%') {
        offset.* += 1;
        return byte;
    }
    if (encoded.len - offset.* < 3) return error.InvalidXdsResourceName;
    const high = std.fmt.charToDigit(encoded[offset.* + 1], 16) catch return error.InvalidXdsResourceName;
    const low = std.fmt.charToDigit(encoded[offset.* + 2], 16) catch return error.InvalidXdsResourceName;
    offset.* += 3;
    return high * 16 + low;
}

/// Validate decoded UTF-8 one code point at a time without allocating.
fn authorityLength(encoded: []const u8) Error!usize {
    if (encoded.len == 0) return error.InvalidXdsResourceName;
    var offset: usize = 0;
    var length: usize = 0;
    while (try authorityByte(encoded, &offset)) |first| {
        const count = std.unicode.utf8ByteSequenceLength(first) catch return error.InvalidXdsResourceName;
        var bytes: [4]u8 = undefined;
        bytes[0] = first;
        for (1..count) |index| bytes[index] = (try authorityByte(encoded, &offset)) orelse return error.InvalidXdsResourceName;
        _ = std.unicode.utf8Decode(bytes[0..count]) catch return error.InvalidXdsResourceName;
        length += count;
    }
    return length;
}

/// Decode an authority for case-sensitive Bootstrap lookup. The caller owns
/// the result. Decoding happens once: `%252F` becomes `%2F`, not `/`.
pub fn decodeAuthority(gpa: std.mem.Allocator, encoded: []const u8) (std.mem.Allocator.Error || Error)![]u8 {
    const result = try gpa.alloc(u8, try authorityLength(encoded));
    var offset: usize = 0;
    for (result) |*byte| byte.* = (authorityByte(encoded, &offset) catch unreachable).?;
    return result;
}

/// Compare a URI-encoded authority with a raw Bootstrap name, preserving case.
/// Invalid escapes or decoded UTF-8 never match. This does not allocate.
pub fn authorityMatches(encoded: []const u8, raw: []const u8) bool {
    if (!std.unicode.utf8ValidateSlice(raw)) return false;
    const length = authorityLength(encoded) catch return false;
    if (length != raw.len) return false;
    var offset: usize = 0;
    for (raw) |byte| if ((authorityByte(encoded, &offset) catch unreachable).? != byte) return false;
    return true;
}

/// True for an old-style name or an xdstp name whose decoded authority is in
/// the raw Bootstrap `authorities` and whose short type matches.
pub fn matchesAuthorities(
    name: []const u8,
    authorities: []const []const u8,
    type_url: []const u8,
) bool {
    const parsed = parse(name) catch return false;
    const parsed_authority = parsed.authority orelse return true;
    if (!std.mem.eql(u8, parsed.type_url.?, shortType(type_url))) return false;
    for (authorities) |authority| {
        if (authorityMatches(parsed_authority, authority)) return true;
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

test "xDS authorities decode escapes once and retain case-sensitive lookup" {
    const gpa = std.testing.allocator;
    for ([_]struct { encoded: []const u8, raw: []const u8 }{
        .{ .encoded = "a%2Fb", .raw = "a/b" },
        .{ .encoded = "a%2fb", .raw = "a/b" },
        .{ .encoded = "%25%E5%90%8D", .raw = "%名" },
        .{ .encoded = "名", .raw = "名" },
        .{ .encoded = "%252F", .raw = "%2F" },
        .{ .encoded = "%41uth", .raw = "Auth" },
    }) |case| {
        const decoded = try decodeAuthority(gpa, case.encoded);
        defer gpa.free(decoded);
        try std.testing.expectEqualStrings(case.raw, decoded);
        try std.testing.expect(authorityMatches(case.encoded, case.raw));
    }
    const parsed = try parse("xdstp://a%2Fb/type/id");
    try std.testing.expectEqualStrings("a%2Fb", parsed.authority.?);
    try std.testing.expect(matches("xdstp://a%2Fb/type/id", "a/b", "type"));
    try std.testing.expect(!authorityMatches("%41uth", "auth"));
    for ([_][]const u8{ "%", "%2", "%GG", "%FF", "%C0%AF", "%E5%90", "%ED%A0%80", "\xff" }) |invalid| {
        try std.testing.expectError(error.InvalidXdsResourceName, decodeAuthority(gpa, invalid));
        try std.testing.expect(!authorityMatches(invalid, invalid));
        const name = try std.fmt.allocPrint(gpa, "xdstp://{s}/type/id", .{invalid});
        defer gpa.free(name);
        try std.testing.expectError(error.InvalidXdsResourceName, parse(name));
    }
}
