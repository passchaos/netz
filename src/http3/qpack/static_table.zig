//! QPACK static table from RFC 9204 Appendix A.

const std = @import("std");

pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

const StaticMatch = struct {
    index: u64,
    full_match: bool,
};

// RFC 9204 Appendix A static table.  Keeping the full table makes the
// bootstrap encoder interoperate with peers that use common indexed field
// lines without introducing dynamic-table state or head-of-line blocking.
pub const entries = [_]Entry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" },
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" },
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" },
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" },
};

pub fn get(index: usize) ?Entry {
    if (index >= entries.len) return null;
    return entries[index];
}

const name_index = std.StaticStringMap([]const u8).initComptime(.{
    .{ ":authority", &[_]u8{0} },
    .{ ":path", &[_]u8{1} },
    .{ "age", &[_]u8{2} },
    .{ "content-disposition", &[_]u8{3} },
    .{ "content-length", &[_]u8{4} },
    .{ "cookie", &[_]u8{5} },
    .{ "date", &[_]u8{6} },
    .{ "etag", &[_]u8{7} },
    .{ "if-modified-since", &[_]u8{8} },
    .{ "if-none-match", &[_]u8{9} },
    .{ "last-modified", &[_]u8{10} },
    .{ "link", &[_]u8{11} },
    .{ "location", &[_]u8{12} },
    .{ "referer", &[_]u8{13} },
    .{ "set-cookie", &[_]u8{14} },
    .{ ":method", &[_]u8{ 15, 16, 17, 18, 19, 20, 21 } },
    .{ ":scheme", &[_]u8{ 22, 23 } },
    .{ ":status", &[_]u8{ 24, 25, 26, 27, 28, 63, 64, 65, 66, 67, 68, 69, 70, 71 } },
    .{ "accept", &[_]u8{ 29, 30 } },
    .{ "accept-encoding", &[_]u8{31} },
    .{ "accept-ranges", &[_]u8{32} },
    .{ "access-control-allow-headers", &[_]u8{ 33, 34, 75 } },
    .{ "access-control-allow-origin", &[_]u8{35} },
    .{ "cache-control", &[_]u8{ 36, 37, 38, 39, 40, 41 } },
    .{ "content-encoding", &[_]u8{ 42, 43 } },
    .{ "content-type", &[_]u8{ 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54 } },
    .{ "range", &[_]u8{55} },
    .{ "strict-transport-security", &[_]u8{ 56, 57, 58 } },
    .{ "vary", &[_]u8{ 59, 60 } },
    .{ "x-content-type-options", &[_]u8{61} },
    .{ "x-xss-protection", &[_]u8{62} },
    .{ "accept-language", &[_]u8{72} },
    .{ "access-control-allow-credentials", &[_]u8{ 73, 74 } },
    .{ "access-control-allow-methods", &[_]u8{ 76, 77, 78 } },
    .{ "access-control-expose-headers", &[_]u8{79} },
    .{ "access-control-request-headers", &[_]u8{80} },
    .{ "access-control-request-method", &[_]u8{ 81, 82 } },
    .{ "alt-svc", &[_]u8{83} },
    .{ "authorization", &[_]u8{84} },
    .{ "content-security-policy", &[_]u8{85} },
    .{ "early-data", &[_]u8{86} },
    .{ "expect-ct", &[_]u8{87} },
    .{ "forwarded", &[_]u8{88} },
    .{ "if-range", &[_]u8{89} },
    .{ "origin", &[_]u8{90} },
    .{ "purpose", &[_]u8{91} },
    .{ "server", &[_]u8{92} },
    .{ "timing-allow-origin", &[_]u8{93} },
    .{ "upgrade-insecure-requests", &[_]u8{94} },
    .{ "user-agent", &[_]u8{95} },
    .{ "x-forwarded-for", &[_]u8{96} },
    .{ "x-frame-options", &[_]u8{ 97, 98 } },
});

pub fn findMatch(name: []const u8, value: []const u8) ?StaticMatch {
    if (fastPseudoHeaderMatch(name, value)) |match| return match;
    const indexes = name_index.get(name) orelse return null;
    // QPACK encoders probe the static table for every field section.  The
    // reference Zig implementations under ~/Work scan all 99 entries; keep a
    // no-allocation comptime name index so common fields inspect only their
    // small equivalence class while preserving RFC table-order tie breaking.
    for (indexes) |index| {
        const entry = entries[index];
        if (std.mem.eql(u8, entry.value, value)) {
            return .{ .index = index, .full_match = true };
        }
    }
    return .{ .index = indexes[0], .full_match = false };
}

pub fn findName(name: []const u8) ?u64 {
    if (fastPseudoHeaderName(name)) |index| return index;
    const indexes = name_index.get(name) orelse return null;
    return indexes[0];
}

fn fastPseudoHeaderMatch(
    name: []const u8,
    value: []const u8,
) ?StaticMatch {
    if (std.mem.eql(u8, name, ":method")) {
        if (std.mem.eql(u8, value, "CONNECT")) return .{ .index = 15, .full_match = true };
        if (std.mem.eql(u8, value, "DELETE")) return .{ .index = 16, .full_match = true };
        if (std.mem.eql(u8, value, "GET")) return .{ .index = 17, .full_match = true };
        if (std.mem.eql(u8, value, "HEAD")) return .{ .index = 18, .full_match = true };
        if (std.mem.eql(u8, value, "OPTIONS")) return .{ .index = 19, .full_match = true };
        if (std.mem.eql(u8, value, "POST")) return .{ .index = 20, .full_match = true };
        if (std.mem.eql(u8, value, "PUT")) return .{ .index = 21, .full_match = true };
        return .{ .index = 15, .full_match = false };
    }
    if (std.mem.eql(u8, name, ":scheme")) {
        if (std.mem.eql(u8, value, "http")) return .{ .index = 22, .full_match = true };
        if (std.mem.eql(u8, value, "https")) return .{ .index = 23, .full_match = true };
        return .{ .index = 22, .full_match = false };
    }
    if (std.mem.eql(u8, name, ":status")) {
        if (std.mem.eql(u8, value, "103")) return .{ .index = 24, .full_match = true };
        if (std.mem.eql(u8, value, "200")) return .{ .index = 25, .full_match = true };
        if (std.mem.eql(u8, value, "304")) return .{ .index = 26, .full_match = true };
        if (std.mem.eql(u8, value, "404")) return .{ .index = 27, .full_match = true };
        if (std.mem.eql(u8, value, "503")) return .{ .index = 28, .full_match = true };
        if (std.mem.eql(u8, value, "100")) return .{ .index = 63, .full_match = true };
        if (std.mem.eql(u8, value, "204")) return .{ .index = 64, .full_match = true };
        if (std.mem.eql(u8, value, "206")) return .{ .index = 65, .full_match = true };
        if (std.mem.eql(u8, value, "302")) return .{ .index = 66, .full_match = true };
        if (std.mem.eql(u8, value, "400")) return .{ .index = 67, .full_match = true };
        if (std.mem.eql(u8, value, "403")) return .{ .index = 68, .full_match = true };
        if (std.mem.eql(u8, value, "421")) return .{ .index = 69, .full_match = true };
        if (std.mem.eql(u8, value, "425")) return .{ .index = 70, .full_match = true };
        if (std.mem.eql(u8, value, "500")) return .{ .index = 71, .full_match = true };
        return .{ .index = 24, .full_match = false };
    }
    if (std.mem.eql(u8, name, ":authority")) {
        return .{ .index = 0, .full_match = value.len == 0 };
    }
    if (std.mem.eql(u8, name, ":path")) {
        return .{ .index = 1, .full_match = std.mem.eql(u8, value, "/") };
    }
    if (std.mem.eql(u8, name, "content-length")) {
        return .{ .index = 4, .full_match = std.mem.eql(u8, value, "0") };
    }
    if (std.mem.eql(u8, name, "accept")) {
        if (std.mem.eql(u8, value, "*/*")) return .{ .index = 29, .full_match = true };
        if (std.mem.eql(u8, value, "application/dns-message")) return .{ .index = 30, .full_match = true };
        return null;
    }
    if (std.mem.eql(u8, name, "accept-encoding")) {
        return .{ .index = 31, .full_match = std.mem.eql(u8, value, "gzip, deflate, br") };
    }
    if (std.mem.eql(u8, name, "cache-control")) {
        if (std.mem.eql(u8, value, "max-age=0")) return .{ .index = 36, .full_match = true };
        if (std.mem.eql(u8, value, "no-cache")) return .{ .index = 39, .full_match = true };
        if (std.mem.eql(u8, value, "no-store")) return .{ .index = 40, .full_match = true };
        return null;
    }
    if (std.mem.eql(u8, name, "content-type")) {
        if (std.mem.eql(u8, value, "application/json")) return .{ .index = 46, .full_match = true };
        if (std.mem.eql(u8, value, "text/html; charset=utf-8")) return .{ .index = 52, .full_match = true };
        if (std.mem.eql(u8, value, "text/plain")) return .{ .index = 53, .full_match = true };
        return null;
    }
    return null;
}

fn fastPseudoHeaderName(name: []const u8) ?u64 {
    if (std.mem.eql(u8, name, ":authority")) return 0;
    if (std.mem.eql(u8, name, ":path")) return 1;
    if (std.mem.eql(u8, name, ":method")) return 15;
    if (std.mem.eql(u8, name, ":scheme")) return 22;
    if (std.mem.eql(u8, name, ":status")) return 24;
    if (std.mem.eql(u8, name, "content-length")) return 4;
    if (std.mem.eql(u8, name, "accept")) return 29;
    if (std.mem.eql(u8, name, "accept-encoding")) return 31;
    if (std.mem.eql(u8, name, "cache-control")) return 36;
    if (std.mem.eql(u8, name, "content-type")) return 44;
    return null;
}
