//! Set-Cookie syntax and attribute parsing without storage policy.

const std = @import("std");
const cookie_date = @import("date.zig");

const max_attribute_value_bytes: usize = 1024;

pub const SameSite = enum {
    default,
    strict,
    lax,
    none,
};

pub const ParsedCookie = struct {
    name: []const u8,
    value: []const u8,
    domain: ?[]const u8 = null,
    path: ?[]const u8 = null,
    expires_at: ?i64 = null,
    secure: bool = false,
    http_only: bool = false,
    partitioned: bool = false,
    same_site: SameSite = .default,
};

pub fn parse(
    value: []const u8,
    max_cookie_bytes: usize,
    now: i64,
) ?ParsedCookie {
    for (value) |byte| {
        if ((byte <= 0x08) or (byte >= 0x0a and byte <= 0x1f) or
            byte == 0x7f) return null;
    }
    var members = std.mem.splitScalar(u8, value, ';');
    const pair = trim(members.next() orelse return null);
    const equal = std.mem.indexOfScalar(u8, pair, '=');
    const name = trim(if (equal) |at| pair[0..at] else &.{});
    const cookie_value = trim(if (equal) |at| pair[at + 1 ..] else pair);
    if ((name.len == 0 and cookie_value.len == 0) or
        name.len > max_cookie_bytes or
        cookie_value.len > max_cookie_bytes - name.len)
    {
        return null;
    }

    var result = ParsedCookie{ .name = name, .value = cookie_value };
    var max_age: ?i64 = null;
    while (members.next()) |raw_attribute| {
        const attribute = trim(raw_attribute);
        if (attribute.len == 0) continue;
        const separator = std.mem.indexOfScalar(u8, attribute, '=');
        const attribute_name = trim(if (separator) |at|
            attribute[0..at]
        else
            attribute);
        const attribute_value = trim(if (separator) |at|
            attribute[at + 1 ..]
        else
            &.{});

        if (std.ascii.eqlIgnoreCase(attribute_name, "expires")) {
            if (cookie_date.parse(attribute_value)) |deadline| {
                result.expires_at = deadline;
            }
        } else if (std.ascii.eqlIgnoreCase(attribute_name, "max-age")) {
            if (parseMaxAge(attribute_value)) |seconds| max_age = seconds;
        } else if (std.ascii.eqlIgnoreCase(attribute_name, "domain")) {
            if (attribute_value.len <= max_attribute_value_bytes) {
                result.domain = attribute_value;
            }
        } else if (std.ascii.eqlIgnoreCase(attribute_name, "path")) {
            if (attribute_value.len <= max_attribute_value_bytes) {
                result.path = attribute_value;
            }
        } else if (std.ascii.eqlIgnoreCase(attribute_name, "secure")) {
            result.secure = true;
        } else if (std.ascii.eqlIgnoreCase(attribute_name, "httponly")) {
            result.http_only = true;
        } else if (std.ascii.eqlIgnoreCase(attribute_name, "partitioned")) {
            result.partitioned = true;
        } else if (std.ascii.eqlIgnoreCase(attribute_name, "samesite")) {
            result.same_site = if (std.ascii.eqlIgnoreCase(
                attribute_value,
                "strict",
            ))
                .strict
            else if (std.ascii.eqlIgnoreCase(attribute_value, "lax"))
                .lax
            else if (std.ascii.eqlIgnoreCase(attribute_value, "none"))
                .none
            else
                .default;
        }
    }

    if (max_age) |seconds| {
        result.expires_at = if (seconds <= 0)
            now -| 1
        else
            std.math.add(i64, now, seconds) catch std.math.maxInt(i64);
    }
    return result;
}

fn parseMaxAge(value: []const u8) ?i64 {
    if (value.len == 0) return null;
    var index: usize = 0;
    var negative = false;
    if (value[0] == '-') {
        negative = true;
        index = 1;
    } else if (value[0] == '+') {
        return null;
    }
    if (index == value.len) return null;
    var magnitude: u64 = 0;
    for (value[index..]) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
        magnitude = std.math.mul(u64, magnitude, 10) catch
            std.math.maxInt(u64);
        magnitude = std.math.add(u64, magnitude, byte - '0') catch
            std.math.maxInt(u64);
    }
    if (negative) return if (magnitude == 0) 0 else std.math.minInt(i64);
    return @intCast(@min(magnitude, @as(u64, std.math.maxInt(i64))));
}

fn trim(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

test {
    _ = cookie_date;
}

test "Set-Cookie syntax validates pair and attribute grammar" {
    const parsed = parse(
        "sid=\"a:b\"; Domain=.Example.COM; Path=/docs; " ++
            "Secure; HttpOnly; SameSite=Lax; Max-Age=60",
        4096,
        100,
    ).?;
    try std.testing.expectEqualStrings("sid", parsed.name);
    try std.testing.expectEqualStrings("\"a:b\"", parsed.value);
    try std.testing.expectEqualStrings(".Example.COM", parsed.domain.?);
    try std.testing.expectEqualStrings("/docs", parsed.path.?);
    try std.testing.expect(parsed.secure);
    try std.testing.expect(parsed.http_only);
    try std.testing.expect(!parsed.partitioned);
    try std.testing.expectEqual(SameSite.lax, parsed.same_site);
    try std.testing.expectEqual(@as(?i64, 160), parsed.expires_at);

    try std.testing.expectEqualStrings(
        "bad name",
        parse("bad name=x", 4096, 0).?.name,
    );
    try std.testing.expectEqualStrings(
        "bad value",
        parse("name=bad value", 4096, 0).?.value,
    );
    try std.testing.expectEqualStrings(
        "value-only",
        parse("value-only", 4096, 0).?.value,
    );
    try std.testing.expect(parse("name=bad\x7fvalue", 4096, 0) == null);
    try std.testing.expect(parse("=", 4096, 0) == null);
    try std.testing.expect(parse("name=value", 8, 0) == null);
}

test "Set-Cookie syntax recognizes Partitioned case-insensitively" {
    try std.testing.expect(parse(
        "sid=one; pArTiTiOnEd=value",
        4096,
        0,
    ).?.partitioned);
}

test "Set-Cookie Max-Age is strict saturating and overrides Expires" {
    try std.testing.expectEqual(
        @as(?i64, 9),
        parse(
            "a=1; Expires=Fri, 31 Dec 9999 23:59:59 GMT; Max-Age=0",
            4096,
            10,
        ).?.expires_at,
    );
    try std.testing.expectEqual(
        @as(?i64, std.math.maxInt(i64)),
        parse(
            "a=1; Max-Age=999999999999999999999999999999",
            4096,
            10,
        ).?.expires_at,
    );
    try std.testing.expect(
        parse("a=1; Max-Age=+1", 4096, 10).?.expires_at == null,
    );
}
