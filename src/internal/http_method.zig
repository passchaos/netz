const std = @import("std");

/// RFC 9110 method names use the case-sensitive `token` grammar.
pub fn isToken(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    for (bytes) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            else => false,
        })) return false;
    }
    return true;
}

/// Safe registered methods known to the library. Unknown extensions remain
/// conservative because their semantics cannot be inferred from their name.
pub fn isSafe(bytes: []const u8) bool {
    return std.mem.eql(u8, bytes, "GET") or
        std.mem.eql(u8, bytes, "HEAD") or
        std.mem.eql(u8, bytes, "OPTIONS") or
        std.mem.eql(u8, bytes, "TRACE") or
        std.mem.eql(u8, bytes, "QUERY");
}

/// Idempotent registered methods known to the library. QUERY is registered as
/// both safe and idempotent by RFC 10008.
pub fn isIdempotent(bytes: []const u8) bool {
    return isSafe(bytes) or
        std.mem.eql(u8, bytes, "PUT") or
        std.mem.eql(u8, bytes, "DELETE");
}

test "HTTP method token and retry semantics are case sensitive" {
    try std.testing.expect(isToken("!#$%&'*+-.^_`|~Az09"));
    try std.testing.expect(!isToken(""));
    try std.testing.expect(!isToken("BAD METHOD"));
    try std.testing.expect(!isToken("BAD:METHOD"));
    try std.testing.expect(!isToken("M\xc3\x89THOD"));

    try std.testing.expect(isSafe("QUERY"));
    try std.testing.expect(isIdempotent("QUERY"));
    try std.testing.expect(isIdempotent("PUT"));
    try std.testing.expect(!isIdempotent("query"));
    try std.testing.expect(!isIdempotent("PATCH"));
    try std.testing.expect(!isIdempotent("PURGE"));
}
