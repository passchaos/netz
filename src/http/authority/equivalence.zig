//! Scheme-based HTTP authority comparison without DNS or allocations.
const std = @import("std");
const parser = @import("parse.zig");

pub fn defaultPort(scheme: []const u8) ?u16 {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return 80;
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return 443;
    return null;
}

pub fn equivalent(scheme: []const u8, left: []const u8, right: []const u8) bool {
    const a = parser.parse(left) catch return false;
    const b = parser.parse(right) catch return false;
    const a_port: ?u16 = a.port orelse defaultPort(scheme);
    const b_port: ?u16 = b.port orelse defaultPort(scheme);
    if (a_port != b_port or a.kind != b.kind) return false;
    if (a.kind == .ipv6) return std.mem.eql(u8, &a.address, &b.address);
    var a_index: usize = 0;
    var b_index: usize = 0;
    while (a_index < a.host.len and b_index < b.host.len) {
        if (next(a.host, &a_index) != next(b.host, &b_index)) return false;
    }
    return a_index == a.host.len and b_index == b.host.len;
}

fn next(host: []const u8, index: *usize) u8 {
    const byte = host[index.*];
    if (byte == '%') {
        const decoded = (std.fmt.charToDigit(host[index.* + 1], 16) catch unreachable) * 16 +
            (std.fmt.charToDigit(host[index.* + 2], 16) catch unreachable);
        if (parser.unreserved(decoded)) {
            index.* += 3;
            return std.ascii.toLower(decoded);
        }
    }
    index.* += 1;
    return std.ascii.toLower(byte);
}
