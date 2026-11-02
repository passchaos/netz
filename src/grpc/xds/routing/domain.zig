//! Virtual-host precedence and wildcard matching from grpc-core XdsRouting.
const std = @import("std");
pub const Kind = enum { exact, suffix, prefix, universe };
pub fn kind(pattern: []const u8) ?Kind {
    if (pattern.len == 0) return null;
    if (std.mem.indexOfScalar(u8, pattern, '*') == null) return .exact;
    if (std.mem.eql(u8, pattern, "*")) return .universe;
    // Only one edge wildcard is meaningful; never reinterpret interior stars.
    if (pattern[0] == '*' and std.mem.indexOfScalar(u8, pattern[1..], '*') == null) return .suffix;
    if (pattern[pattern.len - 1] == '*' and std.mem.indexOfScalar(u8, pattern[0 .. pattern.len - 1], '*') == null) return .prefix;
    return null;
}
pub fn matches(pattern: []const u8, host: []const u8) bool {
    return switch (kind(pattern) orelse return false) {
        .exact => std.ascii.eqlIgnoreCase(pattern, host),
        .universe => true,
        .suffix => host.len >= pattern.len and std.ascii.eqlIgnoreCase(pattern[1..], host[host.len - pattern.len + 1 ..]),
        .prefix => host.len >= pattern.len and std.ascii.eqlIgnoreCase(pattern[0 .. pattern.len - 1], host[0 .. pattern.len - 1]),
    };
}
/// Hosts expose `.domains`. Equal specificity retains the first virtual host.
pub fn select(hosts: anytype, authority: []const u8) ?usize {
    var best: ?usize = null;
    var best_kind: u8 = 255;
    var longest: usize = 0;
    for (hosts, 0..) |host, index| for (host.domains) |pattern| {
        const rank: u8 = @intFromEnum(kind(pattern) orelse continue);
        if (rank > best_kind or (rank == best_kind and pattern.len <= longest)) continue;
        if (!matches(pattern, authority)) continue;
        best = index;
        best_kind = rank;
        longest = pattern.len;
    };
    return best;
}
