//! Owned endpoint defaults and borrowed per-request HTTP authority selection.
const std = @import("std");
const http2 = @import("../../mod.zig");

/// HTTP origin authority excludes IPv6 socket interface/flow metadata. The
/// standard address formatter supplies brackets and an explicit numeric port.
pub fn ipAlloc(allocator: std.mem.Allocator, address: std.Io.net.IpAddress) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{f}", .{address});
}

/// Allocate before retiring the previous value, including when the input
/// borrows that value. OOM leaves the connection's authority owned and valid.
pub fn replace(allocator: std.mem.Allocator, destination: *?[]u8, value: []const u8) std.mem.Allocator.Error!void {
    const owned = try allocator.dupe(u8, value);
    if (destination.*) |previous| allocator.free(previous);
    destination.* = owned;
}

/// Caller :authority, translated HTTP/1 Host, then the connection's endpoint.
/// Header validation still rejects duplicate Host fields and disagreements
/// between an explicit :authority and Host before the request reaches I/O.
pub fn resolve(explicit: ?[]const u8, headers: []const http2.Hpack.HeaderField, fallback: ?[]const u8) ?[]const u8 {
    if (explicit) |value| return value;
    for (headers) |field| if (std.ascii.eqlIgnoreCase(field.name, "host")) return field.value;
    return fallback;
}

test "HTTP/2 IP authority brackets IPv6 and excludes socket scope metadata" {
    const allocator = std.testing.allocator;
    var address: std.Io.net.IpAddress = .{ .ip6 = .loopback(443) };
    address.ip6.interface = .{ .index = 123 };
    address.ip6.flow = 99;
    const authority = try ipAlloc(allocator, address);
    defer allocator.free(authority);
    try std.testing.expectEqualStrings("[::1]:443", authority);
}

test "HTTP/2 IP authority replacement preserves ownership on OOM and aliasing" {
    const allocator = std.testing.allocator;
    var owned: ?[]u8 = try allocator.dupe(u8, "old.example:80");
    defer if (owned) |bytes| allocator.free(bytes);
    const original = owned.?.ptr;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, replace(failing.allocator(), &owned, "new.example:443"));
    try std.testing.expectEqual(original, owned.?.ptr);
    try std.testing.expectEqualStrings("old.example:80", owned.?);
    try replace(allocator, &owned, owned.?[4..]);
    try std.testing.expectEqualStrings("example:80", owned.?);
}
