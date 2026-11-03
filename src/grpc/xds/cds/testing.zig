//! Small wire fixtures; interop uses the independent official Envoy schemas.
const std = @import("std");
pub const Builder = struct {
    allocator: std.mem.Allocator,
    data: std.ArrayList(u8) = .empty,
    pub fn deinit(self: *Builder) void {
        self.data.deinit(self.allocator);
    }
    fn integer(self: *Builder, raw: u64) !void {
        var value = raw;
        while (value >= 128) : (value >>= 7) try self.data.append(self.allocator, @as(u8, @truncate(value)) | 0x80);
        try self.data.append(self.allocator, @intCast(value));
    }
    pub fn number(self: *Builder, field: u32, value: u64) !void {
        try self.integer(@as(u64, field) * 8);
        try self.integer(value);
    }
    pub fn bytes(self: *Builder, field: u32, value: []const u8) !void {
        try self.integer(@as(u64, field) * 8 + 2);
        try self.integer(value.len);
        try self.data.appendSlice(self.allocator, value);
    }
    pub fn wrapper(self: *Builder, field: u32, value: u64) !void {
        var nested = Builder{ .allocator = self.allocator };
        defer nested.deinit();
        try nested.number(1, value);
        try self.bytes(field, nested.data.items);
    }
};
pub fn cluster(gpa: std.mem.Allocator, name: []const u8, service: []const u8, extra: []const u8) ![]u8 {
    var builder = Builder{ .allocator = gpa };
    errdefer builder.deinit();
    try builder.bytes(1, name);
    try builder.number(2, 3);
    var config = Builder{ .allocator = gpa };
    defer config.deinit();
    try config.bytes(1, "\x1a\x00"); // ConfigSource.ads
    try config.bytes(2, service);
    try builder.bytes(3, config.data.items);
    try builder.data.appendSlice(gpa, extra);
    return builder.data.toOwnedSlice(gpa);
}
pub const Host = struct { host: []const u8, port: u16 };
pub fn assignment(gpa: std.mem.Allocator, name: []const u8, host: []const u8, port: u16) ![]u8 {
    return assignmentHosts(gpa, name, &.{.{ .host = host, .port = port }});
}
pub fn assignmentHosts(gpa: std.mem.Allocator, name: []const u8, hosts: []const Host) ![]u8 {
    var locality = Builder{ .allocator = gpa };
    defer locality.deinit();
    try locality.bytes(1, "");
    try locality.wrapper(3, 1);
    for (hosts) |host| {
        var socket = Builder{ .allocator = gpa };
        defer socket.deinit();
        try socket.bytes(2, host.host);
        try socket.number(3, host.port);
        var address = Builder{ .allocator = gpa };
        defer address.deinit();
        try address.bytes(1, socket.data.items);
        var endpoint = Builder{ .allocator = gpa };
        defer endpoint.deinit();
        try endpoint.bytes(1, address.data.items);
        var lb = Builder{ .allocator = gpa };
        defer lb.deinit();
        try lb.bytes(1, endpoint.data.items);
        try locality.bytes(2, lb.data.items);
    }
    var out = Builder{ .allocator = gpa };
    errdefer out.deinit();
    try out.bytes(1, name);
    try out.bytes(2, locality.data.items);
    return out.data.toOwnedSlice(gpa);
}
pub fn staticCluster(gpa: std.mem.Allocator, name: []const u8, host: []const u8, port: u16) ![]u8 {
    return discoveryCluster(gpa, name, host, port, 0);
}
pub fn dnsCluster(gpa: std.mem.Allocator, name: []const u8, host: []const u8, port: u16, kind: u32) ![]u8 {
    return discoveryCluster(gpa, name, host, port, kind);
}
pub fn dnsClusterHosts(gpa: std.mem.Allocator, name: []const u8, kind: u32, hosts: []const Host) ![]u8 {
    const assign = try assignmentHosts(gpa, name, hosts);
    defer gpa.free(assign);
    return discoveryClusterBytes(gpa, name, kind, assign);
}
fn discoveryCluster(gpa: std.mem.Allocator, name: []const u8, host: []const u8, port: u16, kind: u32) ![]u8 {
    const assign = try assignment(gpa, name, host, port);
    defer gpa.free(assign);
    return discoveryClusterBytes(gpa, name, kind, assign);
}
fn discoveryClusterBytes(gpa: std.mem.Allocator, name: []const u8, kind: u32, assign: []const u8) ![]u8 {
    var builder = Builder{ .allocator = gpa };
    errdefer builder.deinit();
    try builder.bytes(1, name);
    try builder.number(2, kind);
    try builder.bytes(33, assign);
    return builder.data.toOwnedSlice(gpa);
}
pub fn typed(gpa: std.mem.Allocator, type_url: []const u8, payload: []const u8) ![]u8 {
    var any = Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, type_url);
    try any.bytes(2, payload);
    var extension = Builder{ .allocator = gpa };
    defer extension.deinit();
    try extension.bytes(2, any.data.items);
    var policy = Builder{ .allocator = gpa };
    defer policy.deinit();
    try policy.bytes(4, extension.data.items);
    var out = Builder{ .allocator = gpa };
    errdefer out.deinit();
    try out.bytes(1, policy.data.items);
    return out.data.toOwnedSlice(gpa);
}
