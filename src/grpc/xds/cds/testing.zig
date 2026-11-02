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
