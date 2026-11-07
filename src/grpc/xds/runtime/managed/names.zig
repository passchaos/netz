//! Owned global desired watches, partitioned by decoded bootstrap authority.
const std = @import("std");
const resource = @import("../../resource_name.zig");

pub const Names = struct {
    allocator: std.mem.Allocator,
    type_url: []u8,
    storage: []u8,
    values: [][]const u8,

    pub fn create(gpa: std.mem.Allocator, type_url: []const u8, names: []const []const u8) std.mem.Allocator.Error!Names {
        const owned_type = try gpa.dupe(u8, type_url);
        errdefer gpa.free(owned_type);
        var length: usize = 0;
        for (names) |name| length = std.math.add(usize, length, name.len) catch return error.OutOfMemory;
        const storage = try gpa.alloc(u8, length);
        errdefer gpa.free(storage);
        const values = try gpa.alloc([]const u8, names.len);
        var offset: usize = 0;
        for (names, values) |name, *copy| {
            copy.* = storage[offset..][0..name.len];
            @memcpy(storage[offset..][0..name.len], name);
            offset += name.len;
        }
        return .{ .allocator = gpa, .type_url = owned_type, .storage = storage, .values = values };
    }

    pub fn deinit(self: *Names) void {
        self.allocator.free(self.type_url);
        self.allocator.free(self.storage);
        self.allocator.free(self.values);
    }

    pub fn partition(self: *const Names, gpa: std.mem.Allocator, authority: []const u8) std.mem.Allocator.Error![]const []const u8 {
        var count: usize = 0;
        for (self.values) |name| if (belongs(name, authority)) {
            count += 1;
        };
        const values = try gpa.alloc([]const u8, count);
        var index: usize = 0;
        for (self.values) |name| if (belongs(name, authority)) {
            values[index] = name;
            index += 1;
        };
        return values;
    }
};

pub fn belongs(name: []const u8, authority: []const u8) bool {
    const parsed = resource.parse(name) catch return false;
    return if (parsed.authority) |encoded| resource.authorityMatches(encoded, authority) else authority.len == 0;
}
