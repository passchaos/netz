//! Stack-first unique address collection shared by system DNS callers.
const std = @import("std");
const net = std.Io.net;

pub const stack_capacity: usize = 16;

pub const Collector = struct {
    allocator: std.mem.Allocator,
    stack: [stack_capacity]net.IpAddress = undefined,
    stack_len: usize = 0,
    overflow: std.ArrayList(net.IpAddress) = .empty,

    pub fn init(allocator: std.mem.Allocator) Collector {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Collector) void {
        self.overflow.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn items(self: *const Collector) []const net.IpAddress {
        if (self.overflow.items.len != 0) return self.overflow.items;
        return self.stack[0..self.stack_len];
    }

    pub fn count(self: *const Collector) usize {
        return self.items().len;
    }

    pub fn appendUnique(
        self: *Collector,
        address: net.IpAddress,
    ) std.mem.Allocator.Error!void {
        for (self.items()) |*existing| {
            if (existing.eql(&address)) return;
        }
        if (self.overflow.items.len != 0) {
            try self.overflow.append(self.allocator, address);
            return;
        }
        if (self.stack_len < self.stack.len) {
            self.stack[self.stack_len] = address;
            self.stack_len += 1;
            return;
        }
        var overflow = try std.ArrayList(net.IpAddress).initCapacity(
            self.allocator,
            self.stack.len + 1,
        );
        overflow.appendSliceAssumeCapacity(self.stack[0..self.stack_len]);
        overflow.appendAssumeCapacity(address);
        self.overflow = overflow;
    }

    pub fn toOwnedSlice(
        self: *Collector,
    ) std.mem.Allocator.Error![]net.IpAddress {
        if (self.overflow.items.len != 0) {
            return self.overflow.toOwnedSlice(self.allocator);
        }
        return self.allocator.dupe(
            net.IpAddress,
            self.stack[0..self.stack_len],
        );
    }
};
