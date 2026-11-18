//! Amortized O(1) FIFO queue with an explicit front index.
//!
//! `std.ArrayList.orderedRemove(0)` shifts every remaining element on each
//! pop. Command and task queues only need FIFO order, so they retain the
//! backing array and advance a head index instead. The consumed prefix is
//! compacted once it is both non-trivial and at least half the array.

const std = @import("std");

pub fn Fifo(comptime T: type) type {
    return struct {
        const Self = @This();
        const compact_threshold = 32;

        pub const empty: Self = .{};

        items: std.ArrayList(T) = .empty,
        head: usize = 0,

        pub fn len(self: *const Self) usize {
            return self.items.items.len - self.head;
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.head == self.items.items.len;
        }

        /// Live entries in FIFO order. The slice is invalidated by append,
        /// pop, clear, or deinit.
        pub fn slice(self: *const Self) []T {
            return self.items.items[self.head..];
        }

        pub fn append(self: *Self, allocator: std.mem.Allocator, value: T) !void {
            try self.items.append(allocator, value);
        }

        pub fn ensureUnusedCapacity(self: *Self, allocator: std.mem.Allocator, additional: usize) !void {
            try self.items.ensureUnusedCapacity(allocator, additional);
        }

        pub fn ensureTotalCapacity(self: *Self, allocator: std.mem.Allocator, new_capacity: usize) !void {
            try self.items.ensureTotalCapacity(allocator, new_capacity);
        }

        /// Front entry without removing it. Caller must ensure `!isEmpty()`.
        pub fn front(self: *const Self) T {
            return self.items.items[self.head];
        }

        pub fn appendAssumeCapacity(self: *Self, value: T) void {
            self.items.appendAssumeCapacity(value);
        }

        pub fn popFront(self: *Self) ?T {
            if (self.isEmpty()) return null;
            const value = self.items.items[self.head];
            self.head += 1;
            self.compact();
            return value;
        }

        pub fn clearRetainingCapacity(self: *Self) void {
            self.items.clearRetainingCapacity();
            self.head = 0;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.items.deinit(allocator);
            self.* = .{};
        }

        fn compact(self: *Self) void {
            if (self.head < compact_threshold or
                self.head * 2 < self.items.items.len)
            {
                return;
            }
            const remaining = self.items.items.len - self.head;
            std.mem.copyForwards(
                T,
                self.items.items[0..remaining],
                self.items.items[self.head..],
            );
            self.items.shrinkRetainingCapacity(remaining);
            self.head = 0;
        }
    };
}

test "fifo preserves order across compaction" {
    const allocator = std.testing.allocator;
    var queue: Fifo(u32) = .{};
    defer queue.deinit(allocator);

    for (0..100) |value| try queue.append(allocator, @intCast(value));
    for (0..64) |value| {
        try std.testing.expectEqual(@as(u32, @intCast(value)), queue.popFront().?);
    }
    // The head index has crossed the compaction threshold; later values must
    // still arrive in order after the backing array shifts down.
    for (100..120) |value| try queue.append(allocator, @intCast(value));
    for (64..120) |value| {
        try std.testing.expectEqual(@as(u32, @intCast(value)), queue.popFront().?);
    }
    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(?u32, null), queue.popFront());
}

test "fifo clear resets the head index" {
    const allocator = std.testing.allocator;
    var queue: Fifo(u8) = .{};
    defer queue.deinit(allocator);

    try queue.append(allocator, 'a');
    try queue.append(allocator, 'b');
    _ = queue.popFront();
    queue.clearRetainingCapacity();
    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), queue.head);
    try queue.append(allocator, 'c');
    try std.testing.expectEqual(@as(u8, 'c'), queue.popFront().?);
}
