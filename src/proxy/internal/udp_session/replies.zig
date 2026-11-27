//! Owned encoded replies retain FIFO order across retryable QUIC refusal.
const std = @import("std");

pub const Replies = struct {
    pub const capacity = 8;
    slots: [capacity]?[]u8 = @splat(null),
    head: usize = 0,
    count: usize = 0,

    /// Transfer ownership only when accepted; refusal leaves bytes with caller.
    pub fn enqueue(self: *Replies, bytes: []u8) bool {
        if (self.count == capacity) return false;
        const index = (self.head + self.count) % capacity;
        std.debug.assert(self.slots[index] == null);
        self.slots[index] = bytes;
        self.count += 1;
        return true;
    }

    /// Borrow the oldest reply until pop; a refused send leaves it queued.
    pub fn peek(self: *const Replies) ?[]const u8 {
        if (self.count == 0) return null;
        return self.slots[self.head].?;
    }

    /// Transfer the oldest reply to the caller after success or fatal failure.
    pub fn pop(self: *Replies) ?[]u8 {
        if (self.count == 0) return null;
        const bytes = self.slots[self.head].?;
        self.slots[self.head] = null;
        self.head = (self.head + 1) % capacity;
        self.count -= 1;
        return bytes;
    }

    pub fn deinit(self: *Replies, allocator: std.mem.Allocator) void {
        while (self.pop()) |bytes| allocator.free(bytes);
    }
};

test "proxy UDP reply FIFO retains blocked front through slot reuse and retirement" {
    const allocator = std.testing.allocator;
    var replies: Replies = .{};
    defer replies.deinit(allocator);
    for (0..Replies.capacity) |i| {
        const bytes = try allocator.dupe(u8, &.{@intCast(i)});
        try std.testing.expect(replies.enqueue(bytes));
    }
    const refused = try allocator.dupe(u8, "full");
    defer allocator.free(refused);
    try std.testing.expect(!replies.enqueue(refused));
    for (0..3) |i| {
        try std.testing.expectEqualSlices(u8, &.{@intCast(i)}, replies.peek().?);
        allocator.free(replies.pop().?);
    }
    // The first remaining packet stays borrowed while earlier slots are reused.
    const blocked = replies.peek().?;
    for (Replies.capacity..Replies.capacity + 3) |i| {
        try std.testing.expect(replies.enqueue(try allocator.dupe(u8, &.{@intCast(i)})));
        try std.testing.expectEqualSlices(u8, &.{3}, replies.peek().?);
        try std.testing.expectEqual(blocked.ptr, replies.peek().?.ptr);
    }
    for (3..Replies.capacity + 3) |i| {
        try std.testing.expectEqualSlices(u8, &.{@intCast(i)}, replies.peek().?);
        allocator.free(replies.pop().?);
    }
    try std.testing.expect(replies.peek() == null);
    try std.testing.expect(replies.pop() == null);
    try std.testing.expect(replies.enqueue(try allocator.dupe(u8, "retire")));
    replies.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), replies.count);
}
