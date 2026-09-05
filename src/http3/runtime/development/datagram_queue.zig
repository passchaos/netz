const std = @import("std");
const quic = @import("../../../quic/mod.zig");

pub const Error = std.mem.Allocator.Error || error{ExcessiveLoad};

/// Bounded FIFO of raw development-runtime datagrams retained after HTTP/3
/// STREAM processing. Oldest-drop semantics match QUIC DATAGRAM unreliability
/// while retaining ownership of whole parsed packets for protocol adapters.
pub const Queue = struct {
    allocator: std.mem.Allocator,
    datagrams: std.ArrayList(quic.runtime.OwnedDatagram) = .empty,
    head: usize = 0,
    queued_bytes: usize = 0,
    max_count: usize,
    max_bytes: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        max_count: usize,
        max_bytes: usize,
    ) Queue {
        return .{
            .allocator = allocator,
            .max_count = max_count,
            .max_bytes = max_bytes,
        };
    }

    pub fn deinit(self: *Queue) void {
        for (self.datagrams.items[self.head..]) |*datagram| {
            datagram.deinit(self.allocator);
        }
        self.datagrams.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: Queue) usize {
        return self.datagrams.items.len - self.head;
    }

    fn compact(self: *Queue) void {
        if (self.head == 0) return;
        const remaining = self.count();
        if (remaining != 0) {
            @memmove(
                self.datagrams.items[0..remaining],
                self.datagrams.items[self.head..],
            );
        }
        self.datagrams.items.len = remaining;
        self.head = 0;
    }

    fn dropOldest(self: *Queue) void {
        var dropped = self.datagrams.items[self.head];
        self.queued_bytes -= dropped.bytes.len;
        dropped.deinit(self.allocator);
        self.head += 1;
        if (self.head == self.datagrams.items.len) {
            self.datagrams.clearRetainingCapacity();
            self.head = 0;
        } else if (self.head >= self.datagrams.items.len / 2) {
            self.compact();
        }
    }

    pub fn push(
        self: *Queue,
        datagram: *quic.runtime.OwnedDatagram,
    ) Error!void {
        // A successful call always consumes `datagram`. Disabled retention or
        // an individually oversized packet is an intentional unreliable-
        // DATAGRAM drop rather than an ownership exception for the caller.
        if (self.max_count == 0 or self.max_bytes == 0) {
            datagram.deinit(self.allocator);
            return;
        }
        // Configurations smaller than a legal incoming packet cannot honor
        // their own byte bound. Surface that mismatch instead of silently
        // dropping a syntactically valid DATAGRAM after consuming the socket.
        if (datagram.bytes.len > self.max_bytes) return error.ExcessiveLoad;
        if (self.head != 0 and
            self.datagrams.items.len == self.datagrams.capacity)
        {
            self.compact();
        }
        try self.datagrams.ensureUnusedCapacity(self.allocator, 1);
        while (self.count() >= self.max_count or
            self.queued_bytes > self.max_bytes - datagram.bytes.len)
        {
            self.dropOldest();
        }
        self.datagrams.appendAssumeCapacity(datagram.*);
        self.queued_bytes += datagram.bytes.len;
        datagram.* = undefined;
    }

    pub fn pop(self: *Queue) ?quic.runtime.OwnedDatagram {
        if (self.count() == 0) return null;
        const datagram = self.datagrams.items[self.head];
        self.queued_bytes -= datagram.bytes.len;
        self.head += 1;
        if (self.head == self.datagrams.items.len) {
            self.datagrams.clearRetainingCapacity();
            self.head = 0;
        }
        return datagram;
    }
};

fn ownedDatagram(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !quic.runtime.OwnedDatagram {
    return .{
        .from = .{ .ip4 = .loopback(443) },
        .bytes = try allocator.dupe(u8, bytes),
        .frames = try allocator.alloc(quic.Frame, 0),
    };
}

test "HTTP/3 development datagram queue bounds count bytes and ownership" {
    const allocator = std.testing.allocator;

    var queue = Queue.init(allocator, 3, 8);
    defer queue.deinit();
    var first = try ownedDatagram(allocator, "one");
    try queue.push(&first);
    var second = try ownedDatagram(allocator, "two");
    try queue.push(&second);
    var third = try ownedDatagram(allocator, "three");
    try queue.push(&third);

    // The byte limit evicts "one" while the count limit still has room.
    var retained = queue.pop() orelse return error.TestUnexpectedResult;
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings("two", retained.bytes);
    var retained_last = queue.pop() orelse return error.TestUnexpectedResult;
    defer retained_last.deinit(allocator);
    try std.testing.expectEqualStrings("three", retained_last.bytes);
    try std.testing.expect(queue.pop() == null);

    var count_bounded = Queue.init(allocator, 2, 100);
    defer count_bounded.deinit();
    var count_first = try ownedDatagram(allocator, "1");
    try count_bounded.push(&count_first);
    var count_second = try ownedDatagram(allocator, "2");
    try count_bounded.push(&count_second);
    var count_third = try ownedDatagram(allocator, "3");
    try count_bounded.push(&count_third);
    var count_retained = count_bounded.pop() orelse
        return error.TestUnexpectedResult;
    defer count_retained.deinit(allocator);
    try std.testing.expectEqualStrings("2", count_retained.bytes);
    var count_retained_last = count_bounded.pop() orelse
        return error.TestUnexpectedResult;
    defer count_retained_last.deinit(allocator);
    try std.testing.expectEqualStrings("3", count_retained_last.bytes);
    try std.testing.expect(count_bounded.pop() == null);

    var disabled = Queue.init(allocator, 0, 7);
    defer disabled.deinit();
    var dropped_disabled = try ownedDatagram(allocator, "x");
    try disabled.push(&dropped_disabled);
    try std.testing.expect(disabled.pop() == null);

    var oversized = Queue.init(allocator, 2, 2);
    defer oversized.deinit();
    var rejected_oversized = try ownedDatagram(allocator, "big");
    defer rejected_oversized.deinit(allocator);
    try std.testing.expectError(
        error.ExcessiveLoad,
        oversized.push(&rejected_oversized),
    );
    try std.testing.expect(oversized.pop() == null);
}
