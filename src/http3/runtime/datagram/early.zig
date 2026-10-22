//! Opt-in buffering before an Extended CONNECT association is registered.
//! Payload ownership moves into the ordinary queue when registration succeeds.

const std = @import("std");
const range_set = @import("../../../internal/exact_range_set.zig");

pub const Limits = struct {
    max_datagrams: usize = 0,
    max_bytes: usize = 0,
    max_age: std.Io.Duration = .fromSeconds(30),
    /// Compact history prevents a removed association from being recreated by
    /// a late DATAGRAM. Contiguous request IDs consume no sparse ranges.
    max_known_ranges: usize = 128,
};

pub const Queue = struct {
    const Entry = struct {
        stream_id: u62,
        payload: []u8,
        received_ns: i96,
    };

    limits: Limits = .{},
    io: ?std.Io = null,
    entries: std.ArrayList(Entry) = .empty,
    bytes: usize = 0,
    known: range_set.Set = .{},

    pub fn init(io: std.Io, limits: Limits) Queue {
        return .{ .io = io, .limits = limits };
    }

    pub fn enabled(self: Queue) bool {
        return self.io != null and self.limits.max_datagrams != 0 and
            self.limits.max_bytes != 0 and self.limits.max_age.nanoseconds > 0;
    }

    pub fn deinit(self: *Queue, allocator: std.mem.Allocator) void {
        self.clear(allocator);
        self.entries.deinit(allocator);
        self.known.deinit(allocator);
        self.* = undefined;
    }

    pub fn clear(self: *Queue, allocator: std.mem.Allocator) void {
        for (self.entries.items) |entry| allocator.free(entry.payload);
        self.entries.clearRetainingCapacity();
        self.bytes = 0;
    }

    pub fn expire(self: *Queue, allocator: std.mem.Allocator) void {
        if (self.entries.items.len == 0) return;
        self.expireAt(allocator, std.Io.Clock.awake.now(self.io.?).nanoseconds);
    }

    pub fn expireAt(self: *Queue, allocator: std.mem.Allocator, now_ns: i96) void {
        while (self.entries.items.len != 0 and
            now_ns - self.entries.items[0].received_ns >= self.limits.max_age.nanoseconds)
        {
            self.dropAt(allocator, 0);
        }
    }

    pub fn remember(self: *Queue, allocator: std.mem.Allocator, stream_id: u62) (std.mem.Allocator.Error || error{ExcessiveLoad})!void {
        try self.prepareRemember(allocator, stream_id);
        self.commitRemember(stream_id);
    }

    pub fn prepareRemember(self: *Queue, allocator: std.mem.Allocator, stream_id: u62) (std.mem.Allocator.Error || error{ExcessiveLoad})!void {
        if (!self.enabled()) return;
        const ordinal: u64 = stream_id / 4;
        if (self.known.contains(ordinal)) return;
        const adjacent = ordinal == self.known.prefix_len or
            (ordinal != 0 and self.known.contains(ordinal - 1)) or
            self.known.contains(ordinal + 1);
        if (!adjacent and self.known.sparseRangeCount() >= self.limits.max_known_ranges) return error.ExcessiveLoad;
        try self.known.prepareInsertValue(allocator, ordinal);
    }

    pub fn commitRemember(self: *Queue, stream_id: u62) void {
        if (self.enabled()) self.known.insertAssumeCapacity(stream_id / 4);
    }

    pub fn prepareRestore(self: *Queue, allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
        if (self.enabled()) try self.entries.ensureTotalCapacity(allocator, self.limits.max_datagrams);
    }

    pub fn restoreOwned(self: *Queue, allocator: std.mem.Allocator, stream_id: u62, payload: []u8) void {
        if (!self.enabled() or payload.len > self.limits.max_bytes) {
            allocator.free(payload);
            return;
        }
        while (self.entries.items.len >= self.limits.max_datagrams or self.bytes > self.limits.max_bytes - payload.len) self.dropAt(allocator, 0);
        self.entries.appendAssumeCapacity(.{ .stream_id = stream_id, .payload = payload, .received_ns = std.Io.Clock.awake.now(self.io.?).nanoseconds });
        self.bytes += payload.len;
    }

    pub fn discard(self: *Queue, allocator: std.mem.Allocator, stream_id: u62) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (self.entries.items[index].stream_id == stream_id)
                self.dropAt(allocator, index)
            else
                index += 1;
        }
    }

    pub fn push(self: *Queue, allocator: std.mem.Allocator, stream_id: u62, payload: []const u8) std.mem.Allocator.Error!void {
        if (!self.enabled() or self.known.contains(stream_id / 4) or
            payload.len > self.limits.max_bytes) return;
        const now_ns = std.Io.Clock.awake.now(self.io.?).nanoseconds;
        self.expireAt(allocator, now_ns);
        // Reserve the replacement first so allocation failure preserves every
        // still-live payload that was previously retained.
        const owned = try allocator.dupe(u8, payload);
        errdefer allocator.free(owned);
        try self.entries.ensureUnusedCapacity(allocator, 1);
        while (self.entries.items.len >= self.limits.max_datagrams or
            self.bytes > self.limits.max_bytes - payload.len)
        {
            self.dropAt(allocator, 0);
        }
        self.entries.appendAssumeCapacity(.{ .stream_id = stream_id, .payload = owned, .received_ns = now_ns });
        self.bytes += payload.len;
    }

    pub fn count(self: Queue, stream_id: u62) usize {
        var result: usize = 0;
        for (self.entries.items) |entry| result += @intFromBool(entry.stream_id == stream_id);
        return result;
    }

    pub fn take(self: *Queue, stream_id: u62) ?[]u8 {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.stream_id != stream_id) continue;
            const removed = self.entries.orderedRemove(index);
            self.bytes -= removed.payload.len;
            return removed.payload;
        }
        return null;
    }

    pub fn takeNewest(self: *Queue, stream_id: u62) ?[]u8 {
        var index = self.entries.items.len;
        while (index != 0) {
            index -= 1;
            if (self.entries.items[index].stream_id != stream_id) continue;
            const removed = self.entries.orderedRemove(index);
            self.bytes -= removed.payload.len;
            return removed.payload;
        }
        return null;
    }

    fn dropAt(self: *Queue, allocator: std.mem.Allocator, index: usize) void {
        const removed = self.entries.orderedRemove(index);
        self.bytes -= removed.payload.len;
        allocator.free(removed.payload);
    }
};

test "HTTP/3 early CONNECT datagrams bound count and bytes across associations" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = Queue.init(threaded.io(), .{ .max_datagrams = 2, .max_bytes = 5 });
    defer queue.deinit(std.testing.allocator);
    try queue.push(std.testing.allocator, 0, "one");
    try queue.push(std.testing.allocator, 4, "two");
    try std.testing.expectEqual(@as(usize, 0), queue.count(0));
    try queue.push(std.testing.allocator, 8, "x");
    try queue.push(std.testing.allocator, 12, "y");
    try std.testing.expectEqual(@as(usize, 2), queue.entries.items.len);
    try std.testing.expectEqual(@as(usize, 2), queue.bytes);
    try queue.push(std.testing.allocator, 16, "oversized");
    try std.testing.expectEqual(@as(usize, 2), queue.entries.items.len);
    const now_ns = std.Io.Clock.awake.now(threaded.io()).nanoseconds;
    queue.expireAt(std.testing.allocator, now_ns + queue.limits.max_age.nanoseconds);
    try std.testing.expectEqual(@as(usize, 0), queue.entries.items.len);
    try std.testing.expectEqual(@as(usize, 0), queue.bytes);
}

test "HTTP/3 early CONNECT datagram history is compact and bounded" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = Queue.init(threaded.io(), .{ .max_datagrams = 2, .max_bytes = 32, .max_known_ranges = 1 });
    defer queue.deinit(std.testing.allocator);
    try queue.remember(std.testing.allocator, 8);
    try std.testing.expectError(error.ExcessiveLoad, queue.remember(std.testing.allocator, 20));
    try queue.remember(std.testing.allocator, 0);
    try queue.remember(std.testing.allocator, 4);
    try std.testing.expectEqual(@as(u64, 3), queue.known.prefix_len);
    try std.testing.expectEqual(@as(usize, 0), queue.known.sparseRangeCount());
    try queue.push(std.testing.allocator, 8, "late");
    try std.testing.expectEqual(@as(usize, 0), queue.entries.items.len);
}
