//! Sparse MQTT 5 Topic Alias state for one Network Connection.
//!
//! MQTT permits alias values through 65,535. Keeping a fixed array made small
//! defaults cheap but incorrectly rejected valid larger negotiated limits. A
//! sparse table preserves bounded-by-use memory while supporting the complete
//! protocol range; every stored Topic Name is owned because packet receive
//! buffers are released after parsing.

const std = @import("std");

pub const Table = struct {
    entries: std.AutoHashMapUnmanaged(u16, []u8) = .empty,
    /// Aliases live for the complete Network Connection and are never removed
    /// individually, so this monotonic cursor makes automatic assignment O(1)
    /// amortized even when a peer advertises the full 65,535-value range.
    next_unused: u32 = 1,

    pub fn deinit(
        self: *Table,
        allocator: std.mem.Allocator,
    ) void {
        var values = self.entries.valueIterator();
        while (values.next()) |topic| allocator.free(topic.*);
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    pub fn get(self: *const Table, alias: u16) ?[]const u8 {
        return self.entries.get(alias);
    }

    pub fn contains(self: *const Table, alias: u16) bool {
        return self.entries.contains(alias);
    }

    /// Install or replace one alias without changing the old mapping if the
    /// new Topic Name cannot be owned.
    pub fn put(
        self: *Table,
        allocator: std.mem.Allocator,
        alias: u16,
        topic: []const u8,
    ) std.mem.Allocator.Error!void {
        std.debug.assert(alias != 0);
        std.debug.assert(topic.len != 0);
        if (self.entries.getPtr(alias)) |old| {
            if (std.mem.eql(u8, old.*, topic)) return;
            const replacement = try allocator.dupe(u8, topic);
            allocator.free(old.*);
            old.* = replacement;
            return;
        }
        const owned = try allocator.dupe(u8, topic);
        errdefer allocator.free(owned);
        try self.entries.putNoClobber(allocator, alias, owned);
        if (alias == self.next_unused) self.advanceNextUnused();
    }

    /// Return the lowest alias already representing topic within the peer's
    /// advertised range. Explicit users may assign the same topic more than
    /// once, so a reverse index could lose deterministic lowest-value
    /// selection after replacement.
    pub fn findTopic(
        self: *const Table,
        topic: []const u8,
        maximum: u16,
    ) ?u16 {
        var found: ?u16 = null;
        var entries = self.entries.iterator();
        while (entries.next()) |entry| {
            const alias = entry.key_ptr.*;
            if (alias > maximum or
                !std.mem.eql(u8, entry.value_ptr.*, topic))
            {
                continue;
            }
            if (found == null or alias < found.?) found = alias;
        }
        return found;
    }

    pub fn firstUnused(
        self: *const Table,
        maximum: u16,
    ) ?u16 {
        if (self.next_unused > maximum) return null;
        return @intCast(self.next_unused);
    }

    pub fn count(self: *const Table) usize {
        return self.entries.count();
    }

    fn advanceNextUnused(self: *Table) void {
        while (self.next_unused <= std.math.maxInt(u16) and
            self.entries.contains(@intCast(self.next_unused)))
        {
            self.next_unused += 1;
        }
    }
};

test "MQTT sparse Topic Alias table supports the full u16 range" {
    const allocator = std.testing.allocator;
    var table: Table = .{};
    defer table.deinit(allocator);

    try table.put(allocator, 65_535, "maximum/topic");
    try table.put(allocator, 17, "shared/topic");
    try table.put(allocator, 42, "shared/topic");
    try std.testing.expectEqualStrings(
        "maximum/topic",
        table.get(65_535).?,
    );
    try std.testing.expectEqual(
        @as(?u16, 17),
        table.findTopic("shared/topic", 65_535),
    );
    try std.testing.expectEqual(@as(?u16, 1), table.firstUnused(65_535));
    try std.testing.expectEqual(@as(usize, 3), table.count());

    try table.put(allocator, 1, "first/topic");
    try table.put(allocator, 2, "second/topic");
    try std.testing.expectEqual(@as(?u16, 3), table.firstUnused(65_535));
}

test "MQTT sparse Topic Alias replacement is transactional" {
    const allocator = std.testing.allocator;
    var table: Table = .{};
    defer table.deinit(allocator);
    try table.put(allocator, 300, "old/topic");

    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        table.put(fail_first.allocator(), 300, "replacement/topic"),
    );
    try std.testing.expectEqualStrings("old/topic", table.get(300).?);
}
