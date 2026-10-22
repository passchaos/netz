const std = @import("std");

/// Exact set of non-negative integers stored as a contiguous prefix plus
/// sorted, merged sparse ranges. Sequential values require no allocation.
pub const Set = struct {
    const Range = struct {
        first: u64,
        last: u64,
    };

    /// Every value below this watermark belongs to the set.
    prefix_len: u64 = 0,
    ranges: std.ArrayList(Range) = .empty,
    range_head: usize = 0,

    pub fn deinit(self: *Set, allocator: std.mem.Allocator) void {
        self.ranges.deinit(allocator);
        self.* = undefined;
    }

    pub fn clone(
        self: Set,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!Set {
        var copy = Set{ .prefix_len = self.prefix_len };
        errdefer copy.deinit(allocator);
        try copy.ranges.appendSlice(allocator, self.activeRanges());
        return copy;
    }

    pub fn prepareInsert(
        self: *Set,
        allocator: std.mem.Allocator,
        count: usize,
    ) std.mem.Allocator.Error!void {
        self.compactRanges();
        try self.ranges.ensureUnusedCapacity(allocator, count);
    }

    /// Reserve only when inserting `value` would create a new sparse range.
    /// Ordered prefixes, duplicates, and values adjacent to an existing range
    /// remain allocation-free.
    pub fn prepareInsertValue(
        self: *Set,
        allocator: std.mem.Allocator,
        value: u64,
    ) std.mem.Allocator.Error!void {
        if (value <= self.prefix_len) return;
        const index = self.insertionIndex(value);
        if (index != self.range_head) {
            const previous = self.ranges.items[index - 1];
            if (value <= previous.last or value - previous.last == 1) return;
        }
        if (index < self.ranges.items.len and
            self.ranges.items[index].first - value == 1)
        {
            return;
        }
        self.compactRanges();
        try self.ranges.ensureUnusedCapacity(allocator, 1);
    }

    pub fn insertAssumeCapacity(self: *Set, value: u64) void {
        if (value < self.prefix_len) return;
        if (value == self.prefix_len) {
            self.prefix_len += 1;
            if (self.range_head < self.ranges.items.len and
                self.ranges.items[self.range_head].first == self.prefix_len)
            {
                self.prefix_len = self.ranges.items[self.range_head].last + 1;
                self.range_head += 1;
                self.compactRangesIfSparse();
            }
            return;
        }
        const index = self.insertionIndex(value);
        if (index != self.range_head) {
            const previous = &self.ranges.items[index - 1];
            if (value <= previous.last) return;
            if (value - previous.last == 1) {
                previous.last = value;
                if (index < self.ranges.items.len) {
                    const next = self.ranges.items[index];
                    if (next.first - value == 1) {
                        previous.last = next.last;
                        _ = self.ranges.orderedRemove(index);
                    }
                }
                return;
            }
        }
        if (index < self.ranges.items.len and
            self.ranges.items[index].first - value == 1)
        {
            self.ranges.items[index].first = value;
            return;
        }
        self.ranges.insertAssumeCapacity(index, .{
            .first = value,
            .last = value,
        });
    }

    pub fn contains(self: Set, value: u64) bool {
        if (value < self.prefix_len) return true;
        var low = self.range_head;
        var high = self.ranges.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const range = self.ranges.items[mid];
            if (value < range.first) {
                high = mid;
            } else if (value > range.last) {
                low = mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }

    /// Include every value below `length` and absorb adjoining sparse ranges.
    /// A protocol owner can fold an authoritative retirement watermark into
    /// its history without iterating over every retired stream ID.
    pub fn includePrefix(self: *Set, length: u64) void {
        if (length <= self.prefix_len) return;
        self.prefix_len = length;
        while (self.range_head < self.ranges.items.len and self.ranges.items[self.range_head].first <= self.prefix_len) {
            self.prefix_len = @max(self.prefix_len, self.ranges.items[self.range_head].last + 1);
            self.range_head += 1;
        }
        self.compactRangesIfSparse();
    }

    /// Fold authoritative ranges only where they touch existing history. This
    /// fills retired holes without retaining a second copy of unrelated ranges.
    pub fn foldFrom(self: *Set, other: Set) void {
        self.includePrefix(other.prefix_len);
        for (other.activeRanges()) |range| self.includeConnectedRange(range.first, range.last);
    }

    fn includeConnectedRange(self: *Set, first: u64, last: u64) void {
        if (first <= self.prefix_len) {
            self.includePrefix(last + 1);
            return;
        }
        var index = self.range_head;
        while (index < self.ranges.items.len) : (index += 1) {
            const range = self.ranges.items[index];
            if (range.last + 1 < first) continue;
            if (range.first > last + 1) return;
            const merged_first = @min(first, range.first);
            var merged_last = @max(last, range.last);
            while (index + 1 < self.ranges.items.len and self.ranges.items[index + 1].first <= merged_last + 1) {
                merged_last = @max(merged_last, self.ranges.orderedRemove(index + 1).last);
            }
            self.ranges.items[index] = .{ .first = merged_first, .last = merged_last };
            return;
        }
    }

    pub fn rangeCount(self: Set) usize {
        return self.sparseRangeCount() + @intFromBool(self.prefix_len != 0);
    }

    pub fn sparseRangeCount(self: Set) usize {
        return self.ranges.items.len - self.range_head;
    }

    fn insertionIndex(self: Set, value: u64) usize {
        var low = self.range_head;
        var high = self.ranges.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.ranges.items[mid].first <= value) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return low;
    }

    fn activeRanges(self: Set) []const Range {
        return self.ranges.items[self.range_head..];
    }

    fn compactRangesIfSparse(self: *Set) void {
        if (self.range_head == 0) return;
        if (self.range_head == self.ranges.items.len or
            self.range_head >= self.ranges.items.len / 2)
        {
            self.compactRanges();
        }
    }

    fn compactRanges(self: *Set) void {
        if (self.range_head == 0) return;
        const remaining = self.sparseRangeCount();
        if (remaining != 0) {
            std.mem.copyForwards(
                Range,
                self.ranges.items[0..remaining],
                self.ranges.items[self.range_head..],
            );
        }
        self.ranges.items.len = remaining;
        self.range_head = 0;
    }
};

test "exact range set folds an authoritative prefix without losing sparse history" {
    var set: Set = .{};
    defer set.deinit(std.testing.allocator);
    for ([_]u64{ 2, 3, 7, 9 }) |value| {
        try set.prepareInsertValue(std.testing.allocator, value);
        set.insertAssumeCapacity(value);
    }
    set.includePrefix(3);
    try std.testing.expectEqual(@as(u64, 4), set.prefix_len);
    try std.testing.expect(set.contains(0) and set.contains(7) and set.contains(9));
    try std.testing.expect(!set.contains(4) and !set.contains(8));
    set.includePrefix(8);
    try std.testing.expectEqual(@as(u64, 8), set.prefix_len);
    try std.testing.expectEqual(@as(usize, 1), set.sparseRangeCount());
    set.includePrefix(9);
    try std.testing.expectEqual(@as(u64, 10), set.prefix_len);
    try std.testing.expectEqual(@as(usize, 0), set.sparseRangeCount());
    set.includePrefix(2);
    try std.testing.expectEqual(@as(u64, 10), set.prefix_len);
}

test "exact range set folds retired holes while an earlier value remains live" {
    var known: Set = .{};
    defer known.deinit(std.testing.allocator);
    var retired: Set = .{};
    defer retired.deinit(std.testing.allocator);
    for ([_]u64{ 0, 4, 8 }) |value| {
        try known.prepareInsertValue(std.testing.allocator, value);
        known.insertAssumeCapacity(value);
    }
    for ([_]u64{ 1, 2, 3, 5, 6, 7, 100 }) |value| {
        try retired.prepareInsertValue(std.testing.allocator, value);
        retired.insertAssumeCapacity(value);
    }
    known.foldFrom(retired);
    try std.testing.expectEqual(@as(u64, 9), known.prefix_len);
    try std.testing.expectEqual(@as(usize, 0), known.sparseRangeCount());
    try std.testing.expect(!known.contains(9) and !known.contains(100));
}
