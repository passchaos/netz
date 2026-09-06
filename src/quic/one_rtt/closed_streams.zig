const std = @import("std");

/// Compressed set of closed stream sequence numbers for one QUIC stream type.
///
/// Stream IDs of one initiator/direction differ by four, so callers store
/// `stream_id >> 2`. Adjacent closures coalesce and the number of disjoint
/// ranges is bounded by the still-open holes in normal bounded-concurrency use.
pub const Set = struct {
    const Range = struct {
        first: u64,
        last: u64,
    };

    /// Every sequence below this watermark is closed. The common in-order
    /// lifecycle therefore needs no range entry at all.
    closed_prefix_len: u64 = 0,
    ranges: std.ArrayList(Range) = .empty,

    pub fn deinit(self: *Set, allocator: std.mem.Allocator) void {
        self.ranges.deinit(allocator);
        self.* = undefined;
    }

    pub fn prepareInsert(
        self: *Set,
        allocator: std.mem.Allocator,
        count: usize,
    ) std.mem.Allocator.Error!void {
        try self.ranges.ensureUnusedCapacity(allocator, count);
    }

    pub fn insertAssumeCapacity(self: *Set, sequence: u64) void {
        if (sequence < self.closed_prefix_len) return;
        if (sequence == self.closed_prefix_len) {
            self.closed_prefix_len += 1;
            while (self.ranges.items.len != 0 and
                self.ranges.items[0].first == self.closed_prefix_len)
            {
                const adjacent = self.ranges.orderedRemove(0);
                self.closed_prefix_len = adjacent.last + 1;
            }
            return;
        }
        for (self.ranges.items, 0..) |*range, index| {
            if (sequence < range.first) {
                if (range.first - sequence == 1) {
                    range.first = sequence;
                    if (index != 0) {
                        const previous = &self.ranges.items[index - 1];
                        if (range.first - previous.last <= 1) {
                            previous.last = range.last;
                            _ = self.ranges.orderedRemove(index);
                        }
                    }
                    return;
                }
                self.ranges.insertAssumeCapacity(index, .{
                    .first = sequence,
                    .last = sequence,
                });
                return;
            }
            if (sequence <= range.last) return;
            if (sequence - range.last == 1) {
                range.last = sequence;
                if (index + 1 < self.ranges.items.len) {
                    const next = self.ranges.items[index + 1];
                    if (next.first - range.last <= 1) {
                        range.last = next.last;
                        _ = self.ranges.orderedRemove(index + 1);
                    }
                }
                return;
            }
        }
        self.ranges.appendAssumeCapacity(.{
            .first = sequence,
            .last = sequence,
        });
    }

    pub fn contains(self: Set, sequence: u64) bool {
        if (sequence < self.closed_prefix_len) return true;
        var low: usize = 0;
        var high = self.ranges.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const range = self.ranges.items[mid];
            if (sequence < range.first) {
                high = mid;
            } else if (sequence > range.last) {
                low = mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }

    pub fn rangeCount(self: Set) usize {
        return self.ranges.items.len + @intFromBool(self.closed_prefix_len != 0);
    }

    pub fn sparseRangeCount(self: Set) usize {
        return self.ranges.items.len;
    }
};
