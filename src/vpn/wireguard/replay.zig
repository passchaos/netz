//! WireGuard transport replay filter.
//!
//! Counters are accepted only once. The sliding window is the protocol's
//! 8192-packet bitmap; packets older than the window are dropped.

const std = @import("std");

pub const window_bits = 8192;
pub const window_bytes = window_bits / 8;

pub const ReplayFilter = struct {
    bitmap: [window_bytes]u8 = [_]u8{0} ** window_bytes,
    last: u64 = 0,
    initialized: bool = false,

    pub fn reset(self: *ReplayFilter) void {
        @memset(&self.bitmap, 0);
        self.last = 0;
        self.initialized = false;
    }

    /// Returns true when `counter` is fresh; the counter is then marked seen.
    /// Counters behind the window and already-seen counters return false.
    pub fn check(self: *ReplayFilter, counter: u64) bool {
        if (!self.initialized) {
            self.initialized = true;
            self.last = counter;
            self.setBit(counter);
            return true;
        }

        if (counter > self.last) {
            const distance = counter - self.last;
            if (distance >= window_bits) {
                @memset(&self.bitmap, 0);
            } else {
                var value = self.last + 1;
                while (value <= counter) : (value += 1) {
                    self.clearBit(value);
                }
            }
            self.last = counter;
            self.setBit(counter);
            return true;
        }

        const distance = self.last - counter;
        if (distance >= window_bits) return false;
        const index = counter % window_bits;
        if (self.isSet(index)) return false;
        self.setBit(counter);
        return true;
    }

    pub fn isSeen(self: *const ReplayFilter, counter: u64) bool {
        if (!self.initialized) return false;
        if (counter > self.last) return false;
        if (self.last - counter >= window_bits) return false;
        return self.isSet(counter % window_bits);
    }

    fn setBit(self: *ReplayFilter, counter: u64) void {
        const index = counter % window_bits;
        self.bitmap[index / 8] |= @as(u8, 1) << @intCast(index % 8);
    }

    fn clearBit(self: *ReplayFilter, counter: u64) void {
        const index = counter % window_bits;
        self.bitmap[index / 8] &= ~(@as(u8, 1) << @intCast(index % 8));
    }

    fn isSet(self: *const ReplayFilter, index: usize) bool {
        return (self.bitmap[index / 8] &
            (@as(u8, 1) << @intCast(index % 8))) != 0;
    }
};

test "accepts increasing counters and rejects duplicates" {
    var filter = ReplayFilter{};
    try std.testing.expect(filter.check(0));
    try std.testing.expect(!filter.check(0));
    try std.testing.expect(filter.check(1));
    try std.testing.expect(filter.check(5));
    try std.testing.expect(!filter.check(5));
    try std.testing.expect(filter.check(4));
    try std.testing.expect(filter.check(3));
    try std.testing.expect(filter.check(2));
    try std.testing.expect(!filter.check(1));
}

test "rejects counters behind the window" {
    var filter = ReplayFilter{};
    try std.testing.expect(filter.check(10_000));
    try std.testing.expect(filter.check(10_001));
    try std.testing.expect(!filter.check(10_000 - window_bits));
    try std.testing.expect(filter.check(10_000 - window_bits + 2));
    try std.testing.expect(!filter.check(10_000 - window_bits));
}

test "large jumps clear stale bits" {
    var filter = ReplayFilter{};
    try std.testing.expect(filter.check(0));
    try std.testing.expect(filter.check(window_bits * 4));
    try std.testing.expect(!filter.check(1));
    try std.testing.expect(filter.check(window_bits * 4 + 1));
}

test "window wrap reuses indices correctly" {
    var filter = ReplayFilter{};
    var counter: u64 = 0;
    while (counter < window_bits * 2 + 17) : (counter += 1) {
        try std.testing.expect(filter.check(counter));
    }
    try std.testing.expect(!filter.check(window_bits * 2 + 16));
    try std.testing.expect(filter.check(window_bits * 2 + 18));
}
