//! Connection-wide defense against excessive HTTP/2 DATA fragmentation.
//!
//! Flow control bounds payload bytes, not frame count. A peer can otherwise
//! spend very little receive credit while forcing the endpoint to parse and
//! retain large numbers of empty or tiny DATA frames.

const std = @import("std");

pub const overhead_threshold: usize = 256;
pub const default_minimum: u32 = overhead_threshold * 100;
pub const max_empty_frames: u8 = 100;
pub const automatic: u32 = std.math.maxInt(u32);

pub const Error = error{BudgetExhausted};

pub const State = struct {
    spent: u32 = 0,
    empty_frames: u8 = 0,

    /// Record one decoded DATA payload and return the charge to release when
    /// the payload leaves library buffering. Final DATA is never charged: one
    /// stream can contribute at most one such frame.
    pub fn record(
        self: *State,
        payload_len: usize,
        end_stream: bool,
        limit: u32,
    ) Error!u8 {
        if (end_stream) return 0;
        if (payload_len == 0) {
            if (self.empty_frames >= max_empty_frames) {
                return error.BudgetExhausted;
            }
            self.empty_frames += 1;
            return 0;
        }
        if (payload_len < overhead_threshold) {
            const charge: u8 = @intCast(overhead_threshold - payload_len);
            const spent = std.math.add(u32, self.spent, charge) catch
                return error.BudgetExhausted;
            if (spent > limit) return error.BudgetExhausted;
            self.spent = spent;
            return charge;
        }
        self.spent -|= std.math.cast(
            u32,
            payload_len - overhead_threshold,
        ) orelse std.math.maxInt(u32);
        return 0;
    }

    pub fn release(self: *State, charge: u8) void {
        self.spent -|= charge;
    }

    pub fn available(self: State, limit: u32) u32 {
        return limit -| self.spent;
    }
};

pub fn maximum(configured: u32, connection_window: u32) u32 {
    if (configured != automatic) return configured;
    return @max(default_minimum, connection_window / 2);
}

test "HTTP/2 DATA frame budget bounds empty frames for connection lifetime" {
    var state = State{};
    const limit = maximum(automatic, 65_535);
    for (0..max_empty_frames) |_| {
        try std.testing.expectEqual(@as(u8, 0), try state.record(0, false, limit));
    }
    // Large DATA replenishes byte charges but cannot erase an empty-frame
    // lifetime count.
    try std.testing.expectEqual(@as(u8, 0), try state.record(4096, false, limit));
    try std.testing.expectError(error.BudgetExhausted, state.record(0, false, limit));
}

test "HTTP/2 DATA frame budget releases consumed small payloads" {
    var state = State{};
    const charge = try state.record(1, false, 255);
    try std.testing.expectEqual(@as(u8, 255), charge);
    try std.testing.expectEqual(@as(u32, 0), state.available(255));
    try std.testing.expectError(error.BudgetExhausted, state.record(1, false, 255));
    state.release(charge);
    try std.testing.expectEqual(@as(u32, 255), state.available(255));
    _ = try state.record(1, false, 255);
}

test "HTTP/2 DATA frame budget ignores final frames and replenishes on large frames" {
    var state = State{};
    _ = try state.record(1, false, 300);
    try std.testing.expectEqual(@as(u32, 45), state.available(300));
    try std.testing.expectEqual(@as(u8, 0), try state.record(0, true, 300));
    try std.testing.expectEqual(@as(u32, 45), state.available(300));
    _ = try state.record(300, false, 300);
    try std.testing.expectEqual(@as(u32, 89), state.available(300));
}

test "HTTP/2 automatic DATA frame budget follows runtime window updates" {
    var state = State{};
    const initial = maximum(automatic, 65_535);
    try std.testing.expectEqual(@as(u32, 32_767), initial);
    const charge = try state.record(1, false, initial);
    const grown = maximum(automatic, 1024 * 1024);
    try std.testing.expectEqual(@as(u32, 512 * 1024), grown);
    try std.testing.expectEqual(
        grown - charge,
        state.available(grown),
    );
    try std.testing.expectEqual(@as(u32, 123), maximum(123, 1024 * 1024));
}
