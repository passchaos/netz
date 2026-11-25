//! Stable per-connection jitter for an armed QUIC Probe Timeout.
//!
//! Deadline queries are observational in netz: endpoint schedulers may call
//! them repeatedly without transport progress.  The jitter is therefore a
//! deterministic function of a private connection seed and the PTO arming
//! epoch, rather than a PRNG draw performed by the deadline getter.

const std = @import("std");
const secure_random = @import("../../internal/secure_random.zig");

pub const max_percentage: u8 = 50;

pub const State = struct {
    percentage: u8 = 0,
    seed: u64 = 0,
    epoch: u64 = 0,

    pub fn init(
        io: std.Io,
        percentage: u8,
    ) (std.Io.RandomSecureError || error{InvalidPtoJitter})!State {
        if (percentage > max_percentage) return error.InvalidPtoJitter;
        if (percentage == 0) return .{};

        var seed_bytes: [@sizeOf(u64)]u8 = undefined;
        try secure_random.fill(io, &seed_bytes);
        return .{
            .percentage = percentage,
            .seed = std.mem.readInt(u64, &seed_bytes, .little),
        };
    }

    pub fn rearm(self: *State) void {
        if (self.percentage == 0) return;
        self.epoch +%= 1;
    }

    pub fn enabled(self: State) bool {
        return self.percentage != 0;
    }

    pub fn currentEpoch(self: State) u64 {
        return self.epoch;
    }

    /// Apply jitter to the unbacked-off base PTO, then apply exponential
    /// backoff. `epoch` changes only at committed transport rearm points.
    pub fn period(self: State, base: u64, backoff_count: u8, minimum: u64, maximum: u64) u64 {
        var jittered = base;
        if (self.percentage != 0) {
            const magnitude = std.math.mul(u64, base, self.percentage) catch std.math.maxInt(u64);
            const maximum_offset = magnitude / 100;
            if (maximum_offset != 0) {
                var epoch_bytes: [@sizeOf(u64)]u8 = undefined;
                std.mem.writeInt(u64, &epoch_bytes, self.epoch, .little);
                // Backoff scales the current PTO but does not resample its
                // signed offset. The next transmitted ack-eliciting packet
                // changes the epoch naturally, while repeated timer reads and
                // a backoff transition retain one predictable ratio.
                const sample = std.hash.Wyhash.hash(self.seed, &epoch_bytes);
                const width = std.math.mul(u64, maximum_offset, 2) catch std.math.maxInt(u64);
                const offset = if (width == std.math.maxInt(u64)) sample else sample % (width + 1);
                jittered = if (offset <= maximum_offset)
                    base -| (maximum_offset - offset)
                else
                    base +| (offset - maximum_offset);
            }
        }

        var result = jittered;
        var remaining = backoff_count;
        while (remaining != 0) : (remaining -= 1) {
            result = std.math.mul(u64, result, 2) catch maximum;
            if (result >= maximum) return maximum;
        }
        return @min(@max(result, minimum), maximum);
    }
};

test "PTO jitter is stable, bounded, and applied before backoff" {
    var state = State{ .percentage = 25, .seed = 0x1234_5678_9abc_def0 };
    const first = state.period(400, 0, 1, 10_000);
    try std.testing.expectEqual(first, state.period(400, 0, 1, 10_000));
    try std.testing.expect(first >= 300 and first <= 500);
    try std.testing.expectEqual(first * 2, state.period(400, 1, 1, 10_000));
    state.rearm();
    try std.testing.expect(first != state.period(400, 0, 1, 10_000));
}

test "PTO jitter zero preserves exact values and clamps safely" {
    const state = State{};
    try std.testing.expectEqual(@as(u64, 325), state.period(325, 0, 1, 10_000));
    try std.testing.expectEqual(@as(u64, 650), state.period(325, 1, 1, 10_000));
    try std.testing.expectEqual(@as(u64, 10), state.period(1, 0, 10, 10_000));
    try std.testing.expectEqual(@as(u64, 10_000), state.period(std.math.maxInt(u64), 50, 1, 10_000));
}

test "PTO jitter validates percentage without entropy when disabled" {
    const disabled = try State.init(undefined, 0);
    try std.testing.expectEqual(@as(u8, 0), disabled.percentage);
    try std.testing.expectError(error.InvalidPtoJitter, State.init(undefined, max_percentage + 1));
}

test "PTO jitter handles maximum percentage and saturating bounds" {
    const state = State{
        .percentage = max_percentage,
        .seed = 0xfedc_ba98_7654_3210,
        .epoch = 9,
    };
    const base: u64 = 1_000_000;
    const period = state.period(base, 0, 1, std.math.maxInt(u64));
    try std.testing.expect(period >= base / 2);
    try std.testing.expect(period <= base + base / 2);
    try std.testing.expectEqual(
        @as(u64, 10_000),
        state.period(1, 0, 10_000, std.math.maxInt(u64)),
    );
    try std.testing.expectEqual(
        @as(u64, 10_000),
        state.period(std.math.maxInt(u64), 8, 1, 10_000),
    );
}

test "PTO jitter seed decorrelates equal recovery epochs" {
    const first = State{ .percentage = 25, .seed = 1, .epoch = 7 };
    const second = State{ .percentage = 25, .seed = 2, .epoch = 7 };
    try std.testing.expect(first.period(1_000_000, 0, 1, 2_000_000) !=
        second.period(1_000_000, 0, 1, 2_000_000));
}

test "PTO jitter covers one and fifty percent deterministic bounds" {
    for ([_]u8{ 1, 50 }) |percentage| {
        var state = State{
            .percentage = percentage,
            .seed = 0x7654_3210_fedc_ba98,
        };
        for (0..64) |_| {
            const base: u64 = 1_000_000;
            const maximum_offset = base * percentage / 100;
            const period = state.period(
                base,
                0,
                1,
                std.math.maxInt(u64),
            );
            try std.testing.expect(period >= base - maximum_offset);
            try std.testing.expect(period <= base + maximum_offset);
            state.rearm();
        }
    }
}
