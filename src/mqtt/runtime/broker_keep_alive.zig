//! One broker-managed MQTT inactivity deadline per live connection.
//!
//! Positive values are awake-clock nanoseconds, zero disables tracking, and
//! the negative sentinel means the broker deadline driver claimed expiry.

const std = @import("std");
const netz_runtime = @import("../../runtime.zig");

const disabled: i64 = 0;
const expired: i64 = -1;

pub const State = struct {
    deadline_ns: std.atomic.Value(i64) = .init(disabled),

    pub fn start(
        self: *State,
        io: std.Io,
        timeout: ?std.Io.Clock.Duration,
    ) ?std.Io.Timestamp {
        const duration = timeout orelse {
            self.deadline_ns.store(disabled, .release);
            return null;
        };
        const next_deadline_ns = deadlineNsFromNow(io, duration);
        self.deadline_ns.store(next_deadline_ns, .release);
        return .{ .nanoseconds = next_deadline_ns };
    }

    /// Extend an active deadline. A driver that already claimed expiry wins
    /// the race and cannot be resurrected by late packet progress.
    pub fn renew(
        self: *State,
        io: std.Io,
        timeout: ?std.Io.Clock.Duration,
    ) void {
        const duration = timeout orelse return;
        const next_deadline_ns = deadlineNsFromNow(io, duration);
        var current = self.deadline_ns.load(.acquire);
        while (current > disabled) {
            current = self.deadline_ns.cmpxchgWeak(
                current,
                next_deadline_ns,
                .release,
                .acquire,
            ) orelse return;
        }
    }

    pub fn deadline(self: *const State) ?std.Io.Timestamp {
        const value = self.deadline_ns.load(.acquire);
        return if (value > disabled) .{ .nanoseconds = value } else null;
    }

    /// Claim exactly the deadline observed by the driver. Concurrent progress
    /// replaces that value first and makes the stale expiry harmless.
    pub fn claimExpired(self: *State, expected_ns: i64) bool {
        std.debug.assert(expected_ns > disabled);
        return self.deadline_ns.cmpxchgStrong(
            expected_ns,
            expired,
            .acq_rel,
            .acquire,
        ) == null;
    }

    pub fn timedOut(self: *const State) bool {
        return self.deadline_ns.load(.acquire) == expired;
    }
};

fn deadlineNsFromNow(
    io: std.Io,
    timeout: std.Io.Clock.Duration,
) i64 {
    std.debug.assert(timeout.clock == .awake);
    const value = netz_runtime.cachedAwakeTimestamp(io)
        .addDuration(timeout).raw.nanoseconds;
    return std.math.cast(i64, value) orelse std.math.maxInt(i64);
}

test "broker Keep Alive state cannot renew after expiry is claimed" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var state: State = .{};

    try std.testing.expect(state.start(io, null) == null);
    const initial = state.start(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    }).?;
    try std.testing.expectEqual(initial, state.deadline().?);
    const initial_ns = std.math.cast(i64, initial.nanoseconds).?;
    try std.testing.expect(!state.claimExpired(initial_ns + 1));
    try std.testing.expect(state.claimExpired(initial_ns));
    state.renew(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    try std.testing.expect(state.timedOut());
    try std.testing.expect(state.deadline() == null);
}
