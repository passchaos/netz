//! Shared absolute-deadline composition for blocking `std.Io` operations.

const std = @import("std");

pub const Error = error{Timeout};

/// Convert an optional relative timeout into an awake-clock timestamp.
pub fn fromTimeout(
    io: std.Io,
    timeout: ?std.Io.Duration,
) Error!?std.Io.Clock.Timestamp {
    const duration = timeout orelse return null;
    if (duration.nanoseconds <= 0) return error.Timeout;
    return .fromNow(io, .{ .raw = duration, .clock = .awake });
}

pub fn earlier(
    a: ?std.Io.Clock.Timestamp,
    b: ?std.Io.Clock.Timestamp,
) ?std.Io.Clock.Timestamp {
    const left = a orelse return b;
    const right = b orelse return left;
    return if (std.Io.Clock.Timestamp.compare(left, .lt, right))
        left
    else
        right;
}

/// Validate a caller-owned deadline before an operation begins. Operations in
/// netz use the awake clock so suspend time and timestamps from other clock
/// domains cannot silently alter a network timeout.
pub fn usableAwake(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) Error!std.Io.Clock.Timestamp {
    if (deadline.clock != .awake or
        deadline.durationFromNow(io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
    return deadline;
}

/// Keep the original absolute timestamp while applying a stricter phase
/// timeout. This prevents time spent in an earlier phase from being regained.
pub fn capTimeout(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    timeout: ?std.Io.Duration,
) Error!std.Io.Clock.Timestamp {
    const outer = try usableAwake(io, deadline);
    return earlier(outer, try fromTimeout(io, timeout)).?;
}

test "deadline composition retains the earlier bound" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const outer = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    const capped = try capTimeout(io, outer, .fromMilliseconds(10));
    try std.testing.expect(std.Io.Clock.Timestamp.compare(capped, .lt, outer));
    try std.testing.expectError(
        error.Timeout,
        usableAwake(io, .{ .raw = .zero, .clock = .real }),
    );
}
