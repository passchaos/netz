//! Opportunistic cumulative ACKs share the application's packet and commit.
const quic = @import("../../../quic/mod.zig");
const std = @import("std");
const bounded = @import("../../../internal/progress_deadline.zig");

/// Returns false when the ACK combination cannot fit the current packet,
/// frame, pacing or congestion budget. The ACK stays pending for its timer,
/// and the caller can submit the unchanged application frames separately.
pub fn trySend(connection: *quic.one_rtt.Connection, frames: []const quic.Frame, frame_limit: usize) quic.one_rtt.Error!bool {
    return trySendUntil(connection, frames, frame_limit, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn trySendUntil(connection: *quic.one_rtt.Connection, frames: []const quic.Frame, frame_limit: usize, deadline: ?std.Io.Clock.Timestamp) (quic.one_rtt.Error || bounded.BudgetError)!bool {
    const extra: usize = @as(usize, 1) + @intFromBool(connection.handshakeDonePending());
    if (frames.len > frame_limit -| extra or connection.ackDelayDeadline() == null) return false;
    const result = if (deadline) |until| boundedSend(connection, frames, until) else connection.trySendWithPendingAck(frames, 0);
    result catch |err| switch (err) {
        error.OutOfMemory,
        error.DatagramTooLarge,
        error.AntiAmplificationLimited,
        error.CongestionLimited,
        error.PacingLimited,
        => return false,
        else => return err,
    };
    return true;
}

fn boundedSend(connection: *quic.one_rtt.Connection, frames: []const quic.Frame, deadline: std.Io.Clock.Timestamp) (quic.one_rtt.Error || bounded.BudgetError)!void {
    const outcome = bounded.before(connection.endpoint.io, deadline, quic.one_rtt.Connection.trySendWithPendingAck, .{ connection, frames, 0 });
    const result = outcome.result orelse return outcome.wait_error orelse error.Unexpected;
    result catch |err| {
        if (err == error.Canceled) if (outcome.wait_error) |wait_error| return wait_error;
        return err;
    };
}
