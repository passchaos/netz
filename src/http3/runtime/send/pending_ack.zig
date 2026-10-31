//! Opportunistic cumulative ACKs share the application's packet and commit.
const quic = @import("../../../quic/mod.zig");

/// Returns false when the ACK combination cannot fit the current packet,
/// frame, pacing or congestion budget. The ACK stays pending for its timer,
/// and the caller can submit the unchanged application frames separately.
pub fn trySend(connection: *quic.one_rtt.Connection, frames: []const quic.Frame, frame_limit: usize) quic.one_rtt.Error!bool {
    const extra: usize = @as(usize, 1) + @intFromBool(connection.handshakeDonePending());
    if (frames.len > frame_limit -| extra or connection.ackDelayDeadline() == null) return false;
    connection.trySendWithPendingAck(frames, 0) catch |err| switch (err) {
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
