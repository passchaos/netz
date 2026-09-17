const quic = @import("../mod.zig");

/// Attempt one already-validated unreliable DATAGRAM send. Pending cumulative
/// ACK state is added when it fits; pre-submission resource/limit failures
/// fall back to the original DATAGRAM-only packet and leave the ACK pending.
pub fn sendOne(
    comptime ConnectionError: type,
    connection: anytype,
    data: []const u8,
    has_pending_ack: bool,
    sent_time_ns: u64,
) ConnectionError!void {
    const frames = [_]quic.Frame{.{ .datagram = .{
        .data = data,
        .length_present = true,
    } }};
    if (has_pending_ack) {
        connection.trySendWithPendingAckAt(
            &frames,
            0,
            sent_time_ns,
        ) catch |err| switch (err) {
            error.OutOfMemory,
            error.DatagramTooLarge,
            error.AntiAmplificationLimited,
            error.CongestionLimited,
            error.PacingLimited,
            => return connection.sendAt(&frames, sent_time_ns),
            else => return err,
        };
        return;
    }
    return connection.sendAt(&frames, sent_time_ns);
}
