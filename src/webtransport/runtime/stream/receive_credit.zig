//! Application receive ownership does not wait for outbound flow feedback.
const std = @import("std");
const quic = @import("../../../quic/mod.zig");

/// Commit exactly this available prefix. QUIC advances the local receive
/// cursor and retains any failed MAX_DATA/MAX_STREAM_DATA advertisement for
/// its connection timer, so a ready read never sleeps for pacing or ACKs.
pub fn commit(connection: *quic.one_rtt.Connection, stream_id: u62, count: u64) quic.one_rtt.Error!void {
    const stats = connection.recvStreamStats(stream_id) orelse return error.StreamStateError;
    const end = std.math.add(u64, stats.bytes_read, count) catch return error.InvalidStreamRange;
    try connection.commitReceivedThrough(stream_id, end);
}
