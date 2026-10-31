//! Blocking DATA writes with exact per-contribution commit boundaries.
const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const sender = @import("body.zig");
const outbound = @import("../stream/outbound_body.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const Error = @import("../error.zig").ReceiveTimeoutError;

pub const Result = enum { complete, cancelled };

/// Each contribution fits the current path, stream/connection credit and
/// congestion budget. It commits atomically, so a later deadline interruption
/// leaves progress at an HTTP/3 DATA boundary and the caller can send its suffix.
pub fn write(connection: *quic.one_rtt.Connection, bodies: *outbound.Set, options: anytype, context: anytype, id: u62, data: []const u8, fin: bool, deadline: ?std.Io.Clock.Timestamp, progress: anytype, comptime hooks: anytype) Error!Result {
    progress.* = .{};
    const current = bodies.find(id) orelse return error.UnexpectedStream;
    var validation = current.*;
    try bodies.prepareChunkForEntry(&validation, data.len, fin);
    if (data.len == 0 and !fin) return .complete;
    const chunk_limit = sender.pacedBodyChunkLimit(options);
    while (progress.committed_bytes < data.len or (fin and !progress.fin_committed)) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
        if (try hooks.before(context, id, deadline)) return .cancelled;
        const remaining = data.len - progress.committed_bytes;
        const credit = connection.streamSendCredit(id);
        var count = sender.responseBodySendCapacity(
            remaining,
            std.math.cast(usize, credit.connection) orelse std.math.maxInt(usize),
            std.math.cast(usize, credit.stream) orelse std.math.maxInt(usize),
            credit.congestion,
            credit.max_datagram_size,
            chunk_limit,
        );
        if (remaining != 0 and count == 0) {
            try hooks.receive(context, id, deadline);
            continue;
        }
        while (true) {
            const last = count == remaining;
            sender.trySendConnectionBodyChunk(connection, bodies, id, data[progress.committed_bytes..][0..count], fin and last, options) catch |err| switch (err) {
                error.DatagramTooLarge => {
                    if (count <= 1) return err;
                    count = @max(@as(usize, 1), count / 2);
                    continue;
                },
                error.PacingLimited => {
                    if (deadline) |absolute| try connection.waitForPacingAvailabilityWithDeadline(absolute) else try connection.waitForPacingAvailability();
                    continue;
                },
                error.FlowControlBlocked, error.CongestionLimited => {
                    try hooks.receive(context, id, deadline);
                    break;
                },
                else => return err,
            };
            progress.committed_bytes += count;
            progress.fin_committed = fin and last;
            if (progress.fin_committed) try hooks.finish(context, id);
            break;
        }
    }
    return .complete;
}
