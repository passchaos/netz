//! Stream-scoped reliable delivery without draining unrelated H3 work.

const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn wait(comptime Error: type, session: anytype, stream_id: u62, deadline: std.Io.Clock.Timestamp, comptime progress: anytype) Error!void {
    const connection: *quic.one_rtt.Connection = &session.established.connection;
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    if (connection.sendStreamStats(stream_id) == null and connection.streamLifecycle(stream_id) != .closed) return error.UnexpectedStream;
    while (connection.pendingStreamDeliveryRecovery(stream_id)) {
        if (connection.closing() or connection.draining() or connection.closed()) return error.ConnectionClosed;
        try progress(session, deadline);
    }
}
