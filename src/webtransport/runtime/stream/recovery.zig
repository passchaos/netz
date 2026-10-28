//! Stream-scoped delivery waiting for an independently owned WT session.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn wait(comptime Error: type, control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, deadline: std.Io.Clock.Timestamp) Error!void {
    const connection = &h3.established.connection;
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    if (registry.get(stream_id)) |stream| {
        if (stream.direction == .unidirectional and !stream.locally_initiated) return error.InvalidStreamState;
    } else if (connection.streamLifecycle(stream_id) != .closed) return error.UnknownStream;
    defer _ = lifecycle.observe(control, h3, registry);
    // A registered but unwritten send direction has no reliable work yet.
    if (connection.pendingStreamDeliveryRecovery(stream_id)) try h3.waitForStreamRecoveryIdleWithDeadline(stream_id, deadline);
    if (lifecycle.terminating(connection)) return error.ConnectionClosed;
    // This send half is already delivered. An ACK for unrelated received
    // traffic cannot invalidate that result. Submit it once; failed feedback
    // keeps QUIC's ACK counters/deadline for its existing connection timer.
    _ = connection.tryFlushPendingAck() catch {};
}
