//! Fatal input publishes termination without freeing an active writer's state.
const std = @import("std");
const common = @import("../common.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn request(connection: anytype) void {
    connection.write_aborted.store(true, .release);
    connection.receive_abort_pending.store(true, .release);
}

/// The send owner, or the final destructor after all active calls joined,
/// retires borrowed descriptors and encoder state. Multiplexed cancellation
/// needs a live output budget; an expired one preserves the retry flag.
pub fn finishLocked(connection: anytype, io: std.Io, deadline: ?std.Io.Clock.Timestamp, comptime needs_wire_budget: bool, comptime abort: anytype) void {
    if (!connection.receive_abort_pending.load(.acquire)) return;
    common.clearPendingOutboundLocked(connection);
    if (needs_wire_budget) {
        if (deadline) |before| _ = deadline_policy.usableAwake(io, before) catch return;
    }
    if (abort(connection, deadline)) connection.receive_abort_pending.store(false, .release);
}
