//! No-op discovery decisions obey the same admission budget as publication.
const std = @import("std");
const shared = @import("../channel/shared.zig");

pub fn unchangedRevisionWithDeadline(destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) shared.Error!u64 {
    const state = destination.state;
    state.retain();
    defer state.release();
    try state.lockBefore(deadline);
    defer state.unlock();
    if (state.closed) return error.SharedChannelClosed;
    return state.config_revision;
}
