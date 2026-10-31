//! Caller commands are consumed by the existing endpoint and resolver owners.
const std = @import("std");
const State = @import("state.zig").State;

pub fn reset(state: *State, deadline: ?std.Io.Clock.Timestamp) State.Failure!void {
    try state.lockBefore(deadline);
    defer state.unlock();
    if (state.closed) return error.SharedChannelClosed;
    for (state.workers.items) |worker| {
        if (worker.retired) continue;
        worker.backoff_reset_requested.store(true, .release);
        worker.wake.set(state.io);
    }
    for (state.sources) |*source| {
        if (source.resolver == null) continue;
        source.backoff_reset_requested = true;
        source.wake.set(state.io);
    }
}
