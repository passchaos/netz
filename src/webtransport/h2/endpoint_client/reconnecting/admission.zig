//! Register callers before state-lock admission and release without relocking.
//! The closing owner waits for every registered caller, including callers
//! waiting on the mutex, before destroying State.
const std = @import("std");
const timed_mutex = @import("../../../../internal/timed_mutex.zig");

pub fn enter(state: anytype, deadline: std.Io.Clock.Timestamp) !void {
    _ = state.active.fetchAdd(1, .acq_rel);
    errdefer leave(state);
    try timed_mutex.lock(&state.mutex, state.io, deadline);
    defer state.mutex.unlock(state.io);
    if (state.closed) return error.ClientClosed;
}

pub fn leave(state: anytype) void {
    // Notify before the final State access. The closer may destroy State as
    // soon as the count reaches zero, so notification cannot follow that drop.
    state.idle.set(state.io);
    const previous = state.active.fetchSub(1, .acq_rel);
    std.debug.assert(previous != 0);
}

pub fn waitForIdle(state: anytype) void {
    while (true) {
        state.idle.reset();
        if (state.active.load(.acquire) == 0) return;
        // A notification may arrive before its caller's final count drop.
        // A bounded event wait resolves that small publication window without
        // needing the caller to access State again after dropping ownership.
        state.idle.waitTimeout(state.io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(1) } }) catch {};
    }
}
