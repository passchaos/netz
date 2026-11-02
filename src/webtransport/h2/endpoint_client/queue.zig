//! Bounded caller command admission; ownership transfers only after commit.
const std = @import("std");
const timed_mutex = @import("../../../internal/timed_mutex.zig");

pub fn enqueue(state: anytype, job: anytype) !void {
    try timed_mutex.lock(&state.mutex, state.io, job.deadline);
    defer state.mutex.unlock(state.io);
    try state.io.checkCancel();
    if (state.closed or state.abortive_shutdown.load(.acquire)) return error.EndpointClosed;
    if (state.failure) |failure| return failure;
    if (state.queued >= state.options.max_queued_commands) return error.EndpointQueueFull;
    job.retain();
    if (state.tail) |tail| tail.next = job else state.head = job;
    state.tail = job;
    state.queued += 1;
    state.wake.set(state.io);
}
