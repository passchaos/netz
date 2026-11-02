//! Bounded caller command admission; ownership transfers only after commit.
const std = @import("std");
const timed_mutex = @import("../../../internal/timed_mutex.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn enqueue(state: anytype, job: anytype, comptime hooks: anytype) !void {
    try timed_mutex.lock(&state.mutex, state.io, job.deadline);
    defer state.mutex.unlock(state.io);
    try state.io.checkCancel();
    if (state.closed) return error.EndpointClosed;
    if (@hasField(@TypeOf(state.*), "abortive_shutdown")) {
        if (state.abortive_shutdown.load(.acquire)) return error.EndpointClosed;
    }
    if (state.failure) |failure| return failure;
    if (@hasField(@TypeOf(hooks), "prepare")) hooks.prepare(state);
    if (state.queued >= state.options.max_queued_commands) return error.EndpointQueueFull;
    _ = try deadline_policy.usableAwake(state.io, job.deadline);
    try state.io.checkCancel();
    if (@hasField(@TypeOf(hooks), "admit")) try hooks.admit(state, job);
    job.retain();
    if (state.tail) |tail| tail.next = job else state.head = job;
    state.tail = job;
    state.queued += 1;
    state.wake.set(state.io);
}
