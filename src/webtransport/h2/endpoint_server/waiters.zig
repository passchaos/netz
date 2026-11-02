//! Bound request-reception callers independently of queued Session commands.
//! Called with the owning endpoint State mutex held.
const std = @import("std");

pub fn reserve(state: anytype, job: anytype) error{RequestWaiterCapacity}!void {
    if (job.command != .receive_request) return;
    if (state.waiting_requests >= state.options.max_request_waiters) return error.RequestWaiterCapacity;
    std.debug.assert(!job.waiting_request);
    job.waiting_request = true;
    state.waiting_requests += 1;
}

pub fn complete(state: anytype, job: anytype) void {
    if (!job.waiting_request) return;
    std.debug.assert(state.waiting_requests != 0);
    job.waiting_request = false;
    state.waiting_requests -= 1;
}

pub fn prune(state: anytype, comptime finish: anytype) void {
    var previous: @TypeOf(state.receive_head) = null;
    var cursor = state.receive_head;
    while (cursor) |job| {
        const next = job.next;
        job.checkExecution(state.io) catch |err| {
            if (previous) |value| value.next = next else state.receive_head = next;
            if (state.receive_tail == job) state.receive_tail = previous;
            job.next = null;
            _ = finish(state, job, err);
            cursor = next;
            continue;
        };
        previous = job;
        cursor = next;
    }
}
