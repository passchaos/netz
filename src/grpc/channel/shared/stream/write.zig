//! Each direction permits one outstanding operation, matching gRPC writers.
const std = @import("std");
const Write = @import("call.zig").Write;
const deadline_policy = @import("../../../../internal/deadline.zig");

pub fn submit(call: anytype, input: Write) @TypeOf(call.parent.*).Failure!void {
    const state = call.parent;
    call.retain();
    defer call.release();
    if (input.payload.len > call.options.requestMessageLimit()) return error.GrpcMessageTooLarge;
    if (input.deadline) |until| _ = try deadline_policy.usableAwake(state.io, until);
    var command = input;
    command.deadline = deadline_policy.earlier(call.deadline, input.deadline);
    if (command.deadline) |until| _ = try deadline_policy.usableAwake(state.io, until);
    state.lock();
    if (state.closed or call.retired or call.cancel_requested or call.request_finished) {
        const failure = call.failure orelse (if (state.closed) error.SharedChannelClosed else error.ConnectionClosed);
        state.unlock();
        return @errorCast(failure);
    }
    if (call.write != null) {
        state.unlock();
        return error.InvalidStreamState;
    }
    call.write = &command;
    state.wakeAllLocked();
    state.unlock();
    while (true) {
        const waited = if (command.deadline) |until|
            command.done.waitTimeout(state.io, .{ .deadline = until })
        else
            command.done.wait(state.io);
        waited catch |err| {
            if (err == error.Timeout and command.deadline.?.durationFromNow(state.io).raw.nanoseconds > 0) continue;
            state.lock();
            if (call.failure == null) call.failure = err;
            state.unlock();
            call.cancel();
            return err;
        };
        break;
    }
    if (command.err) |err| return @errorCast(err);
}
