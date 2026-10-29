//! Each direction permits one outstanding operation, matching gRPC writers.
const std = @import("std");
const call_module = @import("call.zig");
const deadline_policy = @import("../../../../internal/deadline.zig");

pub fn submit(call: anytype, input: call_module.WriteInput) @TypeOf(call.parent.*).Failure!void {
    const state = call.parent;
    call.retain();
    defer call.release();
    if (input.payload.len > call.options.requestMessageLimit()) return error.GrpcMessageTooLarge;
    if (input.deadline) |until| _ = try deadline_policy.usableAwake(state.io, until);
    var owned = input;
    owned.deadline = deadline_policy.earlier(call.deadline, input.deadline);
    if (owned.deadline) |until| _ = try deadline_policy.usableAwake(state.io, until);
    const command = try call_module.Write.create(state.allocator, owned);
    defer command.release();
    // No endpoint can observe the command before this lock succeeds. Keep an
    // admission timeout/cancellation retryable instead of retiring the RPC.
    try state.lockBefore(command.deadline);
    const canceled = call.cancel_requested.load(.acquire);
    if (state.closed or call.retired or canceled or call.request_finished) {
        const failure = call.failureValue() orelse (if (state.closed) error.SharedChannelClosed else if (canceled) error.Canceled else error.ConnectionClosed);
        state.unlock();
        return @errorCast(failure);
    }
    if (call.write != null) {
        state.unlock();
        return error.InvalidStreamState;
    }
    command.retain();
    call.write = command;
    state.wakeAllLocked();
    state.unlock();
    while (true) {
        const waited = if (command.deadline) |until|
            command.done.waitTimeout(state.io, .{ .deadline = until })
        else
            command.done.wait(state.io);
        waited catch |err| {
            if (err == error.Timeout and command.deadline.?.durationFromNow(state.io).raw.nanoseconds > 0) continue;
            if (!command.abandon()) {
                if (command.err) |failure| return @errorCast(failure);
                return;
            }
            call.fail(err);
            call.requestCancel();
            return err;
        };
        break;
    }
    if (command.err) |err| return @errorCast(err);
}
