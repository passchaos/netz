//! Each direction permits one outstanding operation, matching gRPC writers.
const std = @import("std");
const call_module = @import("call.zig");
const deadline_policy = @import("../../../../internal/deadline.zig");

/// Payloads at or above this size are written as prefix+payload slices
/// instead of being copied into a queued staging allocation.
const const_borrow_threshold: usize = 64 * 1024;

pub fn submit(call: anytype, input: call_module.WriteInput) @TypeOf(call.parent.*).Failure!void {
    const state = call.parent;
    if (input.payload.len > call.options.requestMessageLimit()) return error.GrpcMessageTooLarge;
    if (input.deadline) |until| _ = try deadline_policy.usableAwake(state.io, until);
    var owned = input;
    owned.deadline = deadline_policy.earlier(call.deadline, input.deadline);
    if (owned.deadline) |until| _ = try deadline_policy.usableAwake(state.io, until);
    const command = if (!owned.finish_only and
        owned.payload.len >= const_borrow_threshold)
        try call_module.Write.createConstBorrowed(
            state.allocator,
            owned.payload,
            owned,
        )
    else
        try call_module.Write.create(state.allocator, owned);
    return submitCommand(call, command);
}

/// Consumes `message` on every return path. A caller may safely keep a
/// deferred `message.deinit()` because successful consumption clears it.
pub fn submitOwned(
    call: anytype,
    message: *call_module.OwnedWriteMessage,
    input: call_module.WriteInput,
) @TypeOf(call.parent.*).Failure!void {
    defer message.deinit();
    const state = call.parent;
    const payload_len = if (message.storage) |storage| blk: {
        if (storage.len < 5) return error.InvalidStreamState;
        break :blk storage.len - 5;
    } else return error.InvalidStreamState;
    if (payload_len > call.options.requestMessageLimit()) {
        return error.GrpcMessageTooLarge;
    }
    if (input.deadline) |until| {
        _ = try deadline_policy.usableAwake(state.io, until);
    }
    var owned = input;
    owned.deadline = deadline_policy.earlier(call.deadline, input.deadline);
    if (owned.deadline) |until| {
        _ = try deadline_policy.usableAwake(state.io, until);
    }
    const command = try call_module.Write.createOwned(
        state.allocator,
        message,
        owned,
    );
    return submitCommand(call, command);
}

/// Submit a caller-owned prefix-reserved message. The caller must keep
/// `storage` valid and unmodified until this call returns; the endpoint owner
/// writes it in bounded turns without taking ownership.
pub fn submitBorrowed(
    call: anytype,
    storage: []u8,
    input: call_module.WriteInput,
) @TypeOf(call.parent.*).Failure!void {
    const state = call.parent;
    if (storage.len < 5) return error.InvalidStreamState;
    const payload_len = storage.len - 5;
    if (payload_len > call.options.requestMessageLimit()) {
        return error.GrpcMessageTooLarge;
    }
    if (input.deadline) |until| {
        _ = try deadline_policy.usableAwake(state.io, until);
    }
    var owned = input;
    owned.deadline = deadline_policy.earlier(call.deadline, input.deadline);
    if (owned.deadline) |until| {
        _ = try deadline_policy.usableAwake(state.io, until);
    }
    const command = try call_module.Write.createBorrowed(
        state.allocator,
        storage,
        owned,
    );
    return submitCommand(call, command);
}

fn submitCommand(
    call: anytype,
    command: *call_module.Write,
) @TypeOf(call.parent.*).Failure!void {
    const state = call.parent;
    call.retain();
    defer call.release();
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
    if (command.borrowed) {
        // The caller's payload must stay valid until the owner is done. The
        // owner applies `command.deadline` to its bounded write turns, so this
        // wait is bounded even though the submitter cannot abandon the buffer.
        command.done.waitUncancelable(state.io);
        if (command.err) |failure| return @errorCast(failure);
        return;
    }
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
