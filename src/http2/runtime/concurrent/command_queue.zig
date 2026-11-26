//! A handler borrows its stack command until the connection owner releases it.
const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn submit(owner: anytype, command: anytype, deadline: ?std.Io.Clock.Timestamp, comptime inline_execute: anytype, comptime wait: anytype) !void {
    if (deadline) |until| _ = try deadline_policy.usableAwake(owner.io, until);
    try owner.io.checkCancel();
    command.deadline = deadline;
    if (owner.inline_active and owner.inline_slot == command.slot) {
        return inline_execute(owner, command);
    }
    owner.mutex.lockUncancelable(owner.io);
    owner.commands.append(owner.allocator, command) catch |err| {
        owner.mutex.unlock(owner.io);
        return err;
    };
    owner.mutex.unlock(owner.io);
    owner.wake.set(owner.io);
    wait(owner.io, &command.done, deadline) catch |err| {
        command.abandoned.store(true, .release);
        owner.wake.set(owner.io);
        // Cancellation cannot release borrowed headers or DATA while the
        // owner can still reference this command. The event publishes both
        // its result and the fully committed outcome.
        command.done.waitUncancelable(owner.io);
        if (command.succeeded) {
            // Preserve a completed response without consuming the task's
            // actual cancellation notification on behalf of its caller.
            if (err == error.Canceled) std.Io.recancel(owner.io);
            return;
        }
        return err;
    };
    if (command.result) |failure| return failure;
}

pub fn drain(owner: anytype, comptime execute: anytype) !void {
    owner.commands_blocked = false;
    while (true) {
        owner.mutex.lockUncancelable(owner.io);
        if (owner.commands.isEmpty()) {
            owner.mutex.unlock(owner.io);
            return;
        }
        const command = owner.commands.popFront().?;
        owner.mutex.unlock(owner.io);
        if (command.abandoned.load(.acquire)) {
            command.done.set(owner.io);
            continue;
        }
        execute(owner, command) catch |err| switch (err) {
            error.FlowControlBlocked,
            error.CongestionLimited,
            error.PacingLimited,
            => {
                owner.mutex.lockUncancelable(owner.io);
                owner.commands.append(owner.allocator, command) catch {
                    command.result = error.OutOfMemory;
                    command.done.set(owner.io);
                    owner.mutex.unlock(owner.io);
                    continue;
                };
                owner.mutex.unlock(owner.io);
                owner.commands_blocked = true;
                return;
            },
            else => {
                command.result = err;
                command.done.set(owner.io);
                continue;
            },
        };
        command.succeeded = true;
        command.done.set(owner.io);
    }
}
