const std = @import("std");
const State = @import("../state.zig").State;

pub const Manager = struct {
    state: *State,
    activation: std.Io.Event = .unset,
    aborted: std.atomic.Value(bool) = .init(false),

    pub fn run(self: *Manager) std.Io.Cancelable!void {
        const state = self.state;
        defer state.allocator.destroy(self);
        try self.activation.wait(state.io);
        if (self.aborted.load(.acquire)) return;
        while (true) {
            state.lock();
            if (state.closed) {
                state.unlock();
                return;
            }
            const garbage = state.retention.poll(state, std.Io.Clock.awake.now(state.io).nanoseconds);
            const deadline = state.retention.nextDeadline();
            state.retention.wake.reset();
            state.unlock();
            State.Retention.destroyList(garbage);
            if (deadline) |until| {
                state.retention.wake.waitTimeout(state.io, .{ .deadline = .{ .raw = .{ .nanoseconds = until }, .clock = .awake } }) catch |err| {
                    if (err == error.Canceled) return error.Canceled;
                };
            } else try state.retention.wake.wait(state.io);
        }
    }
};
