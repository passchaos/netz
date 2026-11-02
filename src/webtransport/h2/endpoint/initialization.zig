//! Start an endpoint owner with transfer-on-entry failure cleanup.
const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");

/// State already owns its connection and fixed tables. This function consumes
/// that ownership on every path, including worker admission failure.
pub fn start(comptime Owner: type, comptime run: anytype, state: anytype, deadline: ?std.Io.Clock.Timestamp) !Owner {
    var owned = true;
    errdefer if (owned) {
        state.closed = true;
        state.worker_stopped = true;
        if (deadline != null) state.connection.closeWithoutCloseNotify() else state.connection.close();
        state.release();
    };
    if (deadline) |until| {
        _ = try deadline_policy.usableAwake(state.io, until);
        try state.io.checkCancel();
    }
    state.retain();
    state.group.concurrent(state.io, run, .{state}) catch |err| {
        // The worker did not start; release its provisional reference before
        // the transfer-on-entry rollback releases the owning reference.
        state.release();
        return err;
    };
    owned = false;
    var owner = Owner{ .state = state };
    if (deadline) |until| {
        _ = deadline_policy.usableAwake(state.io, until) catch |err| {
            owner.deinitAbortive();
            return err;
        };
        state.io.checkCancel() catch |err| {
            owner.deinitAbortive();
            return err;
        };
    }
    return owner;
}
