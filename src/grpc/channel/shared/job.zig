const std = @import("std");
const call = @import("../../call.zig");

pub const Job = struct {
    options: call.UnaryCallOptions,
    deadline: ?std.Io.Clock.Timestamp,
    wait_for_ready: bool,
    previous_attempts: ?u8,
    next: ?*Job = null,
    phase: enum { queued, assigned, completed } = .queued,
    cancel_requested: bool = false,
    result: ?call.UnaryResponse = null,
    err: ?anyerror = null,
    done: std.Io.Event = .unset,
};
