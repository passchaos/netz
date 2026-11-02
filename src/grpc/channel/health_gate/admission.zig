//! Single-owner ordinary Channel health admission and wait-for-ready budgets.
const std = @import("std");
const gate = @import("../health_gate.zig");
const Sync = @import("sync.zig");

pub const Error = std.Io.Event.WaitTimeoutError || error{ConnectionUnavailable};
pub const Options = struct {
    wait_for_ready: bool,
    deadline: ?std.Io.Clock.Timestamp,
    canceled: *const std.Io.Event,
};

/// `slots` exposes one atomic `health_state` per resolved subchannel. This
/// keeps admission independent of the owning Channel's transport fields.
pub fn wait(io: std.Io, sync: *Sync, slots: anytype, options: Options) Error!void {
    while (true) {
        // A publication after this snapshot must force another state scan.
        const generation = sync.snapshot();
        if (options.canceled.isSet()) return error.Canceled;
        var serving = false;
        var unknown = false;
        for (slots) |*slot| switch (slot.health_state.load(.acquire)) {
            gate.serving => serving = true,
            gate.not_serving => {},
            gate.unknown => unknown = true,
            else => unreachable,
        };
        if (serving) return;
        if (!unknown and !options.wait_for_ready) return error.ConnectionUnavailable;
        if (options.deadline) |bound| {
            if (bound.clock != .awake or bound.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        }
        try sync.wait(io, generation, options.deadline);
    }
}

test {
    _ = @import("admission_tests.zig");
}
