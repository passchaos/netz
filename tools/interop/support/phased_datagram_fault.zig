const std = @import("std");

pub const Mode = enum { loss, reorder };

/// Arms one deterministic datagram fault per protocol phase. A receiver-side
/// acknowledgement separates phases, so a held datagram is known to have been
/// flushed before the next arm.
pub const State = struct {
    mode: Mode,
    armed: std.atomic.Value(bool) = .init(false),
    injected: std.atomic.Value(usize) = .init(0),

    pub fn init(mode: Mode) State {
        return .{ .mode = mode };
    }

    pub fn arm(self: *State) !usize {
        if (self.armed.swap(true, .acq_rel)) return error.FaultAlreadyArmed;
        return self.injected.load(.acquire);
    }

    pub fn completePhase(self: *const State, before: usize) !usize {
        if (self.armed.load(.acquire)) return error.FaultNotExercised;
        const after = self.injected.load(.acquire);
        if (after != before + 1) return error.FaultNotExercised;
        return after - before;
    }

    pub fn injectedCount(self: *const State) usize {
        return self.injected.load(.acquire);
    }

    pub fn shouldDrop(context: *anyopaque, _: []const u8) bool {
        const self: *State = @ptrCast(@alignCast(context));
        return self.mode == .loss and self.inject();
    }

    pub fn shouldHold(context: *anyopaque, _: []const u8) bool {
        const self: *State = @ptrCast(@alignCast(context));
        return self.mode == .reorder and self.inject();
    }

    fn inject(self: *State) bool {
        if (self.armed.cmpxchgStrong(
            true,
            false,
            .acq_rel,
            .acquire,
        ) != null) return false;
        _ = self.injected.fetchAdd(1, .acq_rel);
        return true;
    }
};

test "phased datagram fault injects exactly once per arm" {
    inline for (.{ Mode.loss, Mode.reorder }) |mode| {
        var state = State.init(mode);
        try std.testing.expect(!State.shouldDrop(&state, "before"));
        try std.testing.expect(!State.shouldHold(&state, "before"));

        const first = try state.arm();
        const injected_first = if (mode == .loss)
            State.shouldDrop(&state, "reset")
        else
            State.shouldHold(&state, "reset");
        try std.testing.expect(injected_first);
        try std.testing.expect(!State.shouldDrop(&state, "later"));
        try std.testing.expect(!State.shouldHold(&state, "later"));
        try std.testing.expectEqual(@as(usize, 1), try state.completePhase(first));

        const second = try state.arm();
        const injected_second = if (mode == .loss)
            State.shouldDrop(&state, "fin")
        else
            State.shouldHold(&state, "fin");
        try std.testing.expect(injected_second);
        try std.testing.expectEqual(@as(usize, 1), try state.completePhase(second));
        try std.testing.expectEqual(@as(usize, 2), state.injectedCount());
    }
}

test "phased datagram fault rejects overlapping arms" {
    var state = State.init(.loss);
    _ = try state.arm();
    try std.testing.expectError(error.FaultAlreadyArmed, state.arm());
    try std.testing.expectError(error.FaultNotExercised, state.completePhase(0));
}
