const std = @import("std");

/// Arms one deterministic datagram hold. Endpoint.sendBytes sends the next
/// datagram first and then flushes the held datagram, producing one real UDP
/// reordering pair without parsing encrypted QUIC payloads.
pub const State = struct {
    armed: std.atomic.Value(bool) = .init(false),
    held: std.atomic.Value(usize) = .init(0),

    pub fn arm(self: *State) void {
        self.armed.store(true, .release);
    }

    pub fn heldCount(self: *const State) usize {
        return self.held.load(.acquire);
    }

    pub fn shouldHold(context: *anyopaque, _: []const u8) bool {
        const self: *State = @ptrCast(@alignCast(context));
        if (!self.armed.load(.acquire)) return false;
        return self.held.cmpxchgStrong(
            0,
            1,
            .acq_rel,
            .acquire,
        ) == null;
    }
};

test "one-shot reorder holds exactly one datagram after arming" {
    var state = State{};
    try std.testing.expect(!State.shouldHold(&state, "before"));
    state.arm();
    try std.testing.expect(State.shouldHold(&state, "cancel"));
    try std.testing.expect(!State.shouldHold(&state, "later"));
    try std.testing.expectEqual(@as(usize, 1), state.heldCount());
}
