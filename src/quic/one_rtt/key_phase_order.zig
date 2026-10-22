const std = @import("std");
const protection = @import("../protection.zig");

pub const Error = error{KeyUpdateError};

const none = std.math.maxInt(u64);

/// RFC 9001 section 6.4 packet-number ordering across receive key phases.
///
/// A packet authenticated with the next generation must be newer than every
/// packet accepted with the current generation. While retired keys remain, an
/// old-generation packet is legal only when it is no newer than the lowest
/// packet observed in the current phase.
pub const State = struct {
    lowest_current_packet_number: u64 = none,
    unacknowledged_update_packet_number: u64 = none,

    pub fn validate(
        self: State,
        generation: protection.OpenedKeyGeneration,
        packet_number: u64,
        expected_packet_number: u64,
    ) Error!void {
        switch (generation) {
            .current => {},
            .next => if (expected_packet_number != 0 and
                packet_number < expected_packet_number)
            {
                return error.KeyUpdateError;
            },
            .previous => if (self.lowestCurrent()) |lowest| {
                if (packet_number > lowest) return error.KeyUpdateError;
            },
        }
    }

    pub fn accept(
        self: *State,
        generation: protection.OpenedKeyGeneration,
        packet_number: u64,
    ) void {
        switch (generation) {
            .current => self.lowest_current_packet_number = @min(
                self.lowest_current_packet_number,
                packet_number,
            ),
            .next => self.lowest_current_packet_number = packet_number,
            .previous => {},
        }
    }

    pub fn lowestCurrent(self: State) ?u64 {
        return if (self.lowest_current_packet_number == none)
            null
        else
            self.lowest_current_packet_number;
    }

    pub fn unacknowledgedUpdate(self: State) ?u64 {
        return if (self.unacknowledged_update_packet_number == none)
            null
        else
            self.unacknowledged_update_packet_number;
    }

    pub fn setUnacknowledgedUpdate(
        self: *State,
        packet_number: u64,
    ) void {
        self.unacknowledged_update_packet_number = packet_number;
    }

    pub fn clearUnacknowledgedUpdate(self: *State) void {
        self.unacknowledged_update_packet_number = none;
    }
};

test "QUIC key phase ordering tracks reordered current packets" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(State));
    var state: State = .{};
    state.accept(.current, 5);
    try std.testing.expectError(
        error.KeyUpdateError,
        state.validate(.next, 5, 6),
    );
    try state.validate(.next, 20, 6);
    state.accept(.next, 20);
    state.accept(.current, 10);
    try state.validate(.previous, 7, 21);
    try state.validate(.previous, 10, 21);
    try std.testing.expectError(
        error.KeyUpdateError,
        state.validate(.previous, 15, 21),
    );
    state.setUnacknowledgedUpdate(20);
    try std.testing.expectEqual(@as(?u64, 20), state.unacknowledgedUpdate());
    state.clearUnacknowledgedUpdate();
    try std.testing.expectEqual(@as(?u64, null), state.unacknowledgedUpdate());
}
