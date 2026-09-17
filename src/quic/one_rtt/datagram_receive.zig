const std = @import("std");
const quic = @import("../mod.zig");

pub const Target = struct {
    out: []u8,
    delivered_len: ?usize = null,
    buffer_too_small: bool = false,

    /// Consume at most one frame while a caller-buffer receive is active.
    /// Later frames in the same packet remain available to the queue path.
    pub fn consume(self: *Target, payload: []const u8) bool {
        if (self.delivered_len != null or self.buffer_too_small) return false;
        if (payload.len <= self.out.len) {
            @memcpy(self.out[0..payload.len], payload);
            self.delivered_len = payload.len;
        } else {
            self.buffer_too_small = true;
        }
        return true;
    }
};

pub fn receiveUntil(
    comptime ConnectionError: type,
    connection: anytype,
    out: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) (ConnectionError || quic.runtime.ReceiveTimeoutError)![]u8 {
    if (!connection.datagramReceiveEnabled()) {
        return error.DatagramsNotEnabled;
    }
    if (connection.datagram_receive_target != null) {
        return error.ConcurrencyUnavailable;
    }
    while (true) {
        if (try connection.popDatagram(out)) |payload| return payload;
        var target: Target = .{ .out = out };
        connection.datagram_receive_target = &target;
        const service_result = if (deadline) |bounded|
            connection.servicePacketServicingTimersDeadline(bounded)
        else
            connection.servicePacketServicingTimers();
        connection.datagram_receive_target = null;
        try service_result;
        if (target.delivered_len) |len| return out[0..len];
        if (target.buffer_too_small) return error.DatagramBufferTooSmall;
    }
}

test "caller-buffer target consumes only its first DATAGRAM" {
    var out: [4]u8 = undefined;
    var target: Target = .{ .out = &out };
    try std.testing.expect(target.consume("data"));
    try std.testing.expectEqualStrings("data", out[0..target.delivered_len.?]);
    try std.testing.expect(!target.consume("next"));
}

test "caller-buffer target consumes an oversized DATAGRAM" {
    var out: [2]u8 = undefined;
    var target: Target = .{ .out = &out };
    try std.testing.expect(target.consume("large"));
    try std.testing.expect(target.buffer_too_small);
    try std.testing.expect(!target.consume("ok"));
}
