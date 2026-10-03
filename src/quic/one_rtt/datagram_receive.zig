const std = @import("std");
const quic = @import("../mod.zig");

pub const Target = struct {
    outputs: [][]u8,
    delivered_count: usize = 0,
    buffer_too_small: bool = false,
    visitor_consumes: bool = false,

    /// Consume frames into caller-owned buffers while a direct receive is
    /// active, or mark them consumed when a synchronous borrowed visitor owns
    /// delivery. Frames beyond a copying target remain available to the
    /// bounded queue path.
    pub fn consume(self: *Target, payload: []const u8) bool {
        if (self.visitor_consumes) {
            self.delivered_count +|= 1;
            return true;
        }
        if (self.delivered_count == self.outputs.len or
            self.buffer_too_small) return false;
        const out = self.outputs[self.delivered_count];
        if (payload.len <= out.len) {
            @memcpy(out[0..payload.len], payload);
            self.outputs[self.delivered_count] = out[0..payload.len];
            self.delivered_count += 1;
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
        var outputs = [_][]u8{out};
        var target: Target = .{ .outputs = &outputs };
        connection.datagram_receive_target = &target;
        const service_result = if (deadline) |bounded|
            connection.servicePacketServicingTimersDeadline(bounded)
        else
            connection.servicePacketServicingTimers();
        connection.datagram_receive_target = null;
        try service_result;
        if (target.delivered_count == 1) return outputs[0];
        if (target.buffer_too_small) return error.DatagramBufferTooSmall;
    }
}

pub fn receiveManyUntil(
    comptime ConnectionError: type,
    connection: anytype,
    outputs: [][]u8,
    received_count: *usize,
    deadline: ?std.Io.Clock.Timestamp,
) (ConnectionError || quic.runtime.ReceiveTimeoutError)!void {
    received_count.* = 0;
    if (outputs.len == 0) return;
    if (!connection.datagramReceiveEnabled()) {
        return error.DatagramsNotEnabled;
    }
    if (connection.datagram_receive_target != null) {
        return error.ConcurrencyUnavailable;
    }
    if (outputs.len > quic.runtime.max_receive_batch_messages) {
        return error.BufferTooShort;
    }
    while (received_count.* < outputs.len) {
        if (try connection.popDatagram(outputs[received_count.*])) |payload| {
            outputs[received_count.*] = payload;
            received_count.* += 1;
            continue;
        }
        var target: Target = .{
            .outputs = outputs[received_count.*..],
        };
        connection.datagram_receive_target = &target;
        const service_result = if (deadline) |bounded|
            connection.servicePacketBatchServicingTimersDeadline(bounded)
        else
            connection.servicePacketBatchServicingTimers();
        connection.datagram_receive_target = null;
        received_count.* += target.delivered_count;
        _ = service_result catch |err| return err;
        if (target.buffer_too_small) return error.DatagramBufferTooSmall;
    }
}

test "caller-buffer target consumes only its first DATAGRAM" {
    var out: [4]u8 = undefined;
    var outputs = [_][]u8{&out};
    var target: Target = .{ .outputs = &outputs };
    try std.testing.expect(target.consume("data"));
    try std.testing.expectEqualStrings("data", outputs[0]);
    try std.testing.expect(!target.consume("next"));
}

test "caller-buffer target consumes an oversized DATAGRAM" {
    var out: [2]u8 = undefined;
    var outputs = [_][]u8{&out};
    var target: Target = .{ .outputs = &outputs };
    try std.testing.expect(target.consume("large"));
    try std.testing.expect(target.buffer_too_small);
    try std.testing.expect(!target.consume("ok"));
}

test "caller-buffer target fills a batch and leaves later frames queued" {
    var first: [5]u8 = undefined;
    var second: [6]u8 = undefined;
    var outputs = [_][]u8{ &first, &second };
    var target: Target = .{ .outputs = &outputs };
    try std.testing.expect(target.consume("first"));
    try std.testing.expect(target.consume("second"));
    try std.testing.expect(!target.consume("third"));
    try std.testing.expectEqual(@as(usize, 2), target.delivered_count);
    try std.testing.expectEqualStrings("first", outputs[0]);
    try std.testing.expectEqualStrings("second", outputs[1]);
}

test "borrowed visitor target consumes without copying" {
    var target: Target = .{
        .outputs = &.{},
        .visitor_consumes = true,
    };
    try std.testing.expect(target.consume("first"));
    try std.testing.expect(target.consume("second"));
    try std.testing.expectEqual(@as(usize, 2), target.delivered_count);
    try std.testing.expect(!target.buffer_too_small);
}
