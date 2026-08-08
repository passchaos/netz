const std = @import("std");
const quic = @import("mod.zig");

pub const Error = error{
    FlowControlBlocked,
    FlowControlViolation,
    InvalidWindow,
};

pub const SendFlow = struct {
    limit: u64,
    used: u64 = 0,

    pub fn init(limit: u64) SendFlow {
        return .{ .limit = limit };
    }

    pub fn available(self: SendFlow) u64 {
        return self.limit -| self.used;
    }

    pub fn reserve(self: *SendFlow, amount: u64) Error!void {
        if (amount > self.available()) return error.FlowControlBlocked;
        self.used += amount;
    }

    pub fn updateLimit(self: *SendFlow, new_limit: u64) void {
        self.limit = @max(self.limit, new_limit);
    }

    pub fn dataBlockedFrame(self: SendFlow) quic.Frame {
        return .{ .data_blocked = .{ .maximum_data = self.limit } };
    }

    pub fn streamDataBlockedFrame(self: SendFlow, stream_id: u64) quic.Frame {
        return .{ .stream_data_blocked = .{ .stream_id = stream_id, .maximum_stream_data = self.limit } };
    }
};

pub const RecvFlow = struct {
    limit: u64,
    window: u64,
    highest_received: u64 = 0,
    consumed: u64 = 0,

    pub fn init(initial_limit: u64, window: u64) Error!RecvFlow {
        if (window == 0) return error.InvalidWindow;
        return .{ .limit = initial_limit, .window = window };
    }

    pub fn receive(self: *RecvFlow, end_offset: u64) Error!void {
        if (end_offset > self.limit) return error.FlowControlViolation;
        self.highest_received = @max(self.highest_received, end_offset);
    }

    pub fn consume(self: *RecvFlow, amount: u64) ?u64 {
        self.consumed = @min(self.highest_received, self.consumed +| amount);
        if (self.limit - self.consumed <= self.window / 2) {
            const next_limit = @min(self.consumed +| self.window, quic.varint.max_value);
            if (next_limit <= self.limit) return null;
            self.limit = next_limit;
            return self.limit;
        }
        return null;
    }

    pub fn maxDataFrame(self: RecvFlow) quic.Frame {
        return .{ .max_data = .{ .maximum_data = self.limit } };
    }

    pub fn maxStreamDataFrame(self: RecvFlow, stream_id: u64) quic.Frame {
        return .{ .max_stream_data = .{ .stream_id = stream_id, .maximum_stream_data = self.limit } };
    }
};

pub const StreamFlow = struct {
    stream_id: u64,
    send: SendFlow,
    recv: RecvFlow,

    pub fn init(stream_id: u64, send_limit: u64, recv_limit: u64, recv_window: u64) Error!StreamFlow {
        return .{
            .stream_id = stream_id,
            .send = .init(send_limit),
            .recv = try .init(recv_limit, recv_window),
        };
    }
};

test "QUIC send flow reserves bytes and reports blocked" {
    var flow = SendFlow.init(10);
    try flow.reserve(7);
    try std.testing.expectEqual(@as(u64, 3), flow.available());
    try std.testing.expectError(error.FlowControlBlocked, flow.reserve(4));
    const blocked = flow.dataBlockedFrame();
    try std.testing.expectEqual(@as(u64, 10), blocked.data_blocked.maximum_data);
    flow.updateLimit(20);
    try flow.reserve(4);
    try std.testing.expectEqual(@as(u64, 9), flow.available());
}

test "QUIC receive flow emits MAX_DATA after consumption threshold" {
    var flow = try RecvFlow.init(100, 100);
    try flow.receive(80);
    try std.testing.expectError(error.FlowControlViolation, flow.receive(101));
    try std.testing.expectEqual(@as(?u64, null), flow.consume(20));
    const new_limit = flow.consume(40).?;
    try std.testing.expectEqual(@as(u64, 160), new_limit);
    const frame = flow.maxDataFrame();
    try std.testing.expectEqual(@as(u64, 160), frame.max_data.maximum_data);
}

test "QUIC receive flow consumes and expands near varint ceiling safely" {
    var flow = try RecvFlow.init(quic.varint.max_value - 1, quic.varint.max_value);
    try flow.receive(quic.varint.max_value - 1);

    const new_limit = flow.consume(std.math.maxInt(u64)).?;
    try std.testing.expectEqual(quic.varint.max_value, new_limit);
    try std.testing.expectEqual(quic.varint.max_value - 1, flow.consumed);
    try std.testing.expectEqual(@as(?u64, null), flow.consume(1));
    try std.testing.expectEqual(quic.varint.max_value, flow.limit);
}

test "QUIC stream flow produces stream-specific frames" {
    var flow = try StreamFlow.init(4, 5, 20, 20);
    try std.testing.expectError(error.FlowControlBlocked, flow.send.reserve(6));
    const blocked = flow.send.streamDataBlockedFrame(flow.stream_id);
    try std.testing.expectEqual(@as(u64, 4), blocked.stream_data_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 5), blocked.stream_data_blocked.maximum_stream_data);

    try flow.recv.receive(10);
    _ = flow.recv.consume(10);
    const max_stream = flow.recv.maxStreamDataFrame(flow.stream_id);
    try std.testing.expectEqual(@as(u64, 4), max_stream.max_stream_data.stream_id);
    try std.testing.expectEqual(@as(u64, 30), max_stream.max_stream_data.maximum_stream_data);
}
