const std = @import("std");
const flush = @import("flush.zig");
const allocator = std.testing.allocator;
const Fault = enum { none, transport, state };
const Connection = struct {
    interrupts: usize = 0,
    pub fn interrupt(self: *@This()) error{}!void {
        self.interrupts += 1;
    }
};
const Slot = struct {
    writer_mutex: std.Io.Mutex = .init,
    state: struct { active: bool = true, generation: usize = 1 } = .{},
    connection: ?*Connection,
    fault: Fault = .none,
    flushes: usize = 0,
};
const Broker = struct {
    io: std.Io,
    state_mutex: std.Io.Mutex = .init,
    slots: []Slot,
};
const Context = struct {
    pub const BrokerType = Broker;
    pub const MatchType = struct { subscriber_id: usize };
    pub const ErrorType = error{ ConnectionClosed, CommitFailed };
    pub fn index(value: usize, len: usize) ?usize {
        return if (value % 10 < len) value % 10 else null;
    }
    pub fn id(value: usize, generation: usize) usize {
        return generation * 10 + value;
    }
    pub fn flush(_: *Broker, slot: *Slot, _: bool) ErrorType!void {
        slot.flushes += 1;
        switch (slot.fault) {
            .none => {},
            .transport => return error.ConnectionClosed,
            .state => return error.CommitFailed,
        }
    }
    pub fn transportClosed(err: anyerror) bool {
        return err == error.ConnectionClosed;
    }
};

test "MQTT fanout skips retired generations and isolates recipient transport errors" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var connections = [_]Connection{ .{}, .{} };
    var slots = [_]Slot{ .{ .connection = &connections[0], .state = .{ .generation = 2 } }, .{ .connection = &connections[1] } };
    var broker = Broker{ .io = threaded.io(), .slots = &slots };
    try flush.run(Context, &broker, &.{.{ .subscriber_id = 10 }});
    try std.testing.expectEqual(@as(usize, 0), slots[0].flushes);
    slots[0].fault = .transport;
    try flush.run(Context, &broker, &.{ .{ .subscriber_id = 20 }, .{ .subscriber_id = 11 } });
    try std.testing.expectEqual(@as(usize, 1), connections[0].interrupts);
    try std.testing.expectEqual(@as(usize, 1), slots[1].flushes);
}

test "MQTT fanout preserves non-transport state errors" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var connection: Connection = .{};
    var slots = [_]Slot{.{ .connection = &connection, .fault = .state }};
    var broker = Broker{ .io = threaded.io(), .slots = &slots };
    try std.testing.expectError(error.CommitFailed, flush.run(Context, &broker, &.{.{ .subscriber_id = 10 }}));
    try std.testing.expectEqual(@as(usize, 0), connection.interrupts);
}
