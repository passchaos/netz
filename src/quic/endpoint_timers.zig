//! Endpoint-level timer scheduling for caller-owned QUIC 1-RTT connections.
//!
//! `one_rtt.Connection` already collapses loss/PTO, ACK-delay,
//! path-validation, keep-alive, idle, close, and key-discard work into one
//! `nextTimerDeadline()` selector.  This helper mirrors those per-connection
//! deadlines at an endpoint/event-loop boundary so a multi-connection owner can
//! arm one kernel timer, service the selected connection, and refresh or remove
//! its schedule entry without scanning all connections on every tick.

const std = @import("std");
const one_rtt = @import("one_rtt.zig");

pub const Error = one_rtt.Error || std.mem.Allocator.Error;

pub const EndpointTimerDeadline = struct {
    connection_id: u64,
    timer: one_rtt.TimerDeadline,
};

pub const EndpointTimers = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(EndpointTimerDeadline) = .empty,

    pub fn init(allocator: std.mem.Allocator) EndpointTimers {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *EndpointTimers) void {
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn ensureCapacity(self: *EndpointTimers, capacity: usize) Error!void {
        try self.entries.ensureTotalCapacity(self.allocator, capacity);
    }

    pub fn count(self: EndpointTimers) usize {
        return self.entries.items.len;
    }

    /// Mirror one connection's aggregate timer.  Connections without pending
    /// work are disarmed so stale endpoint entries cannot keep an event loop
    /// awake.
    pub fn armFromConnection(
        self: *EndpointTimers,
        connection_id: u64,
        connection: anytype,
    ) Error!void {
        try self.update(connection_id, connection.nextTimerDeadline());
    }

    pub fn update(
        self: *EndpointTimers,
        connection_id: u64,
        timer: ?one_rtt.TimerDeadline,
    ) Error!void {
        const index = self.findIndex(connection_id);
        if (timer) |deadline| {
            const entry = EndpointTimerDeadline{
                .connection_id = connection_id,
                .timer = deadline,
            };
            if (index) |existing| {
                self.entries.items[existing] = entry;
            } else {
                try self.entries.append(self.allocator, entry);
            }
            return;
        }
        if (index) |existing| _ = self.entries.orderedRemove(existing);
    }

    pub fn disarmConnection(
        self: *EndpointTimers,
        connection_id: u64,
    ) bool {
        const index = self.findIndex(connection_id) orelse return false;
        _ = self.entries.orderedRemove(index);
        return true;
    }

    pub fn deadlineForConnection(
        self: EndpointTimers,
        connection_id: u64,
    ) ?EndpointTimerDeadline {
        const index = self.findIndex(connection_id) orelse return null;
        return self.entries.items[index];
    }

    pub fn earliestDeadline(self: EndpointTimers) ?EndpointTimerDeadline {
        if (self.entries.items.len == 0) return null;
        var earliest = self.entries.items[0];
        for (self.entries.items[1..]) |entry| {
            if (entry.timer.deadline_ns < earliest.timer.deadline_ns) {
                earliest = entry;
            }
        }
        return earliest;
    }

    /// Service the selected connection's due timer and refresh this endpoint
    /// schedule entry from the connection's new aggregate deadline.
    pub fn serviceConnection(
        self: *EndpointTimers,
        connection_id: u64,
        connection: anytype,
        now_ns: u64,
    ) Error!?EndpointTimerDeadline {
        const serviced = try connection.serviceNextTimerAt(now_ns);
        try self.armFromConnection(connection_id, connection);
        const timer = serviced orelse return null;
        return .{
            .connection_id = connection_id,
            .timer = timer,
        };
    }

    fn findIndex(self: EndpointTimers, connection_id: u64) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.connection_id == connection_id) return index;
        }
        return null;
    }
};

const FakeConnection = struct {
    timer: ?one_rtt.TimerDeadline = null,
    serviced_before: ?one_rtt.TimerDeadline = null,
    replacement: ?one_rtt.TimerDeadline = null,

    fn nextTimerDeadline(self: *const FakeConnection) ?one_rtt.TimerDeadline {
        return self.timer;
    }

    fn serviceNextTimerAt(
        self: *FakeConnection,
        now_ns: u64,
    ) Error!?one_rtt.TimerDeadline {
        const timer = self.timer orelse return null;
        if (now_ns < timer.deadline_ns) return null;
        self.serviced_before = timer;
        self.timer = self.replacement;
        return timer;
    }
};

test "QUIC endpoint timers arm update earliest and disarm" {
    const allocator = std.testing.allocator;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();

    try timers.ensureCapacity(2);
    try timers.update(10, .{ .kind = .pto, .deadline_ns = 500 });
    try timers.update(20, .{ .kind = .ack_delay, .deadline_ns = 200 });
    try std.testing.expectEqual(@as(usize, 2), timers.count());
    try std.testing.expectEqual(@as(u64, 20), timers.earliestDeadline().?.connection_id);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.ack_delay,
        timers.deadlineForConnection(20).?.timer.kind,
    );

    try timers.update(20, .{ .kind = .idle_timeout, .deadline_ns = 800 });
    try std.testing.expectEqual(@as(u64, 10), timers.earliestDeadline().?.connection_id);
    try timers.update(10, null);
    try std.testing.expectEqual(@as(usize, 1), timers.count());
    try std.testing.expect(timers.disarmConnection(20));
    try std.testing.expect(!timers.disarmConnection(20));
    try std.testing.expect(timers.earliestDeadline() == null);
}

test "QUIC endpoint timers service connection and refresh deadline" {
    const allocator = std.testing.allocator;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();

    var connection = FakeConnection{
        .timer = .{ .kind = .path_validation, .deadline_ns = 100 },
        .replacement = .{ .kind = .keep_alive, .deadline_ns = 300 },
    };
    try timers.armFromConnection(7, &connection);
    try std.testing.expectEqual(@as(?EndpointTimerDeadline, null), try timers.serviceConnection(7, &connection, 99));
    try std.testing.expectEqual(
        @as(u64, 100),
        timers.deadlineForConnection(7).?.timer.deadline_ns,
    );

    const serviced = (try timers.serviceConnection(7, &connection, 100)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 7), serviced.connection_id);
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.path_validation, serviced.timer.kind);
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.keep_alive, timers.deadlineForConnection(7).?.timer.kind);

    connection.replacement = null;
    _ = try timers.serviceConnection(7, &connection, 300);
    try std.testing.expect(timers.deadlineForConnection(7) == null);
}
