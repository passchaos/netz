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
    /// Maps endpoint-owned connection handles to their current slot in
    /// `entries`. Endpoint loops call update/disarm/deadline lookups on every
    /// packet or timer turn, so keep the common path independent of the number
    /// of active connections. `entries` may swap-remove, therefore removals
    /// must repair the moved connection's slot before future lookups.
    entry_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    earliest_index: ?usize = null,

    pub fn init(allocator: std.mem.Allocator) EndpointTimers {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *EndpointTimers) void {
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn ensureCapacity(self: *EndpointTimers, capacity: usize) Error!void {
        try self.entries.ensureTotalCapacity(self.allocator, capacity);
        const index_capacity = std.math.cast(
            @TypeOf(self.entry_index).Size,
            capacity,
        ) orelse return error.OutOfMemory;
        try self.entry_index.ensureTotalCapacity(self.allocator, index_capacity);
    }

    pub fn count(self: *const EndpointTimers) usize {
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
        if (timer) |deadline| {
            const entry = EndpointTimerDeadline{
                .connection_id = connection_id,
                .timer = deadline,
            };
            const slot = try self.entry_index.getOrPut(
                self.allocator,
                connection_id,
            );
            if (slot.found_existing) {
                const existing = slot.value_ptr.*;
                self.entries.items[existing] = entry;
                self.refreshEarliestAfterUpdate(existing);
            } else {
                errdefer _ = self.entry_index.remove(connection_id);
                try self.entries.ensureUnusedCapacity(self.allocator, 1);
                self.appendEntryAssumeCapacity(entry, slot.value_ptr);
                self.considerEarliestIndex(self.entries.items.len - 1);
            }
            return;
        }
        if (self.findIndex(connection_id)) |existing| self.removeEntry(existing);
    }

    pub fn disarmConnection(
        self: *EndpointTimers,
        connection_id: u64,
    ) bool {
        const index = self.findIndex(connection_id) orelse return false;
        self.removeEntry(index);
        return true;
    }

    pub fn deadlineForConnection(
        self: *const EndpointTimers,
        connection_id: u64,
    ) ?EndpointTimerDeadline {
        const index = self.findIndex(connection_id) orelse return null;
        return self.entries.items[index];
    }

    pub fn earliestDeadline(self: *const EndpointTimers) ?EndpointTimerDeadline {
        const index = self.earliest_index orelse return null;
        std.debug.assert(index < self.entries.items.len);
        return self.entries.items[index];
    }

    /// Service the selected connection's due timer and refresh this endpoint
    /// schedule entry from the connection's new aggregate deadline.
    pub fn serviceConnection(
        self: *EndpointTimers,
        connection_id: u64,
        connection: anytype,
        now_ns: u64,
    ) Error!?EndpointTimerDeadline {
        if (self.findIndex(connection_id) == null) return null;
        const serviced = try connection.serviceNextTimerAt(now_ns);
        const timer = serviced orelse return null;
        try self.armFromConnection(connection_id, connection);
        return .{
            .connection_id = connection_id,
            .timer = timer,
        };
    }

    fn findIndex(self: *const EndpointTimers, connection_id: u64) ?usize {
        if (self.entry_index.count() == 0) return null;
        return self.entry_index.get(connection_id);
    }

    fn appendEntryAssumeCapacity(
        self: *EndpointTimers,
        entry: EndpointTimerDeadline,
        index_slot: *usize,
    ) void {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(entry);
        index_slot.* = index;
    }

    fn refreshEarliestAfterUpdate(
        self: *EndpointTimers,
        updated_index: usize,
    ) void {
        std.debug.assert(updated_index < self.entries.items.len);
        const earliest = self.earliest_index orelse {
            self.earliest_index = updated_index;
            return;
        };
        if (earliest == updated_index) {
            // Updating the cached entry can move it later than another
            // connection. Recompute only for this uncommon case; inserts and
            // non-earliest updates remain O(1).
            self.recomputeEarliest();
            return;
        }
        if (self.entries.items[updated_index].timer.deadline_ns <
            self.entries.items[earliest].timer.deadline_ns)
        {
            self.earliest_index = updated_index;
        }
    }

    fn removeEntry(self: *EndpointTimers, index: usize) void {
        const old_len = self.entries.items.len;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(removed.connection_id);
        if (index != old_len - 1) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(moved.connection_id).?.* = index;
        }
        self.refreshEarliestAfterSwapRemove(index, old_len);
    }

    fn refreshEarliestAfterSwapRemove(
        self: *EndpointTimers,
        removed_index: usize,
        old_len: usize,
    ) void {
        if (self.entries.items.len == 0) {
            self.earliest_index = null;
            return;
        }
        const earliest = self.earliest_index orelse {
            self.recomputeEarliest();
            return;
        };
        const old_last = old_len - 1;
        if (earliest == removed_index) {
            self.recomputeEarliest();
        } else if (earliest == old_last) {
            // swapRemove moved the previously-last (and cached-earliest) entry
            // into the removed slot.  Other indices remain stable because pool
            // timer ordering is maintained by `earliest_index`, not array
            // position.
            self.earliest_index = removed_index;
        }
    }

    fn considerEarliestIndex(self: *EndpointTimers, candidate: usize) void {
        std.debug.assert(candidate < self.entries.items.len);
        const earliest = self.earliest_index orelse {
            self.earliest_index = candidate;
            return;
        };
        if (self.entries.items[candidate].timer.deadline_ns <
            self.entries.items[earliest].timer.deadline_ns)
        {
            self.earliest_index = candidate;
        }
    }

    fn recomputeEarliest(self: *EndpointTimers) void {
        if (self.entries.items.len == 0) {
            self.earliest_index = null;
            return;
        }
        var earliest: usize = 0;
        for (self.entries.items[1..], 1..) |entry, index| {
            if (entry.timer.deadline_ns <
                self.entries.items[earliest].timer.deadline_ns)
            {
                earliest = index;
            }
        }
        self.earliest_index = earliest;
    }
};

const FakeConnection = struct {
    timer: ?one_rtt.TimerDeadline = null,
    serviced_before: ?one_rtt.TimerDeadline = null,
    replacement: ?one_rtt.TimerDeadline = null,
    service_calls: usize = 0,

    fn nextTimerDeadline(self: *const FakeConnection) ?one_rtt.TimerDeadline {
        return self.timer;
    }

    fn serviceNextTimerAt(
        self: *FakeConnection,
        now_ns: u64,
    ) Error!?one_rtt.TimerDeadline {
        self.service_calls += 1;
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
    try std.testing.expectEqual(@as(?usize, 1), timers.earliest_index);
    try std.testing.expectEqual(@as(?usize, 0), timers.entry_index.get(10));
    try std.testing.expectEqual(@as(?usize, 1), timers.entry_index.get(20));
    try std.testing.expectEqual(@as(usize, 2), timers.count());
    try std.testing.expectEqual(@as(u64, 20), timers.earliestDeadline().?.connection_id);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.ack_delay,
        timers.deadlineForConnection(20).?.timer.kind,
    );

    try timers.update(20, .{ .kind = .idle_timeout, .deadline_ns = 800 });
    try std.testing.expectEqual(@as(u64, 10), timers.earliestDeadline().?.connection_id);
    try std.testing.expectEqual(@as(?usize, 0), timers.earliest_index);
    try timers.update(30, .{ .kind = .path_validation, .deadline_ns = 600 });
    try timers.update(40, .{ .kind = .keep_alive, .deadline_ns = 700 });
    try timers.update(10, null);
    // Removing the cached earliest recomputes over the unordered storage left
    // by swapRemove.
    try std.testing.expectEqual(@as(u64, 30), timers.earliestDeadline().?.connection_id);
    try std.testing.expectEqual(@as(?usize, 2), timers.earliest_index);
    try std.testing.expectEqual(@as(?usize, null), timers.entry_index.get(10));
    try std.testing.expectEqual(@as(?usize, 0), timers.entry_index.get(40));
    try std.testing.expectEqual(@as(?usize, 2), timers.entry_index.get(30));
    try std.testing.expectEqual(@as(usize, 3), timers.count());
    try timers.update(30, .{ .kind = .path_validation, .deadline_ns = 900 });
    try std.testing.expectEqual(@as(u64, 40), timers.earliestDeadline().?.connection_id);
    try std.testing.expect(timers.disarmConnection(20));
    try std.testing.expect(timers.disarmConnection(30));
    try std.testing.expect(timers.disarmConnection(40));
    try std.testing.expect(!timers.disarmConnection(20));
    try std.testing.expect(timers.earliestDeadline() == null);
    try std.testing.expectEqual(@as(usize, 0), timers.entry_index.count());
}

test "QUIC endpoint timers retain cached earliest moved by swapRemove" {
    const allocator = std.testing.allocator;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();

    try timers.update(1, .{ .kind = .pto, .deadline_ns = 300 });
    try timers.update(2, .{ .kind = .idle_timeout, .deadline_ns = 200 });
    try timers.update(3, .{ .kind = .ack_delay, .deadline_ns = 100 });
    try std.testing.expectEqual(@as(?usize, 2), timers.earliest_index);

    try std.testing.expect(timers.disarmConnection(1));
    try std.testing.expectEqual(@as(u64, 3), timers.earliestDeadline().?.connection_id);
    try std.testing.expectEqual(@as(?usize, 0), timers.earliest_index);
    try std.testing.expectEqual(@as(?usize, null), timers.entry_index.get(1));
    try std.testing.expectEqual(@as(?usize, 0), timers.entry_index.get(3));
}

test "QUIC endpoint timers skip service for unarmed connections" {
    const allocator = std.testing.allocator;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();

    var connection = FakeConnection{
        .timer = .{ .kind = .pto, .deadline_ns = 1 },
    };
    try std.testing.expectEqual(
        @as(?EndpointTimerDeadline, null),
        try timers.serviceConnection(9, &connection, 1),
    );
    // Multi-connection loops commonly dispatch from this scheduler's selected
    // entry.  If the selected handle was already disarmed, avoid re-scanning
    // or mutating that connection's aggregate transport timers.
    try std.testing.expectEqual(@as(usize, 0), connection.service_calls);

    try timers.armFromConnection(9, &connection);
    _ = try timers.serviceConnection(9, &connection, 1);
    try std.testing.expectEqual(@as(usize, 1), connection.service_calls);
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
