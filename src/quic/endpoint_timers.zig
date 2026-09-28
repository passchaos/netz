//! Endpoint-level timer scheduling for caller-owned QUIC 1-RTT connections.
//!
//! `one_rtt.Connection` already collapses pacing, loss/PTO, ACK-delay,
//! path-validation, keep-alive, idle, close, and key-discard work into one
//! `nextTimerDeadline()` selector.  This helper mirrors those per-connection
//! deadlines at an endpoint/event-loop boundary so a multi-connection owner can
//! arm one kernel timer, service the selected connection, and refresh or remove
//! its schedule entry without scanning all connections on every tick.

const std = @import("std");
const builtin = @import("builtin");
const one_rtt = @import("one_rtt.zig");

pub const Error = one_rtt.Error || std.mem.Allocator.Error;

pub const EndpointTimerDeadline = struct {
    connection_id: u64,
    timer: one_rtt.TimerDeadline,
};

pub const EndpointTimers = struct {
    /// Keep small endpoints on the lower-constant-cost unordered array. Large
    /// endpoints use the same storage as an indexed min-heap so postponing or
    /// removing the current minimum does not scan every connection. Separate
    /// enter/leave thresholds prevent connection churn around the boundary
    /// from repeatedly rebuilding the representation.
    const heap_activation_count: usize = 128;
    const heap_deactivation_count: usize = 64;

    allocator: std.mem.Allocator,
    entries: std.ArrayList(EndpointTimerDeadline) = .empty,
    /// Maps endpoint-owned connection handles to their current slot in
    /// `entries`. Endpoint loops call update/disarm/deadline lookups on every
    /// packet or timer turn, so keep the common path independent of the number
    /// of active connections. `entries` may swap-remove, therefore removals
    /// must repair the moved connection's slot before future lookups.
    entry_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    earliest_index: ?usize = null,
    heap_enabled: bool = false,
    recompute_count: if (builtin.is_test) usize else void =
        if (builtin.is_test) 0 else {},

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
                const existing_timer = self.entries.items[existing].timer;
                if (std.meta.eql(existing_timer, deadline)) return;
                self.entries.items[existing] = entry;
                if (self.heap_enabled) {
                    self.refreshHeapAfterUpdate(
                        existing,
                        existing_timer.deadline_ns,
                    );
                } else {
                    self.refreshEarliestAfterUpdate(
                        existing,
                        existing_timer.deadline_ns,
                    );
                }
            } else {
                errdefer _ = self.entry_index.remove(connection_id);
                try self.entries.ensureUnusedCapacity(self.allocator, 1);
                self.appendEntryAssumeCapacity(entry, slot.value_ptr);
                if (self.heap_enabled) {
                    self.siftUp(self.entries.items.len - 1);
                    self.earliest_index = 0;
                } else if (self.entries.items.len >= heap_activation_count) {
                    self.enableHeap();
                } else {
                    self.considerEarliestIndex(self.entries.items.len - 1);
                }
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

    /// Snapshot due connection IDs into caller storage. Each connection is
    /// returned at most once even if servicing its timer immediately rearms
    /// another already-due deadline. The dispatcher uses this stable snapshot
    /// to bound one event-loop turn without starving socket receive. The
    /// cached minimum rejects the common all-future case before the full
    /// snapshot scan.
    pub fn dueConnectionIdsInto(
        self: *const EndpointTimers,
        now_ns: u64,
        output: []u64,
    ) usize {
        if (output.len == 0) return 0;
        const earliest = self.earliest_index orelse return 0;
        std.debug.assert(earliest < self.entries.items.len);
        if (self.entries.items[earliest].timer.deadline_ns > now_ns) return 0;
        if (self.heap_enabled) {
            return self.dueHeapConnectionIdsInto(now_ns, output);
        }

        var due_count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.timer.deadline_ns > now_ns) continue;
            if (due_count == output.len) break;
            output[due_count] = entry.connection_id;
            due_count += 1;
        }
        return due_count;
    }

    fn dueHeapConnectionIdsInto(
        self: *const EndpointTimers,
        now_ns: u64,
        output: []u64,
    ) usize {
        std.debug.assert(self.heap_enabled);
        std.debug.assert(self.entries.items.len != 0);
        var pending: [@bitSizeOf(usize) + 1]usize = undefined;
        var pending_count: usize = 1;
        pending[0] = 0;
        var due_count: usize = 0;
        while (pending_count != 0 and due_count != output.len) {
            pending_count -= 1;
            const index = pending[pending_count];
            const entry = self.entries.items[index];
            if (entry.timer.deadline_ns > now_ns) continue;
            output[due_count] = entry.connection_id;
            due_count += 1;

            // In a min-heap every descendant is no earlier than its parent.
            // Visit only children of due entries and let the deadline check
            // prune complete future subtrees. Depth-first traversal needs at
            // most one pending sibling per machine-word-sized heap level.
            if (index > (self.entries.items.len - 2) / 2) continue;
            const left = index * 2 + 1;
            const right = left + 1;
            if (right < self.entries.items.len) {
                std.debug.assert(pending_count < pending.len);
                pending[pending_count] = right;
                pending_count += 1;
            }
            std.debug.assert(pending_count < pending.len);
            pending[pending_count] = left;
            pending_count += 1;
        }
        return due_count;
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
        previous_deadline_ns: u64,
    ) void {
        std.debug.assert(updated_index < self.entries.items.len);
        const earliest = self.earliest_index orelse {
            self.earliest_index = updated_index;
            return;
        };
        if (earliest == updated_index) {
            // The cached minimum remains the minimum when its deadline is
            // unchanged or moves earlier. Only a later deadline can expose a
            // different connection as the new minimum.
            if (self.entries.items[updated_index].timer.deadline_ns <=
                previous_deadline_ns)
            {
                return;
            }
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
        if (self.heap_enabled) {
            if (self.entries.items.len < heap_deactivation_count) {
                self.heap_enabled = false;
                self.recomputeEarliest();
            } else {
                if (index < self.entries.items.len) {
                    self.restoreHeapAt(index);
                }
                self.earliest_index = 0;
            }
        } else {
            self.refreshEarliestAfterSwapRemove(index, old_len);
        }
    }

    fn enableHeap(self: *EndpointTimers) void {
        std.debug.assert(!self.heap_enabled);
        std.debug.assert(self.entries.items.len >= heap_activation_count);
        var parent = self.entries.items.len / 2;
        while (parent != 0) {
            parent -= 1;
            self.siftDown(parent);
        }
        self.heap_enabled = true;
        self.earliest_index = 0;
    }

    fn refreshHeapAfterUpdate(
        self: *EndpointTimers,
        updated_index: usize,
        previous_deadline_ns: u64,
    ) void {
        const deadline_ns =
            self.entries.items[updated_index].timer.deadline_ns;
        if (updated_index == 0 and deadline_ns <= previous_deadline_ns) {
            self.earliest_index = 0;
            return;
        }
        if (deadline_ns < previous_deadline_ns) {
            self.siftUp(updated_index);
        } else if (deadline_ns > previous_deadline_ns) {
            self.siftDown(updated_index);
        }
        self.earliest_index = 0;
    }

    fn restoreHeapAt(self: *EndpointTimers, index: usize) void {
        if (index != 0) {
            const parent = (index - 1) / 2;
            if (deadlineLess(
                self.entries.items[index],
                self.entries.items[parent],
            )) {
                self.siftUp(index);
                return;
            }
        }
        self.siftDown(index);
    }

    fn siftUp(self: *EndpointTimers, start: usize) void {
        var index = start;
        while (index != 0) {
            const parent = (index - 1) / 2;
            if (!deadlineLess(
                self.entries.items[index],
                self.entries.items[parent],
            )) return;
            self.swapEntries(index, parent);
            index = parent;
        }
    }

    fn siftDown(self: *EndpointTimers, start: usize) void {
        var index = start;
        while (true) {
            if (index >= self.entries.items.len / 2) return;
            const left = index * 2 + 1;
            const right = left + 1;
            const child = if (right < self.entries.items.len and deadlineLess(
                self.entries.items[right],
                self.entries.items[left],
            )) right else left;
            if (!deadlineLess(
                self.entries.items[child],
                self.entries.items[index],
            )) return;
            self.swapEntries(index, child);
            index = child;
        }
    }

    fn swapEntries(self: *EndpointTimers, a: usize, b: usize) void {
        std.mem.swap(
            EndpointTimerDeadline,
            &self.entries.items[a],
            &self.entries.items[b],
        );
        self.entry_index.getPtr(
            self.entries.items[a].connection_id,
        ).?.* = a;
        self.entry_index.getPtr(
            self.entries.items[b].connection_id,
        ).?.* = b;
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
        if (comptime builtin.is_test) self.recompute_count +|= 1;
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

fn deadlineLess(a: EndpointTimerDeadline, b: EndpointTimerDeadline) bool {
    return a.timer.deadline_ns < b.timer.deadline_ns;
}

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

test "QUIC endpoint timers retain earliest for non-later update" {
    const allocator = std.testing.allocator;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();

    try timers.update(1, .{ .kind = .pto, .deadline_ns = 100 });
    try timers.update(2, .{ .kind = .ack_delay, .deadline_ns = 200 });
    const recomputes_before = timers.recompute_count;

    try timers.update(1, .{ .kind = .pto, .deadline_ns = 100 });
    try std.testing.expectEqual(recomputes_before, timers.recompute_count);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.pto,
        timers.earliestDeadline().?.timer.kind,
    );

    // Timer kind remains observable even when its ordering deadline is
    // unchanged, but changing it cannot affect the cached minimum.
    try timers.update(1, .{ .kind = .idle_timeout, .deadline_ns = 100 });
    try std.testing.expectEqual(recomputes_before, timers.recompute_count);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.idle_timeout,
        timers.earliestDeadline().?.timer.kind,
    );

    try timers.update(1, .{ .kind = .keep_alive, .deadline_ns = 50 });
    try std.testing.expectEqual(recomputes_before, timers.recompute_count);
    try std.testing.expectEqual(@as(u64, 50), timers.earliestDeadline().?.timer.deadline_ns);

    try timers.update(1, .{ .kind = .keep_alive, .deadline_ns = 300 });
    try std.testing.expectEqual(recomputes_before + 1, timers.recompute_count);
    try std.testing.expectEqual(@as(u64, 2), timers.earliestDeadline().?.connection_id);
}

test "QUIC endpoint timers adapt to large indexed heap schedules" {
    const allocator = std.testing.allocator;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();

    try timers.ensureCapacity(EndpointTimers.heap_activation_count);
    for (0..EndpointTimers.heap_activation_count) |connection_id| {
        try timers.update(
            @intCast(connection_id),
            .{
                .kind = .idle_timeout,
                .deadline_ns = @intCast(connection_id + 100),
            },
        );
    }
    try std.testing.expect(timers.heap_enabled);
    try std.testing.expectEqual(
        @as(u64, 0),
        timers.earliestDeadline().?.connection_id,
    );

    const recomputes_before = timers.recompute_count;
    try timers.update(0, .{ .kind = .pto, .deadline_ns = 10_000 });
    try std.testing.expectEqual(recomputes_before, timers.recompute_count);
    try std.testing.expectEqual(
        @as(u64, 1),
        timers.earliestDeadline().?.connection_id,
    );
    try timers.update(127, .{ .kind = .ack_delay, .deadline_ns = 1 });
    try std.testing.expectEqual(
        @as(u64, 127),
        timers.earliestDeadline().?.connection_id,
    );
    try std.testing.expect(timers.disarmConnection(127));
    try std.testing.expectEqual(
        @as(u64, 1),
        timers.earliestDeadline().?.connection_id,
    );

    var connection_id: u64 = 126;
    while (timers.count() >= EndpointTimers.heap_deactivation_count) {
        if (connection_id != 1) {
            try std.testing.expect(timers.disarmConnection(connection_id));
        }
        connection_id -= 1;
    }
    try std.testing.expect(!timers.heap_enabled);
    try std.testing.expectEqual(
        @as(u64, 1),
        timers.earliestDeadline().?.connection_id,
    );
    try std.testing.expectEqual(
        @as(u64, 10_000),
        timers.deadlineForConnection(0).?.timer.deadline_ns,
    );
}

test "QUIC endpoint timer adaptive schedule matches deterministic model" {
    const allocator = std.testing.allocator;
    const connection_count = 256;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();
    try timers.ensureCapacity(connection_count);

    var model: [connection_count]?u64 = @splat(null);
    var due_storage: [connection_count]u64 = undefined;
    var due_seen: [connection_count]bool = undefined;
    for (0..connection_count) |connection_id| {
        const deadline_ns = @as(u64, @intCast(connection_count - connection_id));
        model[connection_id] = deadline_ns;
        try timers.update(
            @intCast(connection_id),
            .{ .kind = .idle_timeout, .deadline_ns = deadline_ns },
        );
    }

    var state: u64 = 0x4d595df4d0f33173;
    for (0..5_000) |operation| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const connection_id: usize = @intCast(state % connection_count);
        if ((state >> 8) & 3 == 0) {
            const expected = model[connection_id] != null;
            try std.testing.expectEqual(
                expected,
                timers.disarmConnection(@intCast(connection_id)),
            );
            model[connection_id] = null;
        } else {
            const deadline_ns = (state >> 16) % 10_000;
            const kind: one_rtt.TimerDeadlineKind = if ((state & 1) == 0)
                .pto
            else
                .idle_timeout;
            try timers.update(
                @intCast(connection_id),
                .{ .kind = kind, .deadline_ns = deadline_ns },
            );
            model[connection_id] = deadline_ns;
        }

        var expected_count: usize = 0;
        var expected_earliest: ?u64 = null;
        for (model) |deadline_ns| {
            const deadline = deadline_ns orelse continue;
            expected_count += 1;
            expected_earliest = if (expected_earliest) |current|
                @min(current, deadline)
            else
                deadline;
        }
        try std.testing.expectEqual(expected_count, timers.count());
        if (expected_earliest) |deadline_ns| {
            const earliest = timers.earliestDeadline().?;
            try std.testing.expectEqual(deadline_ns, earliest.timer.deadline_ns);
            try std.testing.expectEqual(
                deadline_ns,
                model[@intCast(earliest.connection_id)].?,
            );
        } else {
            try std.testing.expect(timers.earliestDeadline() == null);
        }

        if (operation % 97 == 0) {
            const now_ns = (state >> 32) % 10_000;
            @memset(&due_seen, false);
            const due = timers.dueConnectionIdsInto(now_ns, &due_storage);
            var expected_due: usize = 0;
            for (model) |deadline_ns| {
                if (deadline_ns) |deadline| {
                    expected_due += @intFromBool(deadline <= now_ns);
                }
            }
            try std.testing.expectEqual(expected_due, due);
            for (due_storage[0..due]) |due_connection_id| {
                const due_index: usize = @intCast(due_connection_id);
                try std.testing.expect(due_index < connection_count);
                try std.testing.expect(!due_seen[due_index]);
                try std.testing.expect(model[due_index].? <= now_ns);
                due_seen[due_index] = true;
            }
            for (timers.entries.items, 0..) |entry, index| {
                try std.testing.expectEqual(
                    @as(?usize, index),
                    timers.entry_index.get(entry.connection_id),
                );
                try std.testing.expectEqual(
                    model[@intCast(entry.connection_id)].?,
                    entry.timer.deadline_ns,
                );
                if (timers.heap_enabled and index != 0) {
                    try std.testing.expect(!deadlineLess(
                        entry,
                        timers.entries.items[(index - 1) / 2],
                    ));
                }
            }
        }
    }
}

test "QUIC endpoint timer heap prunes future due subtrees" {
    const allocator = std.testing.allocator;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();

    try timers.ensureCapacity(EndpointTimers.heap_activation_count);
    for (0..EndpointTimers.heap_activation_count) |connection_id| {
        try timers.update(
            @intCast(connection_id),
            .{
                .kind = .idle_timeout,
                .deadline_ns = @intCast(connection_id + 1),
            },
        );
    }
    var output: [17]u64 = undefined;
    const due = timers.dueConnectionIdsInto(10, &output);
    try std.testing.expectEqual(@as(usize, 10), due);
    var seen: [10]bool = @splat(false);
    for (output[0..due]) |connection_id| {
        try std.testing.expect(connection_id < seen.len);
        try std.testing.expect(!seen[@intCast(connection_id)]);
        seen[@intCast(connection_id)] = true;
    }
    try std.testing.expect(std.mem.allEqual(bool, &seen, true));

    try std.testing.expectEqual(
        output.len,
        timers.dueConnectionIdsInto(std.math.maxInt(u64), &output),
    );
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

test "QUIC endpoint timers snapshot bounded due connections once" {
    const allocator = std.testing.allocator;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();

    try timers.update(10, .{ .kind = .pto, .deadline_ns = 50 });
    try timers.update(20, .{ .kind = .ack_delay, .deadline_ns = 30 });
    try timers.update(30, .{ .kind = .idle_timeout, .deadline_ns = 40 });
    var storage: [2]u64 = undefined;
    const due = timers.dueConnectionIdsInto(60, &storage);
    try std.testing.expectEqual(@as(usize, 2), due);
    try std.testing.expect(storage[0] != storage[1]);
}

test "QUIC endpoint timers reject an all-future snapshot" {
    const allocator = std.testing.allocator;
    var timers = EndpointTimers.init(allocator);
    defer timers.deinit();

    try timers.update(10, .{ .kind = .pto, .deadline_ns = 50 });
    try timers.update(20, .{ .kind = .ack_delay, .deadline_ns = 30 });
    try timers.update(30, .{ .kind = .idle_timeout, .deadline_ns = 40 });
    var storage: [3]u64 = @splat(std.math.maxInt(u64));
    try std.testing.expectEqual(
        @as(usize, 0),
        timers.dueConnectionIdsInto(29, &storage),
    );
    try std.testing.expectEqual(
        @as(u64, std.math.maxInt(u64)),
        storage[0],
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        timers.dueConnectionIdsInto(30, storage[0..0]),
    );
}
