//! RFC 9218 HTTP/2 priority-update state.
//!
//! A client can reprioritize a request before opening its stream, so state
//! cannot live only beside active streams. The table retains at most one update
//! per stream and separately tracks idle request streams so their resource
//! commitment can be bounded by SETTINGS_MAX_CONCURRENT_STREAMS.

const std = @import("std");
const http2 = @import("../mod.zig");

pub const StoredUpdate = struct {
    stream_id: u31,
    field_value: []u8,

    pub fn priority(self: StoredUpdate) http2.ExtensiblePriority {
        return http2.ExtensiblePriority.parse(self.field_value);
    }

    fn deinit(
        self: *StoredUpdate,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.field_value);
        self.* = undefined;
    }
};

pub const State = struct {
    updates: std.ArrayList(StoredUpdate) = .empty,
    idle_requests: std.ArrayList(u31) = .empty,
    update_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    idle_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    /// Minimum idle request stream cached over the unordered reservation list.
    /// Most request openings are at or below the current reservation frontier;
    /// this lets `openRequest` reject the common no-op case without walking all
    /// speculative RFC 9218 priority updates.
    lowest_idle_request_index: ?usize = null,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        for (self.updates.items) |*update| update.deinit(allocator);
        self.updates.deinit(allocator);
        self.idle_requests.deinit(allocator);
        self.update_index.deinit(allocator);
        self.idle_index.deinit(allocator);
        self.* = undefined;
    }

    pub fn get(
        self: State,
        stream_id: u31,
    ) ?StoredUpdate {
        if (self.update_index.count() == 0) return null;
        const index = self.update_index.get(stream_id) orelse return null;
        if (index >= self.updates.items.len) return null;
        const update = self.updates.items[index];
        if (update.stream_id != stream_id) return null;
        return update;
    }

    pub fn containsIdleRequest(
        self: State,
        stream_id: u31,
    ) bool {
        return self.idle_index.count() != 0 and
            self.idle_index.contains(stream_id);
    }

    pub fn reserveIdleRequest(
        self: *State,
        allocator: std.mem.Allocator,
        stream_id: u31,
        active_stream_count: usize,
        max_concurrent_streams: ?u32,
        max_idle_updates: usize,
    ) (std.mem.Allocator.Error || error{
        PriorityCapacityExceeded,
    })!void {
        if (self.idle_requests.items.len >= max_idle_updates) {
            if (self.containsIdleRequest(stream_id)) return;
            return error.PriorityCapacityExceeded;
        }
        if (max_concurrent_streams) |limit| {
            if (active_stream_count + self.idle_requests.items.len >= limit) {
                if (self.containsIdleRequest(stream_id)) return;
                return error.PriorityCapacityExceeded;
            }
        }
        const slot = try self.idle_index.getOrPut(allocator, stream_id);
        if (slot.found_existing) return;
        errdefer _ = self.idle_index.remove(stream_id);
        const index = self.idle_requests.items.len;
        try self.idle_requests.append(allocator, stream_id);
        slot.value_ptr.* = index;
        self.considerLowestIdleRequest(index);
    }

    pub fn activateRequest(
        self: *State,
        stream_id: u31,
    ) bool {
        if (self.idle_index.count() == 0) return false;
        const index = self.idle_index.get(stream_id) orelse return false;
        self.removeIdleRequestAt(index);
        return true;
    }

    /// Apply the HTTP/2 monotonic stream-ID transition caused by HEADERS.
    /// Lower idle request streams become closed implicitly; the matching
    /// reservation becomes active and keeps its latest priority update.
    pub fn openRequest(
        self: *State,
        allocator: std.mem.Allocator,
        stream_id: u31,
    ) void {
        if (self.lowestIdleRequest()) |lowest| {
            if (lowest > stream_id) return;
        } else return;

        var index: usize = 0;
        while (index < self.idle_requests.items.len) {
            const idle = self.idle_requests.items[index];
            if (idle > stream_id) {
                index += 1;
                continue;
            }
            self.removeIdleRequestAt(index);
            if (idle < stream_id) {
                _ = self.removeUpdate(allocator, idle);
            }
        }
    }

    pub fn store(
        self: *State,
        allocator: std.mem.Allocator,
        stream_id: u31,
        field_value: []const u8,
    ) std.mem.Allocator.Error!void {
        if (self.update_index.count() != 0) {
            if (self.update_index.get(stream_id)) |index| {
                const update = &self.updates.items[index];
                if (std.mem.eql(u8, update.field_value, field_value)) return;
            }
        }
        const owned = try allocator.dupe(u8, field_value);
        errdefer allocator.free(owned);
        const slot = try self.update_index.getOrPut(allocator, stream_id);
        if (slot.found_existing) {
            const update = &self.updates.items[slot.value_ptr.*];
            allocator.free(update.field_value);
            update.field_value = owned;
            return;
        }
        errdefer _ = self.update_index.remove(stream_id);
        const index = self.updates.items.len;
        try self.updates.append(allocator, .{
            .stream_id = stream_id,
            .field_value = owned,
        });
        slot.value_ptr.* = index;
    }

    pub fn remove(
        self: *State,
        allocator: std.mem.Allocator,
        stream_id: u31,
    ) bool {
        _ = self.activateRequest(stream_id);
        return self.removeUpdate(allocator, stream_id);
    }

    fn removeUpdate(
        self: *State,
        allocator: std.mem.Allocator,
        stream_id: u31,
    ) bool {
        if (self.update_index.count() == 0) return false;
        const index = self.update_index.get(stream_id) orelse return false;
        const last_index = self.updates.items.len - 1;
        var removed = self.updates.swapRemove(index);
        _ = self.update_index.remove(stream_id);
        if (index != last_index) {
            const moved = self.updates.items[index];
            self.update_index.getPtr(moved.stream_id).?.* = index;
        }
        removed.deinit(allocator);
        return true;
    }

    fn removeIdleRequestAt(self: *State, index: usize) void {
        const last_index = self.idle_requests.items.len - 1;
        const lowest = self.lowest_idle_request_index;
        const removed = self.idle_requests.swapRemove(index);
        _ = self.idle_index.remove(removed);
        if (index != last_index) {
            const moved = self.idle_requests.items[index];
            self.idle_index.getPtr(moved).?.* = index;
        }
        if (self.idle_requests.items.len == 0) {
            self.lowest_idle_request_index = null;
        } else if (lowest == index) {
            self.recomputeLowestIdleRequest();
        } else if (lowest == last_index) {
            self.lowest_idle_request_index = index;
        }
    }

    fn lowestIdleRequest(self: State) ?u31 {
        const index = self.lowest_idle_request_index orelse return null;
        return self.idle_requests.items[index];
    }

    fn considerLowestIdleRequest(self: *State, index: usize) void {
        const lowest = self.lowest_idle_request_index orelse {
            self.lowest_idle_request_index = index;
            return;
        };
        if (self.idle_requests.items[index] < self.idle_requests.items[lowest]) {
            self.lowest_idle_request_index = index;
        }
    }

    fn recomputeLowestIdleRequest(self: *State) void {
        self.lowest_idle_request_index = null;
        for (self.idle_requests.items, 0..) |_, index| {
            self.considerLowestIdleRequest(index);
        }
    }
};

test "priority updates replace state and bound idle reservations" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);

    try state.reserveIdleRequest(allocator, 1, 0, 2, 2);
    try std.testing.expectEqual(@as(?usize, 0), state.lowest_idle_request_index);
    try state.store(allocator, 1, "u=7");
    try state.store(allocator, 1, "u=1, i");
    try std.testing.expectEqual(@as(u3, 1), state.get(1).?.priority().urgency);
    try std.testing.expect(state.get(1).?.priority().incremental);
    try state.reserveIdleRequest(allocator, 3, 0, 2, 2);
    try std.testing.expectEqual(@as(u31, 1), state.lowestIdleRequest().?);
    try std.testing.expectError(
        error.PriorityCapacityExceeded,
        state.reserveIdleRequest(allocator, 5, 0, 2, 2),
    );
    try std.testing.expect(state.activateRequest(1));
    try std.testing.expectEqual(@as(u31, 3), state.lowestIdleRequest().?);
    try state.reserveIdleRequest(allocator, 5, 1, 3, 2);
    try std.testing.expect(state.remove(allocator, 1));
    try std.testing.expect(state.get(1) == null);

    try state.store(allocator, 3, "u=3");
    try state.store(allocator, 5, "u=5");
    state.openRequest(allocator, 5);
    try std.testing.expectEqual(@as(?u31, null), state.lowestIdleRequest());
    try std.testing.expect(state.get(3) == null);
    try std.testing.expect(state.get(5) != null);
}

test "priority idle capacity rejection does not allocate" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);

    try state.reserveIdleRequest(allocator, 1, 0, null, 1);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    try std.testing.expectError(
        error.PriorityCapacityExceeded,
        state.reserveIdleRequest(
            no_alloc.allocator(),
            3,
            0,
            null,
            1,
        ),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);

    // Repeating an existing reservation remains idempotent even when the
    // configured idle-priority budget is full, and it should not need another
    // hash-map insertion attempt.
    try state.reserveIdleRequest(
        no_alloc.allocator(),
        1,
        0,
        null,
        1,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "priority update identical replacement does not allocate" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);

    try state.store(allocator, 1, "u=2, i");
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    try state.store(no_alloc.allocator(), 1, "u=2, i");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("u=2, i", state.get(1).?.field_value);
}

test "priority state indexes survive swap removals and replacements" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);

    try state.reserveIdleRequest(allocator, 1, 0, 8, 8);
    try state.reserveIdleRequest(allocator, 3, 0, 8, 8);
    try state.reserveIdleRequest(allocator, 5, 0, 8, 8);
    try std.testing.expectEqual(@as(u31, 1), state.lowestIdleRequest().?);
    try state.store(allocator, 1, "u=1");
    try state.store(allocator, 3, "u=3");
    try state.store(allocator, 5, "u=5");

    try std.testing.expect(state.activateRequest(3));
    try std.testing.expectEqual(@as(u31, 1), state.lowestIdleRequest().?);
    try std.testing.expect(!state.containsIdleRequest(3));
    try std.testing.expect(state.containsIdleRequest(1));
    try std.testing.expect(state.containsIdleRequest(5));
    try std.testing.expect(state.get(3) != null);

    try std.testing.expect(state.remove(allocator, 1));
    try std.testing.expectEqual(@as(u31, 5), state.lowestIdleRequest().?);
    try std.testing.expect(state.get(1) == null);
    try std.testing.expect(state.get(5) != null);
    try state.store(allocator, 5, "u=0, i");
    try std.testing.expectEqual(@as(u3, 0), state.get(5).?.priority().urgency);
    try std.testing.expect(state.get(5).?.priority().incremental);

    state.openRequest(allocator, 7);
    try std.testing.expectEqual(@as(usize, 0), state.idle_requests.items.len);
    try std.testing.expectEqual(@as(usize, 0), state.idle_index.count());
    // Stream 3 was already activated above, so a later monotonic open only
    // prunes still-idle lower reservations.  Its update remains available
    // until the active stream is explicitly removed.
    try std.testing.expect(state.get(3) != null);
    try std.testing.expect(state.get(5) == null);
    try std.testing.expect(state.remove(allocator, 3));
    try std.testing.expect(state.get(3) == null);
    try std.testing.expect(!state.remove(allocator, 9));
    try std.testing.expect(!state.activateRequest(9));
}
