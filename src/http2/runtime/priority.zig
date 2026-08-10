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

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        for (self.updates.items) |*update| update.deinit(allocator);
        self.updates.deinit(allocator);
        self.idle_requests.deinit(allocator);
        self.* = undefined;
    }

    pub fn get(
        self: State,
        stream_id: u31,
    ) ?StoredUpdate {
        for (self.updates.items) |update| {
            if (update.stream_id == stream_id) return update;
        }
        return null;
    }

    pub fn containsIdleRequest(
        self: State,
        stream_id: u31,
    ) bool {
        for (self.idle_requests.items) |idle| {
            if (idle == stream_id) return true;
        }
        return false;
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
        if (self.containsIdleRequest(stream_id)) return;
        if (self.idle_requests.items.len >= max_idle_updates) {
            return error.PriorityCapacityExceeded;
        }
        if (max_concurrent_streams) |limit| {
            if (active_stream_count + self.idle_requests.items.len >= limit) {
                return error.PriorityCapacityExceeded;
            }
        }
        try self.idle_requests.append(allocator, stream_id);
    }

    pub fn activateRequest(
        self: *State,
        stream_id: u31,
    ) bool {
        for (self.idle_requests.items, 0..) |idle, index| {
            if (idle == stream_id) {
                _ = self.idle_requests.swapRemove(index);
                return true;
            }
        }
        return false;
    }

    /// Apply the HTTP/2 monotonic stream-ID transition caused by HEADERS.
    /// Lower idle request streams become closed implicitly; the matching
    /// reservation becomes active and keeps its latest priority update.
    pub fn openRequest(
        self: *State,
        allocator: std.mem.Allocator,
        stream_id: u31,
    ) void {
        var index: usize = 0;
        while (index < self.idle_requests.items.len) {
            const idle = self.idle_requests.items[index];
            if (idle > stream_id) {
                index += 1;
                continue;
            }
            _ = self.idle_requests.swapRemove(index);
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
        const owned = try allocator.dupe(u8, field_value);
        errdefer allocator.free(owned);
        for (self.updates.items) |*update| {
            if (update.stream_id == stream_id) {
                allocator.free(update.field_value);
                update.field_value = owned;
                return;
            }
        }
        try self.updates.append(allocator, .{
            .stream_id = stream_id,
            .field_value = owned,
        });
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
        for (self.updates.items, 0..) |update, index| {
            if (update.stream_id == stream_id) {
                var removed = self.updates.swapRemove(index);
                removed.deinit(allocator);
                return true;
            }
        }
        return false;
    }
};

test "priority updates replace state and bound idle reservations" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);

    try state.reserveIdleRequest(allocator, 1, 0, 2, 2);
    try state.store(allocator, 1, "u=7");
    try state.store(allocator, 1, "u=1, i");
    try std.testing.expectEqual(@as(u3, 1), state.get(1).?.priority().urgency);
    try std.testing.expect(state.get(1).?.priority().incremental);
    try state.reserveIdleRequest(allocator, 3, 0, 2, 2);
    try std.testing.expectError(
        error.PriorityCapacityExceeded,
        state.reserveIdleRequest(allocator, 5, 0, 2, 2),
    );
    try std.testing.expect(state.activateRequest(1));
    try state.reserveIdleRequest(allocator, 5, 1, 3, 2);
    try std.testing.expect(state.remove(allocator, 1));
    try std.testing.expect(state.get(1) == null);

    try state.store(allocator, 3, "u=3");
    try state.store(allocator, 5, "u=5");
    state.openRequest(allocator, 5);
    try std.testing.expect(state.get(3) == null);
    try std.testing.expect(state.get(5) != null);
}
