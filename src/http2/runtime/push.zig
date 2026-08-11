//! HTTP/2 server-push reservation state.
//!
//! PUSH_PROMISE creates a reserved stream. Reserved streams deliberately do
//! not count against SETTINGS_MAX_CONCURRENT_STREAMS; the runtime activates
//! them only when pushed HEADERS are sent or consumed.

const std = @import("std");
const http2 = @import("../mod.zig");

pub const PromisedRequest = struct {
    parent_stream_id: u31,
    promised_stream_id: u31,
    headers: []http2.Hpack.HeaderField,

    pub fn deinit(
        self: *PromisedRequest,
        allocator: std.mem.Allocator,
    ) void {
        freeHeaders(allocator, self.headers);
        self.* = undefined;
    }
};

pub const LocalStatus = enum {
    reserved,
    canceled,
};

const LocalReservation = struct {
    stream_id: u31,
    status: LocalStatus = .reserved,
};

pub const State = struct {
    /// Client-side notifications whose header ownership is still queued.
    pending: std.ArrayList(PromisedRequest) = .empty,
    pending_head: usize = 0,
    pending_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    /// Server-created streams between PUSH_PROMISE and response/cancellation.
    local: std.ArrayList(LocalReservation) = .empty,
    local_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    /// Client-observed streams awaiting acceptance or refusal by the caller.
    remote: std.ArrayList(u31) = .empty,
    remote_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    next_local_stream_id: u31 = 2,
    last_peer_stream_id: ?u31 = null,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        for (self.pending.items[self.pending_head..]) |*promise| {
            promise.deinit(allocator);
        }
        self.pending.deinit(allocator);
        self.pending_index.deinit(allocator);
        self.local.deinit(allocator);
        self.local_index.deinit(allocator);
        self.remote.deinit(allocator);
        self.remote_index.deinit(allocator);
        self.* = undefined;
    }

    pub fn reserveLocal(
        self: *State,
        allocator: std.mem.Allocator,
    ) (error{InvalidStreamId} || std.mem.Allocator.Error)!u31 {
        if (self.next_local_stream_id > std.math.maxInt(u31) - 2) {
            return error.InvalidStreamId;
        }
        const stream_id = self.next_local_stream_id;
        try self.local.ensureUnusedCapacity(allocator, 1);
        try self.local_index.ensureUnusedCapacity(allocator, 1);
        self.local.appendAssumeCapacity(.{ .stream_id = stream_id });
        self.local_index.putAssumeCapacityNoClobber(
            stream_id,
            self.local.items.len - 1,
        );
        self.next_local_stream_id += 2;
        return stream_id;
    }

    pub fn localStatus(
        self: *const State,
        stream_id: u31,
    ) ?LocalStatus {
        const index = self.local_index.get(stream_id) orelse return null;
        return self.local.items[index].status;
    }

    pub fn isLocalReserved(self: *const State, stream_id: u31) bool {
        return self.localStatus(stream_id) == .reserved;
    }

    pub fn cancelLocal(self: *State, stream_id: u31) bool {
        const index = self.local_index.get(stream_id) orelse return false;
        self.local.items[index].status = .canceled;
        return true;
    }

    pub fn releaseLocal(self: *State, stream_id: u31) bool {
        const index = self.local_index.get(stream_id) orelse return false;
        _ = self.local.swapRemove(index);
        _ = self.local_index.remove(stream_id);
        if (index < self.local.items.len) {
            const moved = self.local.items[index];
            self.local_index.getPtr(moved.stream_id).?.* = index;
        }
        return true;
    }

    pub fn validatePeerStreamId(
        self: *const State,
        stream_id: u31,
    ) error{InvalidStreamId}!void {
        if ((stream_id & 1) != 0 or stream_id == 0) {
            return error.InvalidStreamId;
        }
        if (self.last_peer_stream_id) |last| {
            if (stream_id <= last) return error.InvalidStreamId;
        }
    }

    pub fn queue(
        self: *State,
        allocator: std.mem.Allocator,
        promise: PromisedRequest,
    ) std.mem.Allocator.Error!void {
        // Keep reservation identity separate from notification ownership.
        // `take` transfers the request headers to the caller, while the stream
        // must remain reserved until that caller reads or cancels the push.
        if (self.pending_head != 0 and
            self.pending.items.len == self.pending.capacity)
        {
            self.compactPending();
        }
        try self.remote.ensureUnusedCapacity(allocator, 1);
        try self.remote_index.ensureUnusedCapacity(allocator, 1);
        try self.pending.ensureUnusedCapacity(allocator, 1);
        try self.pending_index.ensureUnusedCapacity(allocator, 1);

        self.remote.appendAssumeCapacity(promise.promised_stream_id);
        self.remote_index.putAssumeCapacityNoClobber(
            promise.promised_stream_id,
            self.remote.items.len - 1,
        );
        self.pending.appendAssumeCapacity(promise);
        self.pending_index.putAssumeCapacityNoClobber(
            promise.promised_stream_id,
            self.pending.items.len - 1,
        );
        self.last_peer_stream_id = promise.promised_stream_id;
    }

    pub fn take(self: *State) ?PromisedRequest {
        if (self.pendingCount() == 0) return null;
        const promise = self.pending.items[self.pending_head];
        _ = self.pending_index.remove(promise.promised_stream_id);
        self.pending_head += 1;
        // PUSH_PROMISE delivery is FIFO.  Advancing a cursor makes each pop
        // O(1); occasional compaction reclaims stale slots whose header
        // ownership has already moved to the caller.
        self.compactPendingIfSparse();
        return promise;
    }

    pub fn hasPending(self: *const State, stream_id: u31) bool {
        return self.pending_index.contains(stream_id);
    }

    pub fn isRemoteReserved(self: *const State, stream_id: u31) bool {
        return self.remote_index.contains(stream_id);
    }

    pub fn releaseRemote(self: *State, stream_id: u31) bool {
        const index = self.remote_index.get(stream_id) orelse return false;
        _ = self.remote.swapRemove(index);
        _ = self.remote_index.remove(stream_id);
        if (index < self.remote.items.len) {
            const moved = self.remote.items[index];
            self.remote_index.getPtr(moved).?.* = index;
        }
        return true;
    }

    /// Records a peer-side cancellation and destroys a queued notification if
    /// ownership has not already been transferred through `take`.
    pub fn cancelRemote(
        self: *State,
        allocator: std.mem.Allocator,
        stream_id: u31,
    ) bool {
        if (!self.releaseRemote(stream_id)) return false;
        if (self.pending_index.get(stream_id)) |index| {
            var removed = self.pending.orderedRemove(index);
            _ = self.pending_index.remove(stream_id);
            removed.deinit(allocator);
            self.repairPendingIndexFrom(index);
            self.compactPendingIfSparse();
        }
        return true;
    }

    fn pendingCount(self: *const State) usize {
        return self.pending.items.len - self.pending_head;
    }

    fn compactPendingIfSparse(self: *State) void {
        if (self.pending_head == 0) return;
        if (self.pending_head == self.pending.items.len or
            self.pending_head >= self.pending.items.len / 2)
        {
            self.compactPending();
        }
    }

    fn compactPending(self: *State) void {
        if (self.pending_head == 0) return;
        const remaining = self.pendingCount();
        if (remaining != 0) {
            @memmove(
                self.pending.items[0..remaining],
                self.pending.items[self.pending_head..],
            );
        }
        self.pending.items.len = remaining;
        self.pending_head = 0;
        self.rebuildPendingIndexAssumeCapacity();
    }

    fn rebuildPendingIndexAssumeCapacity(self: *State) void {
        self.pending_index.clearRetainingCapacity();
        for (self.pending.items[self.pending_head..], self.pending_head..) |promise, index| {
            self.pending_index.putAssumeCapacityNoClobber(
                promise.promised_stream_id,
                index,
            );
        }
    }

    fn repairPendingIndexFrom(self: *State, start_index: usize) void {
        var index = @max(start_index, self.pending_head);
        while (index < self.pending.items.len) : (index += 1) {
            const stream_id = self.pending.items[index].promised_stream_id;
            self.pending_index.getPtr(stream_id).?.* = index;
        }
    }
};

fn freeHeaders(
    allocator: std.mem.Allocator,
    headers: []http2.Hpack.HeaderField,
) void {
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}

test "push reservations use monotonic even stream IDs" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);

    try std.testing.expectEqual(
        @as(u31, 2),
        try state.reserveLocal(allocator),
    );
    try std.testing.expectEqual(
        LocalStatus.reserved,
        state.localStatus(2).?,
    );
    try std.testing.expect(state.cancelLocal(2));
    try std.testing.expectEqual(
        LocalStatus.canceled,
        state.localStatus(2).?,
    );
    try std.testing.expect(state.releaseLocal(2));
    try std.testing.expectEqual(
        @as(u31, 4),
        try state.reserveLocal(allocator),
    );
    try state.validatePeerStreamId(2);
    state.last_peer_stream_id = 2;
    try std.testing.expectError(
        error.InvalidStreamId,
        state.validatePeerStreamId(2),
    );
    try std.testing.expectError(
        error.InvalidStreamId,
        state.validatePeerStreamId(3),
    );
}

test "canceling a queued remote reservation frees its request" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);

    const headers = try allocator.alloc(http2.Hpack.HeaderField, 1);
    headers[0] = .{
        .name = try allocator.dupe(u8, ":path"),
        .value = try allocator.dupe(u8, "/canceled"),
    };
    try state.queue(allocator, .{
        .parent_stream_id = 1,
        .promised_stream_id = 2,
        .headers = headers,
    });

    try std.testing.expect(state.hasPending(2));
    try std.testing.expect(state.isRemoteReserved(2));
    try std.testing.expectEqual(@as(usize, 1), state.pending_index.count());
    try std.testing.expectEqual(@as(usize, 1), state.remote_index.count());
    try std.testing.expect(state.cancelRemote(allocator, 2));
    try std.testing.expect(!state.hasPending(2));
    try std.testing.expect(!state.isRemoteReserved(2));
    try std.testing.expectEqual(@as(usize, 0), state.pending_index.count());
    try std.testing.expectEqual(@as(usize, 0), state.remote_index.count());
    try std.testing.expect(!state.cancelRemote(allocator, 2));
}

test "push reservation indexes track local remote and pending lifecycles" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);

    const first_local = try state.reserveLocal(allocator);
    const second_local = try state.reserveLocal(allocator);
    try std.testing.expectEqual(@as(u31, 2), first_local);
    try std.testing.expectEqual(@as(u31, 4), second_local);
    try std.testing.expectEqual(@as(?usize, 0), state.local_index.get(first_local));
    try std.testing.expectEqual(@as(?usize, 1), state.local_index.get(second_local));
    try std.testing.expect(state.releaseLocal(first_local));
    try std.testing.expect(state.local_index.get(first_local) == null);
    try std.testing.expectEqual(@as(?usize, 0), state.local_index.get(second_local));

    for ([_]u31{ 2, 4, 6 }) |stream_id| {
        try queueTestPromise(&state, allocator, allocator, stream_id);
    }
    try std.testing.expectEqual(@as(usize, 3), state.pending_index.count());
    try std.testing.expectEqual(@as(usize, 3), state.remote_index.count());

    var first = state.take() orelse return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 2), first.promised_stream_id);
    try std.testing.expect(!state.hasPending(2));
    try std.testing.expect(state.isRemoteReserved(2));
    try std.testing.expectEqual(@as(?usize, 0), state.pending_index.get(4));
    try std.testing.expectEqual(@as(?usize, 1), state.pending_index.get(6));

    // Canceling a queued promise removes one pending entry with orderedRemove
    // and one remote reservation with swapRemove. Both indexes must be repaired
    // before callers can inspect, cancel, or consume the remaining promise.
    try std.testing.expect(state.cancelRemote(allocator, 4));
    try std.testing.expect(!state.hasPending(4));
    try std.testing.expect(!state.isRemoteReserved(4));
    try std.testing.expectEqual(@as(?usize, 0), state.pending_index.get(6));
    try std.testing.expectEqual(@as(?usize, 0), state.remote_index.get(2));
    try std.testing.expectEqual(@as(?usize, 1), state.remote_index.get(6));

    var remaining = state.take() orelse return error.TestUnexpectedResult;
    defer remaining.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 6), remaining.promised_stream_id);
    try std.testing.expectEqual(@as(usize, 0), state.pending_index.count());
    try std.testing.expect(state.releaseRemote(2));
    try std.testing.expect(state.releaseRemote(6));
    try std.testing.expectEqual(@as(usize, 0), state.remote_index.count());
}

test "pending push notifications reuse consumed FIFO slots" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);

    try state.pending.ensureTotalCapacity(allocator, 4);
    try state.remote.ensureTotalCapacity(allocator, 5);
    for ([_]u31{ 2, 4, 6, 8 }) |stream_id| {
        try queueTestPromise(&state, allocator, allocator, stream_id);
    }

    var first = state.take() orelse return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 2), first.promised_stream_id);
    try std.testing.expectEqual(@as(usize, 3), state.pendingCount());

    // The notification queue is at capacity with one consumed head element.
    // Adding another promise must compact/reuse that stale slot rather than
    // allocating or reporting pressure during a server-push burst.
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try queueTestPromise(&state, allocator, no_alloc.allocator(), 10);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 4), state.pendingCount());
    try std.testing.expectEqual(@as(usize, 4), state.pending_index.count());

    for ([_]u31{ 4, 6, 8, 10 }) |stream_id| {
        var promise = state.take() orelse return error.TestUnexpectedResult;
        defer promise.deinit(allocator);
        try std.testing.expectEqual(stream_id, promise.promised_stream_id);
    }
    try std.testing.expect(state.take() == null);
    try std.testing.expectEqual(@as(usize, 0), state.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), state.pending_index.count());
}

fn queueTestPromise(
    state: *State,
    header_allocator: std.mem.Allocator,
    queue_allocator: std.mem.Allocator,
    promised_stream_id: u31,
) !void {
    const headers = try header_allocator.alloc(http2.Hpack.HeaderField, 1);
    errdefer header_allocator.free(headers);
    const name = try header_allocator.dupe(u8, ":path");
    errdefer header_allocator.free(name);
    const value = try std.fmt.allocPrint(
        header_allocator,
        "/push/{d}",
        .{promised_stream_id},
    );
    errdefer header_allocator.free(value);
    headers[0] = .{
        .name = name,
        .value = value,
    };
    try state.queue(queue_allocator, .{
        .parent_stream_id = 1,
        .promised_stream_id = promised_stream_id,
        .headers = headers,
    });
}
