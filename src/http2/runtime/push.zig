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
    /// Server-created streams between PUSH_PROMISE and response/cancellation.
    local: std.ArrayList(LocalReservation) = .empty,
    /// Client-observed streams awaiting acceptance or refusal by the caller.
    remote: std.ArrayList(u31) = .empty,
    next_local_stream_id: u31 = 2,
    last_peer_stream_id: ?u31 = null,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        for (self.pending.items) |*promise| promise.deinit(allocator);
        self.pending.deinit(allocator);
        self.local.deinit(allocator);
        self.remote.deinit(allocator);
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
        try self.local.append(allocator, .{ .stream_id = stream_id });
        self.next_local_stream_id += 2;
        return stream_id;
    }

    pub fn localStatus(
        self: State,
        stream_id: u31,
    ) ?LocalStatus {
        for (self.local.items) |reservation| {
            if (reservation.stream_id == stream_id) {
                return reservation.status;
            }
        }
        return null;
    }

    pub fn cancelLocal(self: *State, stream_id: u31) bool {
        for (self.local.items) |*reservation| {
            if (reservation.stream_id == stream_id) {
                reservation.status = .canceled;
                return true;
            }
        }
        return false;
    }

    pub fn releaseLocal(self: *State, stream_id: u31) bool {
        for (self.local.items, 0..) |reservation, index| {
            if (reservation.stream_id == stream_id) {
                _ = self.local.swapRemove(index);
                return true;
            }
        }
        return false;
    }

    pub fn validatePeerStreamId(
        self: State,
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
        try self.remote.append(
            allocator,
            promise.promised_stream_id,
        );
        errdefer _ = self.remote.pop();
        try self.pending.append(allocator, promise);
        self.last_peer_stream_id = promise.promised_stream_id;
    }

    pub fn take(self: *State) ?PromisedRequest {
        if (self.pending.items.len == 0) return null;
        return self.pending.orderedRemove(0);
    }

    pub fn hasPending(self: State, stream_id: u31) bool {
        for (self.pending.items) |promise| {
            if (promise.promised_stream_id == stream_id) return true;
        }
        return false;
    }

    pub fn isRemoteReserved(self: State, stream_id: u31) bool {
        for (self.remote.items) |reserved| {
            if (reserved == stream_id) return true;
        }
        return false;
    }

    pub fn releaseRemote(self: *State, stream_id: u31) bool {
        for (self.remote.items, 0..) |reserved, index| {
            if (reserved == stream_id) {
                _ = self.remote.swapRemove(index);
                return true;
            }
        }
        return false;
    }

    /// Records a peer-side cancellation and destroys a queued notification if
    /// ownership has not already been transferred through `take`.
    pub fn cancelRemote(
        self: *State,
        allocator: std.mem.Allocator,
        stream_id: u31,
    ) bool {
        if (!self.releaseRemote(stream_id)) return false;
        for (self.pending.items, 0..) |promise, index| {
            if (promise.promised_stream_id == stream_id) {
                var removed = self.pending.orderedRemove(index);
                removed.deinit(allocator);
                break;
            }
        }
        return true;
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
    try std.testing.expect(state.cancelRemote(allocator, 2));
    try std.testing.expect(!state.hasPending(2));
    try std.testing.expect(!state.isRemoteReserved(2));
    try std.testing.expect(!state.cancelRemote(allocator, 2));
}
