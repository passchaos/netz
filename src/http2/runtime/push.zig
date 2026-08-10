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

pub const State = struct {
    pending: std.ArrayList(PromisedRequest) = .empty,
    next_local_stream_id: u31 = 2,
    last_peer_stream_id: ?u31 = null,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        for (self.pending.items) |*promise| promise.deinit(allocator);
        self.pending.deinit(allocator);
        self.* = undefined;
    }

    pub fn nextLocalStreamId(self: State) error{InvalidStreamId}!u31 {
        if (self.next_local_stream_id > std.math.maxInt(u31) - 2) {
            return error.InvalidStreamId;
        }
        return self.next_local_stream_id;
    }

    pub fn commitLocalStream(self: *State) void {
        self.next_local_stream_id += 2;
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
        try self.pending.append(allocator, promise);
        self.last_peer_stream_id = promise.promised_stream_id;
    }

    pub fn take(self: *State) ?PromisedRequest {
        if (self.pending.items.len == 0) return null;
        return self.pending.orderedRemove(0);
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

    try std.testing.expectEqual(@as(u31, 2), try state.nextLocalStreamId());
    state.commitLocalStream();
    try std.testing.expectEqual(@as(u31, 4), try state.nextLocalStreamId());
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
