const std = @import("std");
const http3 = @import("../../mod.zig");
const Error = @import("../error.zig").Error;
pub const Client = @import("lifecycle/client.zig").Client;

pub const ShutdownState = enum {
    active,
    initial_goaway,
    final_goaway,
};

/// RFC 9114 §5.2 processing certainty for a client-initiated request stream.
/// A stream at or above the server's GOAWAY identifier was not processed and
/// may be retried on another connection, subject to application replay policy.
pub const GoAwayRetryDisposition = enum {
    no_goaway,
    may_have_been_processed,
    safe_to_retry,
};

pub fn goAwayRetryDisposition(
    peer_goaway_id: ?u64,
    stream_id: u62,
) GoAwayRetryDisposition {
    const goaway_id = peer_goaway_id orelse return .no_goaway;
    return if (stream_id >= goaway_id)
        .safe_to_retry
    else
        .may_have_been_processed;
}

pub const Server = struct {
    const ActiveRequest = struct {
        stream_id: u62,
        priority: http3.Priority,
    };

    allocator: std.mem.Allocator,
    active_streams: std.ArrayList(ActiveRequest) = .empty,
    active_stream_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    lowest_active_stream_index: ?usize = null,
    highest_processed_stream_id: ?u62 = null,
    shutdown_state: ShutdownState = .active,

    pub fn init(allocator: std.mem.Allocator) Server {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Server) void {
        self.active_streams.deinit(self.allocator);
        self.active_stream_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn memoryAllocator(self: Server) std.mem.Allocator {
        return self.allocator;
    }

    pub fn count(self: Server) usize {
        return self.active_streams.items.len;
    }

    pub fn markReceived(
        self: *Server,
        stream_id: u62,
        initial_priority: http3.Priority,
    ) Error!void {
        if (self.contains(stream_id)) return error.UnexpectedStream;
        try self.prepareMarkReceived();
        self.markReceivedAssumeCapacity(stream_id, initial_priority);
    }

    pub fn prepareMarkReceived(self: *Server) Error!void {
        try self.active_stream_index.ensureUnusedCapacity(self.allocator, 1);
        try self.active_streams.ensureUnusedCapacity(self.allocator, 1);
    }

    pub fn markReceivedAssumeCapacity(
        self: *Server,
        stream_id: u62,
        initial_priority: http3.Priority,
    ) void {
        const slot = self.active_stream_index.getOrPutAssumeCapacity(stream_id);
        std.debug.assert(!slot.found_existing);
        const index = self.active_streams.items.len;
        self.active_streams.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .priority = initial_priority,
        });
        slot.value_ptr.* = index;
        self.considerLowestActiveStream(index);
        self.highest_processed_stream_id =
            if (self.highest_processed_stream_id) |highest|
                @max(highest, stream_id)
            else
                stream_id;
    }

    pub fn markFinished(self: *Server, stream_id: u64) void {
        const key = std.math.cast(u62, stream_id) orelse return;
        if (self.active_stream_index.count() == 0) return;
        const index = self.active_stream_index.get(key) orelse return;
        const last_index = self.active_streams.items.len - 1;
        const lowest = self.lowest_active_stream_index;
        const removed = self.active_streams.swapRemove(index);
        _ = self.active_stream_index.remove(removed.stream_id);
        if (index != last_index) {
            const moved = self.active_streams.items[index];
            self.active_stream_index.getPtr(moved.stream_id).?.* = index;
        }
        if (self.active_streams.items.len == 0) {
            self.lowest_active_stream_index = null;
        } else if (lowest == index) {
            self.recomputeLowestActiveStream();
        } else if (lowest == last_index) {
            self.lowest_active_stream_index = index;
        }
    }

    pub fn contains(self: Server, stream_id: u62) bool {
        return self.active_stream_index.count() != 0 and
            self.active_stream_index.contains(stream_id);
    }

    pub fn updatePriority(
        self: *Server,
        stream_id: u62,
        updated_priority: http3.Priority,
    ) bool {
        if (self.active_stream_index.count() == 0) return false;
        const index = self.active_stream_index.get(stream_id) orelse
            return false;
        if (index >= self.active_streams.items.len or
            self.active_streams.items[index].stream_id != stream_id)
        {
            return false;
        }
        self.active_streams.items[index].priority = updated_priority;
        return true;
    }

    pub fn state(self: Server) ShutdownState {
        return self.shutdown_state;
    }

    pub fn markInitialGoAwaySent(self: *Server) void {
        std.debug.assert(self.shutdown_state == .active);
        self.shutdown_state = .initial_goaway;
    }

    pub fn markFinalGoAwaySent(self: *Server) void {
        std.debug.assert(self.shutdown_state == .initial_goaway);
        self.shutdown_state = .final_goaway;
    }

    pub fn finalGoAwayId(self: Server) Error!u64 {
        const highest = self.highest_processed_stream_id orelse return 0;
        return std.math.add(u64, highest, 4) catch error.InvalidFrame;
    }

    pub fn drainComplete(
        self: Server,
        lowest_buffered_stream: ?u62,
        lowest_streaming_entry: ?u62,
        lowest_streaming_reset: ?u62,
        local_goaway_id: ?u64,
    ) bool {
        if (self.shutdown_state != .final_goaway) return false;
        const goaway_id = local_goaway_id orelse return false;
        if (self.lowestActiveStream()) |stream_id| {
            if (stream_id < goaway_id) return false;
        }
        if (lowest_buffered_stream) |stream_id| {
            if (stream_id < goaway_id) return false;
        }
        if (lowest_streaming_entry) |stream_id| {
            if (stream_id < goaway_id) return false;
        }
        if (lowest_streaming_reset) |stream_id| {
            if (stream_id < goaway_id) return false;
        }
        return true;
    }

    pub fn lowestActiveStream(self: Server) ?u62 {
        const index = self.lowest_active_stream_index orelse return null;
        return self.active_streams.items[index].stream_id;
    }

    pub fn priority(
        self: Server,
        stream_id: u62,
    ) http3.Priority {
        if (self.active_stream_index.count() == 0) return .{};
        const index = self.active_stream_index.get(stream_id) orelse
            return .{};
        if (index >= self.active_streams.items.len) return .{};
        const active = self.active_streams.items[index];
        if (active.stream_id != stream_id) return .{};
        return active.priority;
    }

    fn considerLowestActiveStream(self: *Server, index: usize) void {
        const lowest = self.lowest_active_stream_index orelse {
            self.lowest_active_stream_index = index;
            return;
        };
        if (self.active_streams.items[index].stream_id <
            self.active_streams.items[lowest].stream_id)
        {
            self.lowest_active_stream_index = index;
        }
    }

    fn recomputeLowestActiveStream(self: *Server) void {
        self.lowest_active_stream_index = null;
        for (self.active_streams.items, 0..) |_, index| {
            self.considerLowestActiveStream(index);
        }
    }
};

test "HTTP/3 server request lifecycle indexes active streams" {
    const allocator = std.testing.allocator;
    var lifecycle = Server.init(allocator);
    defer lifecycle.deinit();

    try lifecycle.markReceived(0, .{ .urgency = 5 });
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    try std.testing.expectEqual(@as(u3, 5), lifecycle.priority(0).urgency);
    try lifecycle.markReceived(4, .{ .urgency = 1 });
    try lifecycle.markReceived(8, .{});
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    try std.testing.expectError(
        error.UnexpectedStream,
        lifecycle.markReceived(4, .{}),
    );
    try std.testing.expectEqual(@as(?u62, 8), lifecycle.highest_processed_stream_id);
    try std.testing.expectEqual(@as(u64, 12), try lifecycle.finalGoAwayId());

    lifecycle.markFinished(4);
    try std.testing.expect(!lifecycle.contains(4));
    try std.testing.expect(lifecycle.contains(8));
    try std.testing.expectEqual(@as(u3, 3), lifecycle.priority(8).urgency);
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    lifecycle.markFinished(8);
    try std.testing.expect(!lifecycle.contains(8));
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    lifecycle.markFinished(999);
    try std.testing.expect(lifecycle.contains(0));
    lifecycle.markFinished(0);
    try std.testing.expectEqual(@as(?u62, null), lifecycle.lowestActiveStream());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.count());
    lifecycle.markFinished(16);
    try std.testing.expectEqual(@as(usize, 0), lifecycle.count());
}

test "HTTP/3 server request lifecycle owns shutdown drain boundaries" {
    const allocator = std.testing.allocator;
    var lifecycle = Server.init(allocator);
    defer lifecycle.deinit();

    try lifecycle.markReceived(0, .{});
    try std.testing.expectEqual(ShutdownState.active, lifecycle.state());
    try std.testing.expect(!lifecycle.drainComplete(null, null, null, 4));

    lifecycle.markInitialGoAwaySent();
    try std.testing.expectEqual(ShutdownState.initial_goaway, lifecycle.state());
    lifecycle.markFinalGoAwaySent();
    try std.testing.expectEqual(ShutdownState.final_goaway, lifecycle.state());
    try std.testing.expect(!lifecycle.drainComplete(null, null, null, 4));

    lifecycle.markFinished(0);
    try std.testing.expect(!lifecycle.drainComplete(0, null, null, 4));
    try std.testing.expect(!lifecycle.drainComplete(null, 0, null, 4));
    try std.testing.expect(!lifecycle.drainComplete(null, null, 0, 4));
    try std.testing.expect(!lifecycle.drainComplete(null, null, null, null));
    try std.testing.expect(lifecycle.drainComplete(4, 8, 12, 4));
}

test "HTTP/3 client GOAWAY classifies request replay safety" {
    try std.testing.expectEqual(
        GoAwayRetryDisposition.no_goaway,
        goAwayRetryDisposition(null, 0),
    );
    try std.testing.expectEqual(
        GoAwayRetryDisposition.may_have_been_processed,
        goAwayRetryDisposition(8, 4),
    );
    try std.testing.expectEqual(
        GoAwayRetryDisposition.safe_to_retry,
        goAwayRetryDisposition(8, 8),
    );
    try std.testing.expectEqual(
        GoAwayRetryDisposition.safe_to_retry,
        goAwayRetryDisposition(8, 12),
    );
}
