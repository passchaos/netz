const std = @import("std");
const http3 = @import("../../../mod.zig");
const Error = @import("../../error.zig").Error;

pub const ShutdownState = enum {
    active,
    initial_goaway,
    final_goaway,
};

pub const Server = struct {
    const ActiveRequest = struct {
        priority: http3.Priority,
        peer_response_cancellation: ?u64 = null,
    };

    allocator: std.mem.Allocator,
    active: std.AutoHashMapUnmanaged(u62, ActiveRequest) = .empty,
    peer_response_cancellations: usize = 0,
    lowest_active_stream_id: ?u62 = null,
    highest_processed_stream_id: ?u62 = null,
    shutdown_state: ShutdownState = .active,

    pub fn init(allocator: std.mem.Allocator) Server {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Server) void {
        self.active.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn memoryAllocator(self: Server) std.mem.Allocator {
        return self.allocator;
    }

    pub fn count(self: Server) usize {
        return self.active.count();
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
        try self.active.ensureUnusedCapacity(self.allocator, 1);
    }

    pub fn markReceivedAssumeCapacity(
        self: *Server,
        stream_id: u62,
        initial_priority: http3.Priority,
    ) void {
        self.active.putAssumeCapacityNoClobber(
            stream_id,
            .{ .priority = initial_priority },
        );
        self.lowest_active_stream_id =
            if (self.lowest_active_stream_id) |lowest|
                @min(lowest, stream_id)
            else
                stream_id;
        self.highest_processed_stream_id =
            if (self.highest_processed_stream_id) |highest|
                @max(highest, stream_id)
            else
                stream_id;
    }

    pub fn markFinished(self: *Server, stream_id: u64) void {
        const key = std.math.cast(u62, stream_id) orelse return;
        const removed = self.active.fetchRemove(key) orelse return;
        if (removed.value.peer_response_cancellation != null) self.peer_response_cancellations -= 1;
        if (self.lowest_active_stream_id == key) {
            self.recomputeLowestActiveStream();
        }
    }

    pub fn contains(self: Server, stream_id: u62) bool {
        return self.active.count() != 0 and self.active.contains(stream_id);
    }

    pub fn updatePriority(
        self: *Server,
        stream_id: u62,
        updated_priority: http3.Priority,
    ) bool {
        const stored = self.active.getPtr(stream_id) orelse return false;
        stored.priority = updated_priority;
        return true;
    }

    /// Preserve the first peer STOP_SENDING until the HTTP owner consumes it.
    /// QUIC may reclaim the acknowledged reset before the next application poll.
    pub fn observePeerResponseCancellation(self: *Server, id: u62, code: u64) void {
        const request = self.active.getPtr(id) orelse return;
        if (request.peer_response_cancellation == null) {
            request.peer_response_cancellation = code;
            self.peer_response_cancellations += 1;
        }
    }

    pub fn peerResponseCancellation(self: Server, id: u62) ?u64 {
        if (self.peer_response_cancellations == 0) return null;
        const request = self.active.get(id) orelse return null;
        return request.peer_response_cancellation;
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
        return self.lowest_active_stream_id;
    }

    pub fn priority(self: Server, stream_id: u62) http3.Priority {
        return if (self.active.get(stream_id)) |request| request.priority else .{};
    }

    fn recomputeLowestActiveStream(self: *Server) void {
        var lowest: ?u62 = null;
        var iterator = self.active.keyIterator();
        while (iterator.next()) |stream_id| {
            lowest = if (lowest) |current|
                @min(current, stream_id.*)
            else
                stream_id.*;
        }
        self.lowest_active_stream_id = lowest;
    }
};

test "HTTP/3 server request lifecycle indexes active streams" {
    const allocator = std.testing.allocator;
    var lifecycle = Server.init(allocator);
    defer lifecycle.deinit();

    try lifecycle.markReceived(8, .{});
    try lifecycle.markReceived(0, .{ .urgency = 5 });
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    try std.testing.expectEqual(@as(u3, 5), lifecycle.priority(0).urgency);
    try lifecycle.markReceived(4, .{ .urgency = 1 });
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    try std.testing.expectError(
        error.UnexpectedStream,
        lifecycle.markReceived(4, .{}),
    );
    try std.testing.expectEqual(@as(?u62, 8), lifecycle.highest_processed_stream_id);
    try std.testing.expectEqual(@as(u64, 12), try lifecycle.finalGoAwayId());

    try std.testing.expect(lifecycle.updatePriority(8, .{ .urgency = 2 }));
    try std.testing.expectEqual(@as(u3, 2), lifecycle.priority(8).urgency);
    try std.testing.expect(!lifecycle.updatePriority(12, .{}));
    lifecycle.markFinished(4);
    try std.testing.expect(!lifecycle.contains(4));
    try std.testing.expect(lifecycle.contains(8));
    lifecycle.markFinished(0);
    try std.testing.expectEqual(@as(?u62, 8), lifecycle.lowestActiveStream());
    lifecycle.markFinished(999);
    try std.testing.expect(lifecycle.contains(8));
    lifecycle.markFinished(8);
    try std.testing.expectEqual(@as(?u62, null), lifecycle.lowestActiveStream());
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

test "HTTP/3 server request lifecycle mark failure is transactional" {
    const allocator = std.testing.allocator;
    var lifecycle = Server.init(allocator);
    defer lifecycle.deinit();
    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    lifecycle.allocator = fail.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        lifecycle.markReceived(0, .{ .urgency = 1 }),
    );
    lifecycle.allocator = allocator;
    try std.testing.expectEqual(@as(usize, 0), lifecycle.count());
    try std.testing.expectEqual(@as(?u62, null), lifecycle.lowestActiveStream());
    try std.testing.expectEqual(@as(?u62, null), lifecycle.highest_processed_stream_id);
}
