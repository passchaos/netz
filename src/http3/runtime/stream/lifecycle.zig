const std = @import("std");
const http3 = @import("../../mod.zig");
const Error = @import("../error.zig").Error;

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

pub const Client = struct {
    const Semantics = struct {
        stream_id: u62,
        method: []u8,
        extended_connect: bool,
    };

    allocator: std.mem.Allocator,
    outstanding: std.ArrayList(u62) = .empty,
    outstanding_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    semantics: std.ArrayList(Semantics) = .empty,
    /// Highest client-initiated bidirectional stream ID allocated locally.
    /// IDs are monotonic and shared by HTTP requests and extension streams.
    /// An allocated ID absent from `outstanding_index` therefore needs no
    /// per-request tombstone: HTTP/3 must ignore it, while an extension
    /// adapter consumes any retained QUIC stream bytes independently.
    highest_allocated_stream_id: ?u62 = null,
    max_streams: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
    ) Client {
        return .{ .allocator = allocator, .max_streams = max_streams };
    }

    pub fn deinit(self: *Client) void {
        for (self.semantics.items) |entry| {
            self.allocator.free(entry.method);
        }
        self.outstanding.deinit(self.allocator);
        self.outstanding_index.deinit(self.allocator);
        self.semantics.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn open(
        self: *Client,
        stream_id: u62,
        method: []const u8,
        extended_connect: bool,
    ) Error!void {
        if (self.outstanding.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        const method_copy = try self.allocator.dupe(u8, method);
        errdefer self.allocator.free(method_copy);
        const slot = try self.outstanding_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) return error.UnexpectedStream;
        errdefer _ = self.outstanding_index.remove(stream_id);
        const index = self.outstanding.items.len;
        try self.outstanding.append(self.allocator, stream_id);
        errdefer _ = self.outstanding.pop();
        try self.semantics.append(self.allocator, .{
            .stream_id = stream_id,
            .method = method_copy,
            .extended_connect = extended_connect,
        });
        slot.value_ptr.* = index;
    }

    pub fn contains(self: Client, stream_id: u62) bool {
        return self.outstanding_index.count() != 0 and
            self.outstanding_index.contains(stream_id);
    }

    pub fn isEmpty(self: Client) bool {
        return self.outstanding.items.len == 0;
    }

    pub fn count(self: Client) usize {
        return self.outstanding.items.len;
    }

    /// Return whether a client-bidirectional ID has been allocated but is no
    /// longer an outstanding HTTP request. This includes extension streams:
    /// their adapters own the retained QUIC bytes, so HTTP/3 must not parse
    /// them as late or unsolicited responses.
    pub fn isFinished(self: Client, stream_id: u62) bool {
        if ((stream_id & 0x03) != 0) return false;
        const highest = self.highest_allocated_stream_id orelse return false;
        return stream_id <= highest and !self.contains(stream_id);
    }

    /// Record a locally allocated client-bidirectional extension stream.
    /// HTTP request IDs are recorded by `open`; WebTransport and other
    /// adapters call this after advancing the shared stream-ID cursor.
    pub fn markAllocated(self: *Client, stream_id: u62) void {
        std.debug.assert((stream_id & 0x03) == 0);
        self.highest_allocated_stream_id =
            if (self.highest_allocated_stream_id) |highest|
                @max(highest, stream_id)
            else
                stream_id;
    }

    pub fn responseDecodeOptions(
        self: Client,
        stream_id: u62,
    ) http3.ResponseDecodeOptions {
        const index = self.outstanding_index.get(stream_id) orelse return .{};
        if (index >= self.semantics.items.len or
            self.semantics.items[index].stream_id != stream_id) return .{};
        const value = self.semantics.items[index];
        return .{
            .request_method = value.method,
            .extended_connect = value.extended_connect,
        };
    }

    pub fn matchesRequest(
        self: Client,
        stream_id: u62,
        method: []const u8,
        extended_connect: bool,
    ) bool {
        const index = self.outstanding_index.get(stream_id) orelse
            return false;
        if (index >= self.semantics.items.len or
            self.semantics.items[index].stream_id != stream_id)
        {
            return false;
        }
        const value = self.semantics.items[index];
        return value.extended_connect == extended_connect and
            std.mem.eql(u8, value.method, method);
    }

    pub fn finish(
        self: *Client,
        stream_id: u62,
    ) Error!bool {
        return self.finishAssumeCapacity(stream_id);
    }

    /// Compatibility preflight for callers that stage several state changes.
    /// Completion history is constant-space, so this cannot allocate.
    pub fn prepareFinish(self: *Client) std.mem.Allocator.Error!void {
        _ = self;
    }

    pub fn finishAssumeCapacity(
        self: *Client,
        stream_id: u62,
    ) bool {
        if (self.outstanding_index.count() == 0) return false;
        const index = self.outstanding_index.get(stream_id) orelse return false;
        const last_index = self.outstanding.items.len - 1;
        const removed = self.outstanding.swapRemove(index);
        const removed_semantics = self.semantics.swapRemove(index);
        std.debug.assert(removed_semantics.stream_id == removed);
        self.allocator.free(removed_semantics.method);
        _ = self.outstanding_index.remove(removed);
        if (index != last_index) {
            const moved = self.outstanding.items[index];
            self.outstanding_index.getPtr(moved).?.* = index;
            std.debug.assert(self.semantics.items[index].stream_id == moved);
        }
        return true;
    }
};

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

test "HTTP/3 client request lifecycle indexes outstanding streams" {
    const allocator = std.testing.allocator;
    var lifecycle = Client.init(allocator, 3);
    defer lifecycle.deinit();

    try std.testing.expect(lifecycle.isEmpty());
    try lifecycle.open(0, "GET", false);
    lifecycle.markAllocated(0);
    try lifecycle.open(4, "HEAD", false);
    lifecycle.markAllocated(4);
    try lifecycle.open(8, "CONNECT", true);
    lifecycle.markAllocated(8);
    try std.testing.expectEqual(@as(usize, 3), lifecycle.count());
    try std.testing.expect(lifecycle.contains(0));
    try std.testing.expect(lifecycle.contains(4));
    try std.testing.expect(lifecycle.contains(8));
    try std.testing.expectError(
        error.ExcessiveLoad,
        lifecycle.open(12, "GET", false),
    );
    try std.testing.expectEqualStrings(
        "HEAD",
        lifecycle.responseDecodeOptions(4).request_method.?,
    );
    try std.testing.expect(lifecycle.responseDecodeOptions(8).extended_connect);

    // Removing from the middle uses swapRemove; the moved stream must keep a
    // valid index because send/receive body paths call contains() frequently.
    try std.testing.expect(try lifecycle.finish(4));
    try std.testing.expect(!lifecycle.contains(4));
    try std.testing.expect(lifecycle.isFinished(4));
    try std.testing.expect(lifecycle.contains(8));
    try std.testing.expect(try lifecycle.finish(8));
    try std.testing.expect(!lifecycle.contains(8));

    try lifecycle.open(12, "POST", false);
    lifecycle.markAllocated(12);
    try std.testing.expect(lifecycle.contains(12));
    try std.testing.expect(!try lifecycle.finish(4));
    try std.testing.expect(try lifecycle.finish(0));
    try std.testing.expect(try lifecycle.finish(12));
    try std.testing.expect(lifecycle.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.outstanding_index.count());
    try std.testing.expect(lifecycle.isFinished(0));
    try std.testing.expect(lifecycle.isFinished(4));
    try std.testing.expect(lifecycle.isFinished(8));
    try std.testing.expect(lifecycle.isFinished(12));
    try std.testing.expect(!lifecycle.isFinished(16));
    try std.testing.expect(!lifecycle.isFinished(1));

    lifecycle.markAllocated(16);
    try std.testing.expect(lifecycle.isFinished(16));
    try lifecycle.open(20, "GET", false);
    try std.testing.expect(!lifecycle.isFinished(20));
    lifecycle.markAllocated(20);
    try std.testing.expect(try lifecycle.finish(20));
    try std.testing.expect(lifecycle.isFinished(20));
}

test "HTTP/3 client request lifecycle does not mark uncommitted opens" {
    const allocator = std.testing.allocator;
    var lifecycle = Client.init(allocator, 2);
    defer lifecycle.deinit();

    try lifecycle.open(0, "GET", false);
    try std.testing.expect(!lifecycle.isFinished(0));
    try std.testing.expect(try lifecycle.finish(0));
    try std.testing.expect(!lifecycle.isFinished(0));

    lifecycle.markAllocated(0);
    try std.testing.expect(lifecycle.isFinished(0));
    lifecycle.markAllocated(4);
    try std.testing.expect(lifecycle.isFinished(4));
    try std.testing.expect(!lifecycle.isFinished(8));
}

test "HTTP/3 client request lifecycle finish is allocation free" {
    const allocator = std.testing.allocator;
    var lifecycle = Client.init(allocator, 1);
    defer lifecycle.deinit();

    try lifecycle.open(0, "GET", false);
    lifecycle.markAllocated(0);
    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    lifecycle.allocator = fail.allocator();
    try std.testing.expect(try lifecycle.finish(0));
    lifecycle.allocator = allocator;
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expect(lifecycle.isFinished(0));
}

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
