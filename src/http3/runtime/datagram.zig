const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");

/// One application payload removed from a detached Extended CONNECT
/// association. Ownership transfers to the caller so polling one association
/// never exposes storage belonging to another.
pub const Owned = struct {
    stream_id: u62,
    payload: []u8,

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const EncodedBatch = struct {
    storage: []const u8,
    datagrams: []const []const u8,
};

pub const Limits = struct {
    max_associations: usize,
    max_queued_per_association: usize,
    max_queued_bytes_per_association: usize,
};

/// Stream-local end state retained until the application has drained every
/// HTTP Datagram that arrived before (or alongside) the terminal signal.
/// Keeping this beside the queue makes terminal reporting stable and avoids
/// conflating a clean request-stream FIN with a connection-wide close.
pub const Terminal = union(enum) {
    peer_fin,
    peer_reset: u64,
    connection_closed,
};

/// Bounded demultiplexer for HTTP Datagrams keyed by the request stream whose
/// Extended CONNECT exchange created the association. Queue overflow follows
/// QUIC DATAGRAM's unreliable semantics: discard the oldest payload so a slow
/// association cannot prevent fresher traffic from being observed.
pub const Registry = struct {
    const Association = struct {
        stream_id: u62,
        queue: std.ArrayList([]u8) = .empty,
        head: usize = 0,
        queued_bytes: usize = 0,
        terminal: ?Terminal = null,

        fn deinit(self: *Association, allocator: std.mem.Allocator) void {
            for (self.queue.items[self.head..]) |payload| allocator.free(payload);
            self.queue.deinit(allocator);
            self.* = undefined;
        }

        fn count(self: Association) usize {
            return self.queue.items.len - self.head;
        }

        fn compact(self: *Association) void {
            if (self.head == 0) return;
            const remaining = self.count();
            if (remaining != 0) {
                @memmove(self.queue.items[0..remaining], self.queue.items[self.head..]);
            }
            self.queue.items.len = remaining;
            self.head = 0;
        }

        fn dropOldest(self: *Association, allocator: std.mem.Allocator) void {
            const payload = self.queue.items[self.head];
            self.queued_bytes -= payload.len;
            allocator.free(payload);
            self.head += 1;
            if (self.head == self.queue.items.len) {
                self.queue.clearRetainingCapacity();
                self.head = 0;
            } else if (self.head >= self.queue.items.len / 2) {
                self.compact();
            }
        }

        fn push(
            self: *Association,
            allocator: std.mem.Allocator,
            payload: []const u8,
            limits: Limits,
        ) std.mem.Allocator.Error!void {
            if (limits.max_queued_per_association == 0 or
                payload.len > limits.max_queued_bytes_per_association) return;
            // Allocate the replacement before applying unreliable-queue
            // eviction. An allocator failure must not destroy datagrams that
            // were already successfully retained for the application.
            const owned = try allocator.dupe(u8, payload);
            errdefer allocator.free(owned);
            if (self.head != 0 and self.queue.items.len == self.queue.capacity) {
                self.compact();
            }
            try self.queue.ensureUnusedCapacity(allocator, 1);
            while (self.count() >= limits.max_queued_per_association or
                self.queued_bytes > limits.max_queued_bytes_per_association - payload.len)
            {
                self.dropOldest(allocator);
            }
            self.queue.appendAssumeCapacity(owned);
            self.queued_bytes += owned.len;
        }

        fn pop(self: *Association) ?[]u8 {
            if (self.count() == 0) return null;
            const payload = self.queue.items[self.head];
            self.queued_bytes -= payload.len;
            self.head += 1;
            if (self.head == self.queue.items.len) {
                self.queue.clearRetainingCapacity();
                self.head = 0;
            }
            return payload;
        }
    };

    allocator: std.mem.Allocator,
    limits: Limits,
    associations: std.ArrayList(Association) = .empty,
    index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    receive_scratch: std.ArrayList(u8) = .empty,
    send_scratch: std.ArrayList(u8) = .empty,
    send_batch_storage: std.ArrayList(u8) = .empty,
    send_batch_datagrams: std.ArrayList([]const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) Registry {
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn deinit(self: *Registry) void {
        for (self.associations.items) |*association| association.deinit(self.allocator);
        self.send_batch_datagrams.deinit(self.allocator);
        self.send_batch_storage.deinit(self.allocator);
        self.send_scratch.deinit(self.allocator);
        self.receive_scratch.deinit(self.allocator);
        self.associations.deinit(self.allocator);
        self.index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn contains(self: Registry, stream_id: u62) bool {
        return self.index.count() != 0 and self.index.contains(stream_id);
    }

    pub fn associationCount(self: Registry) usize {
        return self.associations.items.len;
    }

    pub fn associationStreamId(self: Registry, index: usize) u62 {
        return self.associations.items[index].stream_id;
    }

    pub fn register(self: *Registry, stream_id: u62) !void {
        try validateStreamId(stream_id);
        if (self.contains(stream_id)) return error.UnexpectedStream;
        if (self.associations.items.len >= self.limits.max_associations) {
            return error.ExcessiveLoad;
        }
        const slot = try self.index.getOrPut(self.allocator, stream_id);
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.index.remove(stream_id);
        const index = self.associations.items.len;
        try self.associations.append(self.allocator, .{ .stream_id = stream_id });
        slot.value_ptr.* = index;
    }

    pub fn unregister(self: *Registry, stream_id: u62) void {
        if (self.index.count() == 0) return;
        const index = self.index.get(stream_id) orelse return;
        const last = self.associations.items.len - 1;
        var removed = self.associations.swapRemove(index);
        _ = self.index.remove(stream_id);
        if (index != last) {
            const moved = self.associations.items[index].stream_id;
            self.index.getPtr(moved).?.* = index;
        }
        removed.deinit(self.allocator);
    }

    pub fn clear(self: *Registry) void {
        for (self.associations.items) |*association| {
            association.deinit(self.allocator);
        }
        self.associations.clearRetainingCapacity();
        self.index.clearRetainingCapacity();
    }

    /// Record a terminal signal without discarding payloads already accepted
    /// for the association. The first signal wins so repeated/reordered QUIC
    /// control frames cannot change the error observed after queue drain.
    pub fn markTerminal(
        self: *Registry,
        stream_id: u62,
        state: Terminal,
    ) void {
        const index = self.index.get(stream_id) orelse return;
        if (self.associations.items[index].terminal == null) {
            self.associations.items[index].terminal = state;
        }
    }

    pub fn markAllTerminal(self: *Registry, state: Terminal) void {
        for (self.associations.items) |*association| {
            if (association.terminal == null) association.terminal = state;
        }
    }

    pub fn terminal(self: Registry, stream_id: u62) !?Terminal {
        try validateStreamId(stream_id);
        const index = self.index.get(stream_id) orelse
            return error.UnexpectedStream;
        return self.associations.items[index].terminal;
    }

    /// Expose terminal state only after every previously accepted datagram has
    /// been delivered. The state remains stable until explicit association or
    /// session teardown, which also permits the opposite stream direction to
    /// remain usable after a half-close.
    pub fn drainedTerminal(self: Registry, stream_id: u62) !?Terminal {
        try validateStreamId(stream_id);
        const index = self.index.get(stream_id) orelse
            return error.UnexpectedStream;
        const association = self.associations.items[index];
        if (association.count() != 0) return null;
        return association.terminal;
    }

    /// Route one encoded RFC 9297 HTTP Datagram. Unknown associations are
    /// deliberately ignored, including late datagrams for a closed CONNECT.
    pub fn route(self: *Registry, encoded: []const u8) !void {
        const datagram = try http3.Datagram.parse(encoded);
        const stream_id: u62 = @intCast(datagram.quarter_stream_id << 2);
        const index = self.index.get(stream_id) orelse return;
        // RFC 9297 requires silently dropping datagrams received after the
        // request stream's receive side has closed. A recorded terminal state
        // also protects against frame ordering within one QUIC packet.
        if (self.associations.items[index].terminal != null) return;
        try self.associations.items[index].push(
            self.allocator,
            datagram.payload,
            self.limits,
        );
    }

    pub fn validate(encoded: []const u8) http3.Error!void {
        _ = try http3.Datagram.parse(encoded);
    }

    /// Move every transport-level DATAGRAM into its exact CONNECT queue. The
    /// scratch is sized to the endpoint's UDP receive bound before popping so
    /// `Connection.popDatagram` can never consume a valid item merely because
    /// the caller buffer was too small.
    pub fn drain(self: *Registry, connection: *quic.one_rtt.Connection) !void {
        try self.receive_scratch.resize(
            self.allocator,
            connection.endpoint.limits.max_datagram_size,
        );
        while (try connection.popDatagram(self.receive_scratch.items)) |encoded| {
            try self.route(encoded);
        }
    }

    /// Route exactly one transport-queued DATAGRAM, if present. Packet-aware
    /// HTTP/3 dispatch uses this primitive to preserve ordering relative to
    /// FIN and RESET_STREAM frames within the same authenticated packet.
    pub fn routeNextTransport(
        self: *Registry,
        connection: *quic.one_rtt.Connection,
    ) !bool {
        try self.receive_scratch.resize(
            self.allocator,
            connection.endpoint.limits.max_datagram_size,
        );
        const encoded = (try connection.popDatagram(
            self.receive_scratch.items,
        )) orelse return false;
        try self.route(encoded);
        return true;
    }

    /// Encode into registry-owned reusable storage. The returned bytes remain
    /// valid until the next registry mutation and are intended for the
    /// connection's synchronous `sendDatagram` call.
    pub fn encode(
        self: *Registry,
        stream_id: u62,
        payload: []const u8,
    ) ![]const u8 {
        try validateStreamId(stream_id);
        if (!self.contains(stream_id)) return error.UnexpectedStream;
        self.send_scratch.clearRetainingCapacity();
        try (http3.Datagram{
            .quarter_stream_id = stream_id / 4,
            .payload = payload,
        }).write(&self.send_scratch, self.allocator);
        return self.send_scratch.items;
    }

    /// Encode an ordered application batch into reusable registry-owned
    /// storage. Returned slices remain stable until the next mutable registry
    /// operation or `Registry.deinit`.
    pub fn encodeBatch(
        self: *Registry,
        stream_id: u62,
        payloads: []const []const u8,
    ) !EncodedBatch {
        try validateStreamId(stream_id);
        if (!self.contains(stream_id)) return error.UnexpectedStream;
        const quarter_stream_id = stream_id / 4;
        const prefix_len = try quic.varint.length(quarter_stream_id);
        var total_len: usize = 0;
        for (payloads) |payload| {
            total_len = std.math.add(
                usize,
                total_len,
                std.math.add(usize, prefix_len, payload.len) catch
                    return error.IntegerOverflow,
            ) catch return error.IntegerOverflow;
        }
        self.send_batch_storage.clearRetainingCapacity();
        self.send_batch_datagrams.clearRetainingCapacity();
        try self.send_batch_storage.ensureTotalCapacityPrecise(
            self.allocator,
            total_len,
        );
        try self.send_batch_datagrams.ensureTotalCapacityPrecise(
            self.allocator,
            payloads.len,
        );
        self.send_batch_storage.items.len = total_len;
        self.send_batch_datagrams.items.len = payloads.len;
        const storage = self.send_batch_storage.items;
        const datagrams = self.send_batch_datagrams.items;

        var offset: usize = 0;
        for (payloads, datagrams) |payload, *encoded| {
            const start = offset;
            const prefix = try quic.varint.encodeInto(
                storage[offset..][0..prefix_len],
                quarter_stream_id,
            );
            offset += prefix.len;
            @memcpy(storage[offset..][0..payload.len], payload);
            offset += payload.len;
            encoded.* = storage[start..offset];
        }
        std.debug.assert(offset == storage.len);
        return .{ .storage = storage, .datagrams = datagrams };
    }

    pub fn poll(self: *Registry, stream_id: u62) !?Owned {
        try validateStreamId(stream_id);
        const index = self.index.get(stream_id) orelse return error.UnexpectedStream;
        const payload = self.associations.items[index].pop() orelse return null;
        return .{ .stream_id = stream_id, .payload = payload };
    }

    pub fn queuedCount(self: Registry, stream_id: u62) !usize {
        try validateStreamId(stream_id);
        const index = self.index.get(stream_id) orelse
            return error.UnexpectedStream;
        return self.associations.items[index].count();
    }
};

pub fn validateStreamId(stream_id: u62) error{UnexpectedStream}!void {
    // HTTP request streams are client-initiated bidirectional QUIC streams.
    if (stream_id & 0x3 != 0) return error.UnexpectedStream;
}

test "HTTP/3 CONNECT datagram registry demultiplexes and bounds FIFO queues" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 8,
    });
    defer registry.deinit();
    try registry.register(0);
    try registry.register(4);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{ .quarter_stream_id = 1, .payload = "other" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    encoded.clearRetainingCapacity();
    try (http3.Datagram{ .quarter_stream_id = 0, .payload = "first" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    encoded.clearRetainingCapacity();
    try (http3.Datagram{ .quarter_stream_id = 0, .payload = "two" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    encoded.clearRetainingCapacity();
    try (http3.Datagram{ .quarter_stream_id = 0, .payload = "new" }).write(&encoded, allocator);
    try registry.route(encoded.items);

    var other = (try registry.poll(4)).?;
    defer other.deinit(allocator);
    try std.testing.expectEqualStrings("other", other.payload);
    // The item cap evicts "first" before retaining the newer payloads.
    var first = (try registry.poll(0)).?;
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("two", first.payload);
    var second = (try registry.poll(0)).?;
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("new", second.payload);
    try std.testing.expectEqual(@as(?Owned, null), try registry.poll(0));

    encoded.clearRetainingCapacity();
    try (http3.Datagram{ .quarter_stream_id = 2, .payload = "unknown" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    try std.testing.expectError(error.UnexpectedStream, registry.poll(8));
    try std.testing.expectError(error.UnexpectedStream, registry.register(2));
}

test "HTTP/3 CONNECT datagram registry isolates unknown associations" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{
        .quarter_stream_id = 2,
        .payload = "unknown",
    }).write(&encoded, allocator);
    try registry.route(encoded.items);
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));

    // A Quarter Stream ID whose reconstruction would exceed u62 is malformed.
    encoded.clearRetainingCapacity();
    try quic.varint.encode(
        &encoded,
        allocator,
        http3.Datagram.max_quarter_stream_id + 1,
    );
    try encoded.appendSlice(allocator, "overflow");
    try std.testing.expectError(error.InvalidFrame, registry.route(encoded.items));
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
}

test "HTTP/3 CONNECT datagram batch uses stable exact backing storage" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    const payloads = [_][]const u8{ "one", &.{}, "three" };
    const batch = try registry.encodeBatch(0, &payloads);
    try std.testing.expectEqual(payloads.len, batch.datagrams.len);
    try std.testing.expectEqual(
        payloads[0].len + payloads[1].len + payloads[2].len + payloads.len,
        batch.storage.len,
    );
    for (batch.datagrams, payloads) |encoded, expected| {
        const datagram = try http3.Datagram.parse(encoded);
        try std.testing.expectEqual(@as(u64, 0), datagram.quarter_stream_id);
        try std.testing.expectEqualStrings(expected, datagram.payload);
        try std.testing.expect(@intFromPtr(encoded.ptr) >=
            @intFromPtr(batch.storage.ptr));
        try std.testing.expect(@intFromPtr(encoded.ptr) + encoded.len <=
            @intFromPtr(batch.storage.ptr) + batch.storage.len);
    }

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    registry.allocator = failing.allocator();
    const reused = try registry.encodeBatch(0, &payloads);
    registry.allocator = allocator;
    try std.testing.expectEqual(batch.storage.ptr, reused.storage.ptr);
    try std.testing.expectEqual(batch.datagrams.ptr, reused.datagrams.ptr);
    for (reused.datagrams, payloads) |encoded, expected| {
        const datagram = try http3.Datagram.parse(encoded);
        try std.testing.expectEqualStrings(expected, datagram.payload);
    }
}

test "HTTP/3 CONNECT datagram queue allocation failure is transactional" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 32,
    });
    defer registry.deinit();
    try registry.register(0);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "retained",
    }).write(&encoded, allocator);
    try registry.route(encoded.items);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    registry.allocator = failing.allocator();
    encoded.clearRetainingCapacity();
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "replacement",
    }).write(&encoded, allocator);
    try std.testing.expectError(error.OutOfMemory, registry.route(encoded.items));
    registry.allocator = allocator;

    var retained = (try registry.poll(0)).?;
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings("retained", retained.payload);
}

test "HTTP/3 CONNECT datagram terminal state drains payloads first" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "before reset",
    }).write(&encoded, allocator);
    try registry.route(encoded.items);
    registry.markTerminal(0, .{ .peer_reset = 0x10c });

    // Late datagrams for a closed receive side are silently dropped.
    encoded.clearRetainingCapacity();
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "after reset",
    }).write(&encoded, allocator);
    try registry.route(encoded.items);

    try std.testing.expectEqual(@as(?Terminal, null), try registry.drainedTerminal(0));
    var retained = (try registry.poll(0)).?;
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings("before reset", retained.payload);
    try std.testing.expectEqualDeep(
        Terminal{ .peer_reset = 0x10c },
        (try registry.drainedTerminal(0)).?,
    );
    // Terminal observation is stable until the higher-level association is
    // explicitly retired, which lets its opposite stream direction finish.
    try std.testing.expectEqualDeep(
        Terminal{ .peer_reset = 0x10c },
        (try registry.drainedTerminal(0)).?,
    );
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
}
