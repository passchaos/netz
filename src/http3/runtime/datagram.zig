const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const early = @import("datagram/early.zig");

test {
    _ = @import("datagram/tests/early.zig");
    _ = @import("datagram/tests/registry.zig");
    _ = @import("datagram/tests/pacing.zig");
    _ = @import("datagram/tests/feedback.zig");
    _ = @import("datagram/tests/receive_feedback.zig");
    _ = @import("datagram/tests/preflight.zig");
}

pub const EarlyLimits = early.Limits;

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

/// One synchronous caller-buffer delivery target used while an authenticated
/// packet is being routed. Only the first matching DATAGRAM is delivered
/// directly; later matches retain the ordinary bounded-queue semantics.
pub const ReceiveIntoTarget = struct {
    const State = union(enum) {
        pending,
        received: usize,
        buffer_too_short,
    };

    stream_id: u62,
    output: []u8,
    state: State = .pending,

    pub fn init(stream_id: u62, output: []u8) ReceiveIntoTarget {
        return .{ .stream_id = stream_id, .output = output };
    }

    fn deliver(self: *ReceiveIntoTarget, payload: []const u8) bool {
        if (self.state != .pending or payload.len > self.output.len) {
            if (self.state == .pending) self.state = .buffer_too_short;
            return false;
        }
        @memcpy(self.output[0..payload.len], payload);
        self.state = .{ .received = payload.len };
        return true;
    }

    pub fn finish(self: ReceiveIntoTarget) error{BufferTooShort}!?[]u8 {
        return switch (self.state) {
            .pending => null,
            .received => |len| self.output[0..len],
            .buffer_too_short => error.BufferTooShort,
        };
    }
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
        reserved: bool = false,
        stream_detached: bool = false,
        discard_on_connection_close: bool = false,
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

        fn discard(self: *Association, allocator: std.mem.Allocator) void {
            for (self.queue.items[self.head..]) |payload| allocator.free(payload);
            self.queue.clearRetainingCapacity();
            self.head = 0;
            self.queued_bytes = 0;
        }

        fn markTerminal(self: *Association, allocator: std.mem.Allocator, state: Terminal) void {
            if (state == .connection_closed and self.discard_on_connection_close) {
                self.discard(allocator);
                // Protocols that terminate with their QUIC connection cannot
                // retain an earlier stream FIN as the effective end reason.
                self.terminal = state;
            } else if (self.terminal == null) {
                self.terminal = state;
            }
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
            self.pushOwned(allocator, owned, limits);
        }

        fn pushOwned(self: *Association, allocator: std.mem.Allocator, payload: []u8, limits: Limits) void {
            if (limits.max_queued_per_association == 0 or payload.len > limits.max_queued_bytes_per_association) {
                allocator.free(payload);
                return;
            }
            while (self.count() >= limits.max_queued_per_association or
                self.queued_bytes > limits.max_queued_bytes_per_association - payload.len)
            {
                self.dropOldest(allocator);
            }
            if (self.head != 0 and self.queue.items.len == self.queue.capacity) self.compact();
            self.queue.appendAssumeCapacity(payload);
            self.queued_bytes += payload.len;
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

        fn peek(self: Association) ?[]u8 {
            if (self.count() == 0) return null;
            return self.queue.items[self.head];
        }
    };

    allocator: std.mem.Allocator,
    limits: Limits,
    early_datagrams: early.Queue = .{},
    associations: std.ArrayList(Association) = .empty,
    index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    receive_scratch: std.ArrayList(u8) = .empty,
    send_scratch: std.ArrayList(u8) = .empty,
    send_batch_storage: std.ArrayList(u8) = .empty,
    send_batch_datagrams: std.ArrayList([]const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) Registry {
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn initWithEarly(allocator: std.mem.Allocator, limits: Limits, io: std.Io, early_limits: EarlyLimits) Registry {
        return .{ .allocator = allocator, .limits = limits, .early_datagrams = .init(io, early_limits) };
    }

    pub fn deinit(self: *Registry) void {
        self.early_datagrams.deinit(self.allocator);
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

    pub fn markStreamDetached(
        self: *Registry,
        stream_id: u62,
    ) !void {
        try validateStreamId(stream_id);
        const index = self.index.get(stream_id) orelse
            return error.UnexpectedStream;
        const association = &self.associations.items[index];
        if (association.reserved) {
            self.early_datagrams.expire(self.allocator);
            self.early_datagrams.commitRemember(stream_id);
            association.compact();
            var retaining = association.terminal == null;
            while (self.early_datagrams.takeNewest(stream_id)) |payload| {
                if (payload.len > self.limits.max_queued_bytes_per_association) {
                    self.allocator.free(payload);
                    continue;
                }
                if (association.count() >= self.limits.max_queued_per_association or association.queued_bytes > self.limits.max_queued_bytes_per_association - payload.len) retaining = false;
                if (!retaining) {
                    self.allocator.free(payload);
                    continue;
                }
                association.queue.insertAssumeCapacity(0, payload);
                association.queued_bytes += payload.len;
            }
            association.reserved = false;
        }
        association.stream_detached = true;
    }

    pub fn streamDetached(self: Registry, stream_id: u62) bool {
        const index = self.index.get(stream_id) orelse return false;
        return self.associations.items[index].stream_detached;
    }

    pub fn hasDetachedStreams(self: Registry) bool {
        for (self.associations.items) |association| {
            if (association.stream_detached) return true;
        }
        return false;
    }

    pub fn register(self: *Registry, stream_id: u62) !void {
        return self.registerInternal(stream_id, false);
    }

    /// Prepare an acceptance transaction without consuming early payloads or
    /// recording a retired ID. Unregister rolls this reservation back.
    pub fn reserve(self: *Registry, stream_id: u62) !void {
        for (self.associations.items) |association| {
            if (association.reserved) return error.UnexpectedStream;
        }
        return self.registerInternal(stream_id, true);
    }

    fn registerInternal(self: *Registry, stream_id: u62, reserved: bool) !void {
        try validateStreamId(stream_id);
        if (self.contains(stream_id)) return error.UnexpectedStream;
        if (self.associations.items.len >= self.limits.max_associations) {
            return error.ExcessiveLoad;
        }
        self.early_datagrams.expire(self.allocator);
        var association = Association{ .stream_id = stream_id, .reserved = reserved };
        errdefer association.queue.deinit(self.allocator);
        const early_count = self.early_datagrams.count(stream_id);
        try association.queue.ensureTotalCapacity(self.allocator, if (reserved and early_count != 0) self.limits.max_queued_per_association else @min(early_count, self.limits.max_queued_per_association));
        const slot = try self.index.getOrPut(self.allocator, stream_id);
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.index.remove(stream_id);
        const index = self.associations.items.len;
        try self.associations.ensureUnusedCapacity(self.allocator, 1);
        if (reserved) {
            try self.early_datagrams.prepareRestore(self.allocator);
            try self.early_datagrams.prepareRemember(self.allocator, stream_id);
        } else {
            try self.early_datagrams.remember(self.allocator, stream_id);
            while (self.early_datagrams.take(stream_id)) |payload| association.pushOwned(self.allocator, payload, self.limits);
        }
        self.associations.appendAssumeCapacity(association);
        slot.value_ptr.* = index;
    }

    /// Permanently suppress early DATAGRAMs for a CONNECT rejected before
    /// registration. Call before exposing the rejection on the socket.
    pub fn rejectEarlyAssociation(self: *Registry, stream_id: u62) !void {
        try validateStreamId(stream_id);
        try self.early_datagrams.remember(self.allocator, stream_id);
        self.early_datagrams.discard(self.allocator, stream_id);
    }

    pub fn pruneClosedAssociations(self: *Registry, connection: *const quic.one_rtt.Connection) void {
        if (!self.early_datagrams.enabled()) return;
        const retired = if (connection.config.local_endpoint == .server) connection.closed_peer_bidi_streams else connection.closed_local_bidi_streams;
        self.early_datagrams.known.foldFrom(retired);
        self.early_datagrams.expire(self.allocator);
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
        if (removed.reserved) {
            while (removed.pop()) |payload| self.early_datagrams.restoreOwned(self.allocator, stream_id, payload);
        }
        removed.deinit(self.allocator);
    }

    pub fn clear(self: *Registry) void {
        self.early_datagrams.clear(self.allocator);
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
        const index = self.index.get(stream_id) orelse {
            self.early_datagrams.discard(self.allocator, stream_id);
            return;
        };
        self.associations.items[index].markTerminal(self.allocator, state);
    }

    pub fn markAllTerminal(self: *Registry, state: Terminal) void {
        if (state == .connection_closed) self.early_datagrams.clear(self.allocator);
        for (self.associations.items) |*association| {
            association.markTerminal(self.allocator, state);
        }
    }

    /// Opt a protocol association into immediate queue discard when its
    /// underlying QUIC connection terminates. Registration defaults to the
    /// HTTP Datagram queue-drain contract; WebTransport opts in at acceptance.
    pub fn discardOnConnectionClose(self: *Registry, stream_id: u62) void {
        const index = self.index.get(stream_id) orelse return;
        const association = &self.associations.items[index];
        association.discard_on_connection_close = true;
        if (association.terminal) |state| {
            if (state == .connection_closed) association.discard(self.allocator);
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
    /// ignored unless early retention was explicitly enabled by the adapter.
    pub fn route(self: *Registry, encoded: []const u8) !void {
        return self.routeInto(encoded, null);
    }

    /// Route one encoded HTTP Datagram while optionally copying the first
    /// matching application payload into caller storage. A short output does
    /// not consume the payload: it is retained in the association queue and
    /// reported after packet processing completes.
    pub fn routeInto(
        self: *Registry,
        encoded: []const u8,
        target: ?*ReceiveIntoTarget,
    ) !void {
        const datagram = try http3.Datagram.parse(encoded);
        const stream_id: u62 = @intCast(datagram.quarter_stream_id << 2);
        const index = self.index.get(stream_id) orelse {
            try self.early_datagrams.push(self.allocator, stream_id, datagram.payload);
            return;
        };
        // RFC 9297 requires silently dropping datagrams received after the
        // request stream's receive side has closed. A recorded terminal state
        // also protects against frame ordering within one QUIC packet.
        if (self.associations.items[index].terminal != null) return;
        if (target) |direct| {
            if (direct.stream_id == stream_id and
                direct.state == .pending and
                direct.deliver(datagram.payload)) return;
        }
        try self.associations.items[index].push(
            self.allocator,
            datagram.payload,
            self.limits,
        );
    }

    /// Transport state also suppresses unknown associations after FIN/reset or
    /// retirement; those IDs must never enter the early queue again.
    pub fn routeIntoFromConnection(self: *Registry, encoded: []const u8, target: ?*ReceiveIntoTarget, connection: *quic.one_rtt.Connection) !void {
        if (self.early_datagrams.enabled()) {
            self.pruneClosedAssociations(connection);
            const datagram = try http3.Datagram.parse(encoded);
            const stream_id: u62 = @intCast(datagram.quarter_stream_id << 2);
            if (!self.contains(stream_id)) {
                if (connection.closed() or connection.closing() or connection.draining() or connection.streamLifecycle(stream_id) == .closed) return;
                if (connection.recvStreamStats(stream_id)) |stats| {
                    if (stats.final_size != null or stats.reset != null) return;
                }
            }
        }
        return self.routeInto(encoded, target);
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
            try self.routeIntoFromConnection(encoded, null, connection);
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
        try self.routeIntoFromConnection(encoded, null, connection);
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

    /// Copy the oldest retained payload into caller storage. Buffer failure is
    /// non-consuming so the application can retry with a larger destination.
    pub fn pollInto(
        self: *Registry,
        stream_id: u62,
        output: []u8,
    ) !?[]u8 {
        try validateStreamId(stream_id);
        const index = self.index.get(stream_id) orelse
            return error.UnexpectedStream;
        const association = &self.associations.items[index];
        const payload = association.peek() orelse return null;
        if (payload.len > output.len) return error.BufferTooShort;
        const owned = association.pop().?;
        defer self.allocator.free(owned);
        @memcpy(output[0..owned.len], owned);
        return output[0..owned.len];
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

test {
    _ = @import("datagram/tests/connection_close.zig");
}
