const std = @import("std");
const webtransport = @import("mod.zig");
const wire = @import("../internal/wire.zig");
const quic = @import("../quic/mod.zig");

pub const FrameType = struct {
    /// The first frame on a WebTransport bidirectional stream. Unlike ordinary
    /// HTTP/3 frames it is followed directly by the Session ID and has no
    /// payload-length field.
    pub const webtransport_stream: u64 = 0x41;
};

/// Header carried at offset zero of every WebTransport bidirectional stream.
///
/// Current implementations such as `wtransport` encode the dedicated 0x41
/// frame type followed by the CONNECT Session ID. Older draft code that writes
/// only a Session ID is intentionally rejected as ambiguous with ordinary H3
/// request-stream frame types.
pub const BidirectionalStreamHeader = struct {
    session_id: webtransport.SessionId,
    consumed: usize,

    pub fn parse(
        bytes: []const u8,
    ) webtransport.Error!BidirectionalStreamHeader {
        var cursor = wire.Cursor.init(bytes);
        const frame_type = try quic.varint.decode(&cursor);
        if (frame_type != FrameType.webtransport_stream) {
            return error.InvalidStreamType;
        }
        const session_id = try sessionIdFromWire(
            try quic.varint.decode(&cursor),
        );
        return .{ .session_id = session_id, .consumed = cursor.pos };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        session_id: webtransport.SessionId,
    ) webtransport.Error!void {
        try validateSessionId(session_id);
        const stream_type: u64 = FrameType.webtransport_stream;
        const type_len = try quic.varint.length(stream_type);
        const session_len = try quic.varint.length(session_id.value);
        try list.ensureUnusedCapacity(allocator, type_len + session_len);
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            stream_type,
            type_len,
        );
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            session_id.value,
            session_len,
        );
    }

    pub fn writeInto(
        storage: []u8,
        session_id: webtransport.SessionId,
    ) webtransport.Error![]const u8 {
        try validateSessionId(session_id);
        const type_len = try quic.varint.length(
            FrameType.webtransport_stream,
        );
        const session_len = try quic.varint.length(session_id.value);
        const total_len = type_len + session_len;
        if (storage.len < total_len) return error.BufferTooShort;
        const frame_type = try quic.varint.encodeInto(
            storage[0..type_len],
            FrameType.webtransport_stream,
        );
        _ = try quic.varint.encodeInto(
            storage[frame_type.len..total_len],
            session_id.value,
        );
        return storage[0..total_len];
    }
};

pub const EndpointRole = enum {
    client,
    server,
};

pub const StreamDirection = enum {
    bidirectional,
    unidirectional,
};

pub const StreamLifecycle = enum {
    open,
    fin_sent,
    fin_received,
    closed,
    reset,
};

pub const ReceiveMode = enum {
    unset,
    whole,
    incremental,
};

pub const StreamState = struct {
    stream_id: u62,
    direction: StreamDirection,
    locally_initiated: bool,
    /// Application scheduling priority for this stream's send direction.
    /// Higher values are considered first by multi-stream write batches.
    priority: i32 = 0,
    /// Absolute QUIC stream offset, including the association prefix.
    send_offset: u64 = 0,
    prefix_sent: bool = false,
    prefix_received: bool = false,
    receive_prefix_len: usize = 0,
    /// Whole-FIN and incremental readers consume transport storage
    /// differently and therefore must not be mixed on one receive direction.
    receive_mode: ReceiveMode = .unset,
    /// Application bytes only; association prefixes are intentionally excluded.
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    local_fin: bool = false,
    peer_fin: bool = false,
    /// Error sent in RESET_STREAM or RESET_STREAM_AT for the local direction.
    send_reset: ?webtransport.StreamError = null,
    /// Error received in RESET_STREAM or RESET_STREAM_AT for the peer direction.
    receive_reset: ?webtransport.StreamError = null,
    /// QUIC final size paired with `receive_reset`. Keeping it in the session
    /// registry lets transport storage be reclaimed before the application
    /// consumes the one-shot reset event.
    receive_reset_final_size: ?u64 = null,
    /// Error sent in STOP_SENDING for this stream's peer send direction.
    stop_sent: ?webtransport.StreamError = null,
    /// Error received in STOP_SENDING for this stream's local send direction.
    stopped: ?webtransport.StreamError = null,
    reset_reported: bool = false,
    stopped_reported: bool = false,

    pub fn lifecycle(self: StreamState) StreamLifecycle {
        if (self.send_reset != null or self.receive_reset != null) {
            return .reset;
        }
        if (self.local_fin and self.peer_fin) return .closed;
        if (self.local_fin) return .fin_sent;
        if (self.peer_fin) return .fin_received;
        return .open;
    }
};

/// Session-scoped WebTransport stream registry and credit accounting.
///
/// QUIC enforces transport-wide stream limits separately. These counters apply
/// the WebTransport SETTINGS limits and prevent HTTP/3 critical/request stream
/// IDs from being treated as session streams.
pub const StreamRegistry = struct {
    const IndexEntry = struct {
        position: usize,
        last_batch_epoch: u64 = 0,
    };

    pub const BatchMark = struct {
        stream: *StreamState,
        first: bool,
    };

    allocator: std.mem.Allocator,
    session_id: webtransport.SessionId,
    role: EndpointRole,
    next_local_bidi: u62,
    next_local_uni: u62,
    max_local_bidi: u64,
    max_local_uni: u64,
    max_peer_bidi: u64,
    max_peer_uni: u64,
    opened_local_bidi: u64 = 0,
    opened_local_uni: u64 = 0,
    opened_peer_bidi: u64 = 0,
    opened_peer_uni: u64 = 0,
    streams: std.ArrayList(StreamState) = .empty,
    index: std.AutoHashMapUnmanaged(u62, IndexEntry) = .empty,
    batch_epoch: u64 = 0,
    /// Last productive stream for the incremental whichever-ready reader.
    /// Stable IDs remain valid when registry storage reallocates.
    incremental_poll_cursor: ?u62 = null,

    pub const Config = struct {
        max_local_bidi: u64 = webtransport.default_initial_max_streams_bidi,
        max_local_uni: u64 = webtransport.default_initial_max_streams_uni,
        max_peer_bidi: u64 = webtransport.default_initial_max_streams_bidi,
        max_peer_uni: u64 = webtransport.default_initial_max_streams_uni,
        /// Client uni IDs 2/6/10 and server uni IDs 3/7/11 are reserved for
        /// HTTP/3 control/QPACK streams. The defaults start after them.
        first_local_bidi: ?u62 = null,
        first_local_uni: ?u62 = null,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        session_id: webtransport.SessionId,
        role: EndpointRole,
        config: Config,
    ) webtransport.Error!StreamRegistry {
        try validateSessionId(session_id);
        const default_bidi: u62 = if (role == .client) 4 else 1;
        const default_uni: u62 = if (role == .client) 14 else 15;
        const first_bidi = config.first_local_bidi orelse default_bidi;
        const first_uni = config.first_local_uni orelse default_uni;
        try validateLocalStreamId(role, first_bidi, .bidirectional);
        try validateLocalStreamId(role, first_uni, .unidirectional);
        return .{
            .allocator = allocator,
            .session_id = session_id,
            .role = role,
            .next_local_bidi = first_bidi,
            .next_local_uni = first_uni,
            .max_local_bidi = config.max_local_bidi,
            .max_local_uni = config.max_local_uni,
            .max_peer_bidi = config.max_peer_bidi,
            .max_peer_uni = config.max_peer_uni,
        };
    }

    pub fn deinit(self: *StreamRegistry) void {
        self.streams.deinit(self.allocator);
        self.index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn openLocal(
        self: *StreamRegistry,
        direction: StreamDirection,
    ) webtransport.Error!*StreamState {
        const stream_id = try self.prepareLocal(direction);
        return self.commitPreparedLocal(stream_id, direction);
    }

    pub fn registerPeer(
        self: *StreamRegistry,
        stream_id: u62,
        direction: StreamDirection,
    ) webtransport.Error!*StreamState {
        try validatePeerStreamId(self.role, stream_id, direction);
        if (self.index.contains(stream_id)) return error.DuplicateStream;
        const opened, const limit = switch (direction) {
            .bidirectional => .{
                &self.opened_peer_bidi,
                self.max_peer_bidi,
            },
            .unidirectional => .{
                &self.opened_peer_uni,
                self.max_peer_uni,
            },
        };
        if (opened.* >= limit) return error.StreamLimitExceeded;
        const stream_state = try self.insert(stream_id, direction, false);
        opened.* += 1;
        return stream_state;
    }

    pub fn registerLocal(
        self: *StreamRegistry,
        stream_id: u62,
        direction: StreamDirection,
    ) webtransport.Error!*StreamState {
        try validateLocalStreamId(self.role, stream_id, direction);
        if (self.index.contains(stream_id)) return error.DuplicateStream;
        const opened, const limit = switch (direction) {
            .bidirectional => .{
                &self.opened_local_bidi,
                self.max_local_bidi,
            },
            .unidirectional => .{
                &self.opened_local_uni,
                self.max_local_uni,
            },
        };
        if (opened.* >= limit) return error.StreamLimitExceeded;
        const stream_state = try self.insert(stream_id, direction, true);
        opened.* += 1;
        return stream_state;
    }

    /// Reserve registry capacity and validate the cumulative session policy
    /// before a transport or HTTP/3 stream-ID cursor is consumed. No logical
    /// registry state changes until `commitPreparedLocal` is called.
    pub fn prepareLocal(
        self: *StreamRegistry,
        direction: StreamDirection,
    ) webtransport.Error!u62 {
        const stream_id = switch (direction) {
            .bidirectional => self.next_local_bidi,
            .unidirectional => self.next_local_uni,
        };
        try self.prepareLocalId(stream_id, direction);
        return stream_id;
    }

    /// Preflight an externally shared H3/QUIC stream ID. This is the fallible
    /// half of registration; a successful call makes the matching commit
    /// allocation-free.
    pub fn prepareLocalId(
        self: *StreamRegistry,
        stream_id: u62,
        direction: StreamDirection,
    ) webtransport.Error!void {
        try validateLocalStreamId(self.role, stream_id, direction);
        if (self.index.contains(stream_id)) return error.DuplicateStream;
        const opened, const limit = switch (direction) {
            .bidirectional => .{
                self.opened_local_bidi,
                self.max_local_bidi,
            },
            .unidirectional => .{
                self.opened_local_uni,
                self.max_local_uni,
            },
        };
        if (opened >= limit) return error.StreamLimitExceeded;
        _ = std.math.add(u62, stream_id, 4) catch
            return error.StreamLimitExceeded;
        try self.index.ensureUnusedCapacity(self.allocator, 1);
        try self.streams.ensureUnusedCapacity(self.allocator, 1);
    }

    /// Commit a successfully prepared local stream. The intended adjacent
    /// prepare/commit sequence is allocation-free, but this public boundary
    /// revalidates all invariants and remains safe if a caller interleaves
    /// another registry operation or supplies an arbitrary ID.
    pub fn commitPreparedLocal(
        self: *StreamRegistry,
        stream_id: u62,
        direction: StreamDirection,
    ) webtransport.Error!*StreamState {
        const next, const opened = switch (direction) {
            .bidirectional => .{
                &self.next_local_bidi,
                &self.opened_local_bidi,
            },
            .unidirectional => .{
                &self.next_local_uni,
                &self.opened_local_uni,
            },
        };
        if (stream_id != next.*) return error.InvalidStreamState;
        try self.prepareLocalId(stream_id, direction);
        const advanced = std.math.add(u62, stream_id, 4) catch
            return error.StreamLimitExceeded;
        const stream_state = try self.insert(stream_id, direction, true);
        next.* = advanced;
        opened.* += 1;
        return stream_state;
    }

    pub fn get(self: *StreamRegistry, stream_id: u62) ?*StreamState {
        const entry = self.index.get(stream_id) orelse return null;
        const position = entry.position;
        if (position >= self.streams.items.len) return null;
        return &self.streams.items[position];
    }

    /// Start a transient batch-membership generation. Wrap is practically
    /// unreachable, but clearing the private marks keeps the API correct even
    /// after every nonzero generation has been consumed.
    pub fn beginBatchEpoch(self: *StreamRegistry) u64 {
        self.batch_epoch +%= 1;
        if (self.batch_epoch == 0) {
            var values = self.index.valueIterator();
            while (values.next()) |entry| entry.last_batch_epoch = 0;
            self.batch_epoch = 1;
        }
        return self.batch_epoch;
    }

    /// Mark one registered stream in `epoch` and report whether this is its
    /// first occurrence. Used by runtime batching to validate duplicates and
    /// track selected inputs without a second temporary hash set.
    pub fn markForBatch(
        self: *StreamRegistry,
        stream_id: u62,
        epoch: u64,
    ) ?BatchMark {
        if (epoch == 0 or epoch != self.batch_epoch) return null;
        const entry = self.index.getPtr(stream_id) orelse return null;
        if (entry.position >= self.streams.items.len or
            self.streams.items[entry.position].stream_id != stream_id)
        {
            return null;
        }
        const first = entry.last_batch_epoch != epoch;
        entry.last_batch_epoch = epoch;
        return .{
            .stream = &self.streams.items[entry.position],
            .first = first,
        };
    }

    pub fn markedForBatch(
        self: *StreamRegistry,
        stream_id: u62,
        epoch: u64,
    ) ?bool {
        if (epoch == 0 or epoch != self.batch_epoch) return null;
        const entry = self.index.get(stream_id) orelse return null;
        if (entry.position >= self.streams.items.len or
            self.streams.items[entry.position].stream_id != stream_id)
        {
            return null;
        }
        return entry.last_batch_epoch == epoch;
    }

    /// Update the application-visible send priority. Receive-only directions
    /// reject the operation rather than storing an unusable preference.
    pub fn setPriority(
        self: *StreamRegistry,
        stream_id: u62,
        value: i32,
    ) webtransport.Error!void {
        const stream_state = self.get(stream_id) orelse
            return error.UnknownStream;
        if (stream_state.direction == .unidirectional and
            !stream_state.locally_initiated)
        {
            return error.InvalidStreamState;
        }
        if (stream_state.send_reset != null or
            stream_state.stopped != null or
            stream_state.local_fin)
        {
            return error.InvalidStreamState;
        }
        stream_state.priority = value;
    }

    pub fn priority(
        self: *StreamRegistry,
        stream_id: u62,
    ) webtransport.Error!i32 {
        const stream_state = self.get(stream_id) orelse
            return error.UnknownStream;
        if (stream_state.send_reset != null) {
            return error.InvalidStreamState;
        }
        return stream_state.priority;
    }

    /// Borrow all registered streams for allocation-free runtime polling.
    ///
    /// The slice is invalidated by the next operation that can register a
    /// stream. Runtime adapters use it to observe STOP_SENDING on local
    /// unidirectional streams, which never appear in the receive-stream table.
    pub fn registered(self: *StreamRegistry) []StreamState {
        return self.streams.items;
    }

    pub fn removeLastPeer(
        self: *StreamRegistry,
        stream_id: u62,
    ) void {
        const position = (self.index.get(stream_id) orelse return).position;
        std.debug.assert(position + 1 == self.streams.items.len);
        const stream_state = self.streams.items[position];
        std.debug.assert(!stream_state.locally_initiated);
        _ = self.index.remove(stream_id);
        _ = self.streams.pop();
        switch (stream_state.direction) {
            .bidirectional => self.opened_peer_bidi -= 1,
            .unidirectional => self.opened_peer_uni -= 1,
        }
    }

    pub fn recordSent(
        self: *StreamRegistry,
        stream_id: u62,
        bytes: usize,
        fin: bool,
    ) webtransport.Error!void {
        const stream_state = self.get(stream_id) orelse
            return error.UnknownStream;
        if (stream_state.direction == .unidirectional and
            !stream_state.locally_initiated)
        {
            return error.InvalidStreamState;
        }
        if (stream_state.send_reset != null or
            stream_state.stopped != null or
            stream_state.local_fin)
        {
            return error.InvalidStreamState;
        }
        stream_state.bytes_sent = std.math.add(
            u64,
            stream_state.bytes_sent,
            bytes,
        ) catch return error.IntegerOverflow;
        if (fin) stream_state.local_fin = true;
    }

    pub fn recordReceived(
        self: *StreamRegistry,
        stream_id: u62,
        bytes: usize,
        fin: bool,
    ) webtransport.Error!void {
        const stream_state = self.get(stream_id) orelse
            return error.UnknownStream;
        if (stream_state.direction == .unidirectional and
            stream_state.locally_initiated)
        {
            return error.InvalidStreamState;
        }
        if (stream_state.receive_reset != null or
            stream_state.stop_sent != null or
            stream_state.peer_fin)
        {
            return error.InvalidStreamState;
        }
        stream_state.bytes_received = std.math.add(
            u64,
            stream_state.bytes_received,
            bytes,
        ) catch return error.IntegerOverflow;
        if (fin) stream_state.peer_fin = true;
    }

    pub fn markReset(
        self: *StreamRegistry,
        stream_id: u62,
        http3_code: u64,
    ) webtransport.Error!void {
        const stream_state = self.get(stream_id) orelse
            return error.UnknownStream;
        stream_state.receive_reset = .fromHttp3(http3_code);
    }

    pub fn markStopped(
        self: *StreamRegistry,
        stream_id: u62,
        http3_code: u64,
    ) webtransport.Error!void {
        const stream_state = self.get(stream_id) orelse
            return error.UnknownStream;
        stream_state.stopped = .fromHttp3(http3_code);
    }

    fn insert(
        self: *StreamRegistry,
        stream_id: u62,
        direction: StreamDirection,
        locally_initiated: bool,
    ) webtransport.Error!*StreamState {
        const slot = try self.index.getOrPut(self.allocator, stream_id);
        if (slot.found_existing) return error.DuplicateStream;
        errdefer _ = self.index.remove(stream_id);
        try self.streams.ensureUnusedCapacity(self.allocator, 1);
        const position = self.streams.items.len;
        self.streams.appendAssumeCapacity(newStreamState(
            stream_id,
            direction,
            locally_initiated,
        ));
        slot.value_ptr.* = .{ .position = position };
        return &self.streams.items[position];
    }
};

fn newStreamState(
    stream_id: u62,
    direction: StreamDirection,
    locally_initiated: bool,
) StreamState {
    return .{
        .stream_id = stream_id,
        .direction = direction,
        .locally_initiated = locally_initiated,
        // Only the initiator writes/reads the association prefix. The reverse
        // side of a bidirectional stream starts with application data.
        .prefix_sent = !locally_initiated,
        .prefix_received = locally_initiated,
    };
}

test "WebTransport stream priority validates send direction and lifecycle" {
    var registry = try StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{},
    );
    defer registry.deinit();
    const local = try registry.openLocal(.unidirectional);
    try std.testing.expectEqual(@as(i32, 0), try registry.priority(
        local.stream_id,
    ));
    try registry.setPriority(local.stream_id, 42);
    try std.testing.expectEqual(@as(i32, 42), try registry.priority(
        local.stream_id,
    ));

    const peer = try registry.registerPeer(3, .unidirectional);
    try std.testing.expectError(
        error.InvalidStreamState,
        registry.setPriority(peer.stream_id, 1),
    );
    local.send_reset = .fromHttp3(7);
    try std.testing.expectError(
        error.InvalidStreamState,
        registry.priority(local.stream_id),
    );
    try std.testing.expectError(
        error.UnknownStream,
        registry.setPriority(100, 1),
    );
}

test "WebTransport bidirectional stream header writes transactionally" {
    const allocator = std.testing.allocator;
    const session_id: webtransport.SessionId = .init(256);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.ensureTotalCapacityPrecise(allocator, 2);
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        BidirectionalStreamHeader.write(
            &encoded,
            failing.allocator(),
            session_id,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    var short = [_]u8{0xa5} ** 3;
    try std.testing.expectError(
        error.BufferTooShort,
        BidirectionalStreamHeader.writeInto(&short, session_id),
    );
    try std.testing.expectEqualSlices(u8, &.{ 0xa5, 0xa5, 0xa5 }, &short);
}

test "WebTransport stream registry batch epochs track membership" {
    var registry = try StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{},
    );
    defer registry.deinit();
    const first = (try registry.openLocal(.bidirectional)).stream_id;
    const second = (try registry.openLocal(.bidirectional)).stream_id;

    const initial = registry.beginBatchEpoch();
    try std.testing.expect(registry.markForBatch(first, initial).?.first);
    try std.testing.expect(!registry.markForBatch(first, initial).?.first);
    try std.testing.expectEqual(false, registry.markedForBatch(
        second,
        initial,
    ).?);
    try std.testing.expect(registry.markForBatch(999, initial) == null);

    const next = registry.beginBatchEpoch();
    try std.testing.expect(next != initial);
    try std.testing.expectEqual(false, registry.markedForBatch(first, next).?);
    try std.testing.expect(registry.markForBatch(first, next).?.first);

    registry.batch_epoch = std.math.maxInt(u64);
    const wrapped = registry.beginBatchEpoch();
    try std.testing.expectEqual(@as(u64, 1), wrapped);
    try std.testing.expectEqual(
        false,
        registry.markedForBatch(first, wrapped).?,
    );
    try std.testing.expect(registry.markForBatch(first, wrapped).?.first);
}

test "WebTransport local stream preflight commits without allocation" {
    const allocator = std.testing.allocator;
    var registry = try StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 2 },
    );
    defer registry.deinit();

    const first_id = try registry.prepareLocal(.bidirectional);
    try std.testing.expectEqual(@as(u62, 4), first_id);
    try std.testing.expectEqual(@as(usize, 0), registry.streams.items.len);
    const first = try registry.commitPreparedLocal(first_id, .bidirectional);
    try std.testing.expectEqual(first_id, first.stream_id);

    const second_id = try registry.prepareLocal(.bidirectional);
    try std.testing.expectEqual(@as(u62, 8), second_id);
    _ = try registry.commitPreparedLocal(second_id, .bidirectional);
    try std.testing.expectError(
        error.StreamLimitExceeded,
        registry.prepareLocal(.bidirectional),
    );
}

test "WebTransport external local registration preserves open cursor" {
    var registry = try StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 3 },
    );
    defer registry.deinit();

    const external = try registry.registerLocal(12, .bidirectional);
    try std.testing.expectEqual(@as(u62, 12), external.stream_id);
    const opened = try registry.openLocal(.bidirectional);
    try std.testing.expectEqual(@as(u62, 4), opened.stream_id);

    var last = try StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer last.deinit();
    const maximum_local_bidi: u62 = std.math.maxInt(u62) - 3;
    const registered = try last.registerLocal(
        maximum_local_bidi,
        .bidirectional,
    );
    try std.testing.expectEqual(maximum_local_bidi, registered.stream_id);
}

fn validateSessionId(
    session_id: webtransport.SessionId,
) webtransport.Error!void {
    if (!session_id.isClientInitiatedBidirectional()) {
        return error.InvalidSessionId;
    }
}

fn sessionIdFromWire(value: u64) webtransport.Error!webtransport.SessionId {
    const id: u62 = std.math.cast(u62, value) orelse
        return error.InvalidSessionId;
    const session_id = webtransport.SessionId.init(id);
    try validateSessionId(session_id);
    return session_id;
}

fn validateLocalStreamId(
    role: EndpointRole,
    stream_id: u62,
    direction: StreamDirection,
) webtransport.Error!void {
    const id = quic.StreamId.init(stream_id);
    const expected_initiator: @TypeOf(id.initiator()) = switch (role) {
        .client => .client,
        .server => .server,
    };
    const expected_direction: @TypeOf(id.direction()) = switch (direction) {
        .bidirectional => .bidirectional,
        .unidirectional => .unidirectional,
    };
    if (id.initiator() != expected_initiator or
        id.direction() != expected_direction)
    {
        return error.InvalidStreamType;
    }
}

fn validatePeerStreamId(
    role: EndpointRole,
    stream_id: u62,
    direction: StreamDirection,
) webtransport.Error!void {
    const peer: EndpointRole = switch (role) {
        .client => .server,
        .server => .client,
    };
    try validateLocalStreamId(peer, stream_id, direction);
}
