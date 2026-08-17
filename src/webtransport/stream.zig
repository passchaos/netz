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
        try quic.varint.encode(
            list,
            allocator,
            FrameType.webtransport_stream,
        );
        try quic.varint.encode(list, allocator, session_id.value);
    }

    pub fn writeInto(
        storage: []u8,
        session_id: webtransport.SessionId,
    ) webtransport.Error![]const u8 {
        try validateSessionId(session_id);
        const frame_type = try quic.varint.encodeInto(
            storage,
            FrameType.webtransport_stream,
        );
        const session = try quic.varint.encodeInto(
            storage[frame_type.len..],
            session_id.value,
        );
        return storage[0 .. frame_type.len + session.len];
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

pub const StreamState = struct {
    stream_id: u62,
    direction: StreamDirection,
    locally_initiated: bool,
    /// Absolute QUIC stream offset, including the association prefix.
    send_offset: u64 = 0,
    prefix_sent: bool = false,
    prefix_received: bool = false,
    receive_prefix_len: usize = 0,
    /// Application bytes only; association prefixes are intentionally excluded.
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    local_fin: bool = false,
    peer_fin: bool = false,
    reset: bool = false,

    pub fn lifecycle(self: StreamState) StreamLifecycle {
        if (self.reset) return .reset;
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
    index: std.AutoHashMapUnmanaged(u62, usize) = .empty,

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
        const opened, const limit, const next = switch (direction) {
            .bidirectional => .{
                &self.opened_local_bidi,
                self.max_local_bidi,
                &self.next_local_bidi,
            },
            .unidirectional => .{
                &self.opened_local_uni,
                self.max_local_uni,
                &self.next_local_uni,
            },
        };
        if (opened.* >= limit) return error.StreamLimitExceeded;
        const stream_id = next.*;
        next.* = std.math.add(u62, stream_id, 4) catch
            return error.StreamLimitExceeded;
        errdefer next.* = stream_id;
        const stream_state = try self.insert(stream_id, direction, true);
        opened.* += 1;
        return stream_state;
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

    pub fn get(self: *StreamRegistry, stream_id: u62) ?*StreamState {
        const position = self.index.get(stream_id) orelse return null;
        if (position >= self.streams.items.len) return null;
        return &self.streams.items[position];
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
        if (stream_state.reset or stream_state.local_fin) {
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
        if (stream_state.reset or stream_state.peer_fin) {
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
    ) webtransport.Error!void {
        const stream_state = self.get(stream_id) orelse
            return error.UnknownStream;
        stream_state.reset = true;
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
        self.streams.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .direction = direction,
            .locally_initiated = locally_initiated,
            // Only the initiator writes/reads the association prefix. The
            // reverse side of a bidi stream starts with application data.
            .prefix_sent = !locally_initiated,
            .prefix_received = locally_initiated,
        });
        slot.value_ptr.* = position;
        return &self.streams.items[position];
    }
};

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
