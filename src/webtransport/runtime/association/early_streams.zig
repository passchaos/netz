//! Connection-owned early streams remain in QUIC storage until their CONNECT
//! is accepted. This module bounds only their metadata and retained offset span.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const range_set = @import("../../../internal/exact_range_set.zig");
const association = @import("../stream_association.zig");
const rejection = @import("rejection.zig");

pub const Error = association.Error || http3.runtime.Error;
pub const Limits = struct {
    max_streams: usize = 64,
    max_bytes: u64 = 256 * 1024,
    max_age: std.Io.Duration = .fromSeconds(30),
    max_closed_session_ranges: usize = 128,
};

pub const Owners = struct {
    sessions: association.SessionLookup,
    ownsStreamFn: ?*const fn (*const anyopaque, u64, u62) bool = null,

    fn owns(self: Owners, stream_id: u62) bool {
        const function = self.ownsStreamFn orelse return false;
        return function(self.sessions.context, self.sessions.scope, stream_id);
    }
};

const Header = struct {
    direction: webtransport.StreamDirection,
    session_id: ?u62,
    invalid: bool = false,
};

pub const State = struct {
    const Entry = struct {
        stream_id: u62,
        header: Header,
        received_ns: i96,
        bytes: u64,
    };
    const Rejection = struct {
        stream_id: u62,
        direction: webtransport.StreamDirection,
        code: u64,
    };

    limits: Limits = .{},
    entries: std.ArrayList(Entry) = .empty,
    bytes: u64 = 0,
    pending: ?Rejection = null,
    closed_sessions: range_set.Set = .{},

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
        self.closed_sessions.deinit(allocator);
        self.* = undefined;
    }

    pub fn rejectSession(self: *State, allocator: std.mem.Allocator, connection: *const quic.one_rtt.Connection, session_id: u62) Error!void {
        self.foldClosed(connection);
        const ordinal: u64 = session_id / 4;
        if (!self.closed_sessions.contains(ordinal)) {
            const adjacent = ordinal == self.closed_sessions.prefix_len or
                (ordinal != 0 and self.closed_sessions.contains(ordinal - 1)) or self.closed_sessions.contains(ordinal + 1);
            if (!adjacent and self.closed_sessions.sparseRangeCount() >= self.limits.max_closed_session_ranges) return error.ExcessiveLoad;
            try self.closed_sessions.prepareInsertValue(allocator, ordinal);
            self.closed_sessions.insertAssumeCapacity(ordinal);
        }
    }

    fn foldClosed(self: *State, connection: *const quic.one_rtt.Connection) void {
        const retired = if (connection.config.local_endpoint == .server) connection.closed_peer_bidi_streams else connection.closed_local_bidi_streams;
        self.closed_sessions.foldFrom(retired);
    }

    pub fn nextExpiry(self: *const State) ?i96 {
        if (self.pending != null) return null;
        var earliest: ?i96 = null;
        for (self.entries.items) |entry| {
            const expiry = entry.received_ns +| self.limits.max_age.nanoseconds;
            if (earliest == null or expiry < earliest.?) earliest = expiry;
        }
        return earliest;
    }

    /// One nonblocking transport submission at most. Active Session readers
    /// keep their ownership and every rejected stream keeps its exact code.
    pub fn poll(self: *State, allocator: std.mem.Allocator, connection: *quic.one_rtt.Connection, owners: Owners) Error!bool {
        const active = owners.sessions;
        if (connection.closed() or connection.closing() or connection.draining()) return false;
        self.foldClosed(connection);
        if (self.pending != null) return self.submitPending(connection);
        const now_ns = std.Io.Clock.awake.now(connection.endpoint.io).nanoseconds;
        self.bytes = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = &self.entries.items[index];
            if (owners.owns(entry.stream_id) or connection.streamLifecycle(entry.stream_id) == .closed or
                (entry.header.session_id != null and active.contains(entry.header.session_id.?)))
            {
                _ = self.entries.orderedRemove(index);
                continue;
            }
            if (peek(connection, entry.stream_id)) |header| entry.header = header;
            if (entry.header.invalid) return invalidSession(connection);
            if (entry.header.session_id) |session_id| {
                if (active.contains(session_id)) {
                    _ = self.entries.orderedRemove(index);
                    continue;
                }
            }
            entry.bytes = retainedSpan(connection, entry.stream_id);
            self.bytes += entry.bytes;
            if (gone(self, connection, entry.header.session_id)) {
                self.pending = .{ .stream_id = entry.stream_id, .direction = entry.header.direction, .code = webtransport.ApplicationErrorCode.session_gone };
            } else if (now_ns - entry.received_ns >= self.limits.max_age.nanoseconds or self.bytes > self.limits.max_bytes) {
                self.pending = .{ .stream_id = entry.stream_id, .direction = entry.header.direction, .code = webtransport.ApplicationErrorCode.buffered_stream_rejected };
            }
            if (self.pending != null) return self.submitPending(connection);
            index += 1;
        }
        var ids_buffer: [256]u62 = undefined;
        var after: ?u62 = null;
        while (true) {
            const ids = connection.receivedStreamIdsAfterInto(after, &ids_buffer);
            for (ids) |id| {
                const direction: webtransport.StreamDirection = if (quic.StreamId.init(id).direction() == .bidirectional) .bidirectional else .unidirectional;
                const peer_initiated = if (connection.config.local_endpoint == .server) quic.StreamId.init(id).initiator() == .client else quic.StreamId.init(id).initiator() == .server;
                if (!peer_initiated) continue;
                if (connection.streamLifecycle(id) == .closed) continue;
                if (owners.owns(id)) continue;
                if (rejection.code(connection, id, direction)) |code| {
                    if (try rejection.advance(connection, id, direction, code, true)) return true;
                    continue;
                }
                if (self.find(id) != null) continue;
                const header = peek(connection, id) orelse continue;
                if (header.invalid) return invalidSession(connection);
                if (header.session_id) |session_id| {
                    if (active.contains(session_id)) continue;
                }
                const bytes = retainedSpan(connection, id);
                const code: ?u64 = if (gone(self, connection, header.session_id)) webtransport.ApplicationErrorCode.session_gone else if (self.entries.items.len >= self.limits.max_streams or bytes > self.limits.max_bytes -| self.bytes or self.limits.max_age.nanoseconds <= 0)
                    webtransport.ApplicationErrorCode.buffered_stream_rejected
                else
                    null;
                if (code) |value| {
                    self.pending = .{ .stream_id = id, .direction = direction, .code = value };
                    return self.submitPending(connection);
                }
                try self.entries.append(allocator, .{ .stream_id = id, .header = header, .received_ns = now_ns, .bytes = bytes });
                self.bytes += bytes;
            }
            if (ids.len < ids_buffer.len) return false;
            after = ids[ids.len - 1];
        }
    }

    fn submitPending(self: *State, connection: *quic.one_rtt.Connection) Error!bool {
        const pending = self.pending.?;
        const submitted = try rejection.advance(connection, pending.stream_id, pending.direction, pending.code, true);
        if (self.find(pending.stream_id)) |index| {
            const removed = self.entries.orderedRemove(index);
            self.bytes -|= removed.bytes;
        }
        self.pending = null;
        return submitted;
    }

    fn find(self: State, stream_id: u62) ?usize {
        for (self.entries.items, 0..) |entry, index| if (entry.stream_id == stream_id) return index;
        return null;
    }
};

fn retainedSpan(connection: *const quic.one_rtt.Connection, stream_id: u62) u64 {
    const stats = connection.recvStreamStats(stream_id) orelse return 0;
    return stats.highest_received_offset -| stats.bytes_read;
}

fn gone(self: *const State, connection: *const quic.one_rtt.Connection, session_id: ?u62) bool {
    const id = session_id orelse return false;
    if (self.closed_sessions.contains(id / 4) or connection.streamLifecycle(id) == .closed) return true;
    if (connection.recvStreamStats(id)) |stats| {
        if (stats.final_size != null or stats.reset != null) return true;
    }
    if (connection.sendStreamStats(id)) |stats| {
        if (stats.final_size != null or stats.reset != null) return true;
    }
    return false;
}

fn peek(connection: *quic.one_rtt.Connection, stream_id: u62) ?Header {
    const bytes = connection.retainedReceivedStream(stream_id) orelse return null;
    const kind = quic.varint.decodeSlice(bytes) catch return null;
    const direction: webtransport.StreamDirection = if (quic.StreamId.init(stream_id).direction() == .bidirectional) .bidirectional else .unidirectional;
    const expected: u64 = if (direction == .bidirectional) http3.FrameType.webtransport_stream else @intFromEnum(http3.StreamType.webtransport_unidirectional);
    if (kind.value != expected) return null;
    const session_id = quic.varint.decodeSlice(bytes[kind.len..]) catch return .{ .direction = direction, .session_id = null };
    const id = std.math.cast(u62, session_id.value) orelse return .{ .direction = direction, .session_id = null, .invalid = true };
    if (!webtransport.SessionId.init(id).isClientInitiatedBidirectional()) return .{ .direction = direction, .session_id = null, .invalid = true };
    return .{ .direction = direction, .session_id = id };
}

fn invalidSession(connection: *quic.one_rtt.Connection) Error!bool {
    try http3.runtime.closeConnectionForProtocolError(connection, error.IdError);
    return error.InvalidSessionId;
}
