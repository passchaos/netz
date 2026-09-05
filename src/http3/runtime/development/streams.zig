const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");

const net = std.Io.net;
const Error = runtime_error.Error;

pub const Direction = enum {
    bidirectional,
    unidirectional,
};

pub const EndpointRole = enum { client, server };

/// A FIN-complete non-HTTP/3 stream retained by the cleartext packet pump.
/// Protocol adapters own interpretation of the leading bytes; HTTP/3 only
/// guarantees peer/stream isolation and bounded reassembly.
pub const Stream = struct {
    allocator: std.mem.Allocator,
    from: net.IpAddress,
    stream_id: u62,
    direction: Direction,
    bytes: []u8,

    pub fn deinit(self: *Stream) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const Match = struct {
    session_id: u62,
    local_role: EndpointRole,
    /// A locally-created bidirectional stream has already consumed its
    /// association prefix in the outbound direction. Its reverse direction
    /// therefore starts directly with application bytes.
    context: ?*const anyopaque = null,
    is_local_bidirectional: ?*const fn (*const anyopaque, u62) bool = null,

    fn ownsLocalBidirectional(self: Match, stream_id: u62) bool {
        const context = self.context orelse return false;
        const predicate = self.is_local_bidirectional orelse return false;
        return predicate(context, stream_id);
    }
};

pub const DebugCounts = struct {
    /// Receive buffers whose association prefix identifies this session.
    receives: usize,
    sends: usize,
    /// Every extension receive buffer for the peer, including prefixes too
    /// short to expose a Session ID. Intended for lifecycle diagnostics/tests.
    peer_receives: usize,
};

pub const webtransport_bidi_stream_type: u64 = 0x41;
const webtransport_uni_stream_type: u64 =
    @intFromEnum(http3.StreamType.webtransport_unidirectional);

/// Bounded receive storage for extension streams sharing the development
/// endpoint's one packet pump. Peer identity is part of the key because every
/// cleartext client starts an independent stream-number space.
pub const ReceiveSet = struct {
    pub const Classification = enum { incomplete, webtransport, other };

    pub const Entry = struct {
        from: net.IpAddress,
        receive: quic.stream_state.RecvState,

        pub fn deinit(self: *Entry) void {
            self.receive.deinit();
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    max_stream_buffer: usize,
    max_streams: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        max_stream_buffer: usize,
        max_streams: usize,
    ) ReceiveSet {
        return .{
            .allocator = allocator,
            .max_stream_buffer = max_stream_buffer,
            .max_streams = max_streams,
        };
    }

    pub fn deinit(self: *ReceiveSet) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn insert(
        self: *ReceiveSet,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!void {
        const stream_id: u62 = std.math.cast(u62, frame.stream_id) orelse
            return error.UnexpectedStream;
        const entry = self.find(from, stream_id) orelse blk: {
            if (self.entries.items.len >= self.max_streams) {
                return error.ExcessiveLoad;
            }
            try self.entries.append(self.allocator, .{
                .from = from,
                .receive = .init(
                    self.allocator,
                    stream_id,
                    self.max_stream_buffer,
                ),
            });
            break :blk &self.entries.items[self.entries.items.len - 1];
        };
        try entry.receive.insert(frame);
    }

    pub fn removeMatching(
        self: *ReceiveSet,
        peer: net.IpAddress,
        match: Match,
    ) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = &self.entries.items[index];
            if (!entry.from.eql(&peer) or
                !mayBelongTo(
                    entry.receive.available(),
                    @intCast(entry.receive.stream_id),
                    match,
                ))
            {
                index += 1;
                continue;
            }
            entry.deinit();
            _ = self.entries.swapRemove(index);
        }
    }

    /// Discard every extension receive buffer for a definitively retired peer.
    pub fn removePeer(self: *ReceiveSet, peer: net.IpAddress) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = &self.entries.items[index];
            if (!entry.from.eql(&peer)) {
                index += 1;
                continue;
            }
            entry.deinit();
            _ = self.entries.swapRemove(index);
        }
    }

    pub fn clear(self: *ReceiveSet) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.clearRetainingCapacity();
    }

    pub fn find(
        self: *ReceiveSet,
        from: net.IpAddress,
        stream_id: u62,
    ) ?*Entry {
        for (self.entries.items) |*entry| {
            if (entry.receive.stream_id == stream_id and
                entry.from.eql(&from)) return entry;
        }
        return null;
    }

    pub fn contains(
        self: *ReceiveSet,
        from: net.IpAddress,
        stream_id: u62,
    ) bool {
        return self.find(from, stream_id) != null;
    }

    pub fn classifyBidirectional(
        self: *ReceiveSet,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!Classification {
        const entry = self.find(from, stream_id) orelse
            return error.UnexpectedStream;
        const available = entry.receive.available();
        const decoded_prefix = quic.varint.decodeSlice(available) catch |err|
            switch (err) {
                error.BufferTooShort => return if (entry.receive.final_size != null)
                    error.InvalidStreamType
                else
                    .incomplete,
                else => return err,
            };
        return if (decoded_prefix.value == webtransport_bidi_stream_type)
            .webtransport
        else
            .other;
    }

    pub fn takeEntry(
        self: *ReceiveSet,
        from: net.IpAddress,
        stream_id: u62,
    ) ?Entry {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.receive.stream_id == stream_id and
                entry.from.eql(&from)) return self.entries.swapRemove(index);
        }
        return null;
    }

    pub fn takeMatchingComplete(
        self: *ReceiveSet,
        peer: net.IpAddress,
        match: Match,
    ) Error!?Stream {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = &self.entries.items[index];
            if (!entry.from.eql(&peer)) {
                index += 1;
                continue;
            }
            const final_size = entry.receive.final_size orelse {
                index += 1;
                continue;
            };
            if (entry.receive.contiguous_end < final_size) {
                index += 1;
                continue;
            }
            const bytes = entry.receive.buffer.items[0..final_size];
            const stream_id: u62 = @intCast(entry.receive.stream_id);
            const stream_direction = direction(stream_id);
            const classified = prefix(
                bytes,
                stream_id,
                stream_direction,
                match,
            ) catch |err| {
                entry.deinit();
                _ = self.entries.swapRemove(index);
                return err;
            };
            const prefix_len = switch (classified) {
                .match => |len| len,
                .other_session => {
                    index += 1;
                    continue;
                },
                .not_webtransport => {
                    entry.deinit();
                    _ = self.entries.swapRemove(index);
                    continue;
                },
            };
            const payload = try self.allocator.dupe(u8, bytes[prefix_len..]);
            const from = entry.from;
            entry.deinit();
            _ = self.entries.swapRemove(index);
            return .{
                .allocator = self.allocator,
                .from = from,
                .stream_id = stream_id,
                .direction = stream_direction,
                .bytes = payload,
            };
        }
        return null;
    }
};

/// Exactly-once offset/FIN state for client-owned development streams.
pub const SendSet = struct {
    pub const Entry = struct {
        session_id: u62,
        send: quic.stream_state.SendState,
        unusable: bool = false,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    max_streams: usize,

    pub fn init(allocator: std.mem.Allocator, max_streams: usize) SendSet {
        return .{ .allocator = allocator, .max_streams = max_streams };
    }

    pub fn deinit(self: *SendSet) void {
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn open(
        self: *SendSet,
        session_id: u62,
        stream_id: u62,
    ) Error!void {
        if (self.find(stream_id) != null) return error.UnexpectedStream;
        if (self.entries.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        try self.entries.append(self.allocator, .{
            .session_id = session_id,
            .send = .init(stream_id),
        });
    }

    pub fn prepareOpen(self: *SendSet, stream_id: u62) Error!void {
        if (self.find(stream_id) != null) return error.UnexpectedStream;
        if (self.entries.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
    }

    pub fn commitPreparedOpen(
        self: *SendSet,
        session_id: u62,
        stream_id: u62,
    ) void {
        self.entries.appendAssumeCapacity(.{
            .session_id = session_id,
            .send = .init(stream_id),
        });
    }

    pub fn removeLast(self: *SendSet, stream_id: u62) void {
        if (self.entries.items.len == 0) return;
        if (self.entries.items[self.entries.items.len - 1].send.stream_id ==
            stream_id) _ = self.entries.pop();
    }

    pub fn find(
        self: *SendSet,
        stream_id: u62,
    ) ?*quic.stream_state.SendState {
        for (self.entries.items) |*entry| {
            if (entry.send.stream_id == stream_id) return &entry.send;
        }
        return null;
    }

    pub fn findEntry(self: *SendSet, stream_id: u62) ?*Entry {
        for (self.entries.items) |*entry| {
            if (entry.send.stream_id == stream_id) return entry;
        }
        return null;
    }

    pub fn removeSession(self: *SendSet, session_id: u62) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (self.entries.items[index].session_id != session_id) {
                index += 1;
                continue;
            }
            _ = self.entries.swapRemove(index);
        }
    }

    pub fn clear(self: *SendSet) void {
        self.entries.clearRetainingCapacity();
    }

    pub fn contains(self: *SendSet, stream_id: u62) bool {
        return self.find(stream_id) != null;
    }

    pub fn sessionId(self: *SendSet, stream_id: u62) ?u62 {
        for (self.entries.items) |entry| {
            if (entry.send.stream_id == stream_id) return entry.session_id;
        }
        return null;
    }
};

/// Per-peer send offsets and monotonically allocated extension-stream IDs.
pub const PeerSendSet = struct {
    pub const Entry = struct {
        to: net.IpAddress,
        session_id: u62,
        send: quic.stream_state.SendState,
        unusable: bool = false,
    };
    const Cursor = struct {
        peer: net.IpAddress,
        next_bidi: u62 = 1,
        next_uni: u62 = 15,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    cursors: std.ArrayList(Cursor) = .empty,
    max_streams: usize,

    pub fn init(allocator: std.mem.Allocator, max_streams: usize) PeerSendSet {
        return .{ .allocator = allocator, .max_streams = max_streams };
    }

    pub fn deinit(self: *PeerSendSet) void {
        self.cursors.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn open(
        self: *PeerSendSet,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
    ) Error!void {
        if (self.find(to, stream_id) != null) return error.UnexpectedStream;
        if (self.entries.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        try self.entries.append(self.allocator, .{
            .to = to,
            .session_id = session_id,
            .send = .init(stream_id),
        });
    }

    pub fn removeLast(
        self: *PeerSendSet,
        to: net.IpAddress,
        stream_id: u62,
    ) void {
        if (self.entries.items.len == 0) return;
        const last = self.entries.items[self.entries.items.len - 1];
        if (last.send.stream_id == stream_id and last.to.eql(&to)) {
            _ = self.entries.pop();
        }
    }

    pub fn find(
        self: *PeerSendSet,
        to: net.IpAddress,
        stream_id: u62,
    ) ?*quic.stream_state.SendState {
        for (self.entries.items) |*entry| {
            if (entry.send.stream_id == stream_id and
                entry.to.eql(&to)) return &entry.send;
        }
        return null;
    }

    pub fn findEntry(
        self: *PeerSendSet,
        to: net.IpAddress,
        stream_id: u62,
    ) ?*Entry {
        for (self.entries.items) |*entry| {
            if (entry.send.stream_id == stream_id and
                entry.to.eql(&to)) return entry;
        }
        return null;
    }

    pub fn removeMatching(
        self: *PeerSendSet,
        peer: net.IpAddress,
        session_id: u62,
    ) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = self.entries.items[index];
            if (!entry.to.eql(&peer) or entry.session_id != session_id) {
                index += 1;
                continue;
            }
            _ = self.entries.swapRemove(index);
        }
    }

    pub fn hasPeerEntries(
        self: *PeerSendSet,
        peer: net.IpAddress,
    ) bool {
        for (self.entries.items) |entry| {
            if (entry.to.eql(&peer)) return true;
        }
        return false;
    }

    /// Forget a peer's ID cursor only after all send entries have gone away.
    pub fn retirePeer(self: *PeerSendSet, peer: net.IpAddress) bool {
        if (self.hasPeerEntries(peer)) return false;
        for (self.cursors.items, 0..) |cursor, index| {
            if (!cursor.peer.eql(&peer)) continue;
            _ = self.cursors.swapRemove(index);
            return true;
        }
        return false;
    }

    pub fn contains(
        self: *PeerSendSet,
        to: net.IpAddress,
        stream_id: u62,
    ) bool {
        return self.find(to, stream_id) != null;
    }

    pub fn sessionId(
        self: *PeerSendSet,
        to: net.IpAddress,
        stream_id: u62,
    ) ?u62 {
        for (self.entries.items) |entry| {
            if (entry.send.stream_id == stream_id and entry.to.eql(&to)) {
                return entry.session_id;
            }
        }
        return null;
    }

    pub fn reserve(
        self: *PeerSendSet,
        to: net.IpAddress,
        session_id: u62,
        stream_direction: Direction,
    ) Error!u62 {
        if (self.entries.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        var cursor: ?*Cursor = null;
        for (self.cursors.items) |*candidate| {
            if (candidate.peer.eql(&to)) {
                cursor = candidate;
                break;
            }
        }
        if (cursor == null) {
            if (self.cursors.items.len >= self.max_streams) {
                return error.ExcessiveLoad;
            }
            try self.cursors.append(self.allocator, .{ .peer = to });
            cursor = &self.cursors.items[self.cursors.items.len - 1];
        }
        const next = switch (stream_direction) {
            .bidirectional => &cursor.?.next_bidi,
            .unidirectional => &cursor.?.next_uni,
        };
        const stream_id = next.*;
        const advanced = std.math.add(u62, stream_id, 4) catch
            return error.StreamCreationError;
        self.entries.appendAssumeCapacity(.{
            .to = to,
            .session_id = session_id,
            .send = .init(stream_id),
        });
        next.* = advanced;
        return stream_id;
    }
};

pub fn direction(stream_id: u62) Direction {
    return if ((stream_id & 0x02) == 0)
        .bidirectional
    else
        .unidirectional;
}

const Prefix = union(enum) {
    match: usize,
    other_session,
    not_webtransport,
};

fn prefix(
    bytes: []const u8,
    stream_id: u62,
    stream_direction: Direction,
    match: Match,
) Error!Prefix {
    if (stream_direction == .bidirectional) {
        if (match.ownsLocalBidirectional(stream_id)) {
            return .{ .match = 0 };
        }
        const locally_initiated = switch (match.local_role) {
            .client => (stream_id & 0x01) == 0,
            .server => (stream_id & 0x01) == 1,
        };
        if (locally_initiated) return .other_session;
    }
    const first = quic.varint.decodeSlice(bytes) catch |err| switch (err) {
        error.BufferTooShort => return error.InvalidStreamType,
        else => return err,
    };
    const expected_type = switch (stream_direction) {
        .bidirectional => webtransport_bidi_stream_type,
        .unidirectional => webtransport_uni_stream_type,
    };
    if (first.value != expected_type) return .not_webtransport;
    const session = quic.varint.decodeSlice(bytes[first.len..]) catch |err|
        switch (err) {
            error.BufferTooShort => return error.InvalidStreamType,
            else => return err,
        };
    if (session.value != match.session_id) return .other_session;
    return .{ .match = @as(usize, first.len) + session.len };
}

pub fn mayBelongTo(
    bytes: []const u8,
    stream_id: u62,
    match: Match,
) bool {
    const stream_direction = direction(stream_id);
    if (stream_direction == .bidirectional and
        match.ownsLocalBidirectional(stream_id)) return true;
    const first = quic.varint.decodeSlice(bytes) catch return false;
    const expected_type = switch (stream_direction) {
        .bidirectional => webtransport_bidi_stream_type,
        .unidirectional => webtransport_uni_stream_type,
    };
    if (first.value != expected_type) return false;
    const session = quic.varint.decodeSlice(bytes[first.len..]) catch
        return false;
    return session.value == match.session_id;
}

test "HTTP/3 development peer cursors retire without live ID reuse" {
    const allocator = std.testing.allocator;
    var sends = PeerSendSet.init(allocator, 2);
    defer sends.deinit();
    const first: net.IpAddress = .{ .ip4 = .loopback(1001) };
    const second: net.IpAddress = .{ .ip4 = .loopback(1002) };
    const third: net.IpAddress = .{ .ip4 = .loopback(1003) };

    try std.testing.expectEqual(
        @as(u62, 1),
        try sends.reserve(first, 0, .bidirectional),
    );
    try std.testing.expectEqual(
        @as(u62, 5),
        try sends.reserve(first, 4, .bidirectional),
    );
    sends.removeMatching(first, 0);
    try std.testing.expect(!sends.retirePeer(first));
    sends.removeMatching(first, 4);
    try std.testing.expectEqual(
        @as(u62, 9),
        try sends.reserve(first, 8, .bidirectional),
    );
    sends.removeMatching(first, 8);
    try std.testing.expect(sends.retirePeer(first));
    try std.testing.expectEqual(@as(usize, 0), sends.cursors.items.len);
    try std.testing.expectEqual(
        @as(u62, 1),
        try sends.reserve(second, 12, .bidirectional),
    );
    sends.removeMatching(second, 12);
    try std.testing.expect(sends.retirePeer(second));
    try std.testing.expectEqual(
        @as(u62, 1),
        try sends.reserve(third, 16, .bidirectional),
    );
}

test "HTTP/3 retired development peer drops incomplete stream prefix" {
    const allocator = std.testing.allocator;
    var streams = ReceiveSet.init(allocator, 32, 2);
    defer streams.deinit();
    const retired: net.IpAddress = .{ .ip4 = .loopback(2001) };
    const live: net.IpAddress = .{ .ip4 = .loopback(2002) };

    try streams.insert(retired, .{
        .stream_id = 4,
        .offset = 0,
        .data = &.{0x40},
        .fin = false,
    });
    try streams.insert(live, .{
        .stream_id = 4,
        .offset = 0,
        .data = &.{0x40},
        .fin = false,
    });
    streams.removeMatching(retired, .{
        .session_id = 0,
        .local_role = .server,
    });
    try std.testing.expect(streams.contains(retired, 4));

    streams.removePeer(retired);
    try std.testing.expect(!streams.contains(retired, 4));
    try std.testing.expect(streams.contains(live, 4));
}
