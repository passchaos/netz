//! Virtual QUIC-style streams carried by one ordered HTTP/2 CONNECT stream.
const std = @import("std");
const codec = @import("capsule.zig");
const Closed = @import("../../internal/exact_range_set.zig").Set;
pub const Capsule = codec.Capsule;
pub const Error = codec.Error || error{ StreamStateError, FlowControlError, FlowControlBlocked, SessionClosed, TooManyStreams };
pub const Role = enum(u1) { client = 0, server = 1 };
pub const Direction = enum(u1) { bidirectional = 0, unidirectional = 1 };
pub const max_streams: u64 = @as(u64, 1) << 60;
pub const max_data: u64 = std.math.maxInt(u62);

pub const Limits = struct {
    data: u64 = 0,
    bidi: u64 = 0,
    uni: u64 = 0,
    uni_data: u64 = 0,
    bidi_local_data: u64 = 0,
    bidi_remote_data: u64 = 0,

    pub fn validate(self: Limits) Error!void {
        if (self.data > max_data or self.bidi > max_streams or self.uni > max_streams or
            self.uni_data > max_data or self.bidi_local_data > max_data or self.bidi_remote_data > max_data) return error.FlowControlError;
    }
};

pub const Stream = struct {
    id: u62,
    send_limit: u64,
    receive_limit: u64,
    sent: u64 = 0,
    received: u64 = 0,
    consumed: u64 = 0,
    send_started: bool = false,
    receive_started: bool = false,
    send_fin: bool = false,
    receive_fin: bool = false,
    send_reset: ?codec.Reset = null,
    receive_reset: ?codec.Reset = null,
    stop_sent: ?u32 = null,
    stop_received: ?u32 = null,
};

pub const Event = union(enum) {
    stream: codec.Stream,
    reset: codec.Reset,
    stopped: codec.StreamError,
    datagram: []const u8,
    closed: @import("../capsule.zig").Capsule.CloseSession,
    draining,
    progress,
};

pub const State = struct {
    allocator: std.mem.Allocator,
    role: Role,
    send_limit: Limits,
    receive_limit: Limits,
    max_live_streams: usize,
    streams: std.AutoHashMapUnmanaged(u62, Stream) = .empty,
    closed_ids: [4]Closed = .{ .{}, .{}, .{}, .{} },
    local_opened: [2]u64 = .{ 0, 0 },
    peer_opened: [2]u64 = .{ 0, 0 },
    local_retired: [2]u64 = .{ 0, 0 },
    peer_retired: [2]u64 = .{ 0, 0 },
    peer_reported: [2]u64 = .{ 0, 0 },
    sent_data: u64 = 0,
    received_data: u64 = 0,
    consumed_data: u64 = 0,
    local_closed: bool = false,
    peer_closed: bool = false,
    draining: bool = false,

    pub fn init(allocator: std.mem.Allocator, role: Role, receive_limit: Limits, send_limit: Limits, max_live: usize) Error!State {
        try receive_limit.validate();
        try send_limit.validate();
        if (max_live == 0 or @as(u128, receive_limit.bidi) + receive_limit.uni > max_live) return error.TooManyStreams;
        return .{ .allocator = allocator, .role = role, .send_limit = send_limit, .receive_limit = receive_limit, .max_live_streams = max_live };
    }
    pub fn deinit(self: *State) void {
        self.streams.deinit(self.allocator);
        for (&self.closed_ids) |*set| set.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn local(self: *const State, id: u62) bool {
        return id & 1 == @intFromEnum(self.role);
    }
    pub fn direction(id: u62) Direction {
        return if (id & 2 != 0) .unidirectional else .bidirectional;
    }
    fn ensureOpen(self: *const State) Error!void {
        if (self.local_closed or self.peer_closed) return error.SessionClosed;
    }
    fn canSend(self: *const State, id: u62) bool {
        return direction(id) == .bidirectional or self.local(id);
    }
    fn canReceive(self: *const State, id: u62) bool {
        return direction(id) == .bidirectional or !self.local(id);
    }
    fn activeLocal(self: *const State) u64 {
        return self.local_opened[0] - self.local_retired[0] + self.local_opened[1] - self.local_retired[1];
    }
    fn reservedPeer(self: *const State) u128 {
        return @as(u128, self.receive_limit.bidi - self.peer_retired[0]) + self.receive_limit.uni - self.peer_retired[1];
    }
    fn initial(self: *const State, id: u62) Stream {
        const own = self.local(id);
        return .{ .id = id, .send_limit = if (direction(id) == .unidirectional) self.send_limit.uni_data else if (own) self.send_limit.bidi_remote_data else self.send_limit.bidi_local_data, .receive_limit = if (direction(id) == .unidirectional) self.receive_limit.uni_data else if (own) self.receive_limit.bidi_local_data else self.receive_limit.bidi_remote_data };
    }
    fn retired(self: *const State, id: u62) bool {
        return self.closed_ids[@intCast(id & 3)].contains(id >> 2);
    }
    fn get(self: *State, id: u62) Error!*Stream {
        if (self.retired(id)) return error.StreamStateError;
        if (self.streams.getPtr(id)) |stream| return stream;
        const index: usize = @intFromEnum(direction(id));
        const opened = if (self.local(id)) self.local_opened[index] else self.peer_opened[index];
        if ((id >> 2) >= opened) return error.StreamStateError;
        const entry = try self.streams.getOrPut(self.allocator, id);
        entry.value_ptr.* = self.initial(id);
        return entry.value_ptr;
    }

    /// Reserve local IDs without sending. Higher IDs on the wire implicitly
    /// open all lower IDs of that initiator/direction at the peer.
    pub fn openStream(self: *State, dir: Direction) Error!u62 {
        try self.ensureOpen();
        const index: usize = @intFromEnum(dir);
        const allowed = if (dir == .bidirectional) self.send_limit.bidi else self.send_limit.uni;
        if (self.local_opened[index] >= allowed) return error.FlowControlBlocked;
        if (@as(u128, self.activeLocal()) + self.reservedPeer() >= self.max_live_streams) return error.TooManyStreams;
        const ordinal = self.local_opened[index];
        const id: u62 = @intCast((ordinal << 2) | (@as(u64, @intFromEnum(dir)) << 1) | @intFromEnum(self.role));
        try self.streams.put(self.allocator, id, self.initial(id));
        self.local_opened[index] += 1;
        return id;
    }

    pub fn acceptStream(self: *State, dir: Direction) Error!?u62 {
        try self.ensureOpen();
        const index: usize = @intFromEnum(dir);
        while (self.peer_reported[index] < self.peer_opened[index]) {
            const ordinal = self.peer_reported[index];
            const id: u62 = @intCast((ordinal << 2) | (@as(u64, @intFromEnum(dir)) << 1) | (1 - @as(u64, @intFromEnum(self.role))));
            if (self.retired(id)) {
                self.peer_reported[index] += 1;
                continue;
            }
            _ = try self.get(id);
            self.peer_reported[index] += 1;
            return id;
        }
        return null;
    }

    pub fn prepareStream(self: *State, id: u62, data: []const u8, fin: bool) Error!Capsule {
        try self.prepareStreamLength(id, data.len, fin);
        return .{ .stream = .{ .id = id, .data = data, .fin = fin } };
    }

    /// Length-only stream admission for payloads supplied as multiple slices.
    pub fn prepareStreamLength(self: *State, id: u62, data_len: usize, fin: bool) Error!void {
        try self.ensureOpen();
        if (!self.canSend(id)) return error.StreamStateError;
        const stream = try self.get(id);
        if (stream.send_fin or stream.send_reset != null or stream.stop_received != null) return error.StreamStateError;
        if (data_len == 0 and !fin and stream.send_started) return error.StreamStateError;
        if (data_len > stream.send_limit -| stream.sent or data_len > self.send_limit.data -| self.sent_data) return error.FlowControlBlocked;
    }

    /// Commit a stream write whose payload was supplied as separate slices.
    pub fn commitStreamLength(self: *State, id: u62, data_len: usize, fin: bool) Error!void {
        try self.prepareStreamLength(id, data_len, fin);
        const stream = self.streams.getPtr(id).?;
        stream.sent += data_len;
        self.sent_data += data_len;
        stream.send_started = true;
        stream.send_fin = fin;
    }
    pub fn prepareReset(self: *State, id: u62, application_code: u32) Error!Capsule {
        try self.ensureOpen();
        if (!self.canSend(id)) return error.StreamStateError;
        const stream = try self.get(id);
        if (stream.send_fin or stream.send_reset != null) return error.StreamStateError;
        return .{ .reset_stream = .{ .id = id, .code = application_code, .reliable_size = @intCast(stream.sent) } };
    }
    pub fn prepareStop(self: *State, id: u62, application_code: u32) Error!Capsule {
        try self.ensureOpen();
        if (!self.canReceive(id)) return error.StreamStateError;
        const stream = try self.get(id);
        if (stream.receive_fin or stream.receive_reset != null or stream.stop_sent != null) return error.StreamStateError;
        return .{ .stop_sending = .{ .id = id, .code = application_code } };
    }
    pub fn prepareGrantData(self: *State, limit: u64) Error!Capsule {
        try self.ensureOpen();
        if (limit < self.receive_limit.data or limit > max_data) return error.FlowControlError;
        return .{ .max_data = limit };
    }
    pub fn prepareGrantStreams(self: *State, dir: Direction, limit: u64) Error!Capsule {
        try self.ensureOpen();
        const previous = if (dir == .bidirectional) self.receive_limit.bidi else self.receive_limit.uni;
        if (limit < previous or limit > max_streams) return error.FlowControlError;
        const extra = limit - previous;
        if (@as(u128, self.activeLocal()) + self.reservedPeer() + extra > self.max_live_streams) return error.TooManyStreams;
        return if (dir == .bidirectional) .{ .max_streams_bidi = limit } else .{ .max_streams_uni = limit };
    }
    pub fn prepareGrantStreamData(self: *State, id: u62, limit: u64) Error!Capsule {
        try self.ensureOpen();
        if (!self.canReceive(id)) return error.StreamStateError;
        const stream = try self.get(id);
        if (stream.stop_sent != null) return error.StreamStateError;
        if (limit < stream.receive_limit or limit > max_data) return error.FlowControlError;
        return .{ .max_stream_data = .{ .id = id, .limit = @intCast(limit) } };
    }

    /// Commit only after the complete serialized capsule is submitted.
    pub fn commit(self: *State, capsule: Capsule) Error!void {
        try self.ensureOpen();
        switch (capsule) {
            .stream => |value| try self.commitStreamLength(
                value.id,
                value.data.len,
                value.fin,
            ),
            .reset_stream => |value| {
                const prepared = try self.prepareReset(value.id, value.code);
                if (prepared.reset_stream.reliable_size != value.reliable_size) return error.StreamStateError;
                self.streams.getPtr(value.id).?.send_reset = value;
            },
            .stop_sending => |value| {
                _ = try self.prepareStop(value.id, value.code);
                self.streams.getPtr(value.id).?.stop_sent = value.code;
            },
            .max_data => |limit| {
                _ = try self.prepareGrantData(limit);
                self.receive_limit.data = limit;
            },
            .max_streams_bidi => |limit| {
                _ = try self.prepareGrantStreams(.bidirectional, limit);
                self.receive_limit.bidi = limit;
            },
            .max_streams_uni => |limit| {
                _ = try self.prepareGrantStreams(.unidirectional, limit);
                self.receive_limit.uni = limit;
            },
            .max_stream_data => |value| {
                _ = try self.prepareGrantStreamData(value.id, value.limit);
                self.streams.getPtr(value.id).?.receive_limit = value.limit;
            },
            .close_session => self.local_closed = true,
            .drain_session => self.draining = true,
            else => {},
        }
    }

    fn receiveStream(self: *State, value: codec.Stream) Error!Event {
        if (!self.canReceive(value.id) or self.retired(value.id)) return error.StreamStateError;
        const index: usize = @intFromEnum(direction(value.id));
        const peer_count = (value.id >> 2) + 1;
        if (self.local(value.id)) {
            if (peer_count > self.local_opened[index]) return error.StreamStateError;
        } else {
            const allowed = if (index == 0) self.receive_limit.bidi else self.receive_limit.uni;
            if (peer_count > allowed) return error.FlowControlError;
        }
        const previous = self.streams.get(value.id) orelse self.initial(value.id);
        if (previous.receive_fin or previous.receive_reset != null or (value.data.len == 0 and !value.fin and previous.receive_started)) return error.StreamStateError;
        if (value.data.len > previous.receive_limit -| previous.received or value.data.len > self.receive_limit.data -| self.received_data) return error.FlowControlError;
        const entry = try self.streams.getOrPut(self.allocator, value.id);
        entry.value_ptr.* = previous;
        entry.value_ptr.received += value.data.len;
        entry.value_ptr.receive_started = true;
        entry.value_ptr.receive_fin = value.fin;
        self.received_data += value.data.len;
        if (!self.local(value.id)) self.peer_opened[index] = @max(self.peer_opened[index], peer_count);
        return .{ .stream = value };
    }

    pub fn receive(self: *State, capsule: Capsule) Error!Event {
        if (self.peer_closed) return error.SessionClosed;
        if (self.local_closed and capsule != .close_session and capsule != .padding and capsule != .unknown) return error.SessionClosed;
        switch (capsule) {
            .stream => |value| return self.receiveStream(value),
            .reset_stream => |value| {
                if (!self.canReceive(value.id)) return error.StreamStateError;
                const stream = try self.get(value.id);
                if (stream.receive_fin or stream.receive_reset != null or stream.received != value.reliable_size) return error.StreamStateError;
                stream.receive_reset = value;
                return .{ .reset = value };
            },
            .stop_sending => |value| {
                if (!self.canSend(value.id)) return error.StreamStateError;
                const stream = try self.get(value.id);
                if (stream.stop_received != null) return error.StreamStateError;
                stream.stop_received = value.code;
                return .{ .stopped = value };
            },
            .max_data => |limit| {
                if (limit < self.send_limit.data or limit > max_data) return error.FlowControlError;
                self.send_limit.data = limit;
            },
            .max_streams_bidi, .max_streams_uni => |limit| {
                const previous = if (capsule == .max_streams_bidi) &self.send_limit.bidi else &self.send_limit.uni;
                if (limit < previous.* or limit > max_streams) return error.FlowControlError;
                previous.* = limit;
            },
            .max_stream_data => |value| {
                if (!self.canSend(value.id)) return error.StreamStateError;
                const stream = try self.get(value.id);
                if (stream.stop_received != null) return error.StreamStateError;
                if (value.limit < stream.send_limit) return error.FlowControlError;
                stream.send_limit = value.limit;
            },
            .stream_data_blocked => |value| {
                if (!self.canReceive(value.id)) return error.StreamStateError;
                const stream = try self.get(value.id);
                if (stream.receive_fin or stream.receive_reset != null) return error.StreamStateError;
            },
            .streams_blocked_bidi, .streams_blocked_uni => |value| if (value > max_streams) return error.FlowControlError,
            .data_blocked => |value| if (value > max_data) return error.FlowControlError,
            .datagram => |value| return .{ .datagram = value },
            .close_session => |value| {
                self.peer_closed = true;
                return .{ .closed = value };
            },
            .drain_session => {
                self.draining = true;
                return .draining;
            },
            else => {},
        }
        return .progress;
    }

    pub fn consume(self: *State, id: u62, bytes: u64) Error!void {
        const stream = try self.get(id);
        if (bytes > stream.received - stream.consumed) return error.StreamStateError;
        stream.consumed += bytes;
        self.consumed_data += bytes;
    }
    pub fn receiveFin(self: *State) Event {
        self.peer_closed = true;
        return .{ .closed = .{ .code = 0, .reason = "" } };
    }
    pub fn retireStream(self: *State, id: u62) Error!void {
        const stream = self.streams.get(id) orelse return error.StreamStateError;
        const outgoing_done = stream.send_fin or stream.send_reset != null;
        const incoming_done = stream.receive_fin or stream.receive_reset != null;
        if ((self.canSend(id) and !outgoing_done) or (self.canReceive(id) and !incoming_done) or stream.received != stream.consumed) return error.StreamStateError;
        const closed = &self.closed_ids[@intCast(id & 3)];
        try closed.prepareInsertValue(self.allocator, id >> 2);
        closed.insertAssumeCapacity(id >> 2);
        _ = self.streams.remove(id);
        const index: usize = @intFromEnum(direction(id));
        if (self.local(id)) self.local_retired[index] += 1 else self.peer_retired[index] += 1;
    }
};

test {
    _ = @import("state_tests.zig");
}
