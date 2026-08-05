const std = @import("std");
const wire = @import("../internal/wire.zig");
const quic = @import("../quic/mod.zig");
const http3 = @import("../http3/mod.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidSessionId,
    InvalidCapsule,
    InvalidStreamType,
    IntegerOverflow,
} || std.mem.Allocator.Error;

pub const CapsuleType = struct {
    pub const datagram: u64 = 0x00;
    pub const close_webtransport_session: u64 = 0x2843;
    pub const drain_webtransport_session: u64 = 0x78ae;
};

pub const Setting = struct {
    pub const enable_webtransport: http3.Setting = .{ .id = @intFromEnum(http3.SettingId.webtransport_max_sessions), .value = 1 };
    pub const enable_datagram: http3.Setting = .{ .id = @intFromEnum(http3.SettingId.h3_datagram), .value = 1 };
    pub const enable_connect_protocol: http3.Setting = .{ .id = @intFromEnum(http3.SettingId.enable_connect_protocol), .value = 1 };
};

pub const SessionId = struct {
    value: u62,

    pub fn init(value: u62) SessionId {
        return .{ .value = value };
    }

    pub fn isClientInitiatedBidirectional(self: SessionId) bool {
        const stream = quic.StreamId.init(self.value);
        return stream.initiator() == .client and stream.direction() == .bidirectional;
    }

    pub fn quarterStreamId(self: SessionId) u60 {
        return @truncate(self.value >> 2);
    }
};

pub const Capsule = union(enum) {
    datagram: []const u8,
    close_session: CloseSession,
    drain_session: void,
    unknown: struct { capsule_type: u64, payload: []const u8 },

    pub const CloseSession = struct {
        code: u32,
        reason: []const u8,
    };

    pub fn parse(bytes: []const u8) Error!struct { capsule: Capsule, consumed: usize } {
        var cursor = wire.Cursor.init(bytes);
        const capsule_type = try quic.varint.decode(&cursor);
        const len = try quic.varint.decode(&cursor);
        const payload_len = std.math.cast(usize, len) orelse return error.IntegerOverflow;
        const payload = try cursor.readSlice(payload_len);
        const capsule: Capsule = switch (capsule_type) {
            CapsuleType.datagram => .{ .datagram = payload },
            CapsuleType.close_webtransport_session => blk: {
                if (payload.len < 4) return error.InvalidCapsule;
                const code = std.mem.readInt(u32, payload[0..4], .big);
                break :blk .{ .close_session = .{ .code = code, .reason = payload[4..] } };
            },
            CapsuleType.drain_webtransport_session => .{ .drain_session = {} },
            else => .{ .unknown = .{ .capsule_type = capsule_type, .payload = payload } },
        };
        return .{ .capsule = capsule, .consumed = cursor.pos };
    }

    pub fn write(self: Capsule, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        switch (self) {
            .datagram => |payload| {
                try quic.varint.encode(list, allocator, CapsuleType.datagram);
                try quic.varint.encode(list, allocator, payload.len);
                try list.appendSlice(allocator, payload);
            },
            .close_session => |close| {
                try quic.varint.encode(list, allocator, CapsuleType.close_webtransport_session);
                try quic.varint.encode(list, allocator, 4 + close.reason.len);
                try wire.appendInt(list, allocator, u32, close.code, .big);
                try list.appendSlice(allocator, close.reason);
            },
            .drain_session => {
                try quic.varint.encode(list, allocator, CapsuleType.drain_webtransport_session);
                try quic.varint.encode(list, allocator, 0);
            },
            .unknown => |unknown| {
                try quic.varint.encode(list, allocator, unknown.capsule_type);
                try quic.varint.encode(list, allocator, unknown.payload.len);
                try list.appendSlice(allocator, unknown.payload);
            },
        }
    }
};

pub const UnidirectionalStreamHeader = struct {
    stream_type: http3.StreamType,
    session_id: ?SessionId,
    consumed: usize,

    pub fn parse(bytes: []const u8) Error!UnidirectionalStreamHeader {
        var cursor = wire.Cursor.init(bytes);
        const stream_type: http3.StreamType = @enumFromInt(try quic.varint.decode(&cursor));
        const session_id = if (stream_type == .webtransport_unidirectional) SessionId.init(@intCast(try quic.varint.decode(&cursor))) else null;
        return .{ .stream_type = stream_type, .session_id = session_id, .consumed = cursor.pos };
    }

    pub fn writeWebTransport(list: *std.ArrayList(u8), allocator: std.mem.Allocator, session_id: SessionId) !void {
        try quic.varint.encode(list, allocator, @intFromEnum(http3.StreamType.webtransport_unidirectional));
        try quic.varint.encode(list, allocator, session_id.value);
    }
};

pub const Datagram = struct {
    session_id: SessionId,
    payload: []const u8,

    pub fn parse(bytes: []const u8) Error!Datagram {
        var cursor = wire.Cursor.init(bytes);
        const quarter_stream_id = try quic.varint.decode(&cursor);
        return .{ .session_id = SessionId.init(@intCast(quarter_stream_id << 2)), .payload = bytes[cursor.pos..] };
    }

    pub fn write(self: Datagram, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try quic.varint.encode(list, allocator, self.session_id.quarterStreamId());
        try list.appendSlice(allocator, self.payload);
    }
};

pub fn connectHeaders(authority: []const u8, path: []const u8, origin: []const u8) [5]http3.Qpack.HeaderField {
    return .{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = authority },
        .{ .name = ":path", .value = if (path.len == 0) origin else path },
    };
}

test "WebTransport capsule and stream headers" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Capsule{ .close_session = .{ .code = 42, .reason = "done" } }).write(&encoded, allocator);
    const parsed = try Capsule.parse(encoded.items);
    try std.testing.expectEqual(@as(u32, 42), parsed.capsule.close_session.code);
    try std.testing.expectEqualStrings("done", parsed.capsule.close_session.reason);

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    try UnidirectionalStreamHeader.writeWebTransport(&stream, allocator, SessionId.init(0));
    const header = try UnidirectionalStreamHeader.parse(stream.items);
    try std.testing.expectEqual(http3.StreamType.webtransport_unidirectional, header.stream_type);
    try std.testing.expect(header.session_id.?.isClientInitiatedBidirectional());
}

test "WebTransport datagram maps quarter stream id" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Datagram{ .session_id = .init(8), .payload = "dgram" }).write(&encoded, allocator);
    const parsed = try Datagram.parse(encoded.items);
    try std.testing.expectEqual(@as(u62, 8), parsed.session_id.value);
    try std.testing.expectEqualStrings("dgram", parsed.payload);
}
