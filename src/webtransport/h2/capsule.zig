//! HTTP/2 virtual-stream capsules, distinct from native HTTP/3 association.
const std = @import("std");
const quic = @import("../../quic/mod.zig");
const wire = @import("../../internal/wire.zig");
const wt = @import("../mod.zig");

pub const Error = wt.Error;
pub const CapsuleType = struct {
    pub const padding: u64 = 0x190b4d38;
    pub const reset_stream: u64 = 0x190b4d39;
    pub const stop_sending: u64 = 0x190b4d3a;
    pub const stream_fin: u64 = 0x190b4d3b;
    pub const stream: u64 = 0x190b4d3c;
    pub const max_stream_data: u64 = 0x190b4d3e;
    pub const stream_data_blocked: u64 = 0x190b4d42;
};

pub const Stream = struct { id: u62, data: []const u8, fin: bool = false };
pub const Reset = struct { id: u62, code: u32, reliable_size: u62 };
pub const StreamError = struct { id: u62, code: u32 };
pub const StreamLimit = struct { id: u62, limit: u62 };

/// Maximum encoded stream capsule prefix: type, payload length, and stream id
/// varints (8 bytes each).
pub const max_stream_header_len = 24;

/// Encode the capsule envelope and stream id for a payload supplied as
/// separate slices. The caller writes the payload slices after this header.
pub fn writeStreamHeaderInto(
    storage: *[max_stream_header_len]u8,
    id: u62,
    data_len: usize,
    fin: bool,
) Error![]const u8 {
    const kind: u64 = if (fin) CapsuleType.stream_fin else CapsuleType.stream;
    const id_len = try quic.varint.length(id);
    const payload_len = std.math.add(usize, id_len, data_len) catch
        return error.IntegerOverflow;
    if (payload_len > quic.varint.max_value) return error.IntegerOverflow;
    var offset: usize = 0;
    try append(storage, &offset, kind);
    try append(storage, &offset, payload_len);
    try append(storage, &offset, id);
    return storage[0..offset];
}

pub const Capsule = union(enum) {
    padding: []const u8,
    stream: Stream,
    reset_stream: Reset,
    stop_sending: StreamError,
    max_stream_data: StreamLimit,
    stream_data_blocked: StreamLimit,
    datagram: []const u8,
    close_session: wt.Capsule.CloseSession,
    drain_session,
    max_data: u64,
    max_streams_bidi: u64,
    max_streams_uni: u64,
    data_blocked: u64,
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    unknown: struct { capsule_type: u64, payload: []const u8 },

    fn common(self: Capsule) ?wt.Capsule {
        return switch (self) {
            .datagram => |v| .{ .datagram = v },
            .close_session => |v| .{ .close_session = v },
            .drain_session => .{ .drain_session = {} },
            .max_data => |v| .{ .max_data = v },
            .max_streams_bidi => |v| .{ .max_streams_bidi = v },
            .max_streams_uni => |v| .{ .max_streams_uni = v },
            .data_blocked => |v| .{ .data_blocked = v },
            .streams_blocked_bidi => |v| .{ .streams_blocked_bidi = v },
            .streams_blocked_uni => |v| .{ .streams_blocked_uni = v },
            .unknown => |v| .{ .unknown = .{ .capsule_type = v.capsule_type, .payload = v.payload } },
            else => null,
        };
    }

    const Layout = struct { kind: u64, payload: usize, total: usize };
    fn layout(self: Capsule) Error!Layout {
        if (self.common()) |value| {
            if (self == .unknown and known(self.unknown.capsule_type)) return error.InvalidCapsule;
            return .{ .kind = 0, .payload = 0, .total = try value.encodedLen() };
        }
        const kind: u64, const payload: usize = switch (self) {
            .padding => |bytes| blk: {
                for (bytes) |byte| if (byte != 0) return error.InvalidCapsule;
                break :blk .{ CapsuleType.padding, bytes.len };
            },
            .stream => |v| .{ if (v.fin) CapsuleType.stream_fin else CapsuleType.stream, std.math.add(usize, try quic.varint.length(v.id), v.data.len) catch return error.IntegerOverflow },
            .reset_stream => |v| .{ CapsuleType.reset_stream, @as(usize, try quic.varint.length(v.id)) + try quic.varint.length(v.code) + try quic.varint.length(v.reliable_size) },
            .stop_sending => |v| .{ CapsuleType.stop_sending, @as(usize, try quic.varint.length(v.id)) + try quic.varint.length(v.code) },
            .max_stream_data => |v| .{ CapsuleType.max_stream_data, @as(usize, try quic.varint.length(v.id)) + try quic.varint.length(v.limit) },
            .stream_data_blocked => |v| .{ CapsuleType.stream_data_blocked, @as(usize, try quic.varint.length(v.id)) + try quic.varint.length(v.limit) },
            else => unreachable,
        };
        const prefix = @as(usize, try quic.varint.length(kind)) + try quic.varint.length(payload);
        return .{ .kind = kind, .payload = payload, .total = std.math.add(usize, prefix, payload) catch return error.IntegerOverflow };
    }

    pub fn encodedLen(self: Capsule) Error!usize {
        return (try self.layout()).total;
    }

    /// Validate the whole capsule before changing any output byte.
    pub fn writeInto(self: Capsule, output: []u8) Error![]u8 {
        const info = try self.layout();
        if (output.len < info.total) return error.BufferTooShort;
        if (self.common()) |value| return value.writeInto(output);
        var offset: usize = 0;
        try append(output, &offset, info.kind);
        try append(output, &offset, info.payload);
        switch (self) {
            .padding => |bytes| {
                @memcpy(output[offset..][0..bytes.len], bytes);
                offset += bytes.len;
            },
            .stream => |v| {
                try append(output, &offset, v.id);
                @memcpy(output[offset..][0..v.data.len], v.data);
                offset += v.data.len;
            },
            .reset_stream => |v| {
                try append(output, &offset, v.id);
                try append(output, &offset, v.code);
                try append(output, &offset, v.reliable_size);
            },
            .stop_sending => |v| {
                try append(output, &offset, v.id);
                try append(output, &offset, v.code);
            },
            .max_stream_data, .stream_data_blocked => |v| {
                try append(output, &offset, v.id);
                try append(output, &offset, v.limit);
            },
            else => unreachable,
        }
        std.debug.assert(offset == info.total);
        return output[0..offset];
    }

    /// Admission is transactional: rejected values and OOM retain the prefix.
    pub fn write(self: Capsule, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        const len = try self.encodedLen();
        try list.ensureUnusedCapacity(allocator, len);
        _ = try self.writeInto(list.unusedCapacitySlice()[0..len]);
        list.items.len += len;
    }

    pub fn parse(bytes: []const u8) Error!struct { capsule: Capsule, consumed: usize } {
        var envelope = wire.Cursor.init(bytes);
        const kind = try quic.varint.decode(&envelope);
        const len = std.math.cast(usize, try quic.varint.decode(&envelope)) orelse return error.IntegerOverflow;
        const payload = try envelope.readSlice(len);
        const capsule = try parsePayload(kind, payload);
        return .{ .capsule = capsule, .consumed = envelope.pos };
    }
};

pub fn known(kind: u64) bool {
    return switch (kind) {
        CapsuleType.padding, CapsuleType.reset_stream, CapsuleType.stop_sending, CapsuleType.stream, CapsuleType.stream_fin, CapsuleType.max_stream_data, CapsuleType.stream_data_blocked, wt.CapsuleType.datagram, wt.CapsuleType.close_webtransport_session, wt.CapsuleType.drain_webtransport_session, wt.CapsuleType.max_data, wt.CapsuleType.max_streams_bidi, wt.CapsuleType.max_streams_uni, wt.CapsuleType.data_blocked, wt.CapsuleType.streams_blocked_bidi, wt.CapsuleType.streams_blocked_uni => true,
        else => false,
    };
}

pub fn parsePayload(kind: u64, payload: []const u8) Error!Capsule {
    var cursor = wire.Cursor.init(payload);
    const capsule: Capsule = switch (kind) {
        CapsuleType.padding => return .{ .padding = payload },
        CapsuleType.stream, CapsuleType.stream_fin => blk: {
            const id = try readValue(&cursor);
            break :blk .{ .stream = .{ .id = id, .data = payload[cursor.pos..], .fin = kind == CapsuleType.stream_fin } };
        },
        CapsuleType.reset_stream => .{ .reset_stream = .{ .id = try readValue(&cursor), .code = try readCode(&cursor), .reliable_size = try readValue(&cursor) } },
        CapsuleType.stop_sending => .{ .stop_sending = .{ .id = try readValue(&cursor), .code = try readCode(&cursor) } },
        CapsuleType.max_stream_data => .{ .max_stream_data = .{ .id = try readValue(&cursor), .limit = try readValue(&cursor) } },
        CapsuleType.stream_data_blocked => .{ .stream_data_blocked = .{ .id = try readValue(&cursor), .limit = try readValue(&cursor) } },
        wt.CapsuleType.datagram => return .{ .datagram = payload },
        wt.CapsuleType.close_webtransport_session => {
            if (payload.len < 4 or payload.len > 4 + wt.max_close_reason or !std.unicode.utf8ValidateSlice(payload[4..])) return error.InvalidCapsule;
            return .{ .close_session = .{ .code = std.mem.readInt(u32, payload[0..4], .big), .reason = payload[4..] } };
        },
        wt.CapsuleType.drain_webtransport_session => {
            if (payload.len != 0) return error.InvalidCapsule;
            return .drain_session;
        },
        wt.CapsuleType.max_data => .{ .max_data = try readValue(&cursor) },
        wt.CapsuleType.max_streams_bidi => .{ .max_streams_bidi = try readValue(&cursor) },
        wt.CapsuleType.max_streams_uni => .{ .max_streams_uni = try readValue(&cursor) },
        wt.CapsuleType.data_blocked => .{ .data_blocked = try readValue(&cursor) },
        wt.CapsuleType.streams_blocked_bidi => .{ .streams_blocked_bidi = try readValue(&cursor) },
        wt.CapsuleType.streams_blocked_uni => .{ .streams_blocked_uni = try readValue(&cursor) },
        else => return .{ .unknown = .{ .capsule_type = kind, .payload = payload } },
    };
    if (capsule != .stream and cursor.pos != payload.len) return error.InvalidCapsule;
    return capsule;
}

fn readValue(cursor: *wire.Cursor) Error!u62 {
    return @intCast(quic.varint.decode(cursor) catch return error.InvalidCapsule);
}
fn readCode(cursor: *wire.Cursor) Error!u32 {
    const decoded = try readValue(cursor);
    return std.math.cast(u32, decoded) orelse error.InvalidCapsule;
}
fn append(output: []u8, offset: *usize, number: u64) Error!void {
    offset.* += (try quic.varint.encodeInto(output[offset.*..], number)).len;
}

test {
    _ = @import("capsule_tests.zig");
}
