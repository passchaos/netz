const std = @import("std");
const wire = @import("../internal/wire.zig");
const quic = @import("../quic/mod.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidFrame,
    InvalidSetting,
    InvalidStreamType,
    IntegerOverflow,
    QpackDynamicTableUnsupported,
} || std.mem.Allocator.Error;

pub const FrameType = struct {
    pub const data: u64 = 0x00;
    pub const headers: u64 = 0x01;
    pub const cancel_push: u64 = 0x03;
    pub const settings: u64 = 0x04;
    pub const push_promise: u64 = 0x05;
    pub const goaway: u64 = 0x07;
    pub const max_push_id: u64 = 0x0d;
    pub const webtransport_stream: u64 = 0x41;
};

pub const StreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    webtransport_unidirectional = 0x54,
    _,
};

pub const Frame = struct {
    frame_type: u64,
    payload: []const u8,
    consumed: usize,

    pub fn parse(bytes: []const u8) Error!Frame {
        var cursor = wire.Cursor.init(bytes);
        const frame_type = try quic.varint.decode(&cursor);
        const len = try quic.varint.decode(&cursor);
        const payload_len = std.math.cast(usize, len) orelse return error.IntegerOverflow;
        const payload = try cursor.readSlice(payload_len);
        return .{ .frame_type = frame_type, .payload = payload, .consumed = cursor.pos };
    }

    pub fn write(self: Frame, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try quic.varint.encode(list, allocator, self.frame_type);
        try quic.varint.encode(list, allocator, self.payload.len);
        try list.appendSlice(allocator, self.payload);
    }
};

pub const SettingId = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    enable_connect_protocol = 0x08,
    h3_datagram = 0x33,
    webtransport_max_sessions = 0x2b603742,
    _,
};

pub const Setting = struct {
    id: u64,
    value: u64,
};

pub fn parseSettings(allocator: std.mem.Allocator, payload: []const u8) Error![]Setting {
    var cursor = wire.Cursor.init(payload);
    var settings: std.ArrayList(Setting) = .empty;
    errdefer settings.deinit(allocator);
    while (!cursor.eof()) {
        const id = try quic.varint.decode(&cursor);
        const value = try quic.varint.decode(&cursor);
        try settings.append(allocator, .{ .id = id, .value = value });
    }
    return settings.toOwnedSlice(allocator);
}

pub fn writeSettings(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: []const Setting) !void {
    for (settings) |setting| {
        try quic.varint.encode(list, allocator, setting.id);
        try quic.varint.encode(list, allocator, setting.value);
    }
}

pub const ControlStream = struct {
    stream_type: StreamType,
    frames: []Frame,

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) Error!ControlStream {
        var cursor = wire.Cursor.init(bytes);
        const stream_type: StreamType = @enumFromInt(try quic.varint.decode(&cursor));
        if (stream_type != .control) return error.InvalidStreamType;
        var frames: std.ArrayList(Frame) = .empty;
        errdefer frames.deinit(allocator);
        while (!cursor.eof()) {
            const frame = try Frame.parse(bytes[cursor.pos..]);
            cursor.pos += frame.consumed;
            try frames.append(allocator, frame);
        }
        return .{ .stream_type = stream_type, .frames = try frames.toOwnedSlice(allocator) };
    }

    pub fn deinit(self: *ControlStream, allocator: std.mem.Allocator) void {
        allocator.free(self.frames);
        self.* = undefined;
    }
};

pub const Qpack = struct {
    pub const HeaderField = struct {
        name: []const u8,
        value: []const u8,
    };

    pub fn encodePrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, required_insert_count: u64, base: u64) !void {
        try quic.varint.encode(list, allocator, required_insert_count);
        try quic.varint.encode(list, allocator, base);
    }

    /// Minimal QPACK encoder for deterministic tests and bootstrap clients. It
    /// emits literal field lines without Huffman coding or dynamic references,
    /// which keeps decoding stateless and avoids head-of-line blocking.
    pub fn encodeLiteralBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const HeaderField) !void {
        try encodePrefix(list, allocator, 0, 0);
        for (fields) |field| {
            try list.append(allocator, 0x20); // literal field line with literal name, no indexing
            try encodeString(list, allocator, field.name);
            try encodeString(list, allocator, field.value);
        }
    }

    pub fn decodeLiteralBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
        var cursor = wire.Cursor.init(block);
        const required_insert_count = try quic.varint.decode(&cursor);
        const base = try quic.varint.decode(&cursor);
        if (required_insert_count != 0 or base != 0) return error.QpackDynamicTableUnsupported;

        var fields: std.ArrayList(HeaderField) = .empty;
        errdefer fields.deinit(allocator);
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0xe0) != 0x20) return error.QpackDynamicTableUnsupported;
            const name = try decodeString(&cursor);
            const value = try decodeString(&cursor);
            try fields.append(allocator, .{ .name = name, .value = value });
        }
        return fields.toOwnedSlice(allocator);
    }

    fn encodeString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
        if (value.len > 0x7f) return error.InvalidFrame;
        try list.append(allocator, @intCast(value.len));
        try list.appendSlice(allocator, value);
    }

    fn decodeString(cursor: *wire.Cursor) ![]const u8 {
        const first = try cursor.readByte();
        if ((first & 0x80) != 0) return error.QpackDynamicTableUnsupported;
        return cursor.readSlice(first & 0x7f);
    }
};

pub const Datagram = struct {
    quarter_stream_id: u64,
    payload: []const u8,

    pub fn parse(bytes: []const u8) Error!Datagram {
        var cursor = wire.Cursor.init(bytes);
        const quarter_stream_id = try quic.varint.decode(&cursor);
        return .{ .quarter_stream_id = quarter_stream_id, .payload = bytes[cursor.pos..] };
    }

    pub fn write(self: Datagram, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try quic.varint.encode(list, allocator, self.quarter_stream_id);
        try list.appendSlice(allocator, self.payload);
    }
};

test "HTTP/3 frame settings and qpack literal block" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    const settings = [_]Setting{
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
        .{ .id = @intFromEnum(SettingId.webtransport_max_sessions), .value = 16 },
    };
    try writeSettings(&payload, allocator, &settings);

    var encoded_frame: std.ArrayList(u8) = .empty;
    defer encoded_frame.deinit(allocator);
    try (Frame{ .frame_type = FrameType.settings, .payload = payload.items, .consumed = 0 }).write(&encoded_frame, allocator);
    const frame = try Frame.parse(encoded_frame.items);
    const parsed_settings = try parseSettings(allocator, frame.payload);
    defer allocator.free(parsed_settings);
    try std.testing.expectEqual(@as(u64, 1), parsed_settings[0].value);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const fields = [_]Qpack.HeaderField{ .{ .name = ":method", .value = "GET" }, .{ .name = ":path", .value = "/" } };
    try Qpack.encodeLiteralBlock(&block, allocator, &fields);
    const decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "HTTP/3 datagram" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Datagram{ .quarter_stream_id = 4, .payload = "capsule" }).write(&encoded, allocator);
    const parsed = try Datagram.parse(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.quarter_stream_id);
    try std.testing.expectEqualStrings("capsule", parsed.payload);
}
