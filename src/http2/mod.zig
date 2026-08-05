const std = @import("std");
const wire = @import("../internal/wire.zig");

pub const connection_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidFrameSize,
    InvalidPadding,
    InvalidStreamId,
    InvalidPreface,
    InvalidSetting,
    IntegerOverflow,
} || std.mem.Allocator.Error;

pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

pub const Flags = packed struct(u8) {
    end_stream: bool = false,
    bit1: bool = false,
    end_headers_or_ack: bool = false,
    padded: bool = false,
    bit4: bool = false,
    priority: bool = false,
    bit6: bool = false,
    bit7: bool = false,

    pub fn fromByte(raw: u8) Flags {
        return @bitCast(raw);
    }

    pub fn byte(self: Flags) u8 {
        return @bitCast(self);
    }
};

pub const FrameHeader = struct {
    pub const encoded_len: u64 = 9;

    length: u24,
    frame_type: FrameType,
    flags: u8,
    stream_id: u31,

    pub fn parse(bytes: []const u8) Error!FrameHeader {
        if (bytes.len < encoded_len) return error.BufferTooShort;
        var cursor = wire.Cursor.init(bytes);
        const len = try wire.readU24(&cursor);
        const typ: FrameType = @enumFromInt(try cursor.readByte());
        const flags = try cursor.readByte();
        const raw_stream = try cursor.readInt(u32, .big);
        return .{
            .length = len,
            .frame_type = typ,
            .flags = flags,
            .stream_id = @truncate(raw_stream & 0x7fff_ffff),
        };
    }

    pub fn write(self: FrameHeader, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try wire.appendU24(list, allocator, self.length);
        try list.append(allocator, @intFromEnum(self.frame_type));
        try list.append(allocator, self.flags);
        try wire.appendInt(list, allocator, u32, @as(u32, self.stream_id), .big);
    }
};

pub const Frame = struct {
    header: FrameHeader,
    payload: []const u8,

    pub fn parse(bytes: []const u8) Error!Frame {
        const header = try FrameHeader.parse(bytes);
        const end = FrameHeader.encoded_len + @as(usize, header.length);
        if (bytes.len < end) return error.BufferTooShort;
        return .{ .header = header, .payload = bytes[FrameHeader.encoded_len..end] };
    }

    pub fn consumed(self: Frame) usize {
        return FrameHeader.encoded_len + @as(usize, self.header.length);
    }

    pub fn write(self: Frame, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        var header = self.header;
        header.length = std.math.cast(u24, self.payload.len) orelse return error.InvalidFrameSize;
        try header.write(list, allocator);
        try list.appendSlice(allocator, self.payload);
    }
};

pub const SettingId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    enable_connect_protocol = 0x8,
    no_rfc7540_priorities = 0x9,
    _,
};

pub const Setting = struct {
    id: SettingId,
    value: u32,
};

pub fn parseSettings(allocator: std.mem.Allocator, payload: []const u8) Error![]Setting {
    if (payload.len % 6 != 0) return error.InvalidSetting;
    var cursor = wire.Cursor.init(payload);
    var settings: std.ArrayList(Setting) = .empty;
    errdefer settings.deinit(allocator);
    while (!cursor.eof()) {
        const id: SettingId = @enumFromInt(try cursor.readInt(u16, .big));
        const value = try cursor.readInt(u32, .big);
        try settings.append(allocator, .{ .id = id, .value = value });
    }
    return settings.toOwnedSlice(allocator);
}

pub fn writeSettings(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: []const Setting) !void {
    for (settings) |setting| {
        try wire.appendInt(list, allocator, u16, @intFromEnum(setting.id), .big);
        try wire.appendInt(list, allocator, u32, setting.value, .big);
    }
}

pub const Priority = struct {
    exclusive: bool,
    stream_dependency: u31,
    weight: u8,

    pub fn parse(payload: []const u8) Error!Priority {
        if (payload.len != 5) return error.InvalidFrameSize;
        const dep_raw = std.mem.readInt(u32, payload[0..4], .big);
        return .{
            .exclusive = (dep_raw & 0x8000_0000) != 0,
            .stream_dependency = @truncate(dep_raw & 0x7fff_ffff),
            .weight = payload[4],
        };
    }
};

pub const DataPayload = struct {
    data: []const u8,
    padding_len: u8,

    pub fn parse(frame: Frame) Error!DataPayload {
        const flags = Flags.fromByte(frame.header.flags);
        if (!flags.padded) return .{ .data = frame.payload, .padding_len = 0 };
        if (frame.payload.len == 0) return error.InvalidPadding;
        const pad_len = frame.payload[0];
        if (frame.payload.len < 1 + @as(usize, pad_len)) return error.InvalidPadding;
        return .{
            .data = frame.payload[1 .. frame.payload.len - pad_len],
            .padding_len = pad_len,
        };
    }
};

pub const HeadersPayload = struct {
    header_block: []const u8,
    priority: ?Priority,
    padding_len: u8,

    pub fn parse(frame: Frame) Error!HeadersPayload {
        const flags = Flags.fromByte(frame.header.flags);
        var pos: usize = 0;
        var pad_len: u8 = 0;
        if (flags.padded) {
            if (frame.payload.len == 0) return error.InvalidPadding;
            pad_len = frame.payload[0];
            pos = 1;
        }
        var priority: ?Priority = null;
        if (flags.priority) {
            if (frame.payload.len < pos + 5) return error.InvalidFrameSize;
            priority = try Priority.parse(frame.payload[pos .. pos + 5]);
            pos += 5;
        }
        if (frame.payload.len < pos + @as(usize, pad_len)) return error.InvalidPadding;
        return .{
            .header_block = frame.payload[pos .. frame.payload.len - pad_len],
            .priority = priority,
            .padding_len = pad_len,
        };
    }
};

pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,
};

pub fn validateClientPreface(bytes: []const u8) Error!void {
    if (bytes.len < connection_preface.len) return error.BufferTooShort;
    if (!std.mem.eql(u8, bytes[0..connection_preface.len], connection_preface)) return error.InvalidPreface;
}

pub const Hpack = struct {
    pub const HeaderField = struct {
        name: []const u8,
        value: []const u8,
        never_index: bool = false,
    };

    /// A pragmatic HPACK literal decoder.  It accepts the indexed/literal forms
    /// used in HTTP/2 tests and intentionally does not maintain a dynamic table;
    /// callers that need compression can layer a table implementation on this
    /// representation without changing frame parsing.
    pub fn decodeLiteralBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
        var cursor = wire.Cursor.init(block);
        var fields: std.ArrayList(HeaderField) = .empty;
        errdefer fields.deinit(allocator);
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0x80) != 0) {
                // Indexed field; expose the static index as a pseudo-name so a
                // future dynamic table can resolve it without losing ordering.
                const idx = first & 0x7f;
                const name_buf = try allocator.alloc(u8, 16);
                errdefer allocator.free(name_buf);
                const rendered = try std.fmt.bufPrint(name_buf, ":indexed:{}", .{idx});
                try fields.append(allocator, .{ .name = rendered, .value = "" });
                continue;
            }
            const never_index = (first & 0x10) != 0;
            const name_index = first & 0x0f;
            const name = if (name_index == 0) try decodeString(&cursor) else try staticName(name_index);
            const value = try decodeString(&cursor);
            try fields.append(allocator, .{ .name = name, .value = value, .never_index = never_index });
        }
        return fields.toOwnedSlice(allocator);
    }

    fn decodeString(cursor: *wire.Cursor) ![]const u8 {
        const first = try cursor.readByte();
        const huffman = (first & 0x80) != 0;
        const len = first & 0x7f;
        if (huffman) return error.InvalidEncoding;
        return cursor.readSlice(len);
    }

    fn staticName(index: u8) ![]const u8 {
        return switch (index) {
            1 => ":authority",
            2 => ":method",
            3 => ":method",
            4 => ":path",
            5 => ":path",
            6 => ":scheme",
            7 => ":scheme",
            8 => ":status",
            16 => "accept-encoding",
            31 => "content-type",
            33 => "date",
            38 => "host",
            58 => "user-agent",
            else => error.InvalidEncoding,
        };
    }
};

test "HTTP/2 frame and settings roundtrip" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    const settings = [_]Setting{
        .{ .id = .max_concurrent_streams, .value = 100 },
        .{ .id = .initial_window_size, .value = 65535 },
    };
    try writeSettings(&payload, allocator, &settings);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Frame{ .header = .{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 }, .payload = payload.items }).write(&encoded, allocator);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.settings, frame.header.frame_type);
    const parsed = try parseSettings(allocator, frame.payload);
    defer allocator.free(parsed);
    try std.testing.expectEqual(@as(u32, 100), parsed[0].value);
}

test "HTTP/2 payload helpers" {
    const frame = Frame{
        .header = .{ .length = 6, .frame_type = .data, .flags = (@as(Flags, .{ .padded = true })).byte(), .stream_id = 1 },
        .payload = &.{ 2, 'o', 'k', 0, 0 },
    };
    const data = try DataPayload.parse(frame);
    try std.testing.expectEqualStrings("ok", data.data);
    try validateClientPreface(connection_preface ++ "rest");
}
