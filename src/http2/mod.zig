const std = @import("std");
const wire = @import("../internal/wire.zig");

pub const runtime = @import("runtime.zig");
pub const connection_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidFrameSize,
    InvalidPadding,
    InvalidStreamId,
    InvalidPreface,
    InvalidSetting,
    IntegerOverflow,
    HpackDynamicTableUnsupported,
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

pub const ResetStreamPayload = struct {
    stream_id: u31,
    error_code: ErrorCode,

    pub fn parse(frame: Frame) Error!ResetStreamPayload {
        if (frame.header.frame_type != .rst_stream) return error.InvalidFrameSize;
        if (frame.header.stream_id == 0) return error.InvalidStreamId;
        if (frame.payload.len != 4) return error.InvalidFrameSize;
        return .{
            .stream_id = frame.header.stream_id,
            .error_code = @enumFromInt(std.mem.readInt(u32, frame.payload[0..4], .big)),
        };
    }

    pub fn write(list: *std.ArrayList(u8), allocator: std.mem.Allocator, stream_id: u31, error_code: ErrorCode) Error!void {
        if (stream_id == 0) return error.InvalidStreamId;
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, @intFromEnum(error_code), .big);
        try (Frame{
            .header = .{ .length = 4, .frame_type = .rst_stream, .flags = 0, .stream_id = stream_id },
            .payload = &payload,
        }).write(list, allocator);
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

pub const PingPayload = struct {
    data: [8]u8,

    pub fn parse(frame: Frame) Error!PingPayload {
        if (frame.header.frame_type != .ping or frame.header.stream_id != 0 or frame.payload.len != 8) {
            return error.InvalidFrameSize;
        }
        return .{ .data = frame.payload[0..8].* };
    }

    pub fn write(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: [8]u8, ack: bool) Error!void {
        try (Frame{
            .header = .{ .length = 0, .frame_type = .ping, .flags = if (ack) 0x1 else 0, .stream_id = 0 },
            .payload = &data,
        }).write(list, allocator);
    }
};

pub const GoAwayPayload = struct {
    last_stream_id: u31,
    error_code: ErrorCode,
    debug_data: []const u8,

    pub fn parse(frame: Frame) Error!GoAwayPayload {
        if (frame.header.frame_type != .goaway or frame.header.stream_id != 0 or frame.payload.len < 8) {
            return error.InvalidFrameSize;
        }
        const raw_last = std.mem.readInt(u32, frame.payload[0..4], .big);
        const code: ErrorCode = @enumFromInt(std.mem.readInt(u32, frame.payload[4..8], .big));
        return .{
            .last_stream_id = @truncate(raw_last & 0x7fff_ffff),
            .error_code = code,
            .debug_data = frame.payload[8..],
        };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        last_stream_id: u31,
        error_code: ErrorCode,
        debug_data: []const u8,
    ) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        try wire.appendInt(&payload, allocator, u32, @as(u32, last_stream_id), .big);
        try wire.appendInt(&payload, allocator, u32, @intFromEnum(error_code), .big);
        try payload.appendSlice(allocator, debug_data);
        try (Frame{
            .header = .{ .length = 0, .frame_type = .goaway, .flags = 0, .stream_id = 0 },
            .payload = payload.items,
        }).write(list, allocator);
    }
};

pub const WindowUpdatePayload = struct {
    stream_id: u31,
    increment: u31,

    pub fn parse(frame: Frame) Error!WindowUpdatePayload {
        if (frame.header.frame_type != .window_update or frame.payload.len != 4) return error.InvalidFrameSize;
        const raw = std.mem.readInt(u32, frame.payload[0..4], .big);
        const increment: u31 = @truncate(raw & 0x7fff_ffff);
        if (increment == 0) return error.InvalidFrameSize;
        return .{ .stream_id = frame.header.stream_id, .increment = increment };
    }

    pub fn write(list: *std.ArrayList(u8), allocator: std.mem.Allocator, stream_id: u31, increment: u31) Error!void {
        if (increment == 0) return error.InvalidFrameSize;
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, @as(u32, increment), .big);
        try (Frame{
            .header = .{ .length = 0, .frame_type = .window_update, .flags = 0, .stream_id = stream_id },
            .payload = &payload,
        }).write(list, allocator);
    }
};

pub fn validateClientPreface(bytes: []const u8) Error!void {
    if (bytes.len < connection_preface.len) return error.BufferTooShort;
    if (!std.mem.eql(u8, bytes[0..connection_preface.len], connection_preface)) return error.InvalidPreface;
}

pub const Hpack = struct {
    pub const StaticEntry = struct {
        name: []const u8,
        value: []const u8,
    };

    /// HPACK's static table is one-indexed on the wire (RFC 7541 Appendix A).
    /// The array remains zero-indexed internally; helpers below translate the
    /// public/wire index to keep invalid index 0 easy to reject.
    pub const static_table = [_]StaticEntry{
        .{ .name = ":authority", .value = "" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "204" },
        .{ .name = ":status", .value = "206" },
        .{ .name = ":status", .value = "304" },
        .{ .name = ":status", .value = "400" },
        .{ .name = ":status", .value = "404" },
        .{ .name = ":status", .value = "500" },
        .{ .name = "accept-charset", .value = "" },
        .{ .name = "accept-encoding", .value = "gzip, deflate" },
        .{ .name = "accept-language", .value = "" },
        .{ .name = "accept-ranges", .value = "" },
        .{ .name = "accept", .value = "" },
        .{ .name = "access-control-allow-origin", .value = "" },
        .{ .name = "age", .value = "" },
        .{ .name = "allow", .value = "" },
        .{ .name = "authorization", .value = "" },
        .{ .name = "cache-control", .value = "" },
        .{ .name = "content-disposition", .value = "" },
        .{ .name = "content-encoding", .value = "" },
        .{ .name = "content-language", .value = "" },
        .{ .name = "content-length", .value = "" },
        .{ .name = "content-location", .value = "" },
        .{ .name = "content-range", .value = "" },
        .{ .name = "content-type", .value = "" },
        .{ .name = "cookie", .value = "" },
        .{ .name = "date", .value = "" },
        .{ .name = "etag", .value = "" },
        .{ .name = "expect", .value = "" },
        .{ .name = "expires", .value = "" },
        .{ .name = "from", .value = "" },
        .{ .name = "host", .value = "" },
        .{ .name = "if-match", .value = "" },
        .{ .name = "if-modified-since", .value = "" },
        .{ .name = "if-none-match", .value = "" },
        .{ .name = "if-range", .value = "" },
        .{ .name = "if-unmodified-since", .value = "" },
        .{ .name = "last-modified", .value = "" },
        .{ .name = "link", .value = "" },
        .{ .name = "location", .value = "" },
        .{ .name = "max-forwards", .value = "" },
        .{ .name = "proxy-authenticate", .value = "" },
        .{ .name = "proxy-authorization", .value = "" },
        .{ .name = "range", .value = "" },
        .{ .name = "referer", .value = "" },
        .{ .name = "refresh", .value = "" },
        .{ .name = "retry-after", .value = "" },
        .{ .name = "server", .value = "" },
        .{ .name = "set-cookie", .value = "" },
        .{ .name = "strict-transport-security", .value = "" },
        .{ .name = "transfer-encoding", .value = "" },
        .{ .name = "user-agent", .value = "" },
        .{ .name = "vary", .value = "" },
        .{ .name = "via", .value = "" },
        .{ .name = "www-authenticate", .value = "" },
    };

    pub const HeaderField = struct {
        name: []const u8,
        value: []const u8,
        never_index: bool = false,
    };

    pub fn findStaticIndex(name: []const u8, value: []const u8) ?u64 {
        for (static_table, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return @intCast(i + 1);
            }
        }
        return null;
    }

    pub fn findStaticNameIndex(name: []const u8) ?u64 {
        for (static_table, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) return @intCast(i + 1);
        }
        return null;
    }

    pub fn encodeLiteralBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const HeaderField) !void {
        for (fields) |field| {
            if (!field.never_index) {
                if (findStaticIndex(field.name, field.value)) |index| {
                    try encodeInteger(list, allocator, 7, 0x80, index);
                    continue;
                }
            }

            const representation: u8 = if (field.never_index) 0x10 else 0x00;
            if (findStaticNameIndex(field.name)) |name_index| {
                try encodeInteger(list, allocator, 4, representation, name_index);
            } else {
                try encodeInteger(list, allocator, 4, representation, 0);
                try encodeString(list, allocator, field.name);
            }
            try encodeString(list, allocator, field.value);
        }
    }

    /// A pragmatic HPACK codec. It resolves RFC 7541 static-table references and
    /// literal fields, but intentionally refuses dynamic-table references and
    /// Huffman strings so callers never observe partially-decoded state.
    pub fn decodeLiteralBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
        var cursor = wire.Cursor.init(block);
        var fields: std.ArrayList(HeaderField) = .empty;
        errdefer fields.deinit(allocator);
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0x80) != 0) {
                const entry = try staticEntry(try decodeInteger(first, &cursor, 7));
                try fields.append(allocator, .{ .name = entry.name, .value = entry.value });
                continue;
            }

            const name_index = if ((first & 0x40) != 0)
                try decodeInteger(first, &cursor, 6)
            else if ((first & 0x20) != 0)
                return error.HpackDynamicTableUnsupported
            else
                try decodeInteger(first, &cursor, 4);
            const never_index = (first & 0x10) != 0;
            const name = if (name_index == 0) try decodeString(&cursor) else (try staticEntry(name_index)).name;
            const value = try decodeString(&cursor);
            try fields.append(allocator, .{ .name = name, .value = value, .never_index = never_index });
        }
        return fields.toOwnedSlice(allocator);
    }

    fn encodeInteger(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        comptime prefix_bits: u4,
        high_bits: u8,
        value: u64,
    ) !void {
        const prefix_max = (@as(u16, 1) << prefix_bits) - 1;
        if (value < prefix_max) {
            try list.append(allocator, high_bits | @as(u8, @intCast(value)));
            return;
        }

        try list.append(allocator, high_bits | @as(u8, @intCast(prefix_max)));
        var remaining = value - prefix_max;
        while (remaining >= 128) {
            try list.append(allocator, @as(u8, @intCast(remaining & 0x7f)) | 0x80);
            remaining >>= 7;
        }
        try list.append(allocator, @intCast(remaining));
    }

    fn decodeInteger(first: u8, cursor: *wire.Cursor, comptime prefix_bits: u4) Error!u64 {
        const prefix_max: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
        var value: u64 = first & prefix_max;
        if (value < prefix_max) return value;

        var shift: u6 = 0;
        while (true) {
            const byte = try cursor.readByte();
            value = std.math.add(u64, value, @as(u64, byte & 0x7f) << shift) catch return error.IntegerOverflow;
            if ((byte & 0x80) == 0) return value;
            if (shift >= 56) return error.IntegerOverflow;
            shift += 7;
        }
    }

    fn encodeString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
        try encodeInteger(list, allocator, 7, 0x00, value.len);
        try list.appendSlice(allocator, value);
    }

    fn decodeString(cursor: *wire.Cursor) ![]const u8 {
        const first = try cursor.readByte();
        const huffman = (first & 0x80) != 0;
        if (huffman) return error.InvalidEncoding;
        const len = std.math.cast(usize, try decodeInteger(first, cursor, 7)) orelse return error.IntegerOverflow;
        return cursor.readSlice(len);
    }

    fn staticEntry(index: u64) Error!StaticEntry {
        if (index == 0) return error.InvalidEncoding;
        if (index > static_table.len) return error.HpackDynamicTableUnsupported;
        return static_table[@intCast(index - 1)];
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

test "HTTP/2 ping and goaway payload helpers" {
    const allocator = std.testing.allocator;

    var ping_bytes: std.ArrayList(u8) = .empty;
    defer ping_bytes.deinit(allocator);
    const ping_data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    try PingPayload.write(&ping_bytes, allocator, ping_data, true);
    const ping_frame = try Frame.parse(ping_bytes.items);
    try std.testing.expectEqual(FrameType.ping, ping_frame.header.frame_type);
    try std.testing.expectEqual(@as(u8, 1), ping_frame.header.flags);
    const ping = try PingPayload.parse(ping_frame);
    try std.testing.expectEqualSlices(u8, &ping_data, &ping.data);

    var goaway_bytes: std.ArrayList(u8) = .empty;
    defer goaway_bytes.deinit(allocator);
    try GoAwayPayload.write(&goaway_bytes, allocator, 7, .no_error, "bye");
    const goaway_frame = try Frame.parse(goaway_bytes.items);
    const goaway = try GoAwayPayload.parse(goaway_frame);
    try std.testing.expectEqual(@as(u31, 7), goaway.last_stream_id);
    try std.testing.expectEqual(ErrorCode.no_error, goaway.error_code);
    try std.testing.expectEqualStrings("bye", goaway.debug_data);
}

test "HTTP/2 window update payload helper" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try WindowUpdatePayload.write(&encoded, allocator, 3, 1024);
    const frame = try Frame.parse(encoded.items);
    const update = try WindowUpdatePayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 3), update.stream_id);
    try std.testing.expectEqual(@as(u31, 1024), update.increment);
    try std.testing.expectError(error.InvalidFrameSize, WindowUpdatePayload.write(&encoded, allocator, 0, 0));
}

test "HTTP/2 RST_STREAM payload helper" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try ResetStreamPayload.write(&encoded, allocator, 3, .cancel);
    const frame = try Frame.parse(encoded.items);
    const reset = try ResetStreamPayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 3), reset.stream_id);
    try std.testing.expectEqual(ErrorCode.cancel, reset.error_code);
    try std.testing.expectError(error.InvalidStreamId, ResetStreamPayload.write(&encoded, allocator, 0, .cancel));
}

test "HTTP/2 HPACK static table decode" {
    const allocator = std.testing.allocator;
    // RFC 7541 Appendix C.3: :method GET, :scheme http, :path /,
    // :authority www.example.com.  The literal authority field is accepted but
    // not inserted because this bootstrap decoder has no dynamic table.
    const block = "\x82\x86\x84\x41\x0fwww.example.com";
    const fields = try Hpack.decodeLiteralBlock(allocator, block);
    defer allocator.free(fields);

    try std.testing.expectEqual(@as(usize, 4), fields.len);
    try std.testing.expectEqualStrings(":method", fields[0].name);
    try std.testing.expectEqualStrings("GET", fields[0].value);
    try std.testing.expectEqualStrings(":scheme", fields[1].name);
    try std.testing.expectEqualStrings("http", fields[1].value);
    try std.testing.expectEqualStrings(":authority", fields[3].name);
    try std.testing.expectEqualStrings("www.example.com", fields[3].value);
}

test "HTTP/2 HPACK static-only encode roundtrip" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const fields_in = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/resource" },
        .{ .name = "authorization", .value = "Bearer token", .never_index = true },
        .{ .name = "x-long", .value = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz" },
    };

    try Hpack.encodeLiteralBlock(&encoded, allocator, &fields_in);
    const decoded = try Hpack.decodeLiteralBlock(allocator, encoded.items);
    defer allocator.free(decoded);

    try std.testing.expectEqual(fields_in.len, decoded.len);
    for (fields_in, decoded) |expected, actual| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqualStrings(expected.value, actual.value);
        try std.testing.expectEqual(expected.never_index, actual.never_index);
    }
}

test "HTTP/2 HPACK rejects dynamic table references" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.HpackDynamicTableUnsupported, Hpack.decodeLiteralBlock(allocator, &.{0xfe}));
    try std.testing.expectError(error.HpackDynamicTableUnsupported, Hpack.decodeLiteralBlock(allocator, &.{ 0x20, 0x00 }));
}

test {
    _ = runtime;
}
