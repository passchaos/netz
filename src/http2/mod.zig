const std = @import("std");
const wire = @import("../internal/wire.zig");
const priority_field = @import("../internal/priority.zig");
const huffman_codec = @import("../internal/hpack_huffman.zig");

pub const runtime = @import("runtime.zig");
pub const socks5_runtime = @import("socks5_runtime.zig");
pub const client_pool = @import("client_pool.zig");
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
    HeaderListTooLarge,
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
    altsvc = 0x0a,
    origin = 0x0c,
    priority_update = 0x10,
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
    pub const encoded_len: usize = 9;

    length: u24,
    frame_type: FrameType,
    flags: u8,
    stream_id: u31,

    pub fn parse(bytes: []const u8) Error!FrameHeader {
        if (bytes.len < encoded_len) return error.BufferTooShort;
        const len = (@as(u24, bytes[0]) << 16) | (@as(u24, bytes[1]) << 8) | @as(u24, bytes[2]);
        const typ: FrameType = @enumFromInt(bytes[3]);
        const flags = bytes[4];
        const raw_stream = std.mem.readInt(u32, bytes[5..9], .big);
        return .{
            .length = len,
            .frame_type = typ,
            .flags = flags,
            .stream_id = @truncate(raw_stream & 0x7fff_ffff),
        };
    }

    pub fn write(self: FrameHeader, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        const start = list.items.len;
        try list.ensureUnusedCapacity(allocator, encoded_len);
        list.items.len = start + encoded_len;
        self.writeInto(list.items[start..][0..encoded_len]);
    }

    fn writeInto(self: FrameHeader, out: []u8) void {
        std.debug.assert(out.len >= encoded_len);
        out[0] = @truncate(self.length >> 16);
        out[1] = @truncate(self.length >> 8);
        out[2] = @truncate(self.length);
        out[3] = @intFromEnum(self.frame_type);
        out[4] = self.flags;
        std.mem.writeInt(u32, out[5..][0..4], @as(u32, self.stream_id), .big);
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
        const total_len = std.math.add(usize, FrameHeader.encoded_len, self.payload.len) catch return error.InvalidFrameSize;
        const start = list.items.len;
        try list.ensureUnusedCapacity(allocator, total_len);
        list.items.len = start + total_len;
        header.writeInto(list.items[start..][0..FrameHeader.encoded_len]);
        @memcpy(list.items[start + FrameHeader.encoded_len ..][0..self.payload.len], self.payload);
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
    webtransport_enabled = 0x2b60,
    webtransport_initial_max_data = 0x2b61,
    webtransport_initial_max_stream_data_uni = 0x2b62,
    webtransport_initial_max_stream_data_bidi_local = 0x2b63,
    webtransport_initial_max_streams_uni = 0x2b64,
    webtransport_initial_max_streams_bidi = 0x2b65,
    webtransport_initial_max_stream_data_bidi_remote = 0x2b66,
    _,
};

pub const Setting = struct {
    id: SettingId,
    value: u32,
};

pub const WebTransportSettings = @import("webtransport_settings.zig").Settings;

/// Borrow a complete SETTINGS payload after validating every entry. Unknown
/// identifiers remain ignorable; repeated known identifiers retain wire order.
/// The payload must stay unchanged and alive while the iterator is used.
pub const SettingsIterator = struct {
    payload: []const u8,
    offset: usize = 0,

    pub fn init(payload: []const u8) Error!SettingsIterator {
        if (payload.len % 6 != 0) return error.InvalidSetting;
        var offset: usize = 0;
        while (offset < payload.len) : (offset += 6) {
            const setting = decode(payload[offset..][0..6]);
            try validateSetting(setting.id, setting.value);
        }
        return .{ .payload = payload };
    }

    pub fn next(self: *SettingsIterator) ?Setting {
        if (self.offset == self.payload.len) return null;
        const setting = decode(self.payload[self.offset..][0..6]);
        self.offset += 6;
        return setting;
    }

    fn decode(bytes: *const [6]u8) Setting {
        return .{
            .id = @enumFromInt(std.mem.readInt(u16, bytes[0..2], .big)),
            .value = std.mem.readInt(u32, bytes[2..6], .big),
        };
    }
};

pub fn parseSettings(allocator: std.mem.Allocator, payload: []const u8) Error![]Setting {
    var iterator = try SettingsIterator.init(payload);
    if (payload.len == 0) return @constCast(&[_]Setting{});
    const settings = try allocator.alloc(Setting, payload.len / 6);
    errdefer allocator.free(settings);

    for (settings) |*setting| setting.* = iterator.next().?;
    return settings;
}

pub fn writeSettings(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: []const Setting) Error!void {
    for (settings) |setting| try validateSetting(setting.id, setting.value);

    const payload_len = std.math.mul(usize, settings.len, 6) catch return error.InvalidFrameSize;
    const start = list.items.len;
    try list.ensureUnusedCapacity(allocator, payload_len);
    list.items.len = start + payload_len;

    var pos = start;
    for (settings) |setting| {
        std.mem.writeInt(u16, list.items[pos..][0..2], @intFromEnum(setting.id), .big);
        pos += 2;
        std.mem.writeInt(u32, list.items[pos..][0..4], setting.value, .big);
        pos += 4;
    }
}

pub fn validateSetting(id: SettingId, value: u32) Error!void {
    switch (id) {
        .enable_push => if (value > 1) return error.InvalidSetting,
        .enable_connect_protocol => if (value > 1) return error.InvalidSetting,
        .no_rfc7540_priorities => if (value > 1) return error.InvalidSetting,
        .webtransport_enabled => if (value > 1) return error.InvalidSetting,
        .initial_window_size => if (value > std.math.maxInt(i31)) return error.InvalidSetting,
        .max_frame_size => if (value < 16_384 or value > 16_777_215) return error.InvalidSetting,
        else => {},
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

pub const PriorityPayload = struct {
    stream_id: u31,
    exclusive: bool,
    stream_dependency: u31,
    weight: u8,

    pub fn parse(frame: Frame) Error!PriorityPayload {
        if (frame.header.frame_type != .priority) return error.InvalidFrameSize;
        if (frame.header.stream_id == 0) return error.InvalidStreamId;
        const priority = try Priority.parse(frame.payload);
        if (priority.stream_dependency == frame.header.stream_id) return error.InvalidStreamId;
        return .{
            .stream_id = frame.header.stream_id,
            .exclusive = priority.exclusive,
            .stream_dependency = priority.stream_dependency,
            .weight = priority.weight,
        };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        stream_id: u31,
        exclusive: bool,
        stream_dependency: u31,
        weight: u8,
    ) Error!void {
        if (stream_id == 0) return error.InvalidStreamId;
        if (stream_dependency == stream_id) return error.InvalidStreamId;
        var dep = @as(u32, stream_dependency);
        if (exclusive) dep |= 0x8000_0000;
        const start = list.items.len;
        try list.ensureUnusedCapacity(allocator, FrameHeader.encoded_len + 5);
        list.items.len = start + FrameHeader.encoded_len + 5;
        (FrameHeader{
            .length = 5,
            .frame_type = .priority,
            .flags = 0,
            .stream_id = stream_id,
        }).writeInto(list.items[start..][0..FrameHeader.encoded_len]);
        const payload = list.items[start + FrameHeader.encoded_len ..][0..5];
        std.mem.writeInt(u32, payload[0..4], dep, .big);
        payload[4] = weight;
    }
};

pub const ExtensiblePriority = priority_field.Priority;

pub const PriorityUpdatePayload = struct {
    prioritized_stream_id: u31,
    field_value: []const u8,

    pub fn parse(frame: Frame) Error!PriorityUpdatePayload {
        if (frame.header.frame_type != .priority_update) {
            return error.InvalidFrameSize;
        }
        if (frame.header.stream_id != 0) return error.InvalidStreamId;
        if (frame.payload.len < 4) return error.InvalidFrameSize;
        const raw_id = std.mem.readInt(u32, frame.payload[0..4], .big);
        const field_value = frame.payload[4..];
        if (!priority_field.isAsciiFieldValue(field_value)) {
            return error.InvalidFrameSize;
        }
        _ = priority_field.Priority.parseStrict(field_value) catch {
            return error.InvalidFrameSize;
        };
        const prioritized_stream_id: u31 =
            @truncate(raw_id & 0x7fff_ffff);
        if (prioritized_stream_id == 0) return error.InvalidStreamId;
        return .{
            .prioritized_stream_id = prioritized_stream_id,
            .field_value = field_value,
        };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        prioritized_stream_id: u31,
        field_value: []const u8,
    ) Error!void {
        if (prioritized_stream_id == 0) return error.InvalidStreamId;
        if (!priority_field.isAsciiFieldValue(field_value)) {
            return error.InvalidFrameSize;
        }
        _ = priority_field.Priority.parseStrict(field_value) catch {
            return error.InvalidFrameSize;
        };
        const payload_len = std.math.add(usize, 4, field_value.len) catch return error.InvalidFrameSize;
        const payload_len_u24 = std.math.cast(u24, payload_len) orelse return error.InvalidFrameSize;
        const total_len = FrameHeader.encoded_len + payload_len;
        const start = list.items.len;
        try list.ensureUnusedCapacity(allocator, total_len);
        list.items.len = start + total_len;
        (FrameHeader{
            .length = payload_len_u24,
            .frame_type = .priority_update,
            .flags = 0,
            .stream_id = 0,
        }).writeInto(list.items[start..][0..FrameHeader.encoded_len]);
        const payload = list.items[start + FrameHeader.encoded_len ..][0..payload_len];
        std.mem.writeInt(u32, payload[0..4], prioritized_stream_id, .big);
        @memcpy(payload[4..], field_value);
    }

    pub fn writePriority(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        prioritized_stream_id: u31,
        value: ExtensiblePriority,
    ) Error!void {
        var field_value_buf: [16]u8 = undefined;
        try write(
            list,
            allocator,
            prioritized_stream_id,
            value.serialize(&field_value_buf),
        );
    }

    pub fn priorityValue(
        self: PriorityUpdatePayload,
    ) ExtensiblePriority {
        return ExtensiblePriority.parse(self.field_value);
    }
};

pub const PushPromisePayload = struct {
    stream_id: u31,
    promised_stream_id: u31,
    header_block: []const u8,
    padding_len: u8 = 0,

    pub fn parse(frame: Frame) Error!PushPromisePayload {
        if (frame.header.frame_type != .push_promise) return error.InvalidFrameSize;
        if (frame.header.stream_id == 0) return error.InvalidStreamId;
        const flags = Flags.fromByte(frame.header.flags);
        var pos: usize = 0;
        var pad_len: u8 = 0;
        if (flags.padded) {
            if (frame.payload.len == 0) return error.InvalidPadding;
            pad_len = frame.payload[0];
            pos = 1;
        }
        if (frame.payload.len < pos + 4 + @as(usize, pad_len)) return error.InvalidFrameSize;
        const raw_promised = std.mem.readInt(u32, frame.payload[pos..][0..4], .big);
        const promised_stream_id: u31 = @truncate(raw_promised & 0x7fff_ffff);
        if (promised_stream_id == 0) return error.InvalidStreamId;
        pos += 4;
        return .{
            .stream_id = frame.header.stream_id,
            .promised_stream_id = promised_stream_id,
            .header_block = frame.payload[pos .. frame.payload.len - pad_len],
            .padding_len = pad_len,
        };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        stream_id: u31,
        promised_stream_id: u31,
        header_block: []const u8,
        options: struct {
            end_headers: bool = true,
            padding_len: u8 = 0,
        },
    ) Error!void {
        if (stream_id == 0) return error.InvalidStreamId;
        if (promised_stream_id == 0) return error.InvalidStreamId;
        var payload_len = std.math.add(usize, 4, header_block.len) catch return error.InvalidFrameSize;
        payload_len = std.math.add(usize, payload_len, options.padding_len) catch return error.InvalidFrameSize;
        if (options.padding_len != 0) payload_len = std.math.add(usize, payload_len, 1) catch return error.InvalidFrameSize;

        const payload_len_u24 = std.math.cast(u24, payload_len) orelse return error.InvalidFrameSize;
        const total_len = FrameHeader.encoded_len + payload_len;
        const start = list.items.len;
        try list.ensureUnusedCapacity(allocator, total_len);
        list.items.len = start + total_len;
        (FrameHeader{
            .length = payload_len_u24,
            .frame_type = .push_promise,
            .flags = (if (options.end_headers) @as(u8, 0x4) else 0) |
                if (options.padding_len != 0) @as(u8, 0x8) else 0,
            .stream_id = stream_id,
        }).writeInto(list.items[start..][0..FrameHeader.encoded_len]);
        var payload_pos = start + FrameHeader.encoded_len;
        if (options.padding_len != 0) {
            list.items[payload_pos] = options.padding_len;
            payload_pos += 1;
        }
        std.mem.writeInt(u32, list.items[payload_pos..][0..4], @as(u32, promised_stream_id), .big);
        payload_pos += 4;
        @memcpy(list.items[payload_pos..][0..header_block.len], header_block);
        payload_pos += header_block.len;
        @memset(list.items[payload_pos..][0..options.padding_len], 0);
    }
};

pub const OriginPayload = struct {
    origins: []const []const u8,

    pub fn parse(
        allocator: std.mem.Allocator,
        frame: Frame,
    ) Error!OriginPayload {
        if (frame.header.frame_type != .origin) {
            return error.InvalidFrameSize;
        }
        if (frame.header.stream_id != 0) return error.InvalidStreamId;
        if (frame.payload.len == 0) return .{ .origins = @constCast(&[_][]const u8{}) };
        var cursor = wire.Cursor.init(frame.payload);
        var count: usize = 0;
        while (!cursor.eof()) {
            const len = try cursor.readInt(u16, .big);
            const origin = cursor.readSlice(len) catch
                return error.InvalidFrameSize;
            if (origin.len == 0 or !validOriginAscii(origin)) {
                return error.InvalidFrameSize;
            }
            count += 1;
        }
        const origins = try allocator.alloc([]const u8, count);
        errdefer allocator.free(origins);
        cursor = wire.Cursor.init(frame.payload);
        for (origins) |*out| {
            const len = try cursor.readInt(u16, .big);
            out.* = try cursor.readSlice(len);
        }
        return .{ .origins = origins };
    }

    pub fn deinit(self: *OriginPayload, allocator: std.mem.Allocator) void {
        allocator.free(self.origins);
        self.* = undefined;
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        origins: []const []const u8,
    ) Error!void {
        var payload_len: usize = 0;
        for (origins) |origin| {
            if (origin.len == 0 or
                origin.len > std.math.maxInt(u16) or
                !validOriginAscii(origin))
            {
                return error.InvalidFrameSize;
            }
            payload_len = std.math.add(usize, payload_len, 2) catch return error.InvalidFrameSize;
            payload_len = std.math.add(usize, payload_len, origin.len) catch return error.InvalidFrameSize;
        }

        const payload_len_u24 = std.math.cast(u24, payload_len) orelse return error.InvalidFrameSize;
        const total_len = FrameHeader.encoded_len + payload_len;
        const start = list.items.len;
        try list.ensureUnusedCapacity(allocator, total_len);
        list.items.len = start + total_len;
        (FrameHeader{
            .length = payload_len_u24,
            .frame_type = .origin,
            .flags = 0,
            .stream_id = 0,
        }).writeInto(list.items[start..][0..FrameHeader.encoded_len]);
        var payload_pos = start + FrameHeader.encoded_len;
        for (origins) |origin| {
            std.mem.writeInt(u16, list.items[payload_pos..][0..2], @intCast(origin.len), .big);
            payload_pos += 2;
            @memcpy(list.items[payload_pos..][0..origin.len], origin);
            payload_pos += origin.len;
        }
    }
};

pub const AltSvcPayload = struct {
    origin: []const u8,
    field_value: []const u8,

    pub fn parse(frame: Frame) Error!AltSvcPayload {
        if (frame.header.frame_type != .altsvc or frame.payload.len < 2) {
            return error.InvalidFrameSize;
        }
        const origin_len = std.mem.readInt(u16, frame.payload[0..2], .big);
        if (origin_len > frame.payload.len - 2) {
            return error.InvalidFrameSize;
        }
        const origin = frame.payload[2..][0..origin_len];
        const field_value = frame.payload[2 + origin_len ..];
        if ((origin.len != 0 and !validVisibleAscii(origin)) or
            field_value.len == 0 or
            !validFieldValueAscii(field_value))
        {
            return error.InvalidFrameSize;
        }
        if ((frame.header.stream_id == 0) != (origin.len != 0)) {
            return error.InvalidStreamId;
        }
        return .{ .origin = origin, .field_value = field_value };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        stream_id: u31,
        origin: []const u8,
        field_value: []const u8,
    ) Error!void {
        if (origin.len > std.math.maxInt(u16) or
            (origin.len != 0 and !validVisibleAscii(origin)) or
            field_value.len == 0 or
            !validFieldValueAscii(field_value))
        {
            return error.InvalidFrameSize;
        }
        if ((stream_id == 0) != (origin.len != 0)) {
            return error.InvalidStreamId;
        }
        var payload_len = std.math.add(usize, 2, origin.len) catch return error.InvalidFrameSize;
        payload_len = std.math.add(usize, payload_len, field_value.len) catch return error.InvalidFrameSize;

        const payload_len_u24 = std.math.cast(u24, payload_len) orelse return error.InvalidFrameSize;
        const total_len = FrameHeader.encoded_len + payload_len;
        const start = list.items.len;
        try list.ensureUnusedCapacity(allocator, total_len);
        list.items.len = start + total_len;
        (FrameHeader{
            .length = payload_len_u24,
            .frame_type = .altsvc,
            .flags = 0,
            .stream_id = stream_id,
        }).writeInto(list.items[start..][0..FrameHeader.encoded_len]);
        const payload = list.items[start + FrameHeader.encoded_len ..][0..payload_len];
        std.mem.writeInt(u16, payload[0..2], @intCast(origin.len), .big);
        @memcpy(payload[2..][0..origin.len], origin);
        @memcpy(payload[2 + origin.len ..], field_value);
    }
};

fn validOriginAscii(origin: []const u8) bool {
    return validVisibleAscii(origin);
}

fn validVisibleAscii(value: []const u8) bool {
    for (value) |byte| {
        // RFC 8336 carries the ASCII serialization of an origin. Reject
        // controls, whitespace, and non-ASCII bytes at the frame boundary;
        // URI scheme/host/port validation remains an origin-layer concern.
        if (byte < 0x21 or byte > 0x7e) return false;
    }
    return true;
}

fn validFieldValueAscii(value: []const u8) bool {
    for (value) |byte| {
        // Alt-Svc uses HTTP field-value syntax, where SP and HTAB separators
        // are legal but other controls and non-ASCII octets are not.
        if (byte == '\t' or (byte >= 0x20 and byte <= 0x7e)) continue;
        return false;
    }
    return true;
}

pub const DataPayload = struct {
    data: []const u8,
    padding_len: u8,

    pub fn parse(frame: Frame) Error!DataPayload {
        if (frame.header.frame_type != .data) return error.InvalidFrameSize;
        if (frame.header.stream_id == 0) return error.InvalidStreamId;
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
    pub const encoded_len = FrameHeader.encoded_len + 4;
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
        var encoded: [encoded_len]u8 = undefined;
        const bytes = try writeInto(&encoded, stream_id, error_code);
        try list.appendSlice(allocator, bytes);
    }

    pub fn writeInto(
        storage: *[encoded_len]u8,
        stream_id: u31,
        error_code: ErrorCode,
    ) Error![]const u8 {
        if (stream_id == 0) return error.InvalidStreamId;
        (FrameHeader{
            .length = 4,
            .frame_type = .rst_stream,
            .flags = 0,
            .stream_id = stream_id,
        }).writeInto(storage[0..FrameHeader.encoded_len]);
        std.mem.writeInt(
            u32,
            storage[FrameHeader.encoded_len..][0..4],
            @intFromEnum(error_code),
            .big,
        );
        return storage;
    }
};

pub const HeadersPayload = struct {
    header_block: []const u8,
    priority: ?Priority,
    padding_len: u8,

    pub fn parse(frame: Frame) Error!HeadersPayload {
        return parseInternal(frame, true);
    }

    /// RFC 9218 permits ignoring the deprecated dependency and weight while
    /// retaining the HEADERS field layout, priority length and padding checks.
    /// The returned priority is null so callers cannot apply those signals.
    pub fn parseIgnoringPriority(frame: Frame) Error!HeadersPayload {
        return parseInternal(frame, false);
    }

    fn parseInternal(frame: Frame, use_priority: bool) Error!HeadersPayload {
        if (frame.header.frame_type != .headers) return error.InvalidFrameSize;
        if (frame.header.stream_id == 0) return error.InvalidStreamId;
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
            if (use_priority) {
                priority = try Priority.parse(frame.payload[pos .. pos + 5]);
                if (priority.?.stream_dependency == frame.header.stream_id) return error.InvalidStreamId;
            }
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
    pub const encoded_len = FrameHeader.encoded_len + 8;
    data: [8]u8,

    pub fn parse(frame: Frame) Error!PingPayload {
        if (frame.header.frame_type != .ping or frame.header.stream_id != 0 or frame.payload.len != 8) {
            return error.InvalidFrameSize;
        }
        return .{ .data = frame.payload[0..8].* };
    }

    pub fn write(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: [8]u8, ack: bool) Error!void {
        const start = list.items.len;
        try list.ensureUnusedCapacity(allocator, encoded_len);
        list.items.len += encoded_len;
        _ = writeInto(list.items[start..][0..encoded_len], data, ack);
    }

    /// Encodes the complete frame into caller-owned storage. The returned
    /// slice aliases `storage`, allowing control-plane sends to avoid a
    /// temporary growable buffer.
    pub fn writeInto(
        storage: *[encoded_len]u8,
        data: [8]u8,
        ack: bool,
    ) []const u8 {
        (FrameHeader{
            .length = 8,
            .frame_type = .ping,
            .flags = if (ack) 0x1 else 0,
            .stream_id = 0,
        }).writeInto(storage[0..FrameHeader.encoded_len]);
        @memcpy(storage[FrameHeader.encoded_len..][0..8], &data);
        return storage;
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
        const total_len = try encodedLen(debug_data.len);
        try list.ensureUnusedCapacity(allocator, total_len);
        const start = list.items.len;
        list.items.len += total_len;
        _ = try writeInto(
            list.items[start..],
            last_stream_id,
            error_code,
            debug_data,
        );
    }

    pub fn encodedLen(debug_data_len: usize) Error!usize {
        const payload_len = std.math.add(usize, 8, debug_data_len) catch return error.InvalidFrameSize;
        const payload_len_u24 = std.math.cast(u24, payload_len) orelse return error.InvalidFrameSize;
        _ = payload_len_u24;
        return FrameHeader.encoded_len + payload_len;
    }

    pub fn writeInto(
        storage: []u8,
        last_stream_id: u31,
        error_code: ErrorCode,
        debug_data: []const u8,
    ) Error![]const u8 {
        const payload_len = std.math.add(usize, 8, debug_data.len) catch
            return error.InvalidFrameSize;
        const payload_len_u24 = std.math.cast(u24, payload_len) orelse
            return error.InvalidFrameSize;
        const total_len = FrameHeader.encoded_len + payload_len;
        if (storage.len < total_len) return error.BufferTooShort;
        (FrameHeader{
            .length = payload_len_u24,
            .frame_type = .goaway,
            .flags = 0,
            .stream_id = 0,
        }).writeInto(storage[0..FrameHeader.encoded_len]);
        const payload = storage[FrameHeader.encoded_len..][0..payload_len];
        std.mem.writeInt(u32, payload[0..4], @as(u32, last_stream_id), .big);
        std.mem.writeInt(u32, payload[4..8], @intFromEnum(error_code), .big);
        @memcpy(payload[8..], debug_data);
        return storage[0..total_len];
    }
};

pub const WindowUpdatePayload = struct {
    pub const encoded_len = FrameHeader.encoded_len + 4;
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
        const start = list.items.len;
        try list.ensureUnusedCapacity(allocator, encoded_len);
        list.items.len += encoded_len;
        _ = writeInto(list.items[start..][0..encoded_len], stream_id, increment) catch unreachable;
    }

    /// Encodes the complete frame into caller-owned storage. The returned
    /// slice aliases `storage`; an invalid zero increment leaves it untouched.
    pub fn writeInto(
        storage: *[encoded_len]u8,
        stream_id: u31,
        increment: u31,
    ) Error![]const u8 {
        if (increment == 0) return error.InvalidFrameSize;
        (FrameHeader{
            .length = 4,
            .frame_type = .window_update,
            .flags = 0,
            .stream_id = stream_id,
        }).writeInto(storage[0..FrameHeader.encoded_len]);
        std.mem.writeInt(
            u32,
            storage[FrameHeader.encoded_len..][0..4],
            @as(u32, increment),
            .big,
        );
        return storage;
    }
};

pub fn validateClientPreface(bytes: []const u8) Error!void {
    if (bytes.len < connection_preface.len) return error.BufferTooShort;
    if (!std.mem.eql(u8, bytes[0..connection_preface.len], connection_preface)) return error.InvalidPreface;
}

pub const Hpack = struct {
    pub const default_dynamic_table_size: usize = 4096;
    const owned_plan_stack_fields: usize = 32;
    const owned_string_stack_bytes: usize = 16 * 1024;

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

    const static_name_index = std.StaticStringMap([]const u8).initComptime(.{
        .{ ":authority", &[_]u8{1} },
        .{ ":method", &[_]u8{ 2, 3 } },
        .{ ":path", &[_]u8{ 4, 5 } },
        .{ ":scheme", &[_]u8{ 6, 7 } },
        .{ ":status", &[_]u8{ 8, 9, 10, 11, 12, 13, 14 } },
        .{ "accept-charset", &[_]u8{15} },
        .{ "accept-encoding", &[_]u8{16} },
        .{ "accept-language", &[_]u8{17} },
        .{ "accept-ranges", &[_]u8{18} },
        .{ "accept", &[_]u8{19} },
        .{ "access-control-allow-origin", &[_]u8{20} },
        .{ "age", &[_]u8{21} },
        .{ "allow", &[_]u8{22} },
        .{ "authorization", &[_]u8{23} },
        .{ "cache-control", &[_]u8{24} },
        .{ "content-disposition", &[_]u8{25} },
        .{ "content-encoding", &[_]u8{26} },
        .{ "content-language", &[_]u8{27} },
        .{ "content-length", &[_]u8{28} },
        .{ "content-location", &[_]u8{29} },
        .{ "content-range", &[_]u8{30} },
        .{ "content-type", &[_]u8{31} },
        .{ "cookie", &[_]u8{32} },
        .{ "date", &[_]u8{33} },
        .{ "etag", &[_]u8{34} },
        .{ "expect", &[_]u8{35} },
        .{ "expires", &[_]u8{36} },
        .{ "from", &[_]u8{37} },
        .{ "host", &[_]u8{38} },
        .{ "if-match", &[_]u8{39} },
        .{ "if-modified-since", &[_]u8{40} },
        .{ "if-none-match", &[_]u8{41} },
        .{ "if-range", &[_]u8{42} },
        .{ "if-unmodified-since", &[_]u8{43} },
        .{ "last-modified", &[_]u8{44} },
        .{ "link", &[_]u8{45} },
        .{ "location", &[_]u8{46} },
        .{ "max-forwards", &[_]u8{47} },
        .{ "proxy-authenticate", &[_]u8{48} },
        .{ "proxy-authorization", &[_]u8{49} },
        .{ "range", &[_]u8{50} },
        .{ "referer", &[_]u8{51} },
        .{ "refresh", &[_]u8{52} },
        .{ "retry-after", &[_]u8{53} },
        .{ "server", &[_]u8{54} },
        .{ "set-cookie", &[_]u8{55} },
        .{ "strict-transport-security", &[_]u8{56} },
        .{ "transfer-encoding", &[_]u8{57} },
        .{ "user-agent", &[_]u8{58} },
        .{ "vary", &[_]u8{59} },
        .{ "via", &[_]u8{60} },
        .{ "www-authenticate", &[_]u8{61} },
    });

    fn dynamicStringHash(bytes: []const u8) u64 {
        return std.hash.Wyhash.hash(0, bytes);
    }

    const DynamicExactKey = struct {
        name: []const u8,
        value: []const u8,
    };

    const DynamicExactContext = struct {
        pub fn hash(_: @This(), key: DynamicExactKey) u64 {
            var hasher = std.hash.Wyhash.init(0);
            std.hash.autoHash(&hasher, key.name.len);
            hasher.update(key.name);
            std.hash.autoHash(&hasher, key.value.len);
            hasher.update(key.value);
            return hasher.final();
        }

        pub fn eql(_: @This(), lhs: DynamicExactKey, rhs: DynamicExactKey) bool {
            return std.mem.eql(u8, lhs.name, rhs.name) and
                std.mem.eql(u8, lhs.value, rhs.value);
        }
    };

    const DynamicExactIndex = std.HashMapUnmanaged(
        DynamicExactKey,
        usize,
        DynamicExactContext,
        std.hash_map.default_max_load_percentage,
    );

    pub const HeaderField = struct {
        name: []const u8,
        value: []const u8,
        never_index: bool = false,
        /// Set by decoders when a Huffman string had to be materialized into
        /// owned memory.  Call `freeDecodedFields` on decoder output instead of
        /// only freeing the slice so these allocations are released.
        name_storage: ?[]u8 = null,
        value_storage: ?[]u8 = null,
        /// Allocation shared by name/value. Runtime-owned header lists use it
        /// only on element zero; the allocation may also contain the field
        /// array itself. Dynamic-table entries and decoded dynamic indexed
        /// fields use one string block per field. In every form this keeps the
        /// public slices unchanged while avoiding separate name/value storage.
        block_storage: ?[]u8 = null,
    };

    pub const DynamicTable = struct {
        entries: std.ArrayList(HeaderField) = .empty,
        /// Only encoders need reverse name/value lookup when selecting an
        /// indexed representation. Decoders address entries exclusively by
        /// their wire index, so omitting these maps removes two hash-table
        /// probes and their retained capacity from every inbound insertion.
        maintain_lookup_indexes: bool = true,
        /// Exact indexes point at the latest physical entry for a name or
        /// name/value pair. Keys borrow entry-owned strings and are rebuilt
        /// after compaction or redirected when evicting the current latest.
        latest_name: std.StringHashMapUnmanaged(usize) = .empty,
        latest_exact: DynamicExactIndex = .empty,
        size_limit: usize = default_dynamic_table_size,
        used: usize = 0,
        head: usize = 0,

        pub fn deinit(self: *DynamicTable, allocator: std.mem.Allocator) void {
            self.clear(allocator);
            self.entries.deinit(allocator);
            self.latest_name.deinit(allocator);
            self.latest_exact.deinit(allocator);
            self.* = undefined;
        }

        pub fn clear(self: *DynamicTable, allocator: std.mem.Allocator) void {
            for (self.entries.items[self.head..]) |item| {
                allocator.free(item.block_storage.?);
            }
            self.entries.clearRetainingCapacity();
            self.latest_name.clearRetainingCapacity();
            self.latest_exact.clearRetainingCapacity();
            self.used = 0;
            self.head = 0;
        }

        fn clone(
            self: DynamicTable,
            allocator: std.mem.Allocator,
        ) !DynamicTable {
            var copy = DynamicTable{
                .maintain_lookup_indexes = self.maintain_lookup_indexes,
                .size_limit = self.size_limit,
            };
            errdefer copy.deinit(allocator);
            try copy.entries.ensureTotalCapacity(
                allocator,
                self.entryCount(),
            );
            for (self.entries.items[self.head..]) |entry| {
                try copy.add(allocator, entry.name, entry.value);
            }
            return copy;
        }

        fn copyFromRetainingCapacity(
            self: *DynamicTable,
            allocator: std.mem.Allocator,
            source: *const DynamicTable,
        ) !void {
            std.debug.assert(self != source);
            std.debug.assert(
                self.maintain_lookup_indexes ==
                    source.maintain_lookup_indexes,
            );
            const source_entries =
                source.entries.items[source.head..];
            try self.entries.ensureTotalCapacity(
                allocator,
                source_entries.len,
            );
            if (self.maintain_lookup_indexes) {
                const index_count = std.math.cast(
                    u32,
                    source_entries.len,
                ) orelse return error.OutOfMemory;
                try self.latest_name.ensureTotalCapacity(
                    allocator,
                    index_count,
                );
                try self.latest_exact.ensureTotalCapacity(
                    allocator,
                    index_count,
                );
            }

            if (self.head != 0) {
                const retained = self.entries.items[self.head..];
                @memmove(
                    self.entries.items[0..retained.len],
                    retained,
                );
                self.entries.items.len = retained.len;
                self.head = 0;
            }
            self.latest_name.clearRetainingCapacity();
            self.latest_exact.clearRetainingCapacity();

            var copied: usize = 0;
            while (copied < source_entries.len) : (copied += 1) {
                const source_entry = source_entries[copied];
                const string_len = std.math.add(
                    usize,
                    source_entry.name.len,
                    source_entry.value.len,
                ) catch return error.OutOfMemory;
                var storage = if (copied < self.entries.items.len)
                    self.entries.items[copied].block_storage.?
                else
                    try allocator.alloc(u8, string_len);
                if (storage.len < string_len) {
                    const replacement = try allocator.alloc(u8, string_len);
                    allocator.free(storage);
                    storage = replacement;
                }
                const name = storage[0..source_entry.name.len];
                @memcpy(name, source_entry.name);
                const value = storage[name.len..][0..source_entry.value.len];
                @memcpy(value, source_entry.value);
                const target = HeaderField{
                    .name = name,
                    .value = value,
                    .never_index = source_entry.never_index,
                    .block_storage = storage,
                };
                if (copied < self.entries.items.len) {
                    self.entries.items[copied] = target;
                } else {
                    self.entries.appendAssumeCapacity(target);
                }
            }
            for (self.entries.items[copied..]) |entry| {
                allocator.free(entry.block_storage.?);
            }
            self.entries.items.len = copied;
            self.size_limit = source.size_limit;
            self.used = source.used;
            if (self.maintain_lookup_indexes) self.rebuildIndexes();
        }

        pub fn setLimit(self: *DynamicTable, allocator: std.mem.Allocator, new_limit: usize) void {
            self.size_limit = new_limit;
            self.evictToLimit(allocator);
        }

        pub fn add(self: *DynamicTable, allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
            const size = entrySize(name, value);
            if (size > self.size_limit) {
                // RFC 7541 §4.4: an entry larger than the table size empties the
                // table and is not inserted.  Keeping this branch explicit avoids
                // retaining stale state after an oversized indexed literal.
                self.clear(allocator);
                return;
            }

            self.compactIfNeeded();
            try self.entries.ensureUnusedCapacity(allocator, 1);
            const owned = try ownedHeaderField(
                allocator,
                name,
                value,
                false,
            );
            errdefer allocator.free(owned.block_storage.?);

            const physical_index = self.entries.items.len;
            if (self.maintain_lookup_indexes) {
                // Insert the owned strings into the maps. This ensures map
                // keys never transiently borrow the caller while later map
                // growth can still fail. The errdefers restore both indexes
                // and the single string allocation transactionally.
                const name_slot = try self.latest_name.getOrPut(
                    allocator,
                    owned.name,
                );
                errdefer if (!name_slot.found_existing) {
                    _ = self.latest_name.remove(owned.name);
                };
                const exact_key = DynamicExactKey{
                    .name = owned.name,
                    .value = owned.value,
                };
                const exact_slot = try self.latest_exact.getOrPut(
                    allocator,
                    exact_key,
                );
                errdefer if (!exact_slot.found_existing) {
                    _ = self.latest_exact.remove(exact_key);
                };
                name_slot.key_ptr.* = owned.name;
                name_slot.value_ptr.* = physical_index;
                exact_slot.key_ptr.* = exact_key;
                exact_slot.value_ptr.* = physical_index;
            }
            self.entries.appendAssumeCapacity(owned);
            self.used += size;
            self.evictToLimit(allocator);
        }
        pub fn get(self: DynamicTable, dynamic_index: usize) ?HeaderField {
            const count = self.entryCount();
            if (dynamic_index >= count) return null;
            return self.entries.items[self.entries.items.len - 1 - dynamic_index];
        }

        pub fn findIndex(self: DynamicTable, name: []const u8, value: []const u8) ?u64 {
            std.debug.assert(self.maintain_lookup_indexes);
            if (self.entryCount() == 0) return null;
            const physical_index = self.latest_exact.get(.{ .name = name, .value = value }) orelse return null;
            if (!self.validPhysicalIndex(physical_index)) return null;
            return self.wireIndexForPhysical(physical_index);
        }
        pub fn findNameIndex(self: DynamicTable, name: []const u8) ?u64 {
            std.debug.assert(self.maintain_lookup_indexes);
            if (self.entryCount() == 0) return null;
            const physical_index = self.latest_name.get(name) orelse return null;
            if (!self.validPhysicalIndex(physical_index)) return null;
            return self.wireIndexForPhysical(physical_index);
        }

        fn evictToLimit(self: *DynamicTable, allocator: std.mem.Allocator) void {
            while (self.used > self.size_limit and self.entryCount() != 0) {
                const removed = &self.entries.items[self.head];
                self.used -= entrySize(removed.name, removed.value);
                if (self.maintain_lookup_indexes) {
                    self.removeLatestIndexes(removed.*, self.head);
                }
                allocator.free(removed.block_storage.?);
                self.head += 1;
            }
            self.compactIfNeeded();
        }
        pub fn entryCount(self: DynamicTable) usize {
            return self.entries.items.len - self.head;
        }

        fn validPhysicalIndex(self: DynamicTable, physical_index: usize) bool {
            return physical_index >= self.head and
                physical_index < self.entries.items.len;
        }

        fn wireIndexForPhysical(
            self: DynamicTable,
            physical_index: usize,
        ) u64 {
            const dynamic_index = self.entries.items.len - 1 - physical_index;
            return @intCast(static_table.len + dynamic_index + 1);
        }

        fn removeLatestIndexes(
            self: *DynamicTable,
            entry: HeaderField,
            physical_index: usize,
        ) void {
            if (self.latest_name.get(entry.name) == physical_index) {
                // The dynamic table evicts strictly from oldest to newest. If
                // the latest name entry still points at the removed physical
                // slot, no newer live entry with this name exists; removing
                // the map entry is enough and avoids a reverse scan on every
                // capacity-pressure eviction.
                _ = self.latest_name.remove(entry.name);
            }

            const exact_key = DynamicExactKey{
                .name = entry.name,
                .value = entry.value,
            };
            if (self.latest_exact.get(exact_key) == physical_index) {
                // Same FIFO invariant as above for exact name/value keys.
                _ = self.latest_exact.remove(exact_key);
            }
        }

        fn compactIfNeeded(self: *DynamicTable) void {
            if (self.head == 0) return;
            if (self.head < self.entries.items.len / 2 and self.entryCount() != 0) return;
            const remaining = self.entryCount();
            @memmove(self.entries.items[0..remaining], self.entries.items[self.head..]);
            self.entries.items.len = remaining;
            self.head = 0;
            if (self.maintain_lookup_indexes) self.rebuildIndexes();
        }

        fn rebuildIndexes(self: *DynamicTable) void {
            self.latest_name.clearRetainingCapacity();
            self.latest_exact.clearRetainingCapacity();
            for (self.entries.items, 0..) |entry, index| {
                // Hash-map replacement updates only the value. Rebind keys as
                // well: they borrow entry storage, and a later eviction may
                // free an older duplicate while this slot names a newer one.
                const name_slot = self.latest_name.getOrPutAssumeCapacity(
                    entry.name,
                );
                name_slot.key_ptr.* = entry.name;
                name_slot.value_ptr.* = index;
                const exact_key = DynamicExactKey{
                    .name = entry.name,
                    .value = entry.value,
                };
                const exact_slot = self.latest_exact.getOrPutAssumeCapacity(
                    exact_key,
                );
                exact_slot.key_ptr.* = exact_key;
                exact_slot.value_ptr.* = index;
            }
        }
    };

    pub const Decoder = struct {
        dynamic_table: DynamicTable = .{
            .maintain_lookup_indexes = false,
        },
        max_dynamic_table_size: usize = default_dynamic_table_size,
        last_decode_compression_error: bool = false,

        pub fn deinit(self: *Decoder, allocator: std.mem.Allocator) void {
            self.dynamic_table.deinit(allocator);
            self.* = undefined;
        }

        /// Deep-copy compression state for speculative validation. A caller
        /// can decode queued field sections without advancing the live
        /// connection table, then later decode their retained wire bytes once.
        pub fn clone(
            self: Decoder,
            allocator: std.mem.Allocator,
        ) !Decoder {
            return .{
                .dynamic_table = try self.dynamic_table.clone(allocator),
                .max_dynamic_table_size = self.max_dynamic_table_size,
            };
        }

        pub fn setMaxDynamicTableSize(self: *Decoder, allocator: std.mem.Allocator, max_size: usize) void {
            self.max_dynamic_table_size = max_size;
            if (self.dynamic_table.size_limit > max_size) self.dynamic_table.setLimit(allocator, max_size);
        }

        pub fn decodeBlock(self: *Decoder, allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
            return decodeBlockWithDynamicTable(allocator, block, &self.dynamic_table, self.max_dynamic_table_size);
        }

        pub fn decodeBlockInto(
            self: *Decoder,
            allocator: std.mem.Allocator,
            block: []const u8,
            storage: []HeaderField,
        ) ![]HeaderField {
            return decodeBlockIntoWithDynamicTable(
                allocator,
                block,
                &self.dynamic_table,
                self.max_dynamic_table_size,
                storage,
                std.math.maxInt(usize),
            );
        }

        /// Decode into caller storage while enforcing the RFC 9113
        /// uncompressed header-list size. Once the output limit is crossed,
        /// decoding continues without retaining fields so incremental HPACK
        /// table updates remain synchronized for later streams.
        pub fn decodeBlockIntoWithLimit(
            self: *Decoder,
            allocator: std.mem.Allocator,
            block: []const u8,
            storage: []HeaderField,
            max_header_list_size: usize,
        ) ![]HeaderField {
            return decodeBlockIntoWithDynamicTable(
                allocator,
                block,
                &self.dynamic_table,
                self.max_dynamic_table_size,
                storage,
                max_header_list_size,
            );
        }

        /// Decode into one allocation containing the field array followed by
        /// one contiguous string block. This is the application-ownership path
        /// used by the HTTP/2 runtime;
        /// unlike `decodeBlockIntoWithLimit`, it never creates per-field output
        /// allocations that a caller must immediately clone.
        pub fn decodeBlockOwnedWithLimit(
            self: *Decoder,
            allocator: std.mem.Allocator,
            block: []const u8,
            max_header_fields: usize,
            max_header_list_size: usize,
        ) ![]HeaderField {
            self.last_decode_compression_error = false;
            var field_limit_exceeded = false;
            return decodeBlockOwnedWithDynamicTable(
                allocator,
                block,
                &self.dynamic_table,
                self.max_dynamic_table_size,
                max_header_fields,
                max_header_list_size,
                &field_limit_exceeded,
            ) catch |err| switch (err) {
                error.BufferTooShort,
                error.IntegerOverflow,
                error.InvalidEncoding,
                error.HpackDynamicTableUnsupported,
                => {
                    self.last_decode_compression_error =
                        !field_limit_exceeded;
                    return err;
                },
                else => |other| return other,
            };
        }

        pub fn lastDecodeWasCompressionError(self: Decoder) bool {
            return self.last_decode_compression_error;
        }

        /// Validate a complete rejected field section and apply its dynamic
        /// table updates without allocating application field output.
        pub fn discardBlock(self: *Decoder, allocator: std.mem.Allocator, block: []const u8) !void {
            const fields = self.decodeBlockOwnedWithLimit(allocator, block, 0, std.math.maxInt(usize)) catch |err| {
                if (err == error.BufferTooShort and !self.lastDecodeWasCompressionError()) return;
                return err;
            };
            freeOwnedFields(allocator, fields);
        }
    };

    pub const Encoder = struct {
        const SizeUpdate = union(enum) {
            one: usize,
            two: struct {
                min: usize,
                max: usize,
            },
        };

        dynamic_table: DynamicTable = .{},
        pending_size_update: ?SizeUpdate = null,
        last_emitted_dynamic_table_size: usize = default_dynamic_table_size,
        encoded_scratch: std.ArrayList(u8) = .empty,

        pub fn deinit(self: *Encoder, allocator: std.mem.Allocator) void {
            self.dynamic_table.deinit(allocator);
            self.encoded_scratch.deinit(allocator);
            self.* = undefined;
        }

        /// Deep-copy compression state for transactional multi-frame encoding.
        ///
        /// The encoded scratch itself is deliberately not copied; it carries no
        /// protocol state and the clone will populate it on its first encode.
        pub fn clone(
            self: Encoder,
            allocator: std.mem.Allocator,
        ) !Encoder {
            return .{
                .dynamic_table = try self.dynamic_table.clone(allocator),
                .pending_size_update = self.pending_size_update,
                .last_emitted_dynamic_table_size = self.last_emitted_dynamic_table_size,
            };
        }

        /// Replace this encoder's compression state while retaining all
        /// reusable staging storage. The source remains unchanged.
        pub fn copyFromRetainingCapacity(
            self: *Encoder,
            allocator: std.mem.Allocator,
            source: *const Encoder,
        ) !void {
            std.debug.assert(self != source);
            try self.dynamic_table.copyFromRetainingCapacity(
                allocator,
                &source.dynamic_table,
            );
            self.pending_size_update = source.pending_size_update;
            self.last_emitted_dynamic_table_size =
                source.last_emitted_dynamic_table_size;
            self.encoded_scratch.clearRetainingCapacity();
        }

        pub fn setMaxDynamicTableSize(self: *Encoder, allocator: std.mem.Allocator, max_size: usize) void {
            self.queueSizeUpdate(max_size);
            self.dynamic_table.setLimit(allocator, max_size);
        }

        pub fn encodeBlock(self: *Encoder, list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const HeaderField) !void {
            if (self.pending_size_update) |size_update| {
                // Rust h2/hyper queues SETTINGS_HEADER_TABLE_SIZE changes and
                // emits HPACK dynamic-table-size updates at the beginning of
                // the next header block.  If the peer temporarily lowered its
                // advertised maximum and raised it again before we sent
                // headers, RFC 7541 still requires the smaller value to be
                // signaled first, so keep a min/max pair instead of coalescing
                // blindly to the final size.
                switch (size_update) {
                    .one => |max_size| {
                        try encodeInteger(list, allocator, 5, 0x20, max_size);
                        self.last_emitted_dynamic_table_size = max_size;
                    },
                    .two => |limits| {
                        try encodeInteger(list, allocator, 5, 0x20, limits.min);
                        try encodeInteger(list, allocator, 5, 0x20, limits.max);
                        self.last_emitted_dynamic_table_size = limits.max;
                    },
                }
                self.pending_size_update = null;
            }

            for (fields) |field| {
                const never_index = field.never_index or sensitiveHeaderName(field.name);
                // One static-table probe per field yields both the exact and
                // the name-only index; hashing the same name twice was a hot
                // spot on the response path.
                const static_indexes = findStaticFieldIndexes(
                    field.name,
                    field.value,
                );
                if (!never_index) {
                    if (static_indexes.exact) |index| {
                        try encodeInteger(list, allocator, 7, 0x80, index);
                        continue;
                    }
                    const dynamic_exact_index = if (self.dynamic_table.entryCount() != 0)
                        self.dynamic_table.findIndex(field.name, field.value)
                    else
                        null;
                    if (dynamic_exact_index) |index| {
                        try encodeInteger(list, allocator, 7, 0x80, index);
                        continue;
                    }
                }

                const skip_value_index = skipValueIndex(field.name);
                const can_incrementally_index = !never_index and !skip_value_index and shouldIndexField(field, self.dynamic_table.size_limit);
                const literal_without_indexing_prefix: u8 = if (never_index) 0x10 else 0x00;
                const name_index = static_indexes.name orelse
                    (if (self.dynamic_table.entryCount() != 0)
                        self.dynamic_table.findNameIndex(field.name)
                    else
                        null);
                if (name_index) |index| {
                    if (can_incrementally_index) {
                        try encodeInteger(list, allocator, 6, 0x40, index);
                    } else {
                        try encodeInteger(list, allocator, 4, literal_without_indexing_prefix, index);
                    }
                } else {
                    if (can_incrementally_index) {
                        try encodeInteger(list, allocator, 6, 0x40, 0);
                    } else {
                        try encodeInteger(list, allocator, 4, literal_without_indexing_prefix, 0);
                    }
                    try encodeString(list, allocator, field.name);
                }
                try encodeString(list, allocator, field.value);
                if (can_incrementally_index) try self.dynamic_table.add(allocator, field.name, field.value);
            }
        }

        /// Encode into connection-owned scratch retained by this encoder.
        ///
        /// The returned bytes are valid until the next retained encode or
        /// `deinit`. Runtime connections use this path so a small HEADERS frame
        /// does not allocate and free an ArrayList on every request/response.
        pub fn encodeBlockRetained(
            self: *Encoder,
            allocator: std.mem.Allocator,
            fields: []const HeaderField,
        ) ![]const u8 {
            self.encoded_scratch.clearRetainingCapacity();
            try self.encodeBlock(
                &self.encoded_scratch,
                allocator,
                fields,
            );
            return self.encoded_scratch.items;
        }

        fn queueSizeUpdate(self: *Encoder, max_size: usize) void {
            const pending = self.pending_size_update orelse {
                if (max_size != self.last_emitted_dynamic_table_size) self.pending_size_update = .{ .one = max_size };
                return;
            };

            self.pending_size_update = switch (pending) {
                .one => |old| if (max_size > old)
                    if (old > self.last_emitted_dynamic_table_size)
                        .{ .one = max_size }
                    else
                        .{ .two = .{ .min = old, .max = max_size } }
                else
                    .{ .one = max_size },
                .two => |limits| if (max_size < limits.min)
                    .{ .one = max_size }
                else
                    .{ .two = .{ .min = limits.min, .max = max_size } },
            };
        }
    };

    /// Static-table indexes for one field: the exact (name and value) match
    /// and the name-only match, resolved from one name probe.
    pub const StaticFieldIndexes = struct {
        exact: ?u64 = null,
        name: ?u64 = null,
    };

    pub fn findStaticFieldIndexes(
        name: []const u8,
        value: []const u8,
    ) StaticFieldIndexes {
        if (name.len != 0 and name[0] == ':') {
            return pseudoStaticFieldIndexes(name, value);
        }
        const indexes = static_name_index.get(name) orelse return .{};
        var result = StaticFieldIndexes{ .name = indexes[0] };
        // HPACK field encoding queries the static table for every header.  The
        // Work reference implementations scan the whole 61-entry table; this
        // comptime name index narrows exact probes to only the candidate
        // entries while preserving HPACK's one-indexed RFC order.
        for (indexes) |index| {
            const entry = static_table[index - 1];
            if (std.mem.eql(u8, entry.value, value)) {
                result.exact = index;
                break;
            }
        }
        return result;
    }

    pub fn findStaticIndex(name: []const u8, value: []const u8) ?u64 {
        return findStaticFieldIndexes(name, value).exact;
    }

    pub fn findStaticNameIndex(name: []const u8) ?u64 {
        if (name.len != 0 and name[0] == ':') {
            return pseudoStaticFieldIndexes(name, "").name;
        }
        const indexes = static_name_index.get(name) orelse return null;
        return indexes[0];
    }

    fn pseudoStaticFieldIndexes(
        name: []const u8,
        value: []const u8,
    ) StaticFieldIndexes {
        if (std.mem.eql(u8, name, ":method")) {
            const exact: ?u64 = if (std.mem.eql(u8, value, "GET"))
                2
            else if (std.mem.eql(u8, value, "POST"))
                3
            else
                null;
            return .{ .name = 2, .exact = exact };
        }
        if (std.mem.eql(u8, name, ":path")) {
            const exact: ?u64 = if (std.mem.eql(u8, value, "/"))
                4
            else if (std.mem.eql(u8, value, "/index.html"))
                5
            else
                null;
            return .{ .name = 4, .exact = exact };
        }
        if (std.mem.eql(u8, name, ":scheme")) {
            const exact: ?u64 = if (std.mem.eql(u8, value, "http"))
                6
            else if (std.mem.eql(u8, value, "https"))
                7
            else
                null;
            return .{ .name = 6, .exact = exact };
        }
        if (std.mem.eql(u8, name, ":status")) {
            const exact: ?u64 = if (std.mem.eql(u8, value, "200"))
                8
            else if (std.mem.eql(u8, value, "204"))
                9
            else if (std.mem.eql(u8, value, "206"))
                10
            else if (std.mem.eql(u8, value, "304"))
                11
            else if (std.mem.eql(u8, value, "400"))
                12
            else if (std.mem.eql(u8, value, "404"))
                13
            else if (std.mem.eql(u8, value, "500"))
                14
            else
                null;
            return .{ .name = 8, .exact = exact };
        }
        if (std.mem.eql(u8, name, ":authority")) {
            return .{ .name = 1, .exact = if (value.len == 0) 1 else null };
        }
        // Unknown pseudo-header: no static entry.
        return .{};
    }

    pub fn sensitiveHeaderName(name: []const u8) bool {
        return std.ascii.eqlIgnoreCase(name, "authorization") or
            std.ascii.eqlIgnoreCase(name, "proxy-authorization") or
            std.ascii.eqlIgnoreCase(name, "cookie") or
            std.ascii.eqlIgnoreCase(name, "set-cookie");
    }

    fn skipValueIndex(name: []const u8) bool {
        // Mirroring h2/hyper's HPACK table policy, avoid indexing header values
        // that are usually request-specific or validators.  This is distinct
        // from `never_index`: peers may index these values if they choose, but
        // this encoder does not burn dynamic-table capacity on them.
        return std.mem.eql(u8, name, ":path") or
            std.ascii.eqlIgnoreCase(name, "age") or
            std.ascii.eqlIgnoreCase(name, "content-length") or
            std.ascii.eqlIgnoreCase(name, "etag") or
            std.ascii.eqlIgnoreCase(name, "if-modified-since") or
            std.ascii.eqlIgnoreCase(name, "if-none-match") or
            std.ascii.eqlIgnoreCase(name, "location");
    }

    pub fn encodeLiteralBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const HeaderField) !void {
        var encoder = Encoder{};
        defer encoder.deinit(allocator);
        try encoder.encodeBlock(list, allocator, fields);
    }

    /// Decode a self-contained HPACK field block.  For long-lived HTTP/2
    /// connections use `Hpack.Decoder` so incremental-indexing state survives
    /// across HEADERS/CONTINUATION blocks.  Legal leading dynamic table-size
    /// updates are still honored here because encoders may emit them before the
    /// first literal even when the block later references only static entries.
    /// Decoder-owned string storage (for Huffman literals) is released with
    /// `freeDecodedFields`.
    pub fn decodeLiteralBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
        var dynamic_table = DynamicTable{
            .maintain_lookup_indexes = false,
        };
        defer dynamic_table.deinit(allocator);
        return decodeBlockWithDynamicTable(allocator, block, &dynamic_table, default_dynamic_table_size);
    }

    pub fn freeDecodedFields(allocator: std.mem.Allocator, fields: []HeaderField) void {
        freeFieldStorages(allocator, fields);
        allocator.free(fields);
    }

    pub fn freeDecodedFieldStorages(allocator: std.mem.Allocator, fields: []HeaderField) void {
        freeFieldStorages(allocator, fields);
    }

    fn freeFieldStorages(allocator: std.mem.Allocator, fields: []HeaderField) void {
        for (fields) |*field| {
            if (field.name_storage) |name| {
                allocator.free(name);
                field.name_storage = null;
            }
            if (field.value_storage) |value| {
                allocator.free(value);
                field.value_storage = null;
            }
            if (field.block_storage) |storage| {
                allocator.free(storage);
                field.block_storage = null;
            }
        }
    }

    pub fn encodeHuffman(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
        return huffman_codec.encodeHuffman(allocator, value);
    }

    pub fn encodeHuffmanWithLen(allocator: std.mem.Allocator, value: []const u8, encoded_len: usize) ![]u8 {
        return huffman_codec.encodeHuffmanWithLen(
            allocator,
            value,
            encoded_len,
        );
    }

    pub fn huffmanEncodedLen(value: []const u8) !usize {
        return huffman_codec.encodedLen(value);
    }

    pub fn decodeHuffman(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
        return huffman_codec.decodeHuffman(allocator, encoded);
    }

    fn decodeHuffmanWithLen(
        allocator: std.mem.Allocator,
        encoded: []const u8,
        decoded_len: usize,
    ) ![]u8 {
        return huffman_codec.decodeHuffmanWithLen(
            allocator,
            encoded,
            decoded_len,
        );
    }

    pub fn huffmanDecodedLen(encoded: []const u8) !usize {
        return huffman_codec.decodedLen(encoded);
    }

    const FieldDecoder = @import("hpack/decode_fields.zig").Decoder(struct {
        pub const Header = HeaderField;
        pub const Table = DynamicTable;
        pub const Cursor = wire.Cursor;
        pub const integer = decodeInteger;
        pub const string = decodeString;
        pub const copyField = indexedHeaderOwned;
        pub const copyName = indexedNameOwned;
        pub const freeFields = freeFieldStorages;
    });

    fn decodeBlockWithDynamicTable(
        allocator: std.mem.Allocator,
        block: []const u8,
        dynamic_table: *DynamicTable,
        max_dynamic_table_size: usize,
    ) ![]HeaderField {
        return FieldDecoder.decode(allocator, block, dynamic_table, max_dynamic_table_size);
    }

    fn decodeBlockIntoWithDynamicTable(
        allocator: std.mem.Allocator,
        block: []const u8,
        dynamic_table: *DynamicTable,
        max_dynamic_table_size: usize,
        storage: []HeaderField,
        max_header_list_size: usize,
    ) ![]HeaderField {
        var cursor = wire.Cursor.init(block);
        var count: usize = 0;
        errdefer freeFieldStorages(allocator, storage[0..count]);
        var saw_header = false;
        var header_list_size: usize = 0;
        var header_list_too_large = false;
        var output_too_small = false;
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0x80) != 0) {
                saw_header = true;
                const index = try decodeInteger(first, &cursor, 7);
                const field = try indexedHeader(dynamic_table, index);
                if (!chargeHeaderListSize(
                    &header_list_size,
                    max_header_list_size,
                    field.name.len,
                    field.value.len,
                )) {
                    header_list_too_large = true;
                }
                if (header_list_too_large or output_too_small) continue;
                if (count >= storage.len) {
                    output_too_small = true;
                    continue;
                }
                storage[count] = try indexedHeaderOwned(
                    allocator,
                    dynamic_table,
                    index,
                );
                count += 1;
                continue;
            }

            if ((first & 0xe0) == 0x20) {
                if (saw_header) return error.InvalidEncoding;
                const new_size = std.math.cast(usize, try decodeInteger(first, &cursor, 5)) orelse return error.IntegerOverflow;
                if (new_size > max_dynamic_table_size) return error.InvalidEncoding;
                dynamic_table.setLimit(allocator, new_size);
                continue;
            }

            saw_header = true;
            const indexed_literal = (first & 0x40) != 0;
            const name_index = if (indexed_literal)
                try decodeInteger(first, &cursor, 6)
            else
                try decodeInteger(first, &cursor, 4);
            const never_index = !indexed_literal and (first & 0x10) != 0;

            const literal_name = if (name_index == 0) try scanRawString(&cursor) else null;
            const indexed_name = if (name_index == 0) null else try indexedName(dynamic_table, name_index);
            const value_plan = try scanRawString(&cursor);

            // Decode small strings once into stack scratch and use the
            // written length for header-list accounting. Retained fields
            // still own exact allocations; larger strings keep the exact
            // length walk. Scratch decoding validates without allocating, so
            // a field that crosses the limit causes no output allocation.
            var name_scratch: DecodedScratch = undefined;
            var value_scratch: DecodedScratch = undefined;
            if (literal_name) |plan| try name_scratch.fill(plan);
            try value_scratch.fill(value_plan);
            const name_len = if (literal_name) |plan|
                try name_scratch.decodedLen(plan)
            else
                indexed_name.?.len;
            const value_len = try value_scratch.decodedLen(value_plan);
            if (!chargeHeaderListSize(
                &header_list_size,
                max_header_list_size,
                name_len,
                value_len,
            )) {
                header_list_too_large = true;
            }
            if (!header_list_too_large and !output_too_small and
                count >= storage.len)
            {
                output_too_small = true;
            }
            const retain = !header_list_too_large and !output_too_small;
            // Incremental-indexing fields must still be decoded and inserted
            // after the application output limit is crossed. Otherwise the
            // HPACK table would diverge and corrupt all later header blocks.
            if (!indexed_literal and !retain) continue;

            if (retain) {
                var name = if (literal_name) |plan|
                    try name_scratch.ownedCopy(allocator, plan, name_len)
                else
                    try indexedNameOwned(allocator, dynamic_table, name_index);
                defer if (name.storage) |bytes| allocator.free(bytes);
                var value = try value_scratch.ownedCopy(
                    allocator,
                    value_plan,
                    value_len,
                );
                defer if (value.storage) |bytes| allocator.free(bytes);
                if (indexed_literal) {
                    try dynamic_table.add(allocator, name.value, value.value);
                }
                storage[count] = .{
                    .name = name.value,
                    .value = value.value,
                    .never_index = never_index,
                    .name_storage = name.storage,
                    .value_storage = value.storage,
                };
                name.storage = null;
                value.storage = null;
                count += 1;
                continue;
            }

            // Non-retained incremental-indexing field: decode through
            // stack-first scratch and let the table copy it into persistent
            // storage.
            if (!entryFitsTable(
                dynamic_table.size_limit,
                name_len,
                value_len,
            )) {
                dynamic_table.clear(allocator);
                continue;
            }
            const temporary_len = try addOwnedStringBytes(
                0,
                name_len,
                value_len,
            );
            var temporary_fallback = std.heap.stackFallback(
                default_dynamic_table_size,
                allocator,
            );
            const temporary_allocator = temporary_fallback.get();
            const temporary = try temporary_allocator.alloc(u8, temporary_len);
            defer temporary_allocator.free(temporary);
            const name = temporary[0..name_len];
            if (literal_name) |plan| {
                try plan.decodeInto(name);
            } else {
                @memcpy(name, indexed_name.?);
            }
            const value = temporary[name.len..][0..value_len];
            try value_plan.decodeInto(value);
            try dynamic_table.add(allocator, name, value);
        }
        if (header_list_too_large) return error.HeaderListTooLarge;
        if (output_too_small) return error.BufferTooShort;
        return storage[0..count];
    }

    const OwnedFieldPlan = struct {
        name_offset: usize,
        name_len: usize,
        value_offset: usize,
        value_len: usize,
        never_index: bool,
    };

    fn decodeBlockOwnedWithDynamicTable(
        allocator: std.mem.Allocator,
        block: []const u8,
        dynamic_table: *DynamicTable,
        max_dynamic_table_size: usize,
        max_header_fields: usize,
        max_header_list_size: usize,
        field_limit_exceeded: *bool,
    ) ![]HeaderField {
        field_limit_exceeded.* = false;
        var plan_fallback = std.heap.stackFallback(
            owned_plan_stack_fields * @sizeOf(OwnedFieldPlan),
            allocator,
        );
        const plan_allocator = plan_fallback.get();
        var plans: std.ArrayList(OwnedFieldPlan) = .empty;
        defer plans.deinit(plan_allocator);
        // The default runtime header-list budget fits here, so building the
        // final byte sequence normally stays stack-only. Larger configured
        // sections fall back to the caller allocator, but still avoid one
        // allocation per Huffman or dynamic field.
        var string_fallback = std.heap.stackFallback(
            owned_string_stack_bytes,
            allocator,
        );
        const string_allocator = string_fallback.get();
        var strings: std.ArrayList(u8) = .empty;
        defer strings.deinit(string_allocator);

        var cursor = wire.Cursor.init(block);
        var saw_header = false;
        var header_list_size: usize = 0;
        var header_list_too_large = false;
        var output_too_small = false;
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0x80) != 0) {
                saw_header = true;
                const field = try indexedHeader(
                    dynamic_table,
                    try decodeInteger(first, &cursor, 7),
                );
                if (!chargeHeaderListSize(
                    &header_list_size,
                    max_header_list_size,
                    field.name.len,
                    field.value.len,
                )) header_list_too_large = true;
                if (!header_list_too_large and !output_too_small and
                    plans.items.len >= max_header_fields)
                {
                    output_too_small = true;
                }
                if (header_list_too_large or output_too_small) continue;
                try appendOwnedFieldPlan(
                    &plans,
                    plan_allocator,
                    &strings,
                    string_allocator,
                    .{
                        .raw = field.name,
                        .huffman = false,
                        .decoded_len = field.name.len,
                    },
                    .{
                        .raw = field.value,
                        .huffman = false,
                        .decoded_len = field.value.len,
                    },
                    field.never_index,
                );
                continue;
            }

            if ((first & 0xe0) == 0x20) {
                if (saw_header) return error.InvalidEncoding;
                const new_size = std.math.cast(
                    usize,
                    try decodeInteger(first, &cursor, 5),
                ) orelse return error.IntegerOverflow;
                if (new_size > max_dynamic_table_size) {
                    return error.InvalidEncoding;
                }
                dynamic_table.setLimit(allocator, new_size);
                continue;
            }

            saw_header = true;
            const indexed_literal = (first & 0x40) != 0;
            const name_index = if (indexed_literal)
                try decodeInteger(first, &cursor, 6)
            else
                try decodeInteger(first, &cursor, 4);
            const literal_name = if (name_index == 0)
                try scanRawString(&cursor)
            else
                null;
            const indexed_name = if (literal_name == null)
                try indexedName(dynamic_table, name_index)
            else
                null;
            const name_plan = literal_name orelse RawString{
                .raw = indexed_name.?,
                .huffman = false,
            };
            const value_plan = try scanRawString(&cursor);

            // Decode small strings once into stack scratch and use the
            // written length for header-list accounting. Retained fields are
            // appended to the owned string block; larger strings keep the
            // exact length walk. Scratch decoding validates without
            // allocating, so a field that crosses the limit causes no string
            // block growth.
            var name_scratch: DecodedScratch = undefined;
            var value_scratch: DecodedScratch = undefined;
            try name_scratch.fill(name_plan);
            try value_scratch.fill(value_plan);
            const name_len = try name_scratch.decodedLen(name_plan);
            const value_len = try value_scratch.decodedLen(value_plan);
            if (!chargeHeaderListSize(
                &header_list_size,
                max_header_list_size,
                name_len,
                value_len,
            )) header_list_too_large = true;
            if (!header_list_too_large and !output_too_small and
                plans.items.len >= max_header_fields)
            {
                output_too_small = true;
            }
            const retain = !header_list_too_large and !output_too_small;

            if (retain) {
                const name_offset = strings.items.len;
                try name_scratch.appendTo(
                    &strings,
                    string_allocator,
                    name_plan,
                    name_len,
                );
                const value_offset = strings.items.len;
                try value_scratch.appendTo(
                    &strings,
                    string_allocator,
                    value_plan,
                    value_len,
                );
                if (indexed_literal) {
                    try dynamic_table.add(
                        allocator,
                        strings.items[name_offset..][0..name_len],
                        strings.items[value_offset..][0..value_len],
                    );
                }
                try plans.ensureUnusedCapacity(plan_allocator, 1);
                plans.appendAssumeCapacity(.{
                    .name_offset = name_offset,
                    .name_len = name_len,
                    .value_offset = value_offset,
                    .value_len = value_len,
                    .never_index = !indexed_literal and (first & 0x10) != 0,
                });
                continue;
            }
            if (!indexed_literal) continue;

            // Incremental indexing remains mandatory after an output bound is
            // crossed. Decode at most one field through stack-first scratch;
            // the table immediately copies it into persistent storage.
            if (!entryFitsTable(
                dynamic_table.size_limit,
                name_len,
                value_len,
            )) {
                // RFC 7541 §4.4 only requires clearing the table for an entry
                // larger than its limit. Scanning already validated Huffman,
                // so no potentially huge temporary decode is necessary.
                dynamic_table.clear(allocator);
                continue;
            }
            const temporary_len = try addOwnedStringBytes(
                0,
                name_len,
                value_len,
            );
            var temporary_fallback = std.heap.stackFallback(
                default_dynamic_table_size,
                allocator,
            );
            const temporary_allocator = temporary_fallback.get();
            const temporary = try temporary_allocator.alloc(u8, temporary_len);
            defer temporary_allocator.free(temporary);
            const name = temporary[0..name_len];
            try name_plan.decodeInto(name);
            const value = temporary[name.len..][0..value_len];
            try value_plan.decodeInto(value);
            try dynamic_table.add(allocator, name, value);
        }

        if (header_list_too_large) return error.HeaderListTooLarge;
        if (output_too_small) {
            field_limit_exceeded.* = true;
            return error.BufferTooShort;
        }
        if (plans.items.len == 0) {
            return allocator.alloc(HeaderField, 0);
        }
        const field_bytes = std.math.mul(
            usize,
            plans.items.len,
            @sizeOf(HeaderField),
        ) catch return error.OutOfMemory;
        const allocation_len = std.math.add(
            usize,
            field_bytes,
            strings.items.len,
        ) catch return error.OutOfMemory;
        const allocation = try allocator.alignedAlloc(
            u8,
            .of(HeaderField),
            allocation_len,
        );
        const fields: []HeaderField = @as(
            [*]HeaderField,
            @ptrCast(allocation.ptr),
        )[0..plans.items.len];
        const owned_strings = allocation[field_bytes..];
        @memcpy(owned_strings, strings.items);
        for (plans.items, fields, 0..) |plan, *field, index| {
            field.* = .{
                .name = owned_strings[plan.name_offset..][0..plan.name_len],
                .value = owned_strings[plan.value_offset..][0..plan.value_len],
                .never_index = plan.never_index,
                .block_storage = if (index == 0) allocation else null,
            };
        }
        return fields;
    }

    fn appendOwnedFieldPlan(
        plans: *std.ArrayList(OwnedFieldPlan),
        plan_allocator: std.mem.Allocator,
        strings: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        name: EncodedString,
        value: EncodedString,
        never_index: bool,
    ) !void {
        try plans.ensureUnusedCapacity(plan_allocator, 1);
        const additional = try addOwnedStringBytes(
            0,
            name.decoded_len,
            value.decoded_len,
        );
        try strings.ensureUnusedCapacity(allocator, additional);
        const original_len = strings.items.len;
        errdefer strings.items.len = original_len;
        const name_offset = strings.items.len;
        try name.appendDecodedAssumeCapacity(strings);
        const value_offset = strings.items.len;
        try value.appendDecodedAssumeCapacity(strings);
        plans.appendAssumeCapacity(.{
            .name_offset = name_offset,
            .name_len = name.decoded_len,
            .value_offset = value_offset,
            .value_len = value.decoded_len,
            .never_index = never_index,
        });
    }

    /// Release fields returned by `decodeBlockOwnedWithLimit`, as well as the
    /// legacy two-allocation layout used by callers that clone header lists.
    pub fn freeOwnedFields(
        allocator: std.mem.Allocator,
        fields: []HeaderField,
    ) void {
        if (fields.len != 0) {
            if (fields[0].block_storage) |strings| {
                if (@intFromPtr(fields.ptr) == @intFromPtr(strings.ptr)) {
                    const allocation: []align(@alignOf(HeaderField)) u8 =
                        @alignCast(strings);
                    allocator.free(allocation);
                    return;
                }
                allocator.free(strings);
            }
        }
        allocator.free(fields);
    }

    fn addOwnedStringBytes(
        current: usize,
        name_len: usize,
        value_len: usize,
    ) Error!usize {
        return std.math.add(
            usize,
            std.math.add(usize, current, name_len) catch
                return error.IntegerOverflow,
            value_len,
        ) catch return error.IntegerOverflow;
    }

    fn entryFitsTable(
        limit: usize,
        name_len: usize,
        value_len: usize,
    ) bool {
        if (name_len > limit) return false;
        var remaining = limit - name_len;
        if (value_len > remaining) return false;
        remaining -= value_len;
        return remaining >= 32;
    }
    pub fn encodeInteger(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        comptime prefix_bits: u4,
        high_bits: u8,
        value: u64,
    ) !void {
        try list.ensureUnusedCapacity(allocator, integerEncodedLen(prefix_bits, value));
        const prefix_max = (@as(u16, 1) << prefix_bits) - 1;
        if (value < prefix_max) {
            list.appendAssumeCapacity(high_bits | @as(u8, @intCast(value)));
            return;
        }

        list.appendAssumeCapacity(high_bits | @as(u8, @intCast(prefix_max)));
        var remaining = value - prefix_max;
        while (remaining >= 128) {
            list.appendAssumeCapacity(@as(u8, @intCast(remaining & 0x7f)) | 0x80);
            remaining >>= 7;
        }
        list.appendAssumeCapacity(@intCast(remaining));
    }

    fn integerEncodedLen(comptime prefix_bits: u4, value: u64) usize {
        const prefix_max = (@as(u16, 1) << prefix_bits) - 1;
        if (value < prefix_max) return 1;
        var len: usize = 2;
        var remaining = value - prefix_max;
        while (remaining >= 128) : (remaining >>= 7) {
            len += 1;
        }
        return len;
    }
    pub fn decodeInteger(first: u8, cursor: *wire.Cursor, comptime prefix_bits: u4) Error!u64 {
        const prefix_max: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
        var value: u64 = first & prefix_max;
        if (value < prefix_max) return value;

        var shift: usize = 0;
        while (true) {
            const byte = try cursor.readByte();
            if (shift >= @bitSizeOf(u64)) return error.IntegerOverflow;
            const increment = std.math.shlExact(
                u64,
                @as(u64, byte & 0x7f),
                @intCast(shift),
            ) catch return error.IntegerOverflow;
            value = std.math.add(u64, value, increment) catch
                return error.IntegerOverflow;
            if ((byte & 0x80) == 0) return value;
            if (shift > @bitSizeOf(u64) - 7) {
                return error.IntegerOverflow;
            }
            shift += 7;
        }
    }

    /// Header values up to this length fit the worst-case Huffman scratch
    /// buffer, so they can be encoded once and measured from the result.
    const huffman_encode_scratch_bytes: usize = 512;
    const huffman_encode_scratch_max_input: usize = 320;

    fn encodeString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
        if (value.len == 0) {
            try list.ensureUnusedCapacity(allocator, 1);
            list.appendAssumeCapacity(0);
            return;
        }
        if (value.len <= 2) {
            try list.ensureUnusedCapacity(allocator, 1 + value.len);
            list.appendAssumeCapacity(@intCast(value.len));
            list.appendSliceAssumeCapacity(value);
            return;
        }
        if (value.len <= huffman_encode_scratch_max_input) {
            var scratch: [huffman_encode_scratch_bytes]u8 = undefined;
            const written = huffman_codec.encodeHuffmanIntoBounded(
                &scratch,
                value,
            ) catch unreachable;
            if (written >= value.len) {
                try list.ensureUnusedCapacity(allocator, integerEncodedLen(7, value.len) + value.len);
                try encodeInteger(list, allocator, 7, 0x00, value.len);
                list.appendSliceAssumeCapacity(value);
                return;
            }
            try list.ensureUnusedCapacity(allocator, integerEncodedLen(7, written) + written);
            try encodeInteger(list, allocator, 7, 0x80, written);
            list.appendSliceAssumeCapacity(scratch[0..written]);
            return;
        }
        const huffman_len = try huffmanEncodedLen(value);
        if (huffman_len >= value.len) {
            try list.ensureUnusedCapacity(allocator, integerEncodedLen(7, value.len) + value.len);
            try encodeInteger(list, allocator, 7, 0x00, value.len);
            list.appendSliceAssumeCapacity(value);
            return;
        }
        try list.ensureUnusedCapacity(allocator, integerEncodedLen(7, huffman_len) + huffman_len);
        try encodeInteger(list, allocator, 7, 0x80, huffman_len);
        // The final block already reserves this exact space, so materializing
        // a temporary Huffman allocation only to copy it here wastes an
        // allocation and a full encoded-byte pass on every compressed string.
        const encoded_start = list.items.len;
        huffman_codec.appendHuffmanAssumeCapacity(
            list,
            value,
            huffman_len,
        );
        std.debug.assert(list.items.len == encoded_start + huffman_len);
    }

    const DecodedString = struct {
        value: []const u8,
        storage: ?[]u8 = null,
    };

    const EncodedString = struct {
        raw: []const u8,
        huffman: bool,
        decoded_len: usize,

        fn decodeInto(self: EncodedString, output: []u8) !void {
            if (output.len != self.decoded_len) return error.InvalidEncoding;
            if (self.huffman) {
                return huffman_codec.decodeHuffmanInto(output, self.raw);
            }
            @memcpy(output, self.raw);
        }

        fn appendDecodedAssumeCapacity(
            self: EncodedString,
            output: *std.ArrayList(u8),
        ) !void {
            std.debug.assert(
                output.capacity - output.items.len >= self.decoded_len,
            );
            const start = output.items.len;
            output.items.len += self.decoded_len;
            errdefer output.items.len = start;
            try self.decodeInto(output.items[start..]);
        }
    };

    /// Most HPACK strings decode into far less than this scratch buffer, so
    /// the decoder can obtain both the bytes and their length in one pass
    /// instead of walking the trie twice. Larger strings keep the exact-length
    /// two-pass fallback.
    const decoded_string_scratch_bytes: usize = 512;

    const RawString = struct {
        raw: []const u8,
        huffman: bool,

        fn decodedLen(self: RawString) !usize {
            if (!self.huffman) return self.raw.len;
            return huffmanDecodedLen(self.raw);
        }

        /// Upper bound for the decoded size: every symbol consumes at least
        /// five bits, so eight encoded bits yield at most 8/5 symbols.
        fn maxDecodedLen(self: RawString) usize {
            if (!self.huffman) return self.raw.len;
            const scaled = std.math.mul(usize, self.raw.len, 8) catch
                return std.math.maxInt(usize);
            return scaled / 5;
        }

        fn decodeInto(self: RawString, output: []u8) !void {
            if (!self.huffman) {
                if (output.len != self.raw.len) return error.InvalidEncoding;
                @memcpy(output, self.raw);
                return;
            }
            try huffman_codec.decodeHuffmanInto(output, self.raw);
        }
    };

    fn scanRawString(cursor: *wire.Cursor) !RawString {
        const first = try cursor.readByte();
        const huffman = (first & 0x80) != 0;
        const len = std.math.cast(usize, try decodeInteger(first, cursor, 7)) orelse return error.IntegerOverflow;
        return .{ .raw = try cursor.readSlice(len), .huffman = huffman };
    }

    fn decodeRawStringAlloc(
        allocator: std.mem.Allocator,
        plan: RawString,
    ) !DecodedString {
        if (!plan.huffman) return .{ .value = plan.raw };
        var scratch: [decoded_string_scratch_bytes]u8 = undefined;
        if (huffman_codec.decodeHuffmanIntoBounded(&scratch, plan.raw)) |written| {
            const decoded = try allocator.dupe(u8, scratch[0..written]);
            return .{ .value = decoded, .storage = decoded };
        } else |err| switch (err) {
            error.BufferTooShort => {
                const decoded_len = try huffmanDecodedLen(plan.raw);
                const decoded = try decodeHuffmanWithLen(
                    allocator,
                    plan.raw,
                    decoded_len,
                );
                return .{ .value = decoded, .storage = decoded };
            },
            else => return err,
        }
    }

    /// A stack scratch buffer holding one decoded string. `fill` validates and
    /// decodes small strings without allocating; `decodedLen` falls back to
    /// the length walk for strings that do not fit.
    const DecodedScratch = struct {
        bytes: [decoded_string_scratch_bytes]u8 = undefined,
        written: ?usize = null,

        fn fill(self: *DecodedScratch, plan: RawString) !void {
            self.written = null;
            if (!plan.huffman) return;
            if (plan.maxDecodedLen() > self.bytes.len) return;
            self.written = try huffman_codec.decodeHuffmanIntoBounded(
                &self.bytes,
                plan.raw,
            );
        }

        fn decodedLen(self: *const DecodedScratch, plan: RawString) !usize {
            return self.written orelse try plan.decodedLen();
        }

        /// Return an owned copy for retained caller-buffer fields. Literal
        /// non-Huffman strings keep the historical borrowed representation.
        fn ownedCopy(
            self: *const DecodedScratch,
            allocator: std.mem.Allocator,
            plan: RawString,
            decoded_len: usize,
        ) !DecodedString {
            if (!plan.huffman) return .{ .value = plan.raw };
            if (self.written) |written| {
                const copy = try allocator.dupe(u8, self.bytes[0..written]);
                return .{ .value = copy, .storage = copy };
            }
            const decoded = try decodeHuffmanWithLen(
                allocator,
                plan.raw,
                decoded_len,
            );
            return .{ .value = decoded, .storage = decoded };
        }

        fn appendTo(
            self: *const DecodedScratch,
            strings: *std.ArrayList(u8),
            allocator: std.mem.Allocator,
            plan: RawString,
            decoded_len: usize,
        ) !void {
            if (!plan.huffman) {
                try strings.appendSlice(allocator, plan.raw);
                return;
            }
            if (self.written) |written| {
                try strings.appendSlice(allocator, self.bytes[0..written]);
                return;
            }
            const start = strings.items.len;
            try strings.ensureUnusedCapacity(allocator, decoded_len);
            strings.items.len = start + decoded_len;
            errdefer strings.items.len = start;
            try huffman_codec.decodeHuffmanInto(strings.items[start..], plan.raw);
        }
    };

    fn decodeString(allocator: std.mem.Allocator, cursor: *wire.Cursor) !DecodedString {
        return decodeRawStringAlloc(allocator, try scanRawString(cursor));
    }

    fn scanString(cursor: *wire.Cursor) !EncodedString {
        const first = try cursor.readByte();
        const huffman = (first & 0x80) != 0;
        const len = std.math.cast(usize, try decodeInteger(first, cursor, 7)) orelse return error.IntegerOverflow;
        const raw = try cursor.readSlice(len);
        return .{
            .raw = raw,
            .huffman = huffman,
            .decoded_len = if (huffman) try huffmanDecodedLen(raw) else raw.len,
        };
    }

    fn chargeHeaderListSize(
        total: *usize,
        max_size: usize,
        name_len: usize,
        value_len: usize,
    ) bool {
        const field_size = std.math.add(
            usize,
            std.math.add(usize, name_len, value_len) catch return false,
            32,
        ) catch return false;
        total.* = std.math.add(usize, total.*, field_size) catch return false;
        return total.* <= max_size;
    }

    fn staticEntry(index: u64) Error!StaticEntry {
        if (index == 0) return error.InvalidEncoding;
        if (index > static_table.len) return error.HpackDynamicTableUnsupported;
        return static_table[@intCast(index - 1)];
    }

    fn indexedHeader(
        dynamic_table: *DynamicTable,
        index: u64,
    ) Error!HeaderField {
        if (index <= static_table.len) {
            const entry = try staticEntry(index);
            return .{ .name = entry.name, .value = entry.value };
        }
        const dynamic_index = std.math.cast(
            usize,
            index - static_table.len - 1,
        ) orelse return error.IntegerOverflow;
        return dynamic_table.get(dynamic_index) orelse
            error.HpackDynamicTableUnsupported;
    }

    fn indexedName(
        dynamic_table: *DynamicTable,
        index: u64,
    ) Error![]const u8 {
        return (try indexedHeader(dynamic_table, index)).name;
    }

    fn indexedHeaderOwned(allocator: std.mem.Allocator, dynamic_table: *DynamicTable, index: u64) Error!HeaderField {
        const entry = try indexedHeader(dynamic_table, index);
        if (index <= static_table.len) return entry;
        return ownedHeaderField(
            allocator,
            entry.name,
            entry.value,
            entry.never_index,
        );
    }

    fn ownedHeaderField(
        allocator: std.mem.Allocator,
        name: []const u8,
        value: []const u8,
        never_index: bool,
    ) !HeaderField {
        const string_len = std.math.add(
            usize,
            name.len,
            value.len,
        ) catch return error.OutOfMemory;
        const strings = try allocator.alloc(u8, string_len);
        @memcpy(strings[0..name.len], name);
        @memcpy(strings[name.len..], value);
        return .{
            .name = strings[0..name.len],
            .value = strings[name.len..],
            .never_index = never_index,
            .block_storage = strings,
        };
    }

    fn indexedNameOwned(allocator: std.mem.Allocator, dynamic_table: *DynamicTable, index: u64) Error!DecodedString {
        const name = try indexedName(dynamic_table, index);
        if (index <= static_table.len) return .{ .value = name };
        const copy = try allocator.dupe(u8, name);
        return .{ .value = copy, .storage = copy };
    }

    fn entrySize(name: []const u8, value: []const u8) usize {
        return name.len + value.len + 32;
    }

    fn shouldIndexField(field: HeaderField, table_limit: usize) bool {
        const size = entrySize(field.name, field.value);
        if (size > table_limit) return false;
        // Rust h2/hyper avoids indexing entries that would consume more than
        // 75% of the table.  The threshold keeps a single large value from
        // evicting most useful history while still allowing legal HPACK output.
        const threshold = (table_limit / 4) * 3 + ((table_limit % 4) * 3) / 4;
        return size <= threshold;
    }
};

pub fn checkHpackDecoderTableWithoutLookupIndexes(
    allocator: std.mem.Allocator,
) !void {
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    var output: [1]Hpack.HeaderField = undefined;

    const first = try decoder.decodeBlockInto(
        allocator,
        "\x40\x09x-inbound\x05value",
        &output,
    );
    Hpack.freeDecodedFieldStorages(allocator, first);
    const second = try decoder.decodeBlockInto(
        allocator,
        "\x7e\x06second",
        &output,
    );
    Hpack.freeDecodedFieldStorages(allocator, second);
    const indexed = try decoder.decodeBlockInto(
        allocator,
        &.{0xbe},
        &output,
    );
    defer Hpack.freeDecodedFieldStorages(allocator, indexed);
    var cloned = try decoder.dynamic_table.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expectEqualStrings("second", indexed[0].value);
    try std.testing.expectEqual(@as(usize, 0), decoder.dynamic_table.latest_name.count());
    try std.testing.expectEqual(@as(usize, 0), decoder.dynamic_table.latest_exact.count());
    try std.testing.expect(!cloned.maintain_lookup_indexes);
    try std.testing.expectEqual(@as(usize, 0), cloned.latest_name.count());
    try std.testing.expectEqual(@as(usize, 0), cloned.latest_exact.count());
    try std.testing.expectEqualStrings("second", cloned.get(0).?.value);
}

pub fn checkHpackContiguousDynamicStorage(allocator: std.mem.Allocator) !void {
    var table = Hpack.DynamicTable{};
    defer table.deinit(allocator);
    table.setLimit(allocator, 96);
    try table.add(allocator, "x-one", "one");
    try table.add(allocator, "x-two", "two");
    try table.add(allocator, "x-three", "three");
    try std.testing.expect(table.findIndex("x-one", "one") == null);
    try std.testing.expect(table.findIndex("x-three", "three") != null);

    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeBlock(&block, allocator, &.{.{
        .name = "x-output",
        .value = "value",
    }});
    var scratch: [1]Hpack.HeaderField = undefined;
    const first = try decoder.decodeBlockInto(allocator, block.items, &scratch);
    Hpack.freeDecodedFieldStorages(allocator, first);
    block.clearRetainingCapacity();
    try encoder.encodeBlock(&block, allocator, &.{.{
        .name = "x-output",
        .value = "value",
    }});
    const second = try decoder.decodeBlockInto(allocator, block.items, &scratch);
    defer Hpack.freeDecodedFieldStorages(allocator, second);
    const storage = second[0].block_storage orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(second[0].name_storage == null);
    try std.testing.expect(second[0].value_storage == null);
    try std.testing.expectEqual(storage.ptr, second[0].name.ptr);
    try std.testing.expectEqual(
        storage.ptr + second[0].name.len,
        second[0].value.ptr,
    );
}

pub fn checkHpackOwnedDecode(allocator: std.mem.Allocator) !void {
    const fields = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-compressible-name", .value = "compressible-value" },
        .{ .name = "authorization", .value = "sensitive-value" },
    };
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeBlock(&block, allocator, &fields);

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const first = try decoder.decodeBlockOwnedWithLimit(
        allocator,
        block.items,
        8,
        1024,
    );
    defer Hpack.freeOwnedFields(allocator, first);
    try std.testing.expectEqual(fields.len, first.len);
    try std.testing.expect(first[0].block_storage != null);
    try std.testing.expect(first[1].block_storage == null);
    try std.testing.expectEqual(
        @intFromPtr(first.ptr),
        @intFromPtr(first[0].block_storage.?.ptr),
    );
    try std.testing.expectEqualStrings("x-compressible-name", first[1].name);
    try std.testing.expectEqualStrings("compressible-value", first[1].value);
    try std.testing.expect(first[2].never_index);

    block.clearRetainingCapacity();
    try encoder.encodeBlock(&block, allocator, &fields);
    const second = try decoder.decodeBlockOwnedWithLimit(
        allocator,
        block.items,
        8,
        1024,
    );
    defer Hpack.freeOwnedFields(allocator, second);
    try std.testing.expectEqualStrings("x-compressible-name", second[1].name);
    try std.testing.expectEqualStrings("compressible-value", second[1].value);
}

pub fn checkHpackOwnedDecodeScratchFallback(
    allocator: std.mem.Allocator,
) !void {
    const field_count = Hpack.owned_plan_stack_fields + 1;
    const large_value = [_]u8{'a'} ** (Hpack.owned_string_stack_bytes + 1);
    var fields: [field_count]Hpack.HeaderField = undefined;
    for (&fields, 0..) |*field, index| {
        const value: []const u8 = if (index == 0)
            &large_value
        else
            "v";
        field.* = .{
            .name = "authorization",
            .value = value,
            .never_index = true,
        };
    }
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeBlock(&block, allocator, &fields);

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const decoded = try decoder.decodeBlockOwnedWithLimit(
        allocator,
        block.items,
        field_count,
        32 * 1024,
    );
    defer Hpack.freeOwnedFields(allocator, decoded);
    try std.testing.expectEqual(@as(usize, field_count), decoded.len);
    try std.testing.expectEqual(
        Hpack.owned_string_stack_bytes + 1,
        decoded[0].value.len,
    );
}

test {
    _ = priority_field;
    _ = @import("hpack/tests/decoded_fields.zig");
    _ = @import("runtime/client_pool_tests.zig");
    _ = @import("client_pool/admission_tests.zig");
    _ = @import("runtime/shared_client_pool_tests.zig");
    _ = runtime;
}

test {
    _ = @import("tests.zig");
}
