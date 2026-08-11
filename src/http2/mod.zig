const std = @import("std");
const wire = @import("../internal/wire.zig");
const priority_field = @import("../internal/priority.zig");
const hpack_huffman = @import("hpack_huffman.zig");

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
        try validateSetting(id, value);
        try settings.append(allocator, .{ .id = id, .value = value });
    }
    return settings.toOwnedSlice(allocator);
}

pub fn writeSettings(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: []const Setting) Error!void {
    for (settings) |setting| {
        try validateSetting(setting.id, setting.value);
        try wire.appendInt(list, allocator, u16, @intFromEnum(setting.id), .big);
        try wire.appendInt(list, allocator, u32, setting.value, .big);
    }
}

pub fn validateSetting(id: SettingId, value: u32) Error!void {
    switch (id) {
        .enable_push => if (value > 1) return error.InvalidSetting,
        .enable_connect_protocol => if (value > 1) return error.InvalidSetting,
        .no_rfc7540_priorities => if (value > 1) return error.InvalidSetting,
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
        var payload: [5]u8 = undefined;
        var dep = @as(u32, stream_dependency);
        if (exclusive) dep |= 0x8000_0000;
        std.mem.writeInt(u32, payload[0..4], dep, .big);
        payload[4] = weight;
        try (Frame{
            .header = .{ .length = 0, .frame_type = .priority, .flags = 0, .stream_id = stream_id },
            .payload = &payload,
        }).write(list, allocator);
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
        try wire.appendU24(list, allocator, std.math.cast(u24, payload_len) orelse return error.InvalidFrameSize);
        try list.append(allocator, @intFromEnum(FrameType.priority_update));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u32, 0, .big);
        try wire.appendInt(
            list,
            allocator,
            u32,
            prioritized_stream_id,
            .big,
        );
        try list.appendSlice(allocator, field_value);
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

        try wire.appendU24(list, allocator, std.math.cast(u24, payload_len) orelse return error.InvalidFrameSize);
        try list.append(allocator, @intFromEnum(FrameType.push_promise));
        try list.append(allocator, (if (options.end_headers) @as(u8, 0x4) else 0) | if (options.padding_len != 0) @as(u8, 0x8) else 0);
        try wire.appendInt(list, allocator, u32, @as(u32, stream_id), .big);
        if (options.padding_len != 0) try list.append(allocator, options.padding_len);
        try wire.appendInt(list, allocator, u32, @as(u32, promised_stream_id), .big);
        try list.appendSlice(allocator, header_block);
        try list.appendNTimes(allocator, 0, options.padding_len);
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
        var cursor = wire.Cursor.init(frame.payload);
        var origins: std.ArrayList([]const u8) = .empty;
        errdefer origins.deinit(allocator);
        while (!cursor.eof()) {
            const len = try cursor.readInt(u16, .big);
            const origin = cursor.readSlice(len) catch
                return error.InvalidFrameSize;
            if (origin.len == 0 or !validOriginAscii(origin)) {
                return error.InvalidFrameSize;
            }
            try origins.append(allocator, origin);
        }
        return .{ .origins = try origins.toOwnedSlice(allocator) };
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
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        for (origins) |origin| {
            if (origin.len == 0 or
                origin.len > std.math.maxInt(u16) or
                !validOriginAscii(origin))
            {
                return error.InvalidFrameSize;
            }
            try wire.appendInt(
                &payload,
                allocator,
                u16,
                @intCast(origin.len),
                .big,
            );
            try payload.appendSlice(allocator, origin);
        }
        try (Frame{
            .header = .{
                .length = 0,
                .frame_type = .origin,
                .flags = 0,
                .stream_id = 0,
            },
            .payload = payload.items,
        }).write(list, allocator);
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
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        try wire.appendInt(
            &payload,
            allocator,
            u16,
            @intCast(origin.len),
            .big,
        );
        try payload.appendSlice(allocator, origin);
        try payload.appendSlice(allocator, field_value);
        try (Frame{
            .header = .{
                .length = 0,
                .frame_type = .altsvc,
                .flags = 0,
                .stream_id = stream_id,
            },
            .payload = payload.items,
        }).write(list, allocator);
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
            priority = try Priority.parse(frame.payload[pos .. pos + 5]);
            if (priority.?.stream_dependency == frame.header.stream_id) return error.InvalidStreamId;
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
        const payload_len = std.math.add(usize, 8, debug_data.len) catch return error.InvalidFrameSize;
        try wire.appendU24(list, allocator, std.math.cast(u24, payload_len) orelse return error.InvalidFrameSize);
        try list.append(allocator, @intFromEnum(FrameType.goaway));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u32, 0, .big);
        try wire.appendInt(list, allocator, u32, @as(u32, last_stream_id), .big);
        try wire.appendInt(list, allocator, u32, @intFromEnum(error_code), .big);
        try list.appendSlice(allocator, debug_data);
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
    pub const default_dynamic_table_size: usize = 4096;

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
    };

    pub const DynamicTable = struct {
        entries: std.ArrayList(HeaderField) = .empty,
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
                allocator.free(item.name);
                allocator.free(item.value);
            }
            self.entries.clearRetainingCapacity();
            self.latest_name.clearRetainingCapacity();
            self.latest_exact.clearRetainingCapacity();
            self.used = 0;
            self.head = 0;
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
            const name_slot = try self.latest_name.getOrPut(allocator, name);
            errdefer if (!name_slot.found_existing) {
                _ = self.latest_name.remove(name);
            };
            const exact_key = DynamicExactKey{ .name = name, .value = value };
            const exact_slot = try self.latest_exact.getOrPut(allocator, exact_key);
            errdefer if (!exact_slot.found_existing) {
                _ = self.latest_exact.remove(exact_key);
            };
            const name_copy = try allocator.dupe(u8, name);
            errdefer allocator.free(name_copy);
            const value_copy = try allocator.dupe(u8, value);
            errdefer allocator.free(value_copy);

            const physical_index = self.entries.items.len;
            self.entries.appendAssumeCapacity(.{
                .name = name_copy,
                .value = value_copy,
            });
            name_slot.key_ptr.* = name_copy;
            name_slot.value_ptr.* = physical_index;
            exact_slot.key_ptr.* = .{ .name = name_copy, .value = value_copy };
            exact_slot.value_ptr.* = physical_index;
            self.used += size;
            self.evictToLimit(allocator);
        }

        fn get(self: DynamicTable, dynamic_index: usize) ?HeaderField {
            const count = self.entryCount();
            if (dynamic_index >= count) return null;
            return self.entries.items[self.entries.items.len - 1 - dynamic_index];
        }

        fn findIndex(self: DynamicTable, name: []const u8, value: []const u8) ?u64 {
            if (self.entryCount() == 0) return null;
            const physical_index = self.latest_exact.get(.{ .name = name, .value = value }) orelse return null;
            if (!self.validPhysicalIndex(physical_index)) return null;
            return self.wireIndexForPhysical(physical_index);
        }

        fn findNameIndex(self: DynamicTable, name: []const u8) ?u64 {
            if (self.entryCount() == 0) return null;
            const physical_index = self.latest_name.get(name) orelse return null;
            if (!self.validPhysicalIndex(physical_index)) return null;
            return self.wireIndexForPhysical(physical_index);
        }

        fn evictToLimit(self: *DynamicTable, allocator: std.mem.Allocator) void {
            while (self.used > self.size_limit and self.entryCount() != 0) {
                const removed = &self.entries.items[self.head];
                self.used -= entrySize(removed.name, removed.value);
                self.removeLatestIndexes(removed.*, self.head);
                allocator.free(removed.name);
                allocator.free(removed.value);
                self.head += 1;
            }
            self.compactIfNeeded();
        }

        fn entryCount(self: DynamicTable) usize {
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
            self.rebuildIndexes();
        }

        fn rebuildIndexes(self: *DynamicTable) void {
            self.latest_name.clearRetainingCapacity();
            self.latest_exact.clearRetainingCapacity();
            for (self.entries.items, 0..) |entry, index| {
                self.latest_name.putAssumeCapacity(entry.name, index);
                self.latest_exact.putAssumeCapacity(.{
                    .name = entry.name,
                    .value = entry.value,
                }, index);
            }
        }
    };

    pub const Decoder = struct {
        dynamic_table: DynamicTable = .{},
        max_dynamic_table_size: usize = default_dynamic_table_size,

        pub fn deinit(self: *Decoder, allocator: std.mem.Allocator) void {
            self.dynamic_table.deinit(allocator);
            self.* = undefined;
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
            );
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

        pub fn deinit(self: *Encoder, allocator: std.mem.Allocator) void {
            self.dynamic_table.deinit(allocator);
            self.* = undefined;
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
                if (!never_index) {
                    if (findStaticIndex(field.name, field.value)) |index| {
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
                const dynamic_name_index = if (self.dynamic_table.entryCount() != 0)
                    self.dynamic_table.findNameIndex(field.name)
                else
                    null;
                if (findStaticNameIndex(field.name) orelse dynamic_name_index) |name_index| {
                    if (can_incrementally_index) {
                        try encodeInteger(list, allocator, 6, 0x40, name_index);
                    } else {
                        try encodeInteger(list, allocator, 4, literal_without_indexing_prefix, name_index);
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

    pub fn findStaticIndex(name: []const u8, value: []const u8) ?u64 {
        if (fastStaticPseudoIndex(name, value)) |index| return index;
        const indexes = static_name_index.get(name) orelse return null;
        // HPACK field encoding queries the static table for every header.  The
        // Work reference implementations scan the whole 61-entry table; this
        // comptime name index narrows exact probes to only the candidate
        // entries while preserving HPACK's one-indexed RFC order.
        for (indexes) |index| {
            const entry = static_table[index - 1];
            if (std.mem.eql(u8, entry.value, value)) {
                return index;
            }
        }
        return null;
    }

    pub fn findStaticNameIndex(name: []const u8) ?u64 {
        if (fastStaticPseudoNameIndex(name)) |index| return index;
        const indexes = static_name_index.get(name) orelse return null;
        return indexes[0];
    }

    fn fastStaticPseudoIndex(name: []const u8, value: []const u8) ?u64 {
        if (std.mem.eql(u8, name, ":method")) {
            if (std.mem.eql(u8, value, "GET")) return 2;
            if (std.mem.eql(u8, value, "POST")) return 3;
            return null;
        }
        if (std.mem.eql(u8, name, ":path")) {
            if (std.mem.eql(u8, value, "/")) return 4;
            if (std.mem.eql(u8, value, "/index.html")) return 5;
            return null;
        }
        if (std.mem.eql(u8, name, ":scheme")) {
            if (std.mem.eql(u8, value, "http")) return 6;
            if (std.mem.eql(u8, value, "https")) return 7;
            return null;
        }
        if (std.mem.eql(u8, name, ":status")) {
            if (std.mem.eql(u8, value, "200")) return 8;
            if (std.mem.eql(u8, value, "204")) return 9;
            if (std.mem.eql(u8, value, "206")) return 10;
            if (std.mem.eql(u8, value, "304")) return 11;
            if (std.mem.eql(u8, value, "400")) return 12;
            if (std.mem.eql(u8, value, "404")) return 13;
            if (std.mem.eql(u8, value, "500")) return 14;
            return null;
        }
        if (std.mem.eql(u8, name, ":authority")) {
            if (value.len == 0) return 1;
            return null;
        }
        if (std.mem.eql(u8, name, "accept-encoding")) {
            if (std.mem.eql(u8, value, "gzip, deflate")) return 16;
            return null;
        }
        if (std.mem.eql(u8, name, "accept")) {
            if (value.len == 0) return 19;
            return null;
        }
        if (std.mem.eql(u8, name, "cache-control")) {
            if (value.len == 0) return 24;
            return null;
        }
        if (std.mem.eql(u8, name, "content-length")) {
            if (value.len == 0) return 28;
            return null;
        }
        if (std.mem.eql(u8, name, "content-type")) {
            if (value.len == 0) return 31;
            return null;
        }
        if (std.mem.eql(u8, name, "server")) {
            if (value.len == 0) return 54;
            return null;
        }
        if (std.mem.eql(u8, name, "user-agent")) {
            if (value.len == 0) return 58;
            return null;
        }
        if (std.mem.eql(u8, name, "vary")) {
            if (value.len == 0) return 59;
            return null;
        }
        return null;
    }

    fn fastStaticPseudoNameIndex(name: []const u8) ?u64 {
        if (std.mem.eql(u8, name, ":authority")) return 1;
        if (std.mem.eql(u8, name, ":method")) return 2;
        if (std.mem.eql(u8, name, ":path")) return 4;
        if (std.mem.eql(u8, name, ":scheme")) return 6;
        if (std.mem.eql(u8, name, ":status")) return 8;
        if (std.mem.eql(u8, name, "accept")) return 19;
        if (std.mem.eql(u8, name, "accept-encoding")) return 16;
        if (std.mem.eql(u8, name, "cache-control")) return 24;
        if (std.mem.eql(u8, name, "content-length")) return 28;
        if (std.mem.eql(u8, name, "content-type")) return 31;
        if (std.mem.eql(u8, name, "server")) return 54;
        if (std.mem.eql(u8, name, "user-agent")) return 58;
        if (std.mem.eql(u8, name, "vary")) return 59;
        return null;
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
        var dynamic_table = DynamicTable{};
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
        }
    }

    pub fn encodeHuffman(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
        return encodeHuffmanWithLen(allocator, value, try huffmanEncodedLen(value));
    }

    pub fn encodeHuffmanWithLen(allocator: std.mem.Allocator, value: []const u8, encoded_len: usize) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.ensureTotalCapacity(allocator, encoded_len);

        var bits: u64 = 0;
        var bits_left: u6 = 40;
        for (value) |byte| {
            const entry = hpack_huffman.encode_table[byte];
            bits |= @as(u64, entry.code) << @intCast(bits_left - entry.bits);
            bits_left -= entry.bits;

            while (bits_left <= 32) {
                try out.append(allocator, @truncate(bits >> 32));
                bits <<= 8;
                bits_left += 8;
            }
        }

        if (bits_left != 40) {
            // RFC 7541 §5.2 pads the final octet with a prefix of the EOS code,
            // which is all ones.  The EOS symbol itself is never emitted.
            bits |= (@as(u64, 1) << bits_left) - 1;
            try out.append(allocator, @truncate(bits >> 32));
        }
        std.debug.assert(out.items.len == encoded_len);
        return out.toOwnedSlice(allocator);
    }

    pub fn huffmanEncodedLen(value: []const u8) !usize {
        var bit_len: usize = 0;
        for (value) |byte| {
            bit_len = std.math.add(usize, bit_len, hpack_huffman.encode_table[byte].bits) catch return error.IntegerOverflow;
        }
        return std.math.divCeil(usize, bit_len, 8) catch unreachable;
    }

    pub fn decodeHuffman(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
        if (encoded.len == 0) return @constCast(&[_]u8{});
        const decoded_len = try huffmanDecodedLen(encoded);
        const out = try allocator.alloc(u8, decoded_len);
        errdefer allocator.free(out);
        var out_index: usize = 0;

        var node: u16 = huffman_root_node;
        var pending_code: u32 = 0;
        var pending_bits: u6 = 0;
        for (encoded) |byte| {
            var bit_index: u4 = 0;
            while (bit_index < 8) : (bit_index += 1) {
                const bit: u1 = @truncate((byte >> @intCast(7 - bit_index)) & 1);
                pending_code = (pending_code << 1) | bit;
                pending_bits += 1;
                if (pending_bits > huffman_max_code_bits) return error.InvalidEncoding;

                const next = huffman_decode_trie[node].child[bit] orelse return error.InvalidEncoding;
                node = next;
                if (huffman_decode_trie[node].symbol) |symbol| {
                    if (symbol == hpack_huffman.eos_symbol) return error.InvalidEncoding;
                    out[out_index] = @intCast(symbol);
                    out_index += 1;
                    node = huffman_root_node;
                    pending_code = 0;
                    pending_bits = 0;
                }
            }
        }

        if (pending_bits != 0) {
            // The only legal incomplete suffix is EOS-prefix padding of at most
            // seven one bits (RFC 7541 §5.2).
            if (pending_bits > 7) return error.InvalidEncoding;
            const padding = (@as(u32, 1) << @as(u5, @intCast(pending_bits))) - 1;
            if (pending_code != padding) return error.InvalidEncoding;
        }
        std.debug.assert(out_index == out.len);
        return out;
    }

    pub fn huffmanDecodedLen(encoded: []const u8) !usize {
        if (encoded.len == 0) return 0;
        var len: usize = 0;
        var node: u16 = huffman_root_node;
        var pending_code: u32 = 0;
        var pending_bits: u6 = 0;
        for (encoded) |byte| {
            var bit_index: u4 = 0;
            while (bit_index < 8) : (bit_index += 1) {
                const bit: u1 = @truncate((byte >> @intCast(7 - bit_index)) & 1);
                pending_code = (pending_code << 1) | bit;
                pending_bits += 1;
                if (pending_bits > huffman_max_code_bits) return error.InvalidEncoding;

                const next = huffman_decode_trie[node].child[bit] orelse return error.InvalidEncoding;
                node = next;
                if (huffman_decode_trie[node].symbol) |symbol| {
                    if (symbol == hpack_huffman.eos_symbol) return error.InvalidEncoding;
                    len = std.math.add(usize, len, 1) catch return error.IntegerOverflow;
                    node = huffman_root_node;
                    pending_code = 0;
                    pending_bits = 0;
                }
            }
        }

        if (pending_bits != 0) {
            if (pending_bits > 7) return error.InvalidEncoding;
            const padding = (@as(u32, 1) << @as(u5, @intCast(pending_bits))) - 1;
            if (pending_code != padding) return error.InvalidEncoding;
        }
        return len;
    }

    fn decodeBlockWithDynamicTable(
        allocator: std.mem.Allocator,
        block: []const u8,
        dynamic_table: *DynamicTable,
        max_dynamic_table_size: usize,
    ) ![]HeaderField {
        var cursor = wire.Cursor.init(block);
        var fields: std.ArrayList(HeaderField) = .empty;
        errdefer {
            freeFieldStorages(allocator, fields.items);
            fields.deinit(allocator);
        }
        var saw_header = false;
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0x80) != 0) {
                saw_header = true;
                try fields.append(allocator, try indexedHeaderOwned(allocator, dynamic_table, try decodeInteger(first, &cursor, 7)));
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
            const never_index = (first & 0x10) != 0;

            var field = HeaderField{
                .name = undefined,
                .value = undefined,
                .never_index = never_index,
            };
            if (name_index == 0) {
                const name = try decodeString(allocator, &cursor);
                field.name = name.value;
                field.name_storage = name.storage;
            } else {
                const name = try indexedNameOwned(allocator, dynamic_table, name_index);
                field.name = name.value;
                field.name_storage = name.storage;
            }
            const value = try decodeString(allocator, &cursor);
            field.value = value.value;
            field.value_storage = value.storage;
            if (indexed_literal) try dynamic_table.add(allocator, field.name, field.value);
            try fields.append(allocator, field);
        }
        return fields.toOwnedSlice(allocator);
    }

    fn decodeBlockIntoWithDynamicTable(
        allocator: std.mem.Allocator,
        block: []const u8,
        dynamic_table: *DynamicTable,
        max_dynamic_table_size: usize,
        storage: []HeaderField,
    ) ![]HeaderField {
        var cursor = wire.Cursor.init(block);
        var count: usize = 0;
        errdefer freeFieldStorages(allocator, storage[0..count]);
        var saw_header = false;
        while (!cursor.eof()) {
            const first = try cursor.readByte();
            if ((first & 0x80) != 0) {
                saw_header = true;
                if (count >= storage.len) return error.BufferTooShort;
                storage[count] = try indexedHeaderOwned(allocator, dynamic_table, try decodeInteger(first, &cursor, 7));
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
            if (count >= storage.len) return error.BufferTooShort;
            const indexed_literal = (first & 0x40) != 0;
            const name_index = if (indexed_literal)
                try decodeInteger(first, &cursor, 6)
            else
                try decodeInteger(first, &cursor, 4);
            const never_index = (first & 0x10) != 0;

            var field = HeaderField{
                .name = undefined,
                .value = undefined,
                .never_index = never_index,
            };
            if (name_index == 0) {
                const name = try decodeString(allocator, &cursor);
                field.name = name.value;
                field.name_storage = name.storage;
            } else {
                const name = try indexedNameOwned(allocator, dynamic_table, name_index);
                field.name = name.value;
                field.name_storage = name.storage;
            }
            const value = try decodeString(allocator, &cursor);
            field.value = value.value;
            field.value_storage = value.storage;
            if (indexed_literal) try dynamic_table.add(allocator, field.name, field.value);
            storage[count] = field;
            count += 1;
        }
        return storage[0..count];
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
        if (value.len == 0) {
            try list.append(allocator, 0);
            return;
        }
        if (value.len <= 2) {
            try list.append(allocator, @intCast(value.len));
            try list.appendSlice(allocator, value);
            return;
        }
        const huffman_len = try huffmanEncodedLen(value);
        if (huffman_len >= value.len) {
            try encodeInteger(list, allocator, 7, 0x00, value.len);
            try list.appendSlice(allocator, value);
            return;
        }
        const huffman = try encodeHuffmanWithLen(allocator, value, huffman_len);
        defer allocator.free(huffman);
        std.debug.assert(huffman.len == huffman_len);
        try encodeInteger(list, allocator, 7, 0x80, huffman.len);
        try list.appendSlice(allocator, huffman);
    }

    const DecodedString = struct {
        value: []const u8,
        storage: ?[]u8 = null,
    };

    fn decodeString(allocator: std.mem.Allocator, cursor: *wire.Cursor) !DecodedString {
        const first = try cursor.readByte();
        const huffman = (first & 0x80) != 0;
        const len = std.math.cast(usize, try decodeInteger(first, cursor, 7)) orelse return error.IntegerOverflow;
        const raw = try cursor.readSlice(len);
        if (!huffman) return .{ .value = raw };
        const decoded = try decodeHuffman(allocator, raw);
        return .{ .value = decoded, .storage = decoded };
    }

    fn staticEntry(index: u64) Error!StaticEntry {
        if (index == 0) return error.InvalidEncoding;
        if (index > static_table.len) return error.HpackDynamicTableUnsupported;
        return static_table[@intCast(index - 1)];
    }

    fn indexedHeaderOwned(allocator: std.mem.Allocator, dynamic_table: *DynamicTable, index: u64) Error!HeaderField {
        if (index == 0) return error.InvalidEncoding;
        if (index <= static_table.len) {
            const entry = static_table[@intCast(index - 1)];
            return .{ .name = entry.name, .value = entry.value };
        }
        const dynamic_index = std.math.cast(usize, index - static_table.len - 1) orelse return error.IntegerOverflow;
        const entry = dynamic_table.get(dynamic_index) orelse return error.HpackDynamicTableUnsupported;
        const name = try allocator.dupe(u8, entry.name);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, entry.value);
        return .{ .name = name, .value = value, .name_storage = name, .value_storage = value };
    }

    fn indexedNameOwned(allocator: std.mem.Allocator, dynamic_table: *DynamicTable, index: u64) Error!DecodedString {
        if (index == 0) return error.InvalidEncoding;
        if (index <= static_table.len) return .{ .value = static_table[@intCast(index - 1)].name };
        const dynamic_index = std.math.cast(usize, index - static_table.len - 1) orelse return error.IntegerOverflow;
        const entry = dynamic_table.get(dynamic_index) orelse return error.HpackDynamicTableUnsupported;
        const name = try allocator.dupe(u8, entry.name);
        return .{ .value = name, .storage = name };
    }

    const huffman_root_node: u16 = 0;
    const huffman_max_code_bits: u6 = 30;

    const HuffmanDecodeNode = struct {
        child: [2]?u16 = .{ null, null },
        symbol: ?u16 = null,
    };

    const huffman_decode_trie = buildHuffmanDecodeTrie();

    fn buildHuffmanDecodeTrie() [huffman_decode_node_count]HuffmanDecodeNode {
        @setEvalBranchQuota(200_000);
        var nodes = [_]HuffmanDecodeNode{.{}} ** huffman_decode_node_count;
        var used: u16 = 1;

        for (hpack_huffman.encode_table, 0..) |entry, symbol| {
            var node: u16 = huffman_root_node;
            var bit_index: u6 = 0;
            while (bit_index < entry.bits) : (bit_index += 1) {
                const shift: u5 = @intCast(entry.bits - 1 - bit_index);
                const bit: u1 = @truncate((entry.code >> shift) & 1);
                if (nodes[node].child[bit] == null) {
                    nodes[node].child[bit] = used;
                    used += 1;
                }
                node = nodes[node].child[bit].?;
            }
            nodes[node].symbol = @intCast(symbol);
        }

        return nodes;
    }

    const huffman_decode_node_count = blk: {
        var count: usize = 1;
        for (hpack_huffman.encode_table) |entry| count += entry.bits;
        break :blk count;
    };

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
    try std.testing.expectError(error.InvalidFrameSize, DataPayload.parse(.{
        .header = .{ .length = 0, .frame_type = .headers, .flags = 0, .stream_id = 1 },
        .payload = &.{},
    }));
    try std.testing.expectError(error.InvalidStreamId, DataPayload.parse(.{
        .header = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_id = 0 },
        .payload = &.{},
    }));

    try std.testing.expectError(error.InvalidStreamId, HeadersPayload.parse(.{
        .header = .{ .length = 0, .frame_type = .headers, .flags = 0, .stream_id = 0 },
        .payload = &.{},
    }));
    try std.testing.expectError(error.InvalidFrameSize, HeadersPayload.parse(.{
        .header = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_id = 1 },
        .payload = &.{},
    }));
    try std.testing.expectError(error.InvalidStreamId, HeadersPayload.parse(.{
        .header = .{ .length = 5, .frame_type = .headers, .flags = (@as(Flags, .{ .priority = true })).byte(), .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 1, 16 },
    }));
    try validateClientPreface(connection_preface ++ "rest");
}

test "HTTP/2 PRIORITY payload helper" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try PriorityPayload.write(&encoded, allocator, 5, true, 3, 200);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.priority, frame.header.frame_type);
    const priority = try PriorityPayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 5), priority.stream_id);
    try std.testing.expect(priority.exclusive);
    try std.testing.expectEqual(@as(u31, 3), priority.stream_dependency);
    try std.testing.expectEqual(@as(u8, 200), priority.weight);

    try std.testing.expectError(error.InvalidStreamId, PriorityPayload.write(&encoded, allocator, 0, false, 0, 1));
    try std.testing.expectError(error.InvalidStreamId, PriorityPayload.write(&encoded, allocator, 5, false, 5, 1));
    try std.testing.expectError(error.InvalidFrameSize, PriorityPayload.parse(.{
        .header = .{ .length = 4, .frame_type = .priority, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 0 },
    }));
    try std.testing.expectError(error.InvalidStreamId, PriorityPayload.parse(.{
        .header = .{ .length = 5, .frame_type = .priority, .flags = 0, .stream_id = 5 },
        .payload = &.{ 0, 0, 0, 5, 1 },
    }));
}

test "HTTP/2 PRIORITY_UPDATE payload helper" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try PriorityUpdatePayload.writePriority(
        &encoded,
        allocator,
        5,
        .{ .urgency = 1, .incremental = true },
    );
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(
        FrameType.priority_update,
        frame.header.frame_type,
    );
    try std.testing.expectEqual(@as(u31, 0), frame.header.stream_id);
    const update = try PriorityUpdatePayload.parse(frame);
    try std.testing.expectEqual(
        @as(u31, 5),
        update.prioritized_stream_id,
    );
    try std.testing.expectEqualStrings("u=1, i", update.field_value);
    try std.testing.expectEqual(
        @as(u3, 1),
        update.priorityValue().urgency,
    );
    try std.testing.expect(update.priorityValue().incremental);

    var no_alloc_update: std.ArrayList(u8) = .empty;
    defer no_alloc_update.deinit(allocator);
    try no_alloc_update.ensureTotalCapacity(allocator, 32);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try PriorityUpdatePayload.write(&no_alloc_update, no_alloc.allocator(), 5, "u=1, i");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, encoded.items, no_alloc_update.items);

    try std.testing.expectError(
        error.InvalidStreamId,
        PriorityUpdatePayload.write(&encoded, allocator, 0, "u=1"),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        PriorityUpdatePayload.write(&encoded, allocator, 1, "u=1\n"),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        PriorityUpdatePayload.write(&encoded, allocator, 1, "u=1,"),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        PriorityUpdatePayload.parse(.{
            .header = .{
                .length = 3,
                .frame_type = .priority_update,
                .flags = 0,
                .stream_id = 0,
            },
            .payload = &.{ 0, 0, 1 },
        }),
    );
    try std.testing.expectError(
        error.InvalidStreamId,
        PriorityUpdatePayload.parse(.{
            .header = .{
                .length = 4,
                .frame_type = .priority_update,
                .flags = 0,
                .stream_id = 0,
            },
            .payload = &.{ 0, 0, 0, 0 },
        }),
    );
    try std.testing.expectError(
        error.InvalidStreamId,
        PriorityUpdatePayload.parse(.{
            .header = .{
                .length = 4,
                .frame_type = .priority_update,
                .flags = 0,
                .stream_id = 1,
            },
            .payload = &.{ 0, 0, 0, 1 },
        }),
    );
}

test "HTTP/2 PUSH_PROMISE payload helper" {
    const allocator = std.testing.allocator;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/pushed.css" },
        .{ .name = ":scheme", .value = "https" },
    });

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try PushPromisePayload.write(&encoded, allocator, 1, 2, block.items, .{ .padding_len = 3 });
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.push_promise, frame.header.frame_type);
    try std.testing.expect((frame.header.flags & (@as(Flags, .{ .padded = true })).byte()) != 0);
    const promise = try PushPromisePayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 1), promise.stream_id);
    try std.testing.expectEqual(@as(u31, 2), promise.promised_stream_id);
    try std.testing.expectEqual(@as(u8, 3), promise.padding_len);

    const fields = try Hpack.decodeLiteralBlock(allocator, promise.header_block);
    defer Hpack.freeDecodedFields(allocator, fields);
    try std.testing.expectEqualStrings("/pushed.css", fields[1].value);

    var no_alloc_encoded: std.ArrayList(u8) = .empty;
    defer no_alloc_encoded.deinit(allocator);
    try no_alloc_encoded.ensureTotalCapacity(allocator, encoded.items.len);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try PushPromisePayload.write(&no_alloc_encoded, no_alloc.allocator(), 1, 2, block.items, .{ .padding_len = 3 });
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, encoded.items, no_alloc_encoded.items);

    try std.testing.expectError(error.InvalidStreamId, PushPromisePayload.write(&encoded, allocator, 0, 2, block.items, .{}));
    try std.testing.expectError(error.InvalidStreamId, PushPromisePayload.write(&encoded, allocator, 1, 0, block.items, .{}));
    try std.testing.expectError(error.InvalidStreamId, PushPromisePayload.parse(.{
        .header = .{ .length = 4, .frame_type = .push_promise, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 0 },
    }));
    try std.testing.expectError(error.InvalidFrameSize, PushPromisePayload.parse(.{
        .header = .{ .length = 2, .frame_type = .push_promise, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0 },
    }));
}

test "HTTP/2 ORIGIN frame round trips and validates ASCII entries" {
    const allocator = std.testing.allocator;
    const expected = [_][]const u8{
        "https://example.com",
        "https://cdn.example.com:8443",
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try OriginPayload.write(&encoded, allocator, &expected);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.origin, frame.header.frame_type);
    try std.testing.expectEqual(@as(u31, 0), frame.header.stream_id);
    var parsed = try OriginPayload.parse(allocator, frame);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), parsed.origins.len);
    try std.testing.expectEqualStrings(expected[0], parsed.origins[0]);
    try std.testing.expectEqualStrings(expected[1], parsed.origins[1]);

    var empty: std.ArrayList(u8) = .empty;
    defer empty.deinit(allocator);
    try OriginPayload.write(&empty, allocator, &.{});
    var empty_parsed = try OriginPayload.parse(
        allocator,
        try Frame.parse(empty.items),
    );
    defer empty_parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), empty_parsed.origins.len);

    try std.testing.expectError(
        error.InvalidFrameSize,
        OriginPayload.write(&encoded, allocator, &.{"https://bad host"}),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        OriginPayload.parse(allocator, .{
            .header = .{
                .length = 3,
                .frame_type = .origin,
                .flags = 0,
                .stream_id = 0,
            },
            .payload = &.{ 0, 2, 'x' },
        }),
    );
}

test "HTTP/2 ALTSVC frame validates connection and stream forms" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try AltSvcPayload.write(
        &encoded,
        allocator,
        0,
        "https://example.com",
        "h3=\":443\"; ma=3600",
    );
    const connection_frame = try Frame.parse(encoded.items);
    const connection_alt = try AltSvcPayload.parse(connection_frame);
    try std.testing.expectEqualStrings(
        "https://example.com",
        connection_alt.origin,
    );
    try std.testing.expectEqualStrings(
        "h3=\":443\"; ma=3600",
        connection_alt.field_value,
    );

    encoded.clearRetainingCapacity();
    try AltSvcPayload.write(
        &encoded,
        allocator,
        1,
        "",
        "h2=\"alt.example.com:443\"",
    );
    const stream_alt = try AltSvcPayload.parse(try Frame.parse(encoded.items));
    try std.testing.expectEqual(@as(usize, 0), stream_alt.origin.len);
    try std.testing.expectEqualStrings(
        "h2=\"alt.example.com:443\"",
        stream_alt.field_value,
    );

    try std.testing.expectError(
        error.InvalidStreamId,
        AltSvcPayload.write(
            &encoded,
            allocator,
            0,
            "",
            "h3=\":443\"",
        ),
    );
    try std.testing.expectError(
        error.InvalidStreamId,
        AltSvcPayload.write(
            &encoded,
            allocator,
            1,
            "https://example.com",
            "h3=\":443\"",
        ),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        AltSvcPayload.parse(.{
            .header = .{
                .length = 3,
                .frame_type = .altsvc,
                .flags = 0,
                .stream_id = 0,
            },
            .payload = &.{ 0, 4, 'x' },
        }),
    );
}

test "HTTP/2 SETTINGS validates RFC value bounds" {
    const allocator = std.testing.allocator;

    var invalid_write: std.ArrayList(u8) = .empty;
    defer invalid_write.deinit(allocator);
    try std.testing.expectError(error.InvalidSetting, writeSettings(&invalid_write, allocator, &.{
        .{ .id = .enable_push, .value = 2 },
    }));

    var invalid_enable_push: std.ArrayList(u8) = .empty;
    defer invalid_enable_push.deinit(allocator);
    try wire.appendInt(&invalid_enable_push, allocator, u16, @intFromEnum(SettingId.enable_push), .big);
    try wire.appendInt(&invalid_enable_push, allocator, u32, 2, .big);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, invalid_enable_push.items));

    var invalid_no_rfc7540_priorities: std.ArrayList(u8) = .empty;
    defer invalid_no_rfc7540_priorities.deinit(allocator);
    try wire.appendInt(
        &invalid_no_rfc7540_priorities,
        allocator,
        u16,
        @intFromEnum(SettingId.no_rfc7540_priorities),
        .big,
    );
    try wire.appendInt(
        &invalid_no_rfc7540_priorities,
        allocator,
        u32,
        2,
        .big,
    );
    try std.testing.expectError(
        error.InvalidSetting,
        parseSettings(allocator, invalid_no_rfc7540_priorities.items),
    );

    var invalid_window: std.ArrayList(u8) = .empty;
    defer invalid_window.deinit(allocator);
    try wire.appendInt(&invalid_window, allocator, u16, @intFromEnum(SettingId.initial_window_size), .big);
    try wire.appendInt(&invalid_window, allocator, u32, @as(u32, std.math.maxInt(i31)) + 1, .big);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, invalid_window.items));

    var invalid_frame: std.ArrayList(u8) = .empty;
    defer invalid_frame.deinit(allocator);
    try wire.appendInt(&invalid_frame, allocator, u16, @intFromEnum(SettingId.max_frame_size), .big);
    try wire.appendInt(&invalid_frame, allocator, u32, 16_383, .big);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, invalid_frame.items));

    var valid: std.ArrayList(u8) = .empty;
    defer valid.deinit(allocator);
    try writeSettings(&valid, allocator, &.{
        .{ .id = .enable_push, .value = 0 },
        .{ .id = .enable_connect_protocol, .value = 1 },
        .{ .id = .no_rfc7540_priorities, .value = 1 },
        .{ .id = .initial_window_size, .value = std.math.maxInt(i31) },
        .{ .id = .max_frame_size, .value = 16_777_215 },
    });
    const parsed = try parseSettings(allocator, valid.items);
    defer allocator.free(parsed);
    try std.testing.expectEqual(@as(usize, 5), parsed.len);

    var invalid_connect_protocol: std.ArrayList(u8) = .empty;
    defer invalid_connect_protocol.deinit(allocator);
    try wire.appendInt(&invalid_connect_protocol, allocator, u16, @intFromEnum(SettingId.enable_connect_protocol), .big);
    try wire.appendInt(&invalid_connect_protocol, allocator, u32, 2, .big);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, invalid_connect_protocol.items));
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

    var no_alloc_goaway: std.ArrayList(u8) = .empty;
    defer no_alloc_goaway.deinit(allocator);
    try no_alloc_goaway.ensureTotalCapacity(allocator, goaway_bytes.items.len);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try GoAwayPayload.write(&no_alloc_goaway, no_alloc.allocator(), 7, .no_error, "bye");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, goaway_bytes.items, no_alloc_goaway.items);
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
    defer Hpack.freeDecodedFields(allocator, fields);

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
    defer Hpack.freeDecodedFields(allocator, decoded);

    try std.testing.expectEqual(fields_in.len, decoded.len);
    for (fields_in, decoded) |expected, actual| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqualStrings(expected.value, actual.value);
        try std.testing.expectEqual(expected.never_index, actual.never_index);
    }
}

test "HTTP/2 HPACK static lookup index preserves one-indexed table order" {
    for (Hpack.static_table, 0..) |entry, zero_index| {
        const wire_index: u64 = @intCast(zero_index + 1);
        try std.testing.expectEqual(wire_index, Hpack.findStaticIndex(entry.name, entry.value).?);
        try std.testing.expectEqual(
            Hpack.findStaticNameIndex(entry.name).?,
            (blk: {
                for (Hpack.static_table, 0..) |candidate, first_zero_index| {
                    if (std.mem.eql(u8, candidate.name, entry.name)) {
                        break :blk @as(u64, @intCast(first_zero_index + 1));
                    }
                }
                unreachable;
            }),
        );
    }

    try std.testing.expectEqual(@as(?u64, 2), Hpack.findStaticNameIndex(":method"));
    try std.testing.expectEqual(@as(?u64, 8), Hpack.findStaticNameIndex(":status"));
    try std.testing.expectEqual(@as(?u64, 31), Hpack.findStaticNameIndex("content-type"));
    try std.testing.expectEqual(@as(?u64, 2), Hpack.findStaticIndex(":method", "GET"));
    try std.testing.expectEqual(@as(?u64, 3), Hpack.findStaticIndex(":method", "POST"));
    try std.testing.expectEqual(@as(?u64, 4), Hpack.findStaticIndex(":path", "/"));
    try std.testing.expectEqual(@as(?u64, 7), Hpack.findStaticIndex(":scheme", "https"));
    try std.testing.expectEqual(@as(?u64, 9), Hpack.findStaticIndex(":status", "204"));
    try std.testing.expectEqual(@as(?u64, 16), Hpack.findStaticIndex("accept-encoding", "gzip, deflate"));
    try std.testing.expectEqual(@as(?u64, 19), Hpack.findStaticIndex("accept", ""));
    try std.testing.expectEqual(@as(?u64, 24), Hpack.findStaticIndex("cache-control", ""));
    try std.testing.expectEqual(@as(?u64, 28), Hpack.findStaticIndex("content-length", ""));
    try std.testing.expectEqual(@as(?u64, 31), Hpack.findStaticIndex("content-type", ""));
    try std.testing.expectEqual(@as(?u64, 54), Hpack.findStaticIndex("server", ""));
    try std.testing.expectEqual(@as(?u64, 58), Hpack.findStaticIndex("user-agent", ""));
    try std.testing.expectEqual(@as(?u64, 59), Hpack.findStaticIndex("vary", ""));
    try std.testing.expectEqual(@as(?u64, 19), Hpack.findStaticNameIndex("accept"));
    try std.testing.expectEqual(@as(?u64, 16), Hpack.findStaticNameIndex("accept-encoding"));
    try std.testing.expectEqual(@as(?u64, 54), Hpack.findStaticNameIndex("server"));
    try std.testing.expect(Hpack.findStaticIndex(":status", "418") == null);
    try std.testing.expect(Hpack.findStaticNameIndex("x-not-static") == null);
}

test "HTTP/2 HPACK dynamic table keeps newest-index order without shifts" {
    const allocator = std.testing.allocator;
    var table = Hpack.DynamicTable{};
    defer table.deinit(allocator);
    table.setLimit(allocator, 80);

    try table.add(allocator, "x-a", "1");
    try table.add(allocator, "x-b", "2");
    try table.add(allocator, "x-c", "3");

    try std.testing.expectEqual(@as(usize, 2), table.entries.items.len);
    try std.testing.expectEqualStrings("x-c", table.get(0).?.name);
    try std.testing.expectEqualStrings("x-b", table.get(1).?.name);
    try std.testing.expectEqual(@as(?u64, Hpack.static_table.len + 1), table.findIndex("x-c", "3"));
    try std.testing.expectEqual(@as(?u64, Hpack.static_table.len + 2), table.findNameIndex("x-b"));
    try std.testing.expect(table.findNameIndex("x-a") == null);
}

test "HTTP/2 HPACK dynamic lookup indexes survive eviction and clear" {
    const allocator = std.testing.allocator;
    var table = Hpack.DynamicTable{};
    defer table.deinit(allocator);
    table.setLimit(allocator, 68);

    try std.testing.expect(table.findNameIndex("x") == null);
    try std.testing.expect(table.findIndex("x", "a") == null);

    try table.add(allocator, "x", "a");
    try table.add(allocator, "x", "b");
    try table.add(allocator, "y", "c");
    try std.testing.expectEqual(@as(usize, 2), table.entryCount());
    try std.testing.expectEqual(
        @as(?u64, Hpack.static_table.len + 2),
        table.findNameIndex("x"),
    );
    try std.testing.expectEqual(
        @as(?u64, Hpack.static_table.len + 2),
        table.findIndex("x", "b"),
    );
    try std.testing.expectEqual(@as(?usize, 0), table.latest_name.get("x"));
    try std.testing.expectEqual(@as(?usize, 0), table.latest_exact.get(.{ .name = "x", .value = "b" }));
    try std.testing.expect(table.findIndex("x", "a") == null);

    try table.add(allocator, "z", "d");
    try std.testing.expect(table.findNameIndex("x") == null);
    try std.testing.expect(table.findIndex("x", "b") == null);
    try std.testing.expectEqual(
        @as(?u64, Hpack.static_table.len + 1),
        table.findIndex("z", "d"),
    );

    try table.add(allocator, "too-large", "012345678901234567890123456789");
    try std.testing.expectEqual(@as(usize, 0), table.entryCount());
    try std.testing.expect(table.findNameIndex("z") == null);
    try std.testing.expect(table.findIndex("z", "d") == null);

    try table.add(allocator, "n", "v");
    try std.testing.expectEqual(
        @as(?u64, Hpack.static_table.len + 1),
        table.findIndex("n", "v"),
    );
}

test "HTTP/2 HPACK never-indexes sensitive fields automatically" {
    const allocator = std.testing.allocator;
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoder.encodeBlock(&encoded, allocator, &.{
        .{ .name = "authorization", .value = "Bearer secret" },
        .{ .name = "cookie", .value = "sid=secret" },
        .{ .name = "set-cookie", .value = "sid=secret; HttpOnly" },
    });

    const decoded = try Hpack.decodeLiteralBlock(allocator, encoded.items);
    defer Hpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 3), decoded.len);
    for (decoded) |field| try std.testing.expect(field.never_index);
    try std.testing.expectEqual(@as(usize, 0), encoder.dynamic_table.entries.items.len);

    try std.testing.expect(Hpack.sensitiveHeaderName("Authorization"));
    try std.testing.expect(Hpack.sensitiveHeaderName("proxy-authorization"));
    try std.testing.expect(Hpack.sensitiveHeaderName("cookie"));
    try std.testing.expect(Hpack.sensitiveHeaderName("set-cookie"));
    try std.testing.expect(!Hpack.sensitiveHeaderName("x-token"));
}

test "HTTP/2 HPACK Huffman and dynamic table state" {
    const allocator = std.testing.allocator;

    const huffman = try Hpack.encodeHuffman(allocator, "www.example.com");
    defer allocator.free(huffman);
    try std.testing.expectEqualSlices(u8, &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff }, huffman);
    try std.testing.expectEqual(huffman.len, try Hpack.huffmanEncodedLen("www.example.com"));
    const decoded_huffman = try Hpack.decodeHuffman(allocator, huffman);
    defer allocator.free(decoded_huffman);
    try std.testing.expectEqualStrings("www.example.com", decoded_huffman);
    try std.testing.expectEqual(decoded_huffman.len, try Hpack.huffmanDecodedLen(huffman));
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    const no_alloc_allocator = no_alloc.allocator();
    const no_alloc_decoded = try Hpack.decodeHuffman(no_alloc_allocator, huffman);
    defer no_alloc_allocator.free(no_alloc_decoded);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("www.example.com", no_alloc_decoded);

    var no_alloc_block: std.ArrayList(u8) = .empty;
    defer no_alloc_block.deinit(allocator);
    try no_alloc_block.ensureTotalCapacity(allocator, 96);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const raw_preferred = [_]u8{ 0xff, 0xff, 0xff };
    try Hpack.encodeLiteralBlock(&no_alloc_block, no_alloc.allocator(), &.{
        .{ .name = "accept-encoding", .value = "", .never_index = true },
        .{ .name = "accept-encoding", .value = "ok", .never_index = true },
        .{ .name = "accept-encoding", .value = &raw_preferred, .never_index = true },
    });
    try std.testing.expect(!no_alloc.has_induced_failure);
    const fast_decoded = try Hpack.decodeLiteralBlock(allocator, no_alloc_block.items);
    defer Hpack.freeDecodedFields(allocator, fast_decoded);
    try std.testing.expectEqualStrings("", fast_decoded[0].value);
    try std.testing.expectEqualStrings("ok", fast_decoded[1].value);
    try std.testing.expectEqualSlices(u8, &raw_preferred, fast_decoded[2].value);

    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var first_block: std.ArrayList(u8) = .empty;
    defer first_block.deinit(allocator);
    try encoder.encodeBlock(&first_block, allocator, &.{.{ .name = "x-dynamic", .value = "one" }});
    try std.testing.expect((first_block.items[0] & 0x40) != 0);

    var second_block: std.ArrayList(u8) = .empty;
    defer second_block.deinit(allocator);
    try encoder.encodeBlock(&second_block, allocator, &.{.{ .name = "x-dynamic", .value = "one" }});
    try std.testing.expect((second_block.items[0] & 0x80) != 0);

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const first_fields = try decoder.decodeBlock(allocator, first_block.items);
    defer Hpack.freeDecodedFields(allocator, first_fields);
    try std.testing.expectEqualStrings("x-dynamic", first_fields[0].name);
    try std.testing.expectEqualStrings("one", first_fields[0].value);

    const second_fields = try decoder.decodeBlock(allocator, second_block.items);
    defer Hpack.freeDecodedFields(allocator, second_fields);
    try std.testing.expectEqualStrings("x-dynamic", second_fields[0].name);
    try std.testing.expectEqualStrings("one", second_fields[0].value);
}

test "HTTP/2 HPACK decoder writes into caller storage" {
    const allocator = std.testing.allocator;

    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeBlock(&block, allocator, &.{
        .{ .name = "x-dynamic", .value = "one" },
        .{ .name = ":method", .value = "GET" },
    });

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    var storage: [2]Hpack.HeaderField = undefined;
    const fields = try decoder.decodeBlockInto(allocator, block.items, &storage);
    defer Hpack.freeDecodedFieldStorages(allocator, fields);
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings("x-dynamic", fields[0].name);
    try std.testing.expectEqualStrings("one", fields[0].value);
    try std.testing.expectEqualStrings(":method", fields[1].name);
    try std.testing.expectEqualStrings("GET", fields[1].value);

    var too_small_decoder = Hpack.Decoder{};
    defer too_small_decoder.deinit(allocator);
    var too_small: [1]Hpack.HeaderField = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        too_small_decoder.decodeBlockInto(allocator, block.items, &too_small),
    );
}

test "HTTP/2 HPACK encoder emits table size updates and avoids low-value indexing" {
    const allocator = std.testing.allocator;

    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    encoder.setMaxDynamicTableSize(allocator, 128);
    encoder.setMaxDynamicTableSize(allocator, 512);

    var sized_block: std.ArrayList(u8) = .empty;
    defer sized_block.deinit(allocator);
    try encoder.encodeBlock(&sized_block, allocator, &.{.{ .name = "x-small", .value = "one" }});

    // RFC 7541 requires dynamic table-size updates before any header field when
    // the peer's SETTINGS_HEADER_TABLE_SIZE changes.  h2/hyper emits both the
    // temporary minimum and final value if the limit was lowered then raised
    // before the next HEADERS frame.
    try std.testing.expectEqualSlices(u8, &.{ 0x3f, 0x61, 0x3f, 0xe1, 0x03 }, sized_block.items[0..5]);
    try std.testing.expectEqual(@as(usize, 512), encoder.last_emitted_dynamic_table_size);

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const sized_fields = try decoder.decodeBlock(allocator, sized_block.items);
    defer Hpack.freeDecodedFields(allocator, sized_fields);
    try std.testing.expectEqual(@as(usize, 512), decoder.dynamic_table.size_limit);
    try std.testing.expectEqualStrings("x-small", sized_fields[0].name);

    var indexed_again: std.ArrayList(u8) = .empty;
    defer indexed_again.deinit(allocator);
    try encoder.encodeBlock(&indexed_again, allocator, &.{.{ .name = "x-small", .value = "one" }});
    try std.testing.expect((indexed_again.items[0] & 0x80) != 0);

    var small_table_encoder = Hpack.Encoder{};
    defer small_table_encoder.deinit(allocator);
    small_table_encoder.setMaxDynamicTableSize(allocator, 128);
    var large_block: std.ArrayList(u8) = .empty;
    defer large_block.deinit(allocator);
    try small_table_encoder.encodeBlock(&large_block, allocator, &.{.{ .name = "x-large", .value = "01234567890123456789012345678901234567890123456789012345678901234567890123456789" }});
    try std.testing.expectEqual(@as(usize, 0), small_table_encoder.dynamic_table.entries.items.len);
    try std.testing.expect((large_block.items[2] & 0xc0) == 0x00);

    var content_length_block: std.ArrayList(u8) = .empty;
    defer content_length_block.deinit(allocator);
    try encoder.encodeBlock(&content_length_block, allocator, &.{.{ .name = "content-length", .value = "1234" }});
    try std.testing.expectEqualSlices(u8, &.{ 0x0f, 0x0d }, content_length_block.items[0..2]);
    try std.testing.expect(encoder.dynamic_table.findNameIndex("content-length") == null);
}

test "HTTP/2 HPACK accepts legal size updates and rejects bad dynamic use" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.HpackDynamicTableUnsupported, Hpack.decodeLiteralBlock(allocator, &.{0xfe}));

    // A dynamic table-size update is legal only at the beginning of a header
    // block.  Go's x/net/http2 and Rust h2 both accept such updates before the
    // first representation; keep the stateless helper compatible with peers
    // that emit a size update followed only by static-indexed fields.
    const sized_static = try Hpack.decodeLiteralBlock(allocator, &.{ 0x20, 0x82 });
    defer Hpack.freeDecodedFields(allocator, sized_static);
    try std.testing.expectEqual(@as(usize, 1), sized_static.len);
    try std.testing.expectEqualStrings(":method", sized_static[0].name);
    try std.testing.expectEqualStrings("GET", sized_static[0].value);
    try std.testing.expectError(error.InvalidEncoding, Hpack.decodeLiteralBlock(allocator, &.{ 0x82, 0x20 }));

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    decoder.setMaxDynamicTableSize(allocator, 32);
    try std.testing.expectError(error.InvalidEncoding, decoder.decodeBlock(allocator, &.{ 0x3f, 0x02 }));
}

test {
    _ = runtime;
}
