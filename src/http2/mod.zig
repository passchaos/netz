const std = @import("std");
const wire = @import("../internal/wire.zig");
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
        pos += 4;
        return .{
            .stream_id = frame.header.stream_id,
            .promised_stream_id = @truncate(raw_promised & 0x7fff_ffff),
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
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        if (options.padding_len != 0) try payload.append(allocator, options.padding_len);
        try wire.appendInt(&payload, allocator, u32, @as(u32, promised_stream_id), .big);
        try payload.appendSlice(allocator, header_block);
        try payload.appendNTimes(allocator, 0, options.padding_len);
        try (Frame{
            .header = .{
                .length = 0,
                .frame_type = .push_promise,
                .flags = (if (options.end_headers) @as(u8, 0x4) else 0) | if (options.padding_len != 0) @as(u8, 0x8) else 0,
                .stream_id = stream_id,
            },
            .payload = payload.items,
        }).write(list, allocator);
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
        size_limit: usize = default_dynamic_table_size,
        used: usize = 0,

        pub fn deinit(self: *DynamicTable, allocator: std.mem.Allocator) void {
            self.clear(allocator);
            self.entries.deinit(allocator);
            self.* = undefined;
        }

        pub fn clear(self: *DynamicTable, allocator: std.mem.Allocator) void {
            for (self.entries.items) |item| {
                allocator.free(item.name);
                allocator.free(item.value);
            }
            self.entries.clearRetainingCapacity();
            self.used = 0;
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

            const name_copy = try allocator.dupe(u8, name);
            errdefer allocator.free(name_copy);
            const value_copy = try allocator.dupe(u8, value);
            errdefer allocator.free(value_copy);

            try self.entries.append(allocator, undefined);
            var index = self.entries.items.len - 1;
            while (index > 0) : (index -= 1) {
                self.entries.items[index] = self.entries.items[index - 1];
            }
            self.entries.items[0] = .{ .name = name_copy, .value = value_copy };
            self.used += size;
            self.evictToLimit(allocator);
        }

        fn get(self: DynamicTable, dynamic_index: usize) ?HeaderField {
            if (dynamic_index >= self.entries.items.len) return null;
            return self.entries.items[dynamic_index];
        }

        fn findIndex(self: DynamicTable, name: []const u8, value: []const u8) ?u64 {
            for (self.entries.items, 0..) |item, i| {
                if (std.mem.eql(u8, item.name, name) and std.mem.eql(u8, item.value, value)) {
                    return @intCast(static_table.len + i + 1);
                }
            }
            return null;
        }

        fn findNameIndex(self: DynamicTable, name: []const u8) ?u64 {
            for (self.entries.items, 0..) |item, i| {
                if (std.mem.eql(u8, item.name, name)) return @intCast(static_table.len + i + 1);
            }
            return null;
        }

        fn evictToLimit(self: *DynamicTable, allocator: std.mem.Allocator) void {
            while (self.used > self.size_limit and self.entries.items.len != 0) {
                const removed = self.entries.orderedRemove(self.entries.items.len - 1);
                self.used -= entrySize(removed.name, removed.value);
                allocator.free(removed.name);
                allocator.free(removed.value);
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
    };

    pub const Encoder = struct {
        dynamic_table: DynamicTable = .{},

        pub fn deinit(self: *Encoder, allocator: std.mem.Allocator) void {
            self.dynamic_table.deinit(allocator);
            self.* = undefined;
        }

        pub fn setMaxDynamicTableSize(self: *Encoder, allocator: std.mem.Allocator, max_size: usize) void {
            self.dynamic_table.setLimit(allocator, max_size);
        }

        pub fn encodeBlock(self: *Encoder, list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const HeaderField) !void {
            for (fields) |field| {
                if (!field.never_index) {
                    if (findStaticIndex(field.name, field.value)) |index| {
                        try encodeInteger(list, allocator, 7, 0x80, index);
                        continue;
                    }
                    if (self.dynamic_table.findIndex(field.name, field.value)) |index| {
                        try encodeInteger(list, allocator, 7, 0x80, index);
                        continue;
                    }
                }

                const representation: u8 = if (field.never_index) 0x10 else 0x40;
                if (findStaticNameIndex(field.name) orelse self.dynamic_table.findNameIndex(field.name)) |name_index| {
                    if (field.never_index) {
                        try encodeInteger(list, allocator, 4, representation, name_index);
                    } else {
                        try encodeInteger(list, allocator, 6, representation, name_index);
                    }
                } else {
                    if (field.never_index) {
                        try encodeInteger(list, allocator, 4, representation, 0);
                    } else {
                        try encodeInteger(list, allocator, 6, representation, 0);
                    }
                    try encodeString(list, allocator, field.name);
                }
                try encodeString(list, allocator, field.value);
                if (!field.never_index) try self.dynamic_table.add(allocator, field.name, field.value);
            }
        }
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
        var encoder = Encoder{};
        defer encoder.deinit(allocator);
        try encoder.encodeBlock(list, allocator, fields);
    }

    /// Decode a self-contained HPACK field block.  For long-lived HTTP/2
    /// connections use `Hpack.Decoder` so incremental-indexing state survives
    /// across HEADERS/CONTINUATION blocks.  Decoder-owned string storage (for
    /// Huffman literals) is released with `freeDecodedFields`.
    pub fn decodeLiteralBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
        if (block.len != 0 and (block[0] & 0xe0) == 0x20) return error.HpackDynamicTableUnsupported;
        var dynamic_table = DynamicTable{};
        defer dynamic_table.deinit(allocator);
        return decodeBlockWithDynamicTable(allocator, block, &dynamic_table, default_dynamic_table_size);
    }

    pub fn freeDecodedFields(allocator: std.mem.Allocator, fields: []HeaderField) void {
        freeFieldStorages(allocator, fields);
        allocator.free(fields);
    }

    fn freeFieldStorages(allocator: std.mem.Allocator, fields: []HeaderField) void {
        for (fields) |field| {
            if (field.name_storage) |name| allocator.free(name);
            if (field.value_storage) |value| allocator.free(value);
        }
    }

    pub fn encodeHuffman(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

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
        return out.toOwnedSlice(allocator);
    }

    pub fn decodeHuffman(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        var code: u32 = 0;
        var code_len: u6 = 0;
        for (encoded) |byte| {
            var bit_index: u4 = 0;
            while (bit_index < 8) : (bit_index += 1) {
                const shift: u3 = @intCast(7 - bit_index);
                code = (code << 1) | @as(u32, (byte >> shift) & 1);
                code_len += 1;
                if (code_len > 30) return error.InvalidEncoding;
                if (huffmanSymbol(code, code_len)) |symbol| {
                    if (symbol == hpack_huffman.eos_symbol) return error.InvalidEncoding;
                    try out.append(allocator, @intCast(symbol));
                    code = 0;
                    code_len = 0;
                }
            }
        }

        if (code_len != 0) {
            // The only legal incomplete suffix is EOS-prefix padding of at most
            // seven one bits (RFC 7541 §5.2).
            if (code_len > 7) return error.InvalidEncoding;
            const padding = (@as(u32, 1) << @as(u5, @intCast(code_len))) - 1;
            if (code != padding) return error.InvalidEncoding;
        }
        return out.toOwnedSlice(allocator);
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
        const huffman = try encodeHuffman(allocator, value);
        defer allocator.free(huffman);
        if (huffman.len < value.len) {
            try encodeInteger(list, allocator, 7, 0x80, huffman.len);
            try list.appendSlice(allocator, huffman);
        } else {
            try encodeInteger(list, allocator, 7, 0x00, value.len);
            try list.appendSlice(allocator, value);
        }
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

    fn huffmanSymbol(code: u32, bits: u6) ?usize {
        for (hpack_huffman.encode_table, 0..) |entry, symbol| {
            if (entry.bits == bits and entry.code == code) return symbol;
        }
        return null;
    }

    fn entrySize(name: []const u8, value: []const u8) usize {
        return name.len + value.len + 32;
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

    try std.testing.expectError(error.InvalidStreamId, PushPromisePayload.write(&encoded, allocator, 0, 2, block.items, .{}));
    try std.testing.expectError(error.InvalidFrameSize, PushPromisePayload.parse(.{
        .header = .{ .length = 2, .frame_type = .push_promise, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0 },
    }));
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
        .{ .id = .initial_window_size, .value = std.math.maxInt(i31) },
        .{ .id = .max_frame_size, .value = 16_777_215 },
    });
    const parsed = try parseSettings(allocator, valid.items);
    defer allocator.free(parsed);
    try std.testing.expectEqual(@as(usize, 4), parsed.len);

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

test "HTTP/2 HPACK Huffman and dynamic table state" {
    const allocator = std.testing.allocator;

    const huffman = try Hpack.encodeHuffman(allocator, "www.example.com");
    defer allocator.free(huffman);
    try std.testing.expectEqualSlices(u8, &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff }, huffman);
    const decoded_huffman = try Hpack.decodeHuffman(allocator, huffman);
    defer allocator.free(decoded_huffman);
    try std.testing.expectEqualStrings("www.example.com", decoded_huffman);

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

test "HTTP/2 HPACK rejects unsupported or invalid dynamic table use" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.HpackDynamicTableUnsupported, Hpack.decodeLiteralBlock(allocator, &.{0xfe}));
    try std.testing.expectError(error.HpackDynamicTableUnsupported, Hpack.decodeLiteralBlock(allocator, &.{ 0x20, 0x00 }));

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    decoder.setMaxDynamicTableSize(allocator, 32);
    try std.testing.expectError(error.InvalidEncoding, decoder.decodeBlock(allocator, &.{ 0x3f, 0x02 }));
}

test {
    _ = runtime;
}
